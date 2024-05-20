import logging
from pathlib import Path
from uuid import uuid4

from pycaracal import prober,Probe
from pych_client import ClickHouseClient
from diamond_miner.format import format_ipv6

from diamond_miner.generators import probe_generator_parallel,probe_generator
from diamond_miner.insert import insert_mda_probe_counts, insert_probe_counts
from diamond_miner.queries import (
    CreateTables,
    CreateResultsView,
    CreateLinksView,
    GetLinks,
    InsertLinks,
    InsertPrefixes,
    InsertResults,
    InsertBGP,
    links_table,
)
from diamond_miner.get_target_as import calc_weights,get_subgraph,ttl_filter_group_mapping
from diamond_miner.insert_asprobe import insert_as_probe
from diamond_miner.utilities import get_result_path,run_process_dminer,prepare_bdrmapit,run_bdrmapit,run_add_round
import argparse
import time
import gc
# gc.set_debug(gc.DEBUG_LEAK)
# Configuration
credentials = {
    "base_url": "http://localhost:8123",
    "database": "default",
    "username": "default",
    "password": "",
}
measurement_id = str(uuid4())
probes_filepath = Path("probes.csv.zst")
results_filepath = Path("results.csv")
#bgp_filepath = Path("/home/hongyu/routeviews-rv2-20230317-1200.pfx2as")
bgp_filepath = Path("routeviews_AS")


# ICMP traceroute towards every /24 in 1.0.0.0/22 starting with 6 flows per prefix between TTLs 2-32
parser = argparse.ArgumentParser(description='Run panolink.py with a target prefix.')
parser.add_argument('--target_prefix', type=str, required=True, help='The target prefix to use.')
parser.add_argument('--change_round', type=int, required=False, default=0, help='The round to change asprobe distribution method')
args = parser.parse_args()
target_prefix = args.target_prefix
change_round = args.change_round
# target_prefix = "183.240.20.0/24"


prefixes = [(target_prefix, "udp", range(2, 30), 6)]
total_probes = 0
n_probes_list=[]
n_links_list=[]
bootstrap_rounds = 3
if __name__ == "__main__": 
    logging.basicConfig(level=logging.INFO)
    with ClickHouseClient(**credentials) as client:
        prepare_bdrmapit(client,measurement_id)
        CreateTables().execute(client, measurement_id)
        InsertBGP().execute(client, measurement_id, data=bgp_filepath.read_bytes())        
        candidates = calc_weights(client, measurement_id, target_prefix)
        # print(candidates)
        # time.sleep(5)
        for round_ in range(1, 25):
            logging.info("round=%s", round_)
            if round_ < bootstrap_rounds:
                if round_ > 1:
                    InsertResults().execute(
                        client, measurement_id, data=Path(get_result_path(results_filepath, round_-1)).read_bytes()
                    )
                    run_process_dminer(get_result_path(results_filepath, round_-1))
                # Compute the initial probes
                logging.info("INSERT FINISH!\n\n\n")
                insert_probe_counts(
                    client=client,
                    measurement_id=measurement_id,
                    round_=round_,
                    prefixes=[(target_prefix, "udp", range(2, 21), 3 * round_)],
                )
            else:
                run_add_round(get_result_path(results_filepath, round_-1))
                # Insert results from the previous round
                InsertResults().execute(
                    client, measurement_id, data=Path(get_result_path(results_filepath, round_-1)).read_bytes()
                )
                run_process_dminer(get_result_path(results_filepath, round_-1))
                # if(round_ <= 10):
                run_bdrmapit(client,measurement_id,round_-1)
                if round_ == bootstrap_rounds:
                    # TODO: run bdrmap and 
                    # create lookup_dict 
                    CreateResultsView().execute(client, measurement_id)
                InsertPrefixes().execute(client, measurement_id)
                InsertLinks(round_=round_-1).execute(client, measurement_id)
                len_links = client.json(f"select count(*) from (select distinct near_addr,far_addr from {links_table(measurement_id)})")
                print(f"links in round_{round_}: {len_links}")
                n_links_list.append(len_links)
                # if round_ == bootstrap_rounds:
                    # InsertMap().execute(client, measurement_id)
                    # map_edges = client.json(f"SELECT * FROM map__{measurement_id}".replace("-", "_"))
                if round_ == bootstrap_rounds:
                    get_subgraph(client,measurement_id)
                    ttl_filter_group_mapping(client,measurement_id)
                    #CreateLinksView().execute(client, measurement_id)
                    
                # Compute subsequent probes
                insert_mda_probe_counts(
                    client=client,
                    measurement_id=measurement_id,
                    previous_round=round_ - 1,
                )
                insert_as_probe(client, measurement_id,candidates,round_,change_round=change_round)

            # Write the probes to a file
            n_probes = probe_generator_parallel(
                filepath=probes_filepath,
                client=client,
                measurement_id=measurement_id,
                round_=round_,
            )
            total_probes += n_probes
            n_probes_list.append(n_probes)
            logging.info("n_probes=%s", n_probes)
            if n_probes < 25:
                break

            # Send the probes
            config = prober.Config()
            config.set_output_file_csv(get_result_path(results_filepath, round_))
            config.set_probing_rate(10_000)
            config.set_sniffer_wait_time(3)
            prober.probe(config, str(probes_filepath))

        links = GetLinks().execute(client, measurement_id)
        true_link = client.json(f"SELECT count(*) FROM (SELECT DISTINCT near_addr,far_addr FROM {links_table(measurement_id)} WHERE near_addr != toIPv6('::') AND far_addr != toIPv6('::'))")
        print(f"{len(links)} links, ", end='')
        print(f"{true_link} true links, ", end='')
        print(f"{total_probes} probes  ", end='')
        print(measurement_id.replace('-', '_'))
        print(n_probes_list)
        print(n_links_list)
         # Open the output file in append mode
        with open('output.txt', 'a') as f:
            # Use the print() function's 'file' parameter to write to the file
            print(target_prefix, end=' ', file=f)
            print(f"{len(links)} links, ", end='', file=f)
            print(f"{true_link} true links, ", end='', file=f)
            print(f"{total_probes} probes  ", end='', file=f)
            print(f"change_round: {change_round}  ", end='', file=f)
            print(measurement_id.replace('-', '_'), file=f)
            print(n_probes_list, file=f)
            print(n_links_list, file=f)
            print(file=f)
        filename = "/root/Panolink/wartsfile_panolink"

        # Open the file in read mode and get the first line
        with open(filename, 'r') as file:
            first_line = file.readline().rstrip('\n')

        # Open the file in write mode and overwrite it with the first line
        with open(filename, 'w') as file:
            file.write(first_line)

# gc.collect()  # Run garbage collection
# print(gc.garbage)