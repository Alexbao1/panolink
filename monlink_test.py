import logging
from pathlib import Path
from uuid import uuid4

from pycaracal import Probe, prober
from pych_client import ClickHouseClient

from diamond_miner.format import format_ipv6
from diamond_miner.generators import probe_generator
from diamond_miner.queries import (
    CreateTables,
    InsertResults,
    InsertRtt,
    InsertFarEnd,
    InsertConjest,
    InsertLinkRttInflationTable,
    GetFaultLink,
)

import csv
import pandas as pd
import time
from datetime import datetime
from ipaddress import ip_address, IPv6Address
# Configuration
credentials = {
    "base_url": "http://localhost:8123",
    "database": "default",
    "username": "default",
    "password": "",
}
measurement_id = str(uuid4())
results_filepath = Path("mon_results.csv")
set_cover_filepath = Path("tmp_probe.csv")
prepare_probe_filepath = Path("prepare_probe.csv")
suspect_dst_filepath=Path("suspect_dst.csv")
batch_size = 5

suspect_dst=set()
total_probes = 0

min_fault_round=10
std_threshold=70

def replace_round_column(file_path, new_value):
    df = pd.read_csv(file_path)
    df['round'] = new_value
    df.to_csv(file_path, index=False)

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    with open('suspect_dst.csv', 'w') as file:
        pass
    with ClickHouseClient(**credentials) as client:
        
        CreateTables().execute(client, measurement_id)
        InsertFarEnd().execute(client, measurement_id, data=set_cover_filepath.read_bytes())

        for round_ in range(1,2401):
            with prepare_probe_filepath.open('w') as f1, set_cover_filepath.open('r') as f2:
                reader = csv.reader(f2)
                for row in reader:
                    if((ip_address(row[0])), int(row[1])) in suspect_dst or round_%40==1 or round_%40==2:
                        for i in range(2,int(row[2])+1):
                            f1.write(f"{int(ip_address(row[0]))},{row[1]},{i}\n")
                    else:
                        f1.write(f"{int(ip_address(row[0]))},{row[1]},{int(row[2])}\n")
            
            for i in range(batch_size):
                # Configure pycaracal
                config = prober.Config()
                config.set_output_file_csv(str(results_filepath))
                config.set_probing_rate(4_000)
                config.set_sniffer_wait_time(2)
                with prepare_probe_filepath.open() as f:
                    reader = csv.reader(f)
            
                    probes = (
                        Probe(format_ipv6(int(row[0])), int(row[1]), 33434, int(row[2]), 'udp', 0)
                        for row in reader 
                    )
                    prober_stats, sniffer_stats, pcap_stats = prober.probe(config, probes)
                    # Display some statistics from pycaracal.
                    print(f"round {round_}  {i+1}/{batch_size}")
                    print(f"{prober_stats.read} probes read")
                    total_probes += prober_stats.read
                    print(f"{sniffer_stats.received_count} probes received")

                replace_round_column('mon_results.csv', round_)
                InsertResults().execute(
                    client, measurement_id, data=results_filepath.read_bytes()
                )
            
            InsertRtt(round_=round_).execute(client, measurement_id)
            if round_>=min_fault_round:
                client.json(InsertConjest(round_=round_, std_threshold=std_threshold, min_fault_round = min_fault_round).statement_test_insert(measurement_id))
            if round_ >=2*min_fault_round:
                suspect = client.json(InsertConjest(round_=round_, std_threshold=std_threshold, min_fault_round = min_fault_round).statement_test_suspect_query(measurement_id))
                for row in suspect:
                    suspect_dst.add((ip_address(row['probe_dst_addr']), row['probe_src_port']))
                innocent = client.json(InsertConjest(round_=round_, std_threshold=std_threshold, min_fault_round = min_fault_round).statement_test_innocent_query(measurement_id))
                for row in innocent:
                    if (ip_address(row['probe_dst_addr']), row['probe_src_port']) in suspect_dst:
                        suspect_dst.remove((ip_address(row['probe_dst_addr']), row['probe_src_port']))
            InsertLinkRttInflationTable(round_=round_).execute(client, measurement_id)
            GetFaultLink(round_=round_, min_fault_round=min_fault_round).execute(client, measurement_id)
    print(f"total_probes={total_probes}")
    print(f"""{measurement_id.replace("-", "_")}""")
    with open('output.txt', 'a') as f:
        print("monlink", file=f)
        print(f"total_probes={total_probes}", file=f)
        print(f"""{measurement_id.replace("-", "_")}""", file=f)
        print(file=f)