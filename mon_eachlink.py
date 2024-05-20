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
    InsertLinkRttInflationTable
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
probe_filepath = Path("each_link_monitor_probe.csv")
batch_size = 5

suspect_dst=set()
total_probes = 0

def replace_round_column(file_path, new_value):
    df = pd.read_csv(file_path)
    df['round'] = new_value
    df.to_csv(file_path, index=False)

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    with ClickHouseClient(**credentials) as client:
        
        CreateTables().execute(client, measurement_id)

        for round_ in range(1,1201):

            for i in range(batch_size):
                # Configure pycaracal
                config = prober.Config()
                config.set_output_file_csv(str(results_filepath))
                config.set_probing_rate(4_000)
                config.set_sniffer_wait_time(3)
                with probe_filepath.open() as f:
                    reader = csv.reader(f)
                    probes = (
                        Probe(format_ipv6(int(ip_address(row[0]))), int(row[1]), 33434, int(row[2]), 'udp', 0)
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
            
            InsertLinkRttInflationTable(round_=round_).execute(client, measurement_id)
            
    print(f"total_probes={total_probes}")
    print(f"""{measurement_id.replace("-", "_")}""")
    with open('output.txt', 'a') as f:
        print("monlink", file=f)
        print(f"total_probes={total_probes}", file=f)
        print(f"""{measurement_id.replace("-", "_")}""", file=f)
        print(file=f)