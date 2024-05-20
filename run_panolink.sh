#!/bin/bash

# target_prefixes=("104.0.0.0/12" "104.16.0.0/12" "104.32.0.0/12" "104.48.0.0/12" "104.64.0.0/12" "104.80.0.0/12" "104.96.0.0/12" "104.112.0.0/12" "104.128.0.0/12" "104.144.0.0/12" "104.160.0.0/12" "104.176.0.0/12" "104.192.0.0/12" "104.208.0.0/12" "104.224.0.0/12" "104.240.0.0/12")
target_prefixes=("104.64.0.0/12" )
for target_prefix in "${target_prefixes[@]}"; do
    python ./panolink.py --target_prefix $target_prefix --change_round 7
done

# for i in {7..7}; do
#     # Create the IP address string
#     target_prefix="104.0.0.0/12"
#     python ./panolink.py --target_prefix $target_prefix --change_round $i
# done