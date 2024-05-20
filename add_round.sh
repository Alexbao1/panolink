#!/bin/bash

# Input file
INPUT_FILE=$1

# Extract the number from the input file name
NUMBER=$(echo "$INPUT_FILE" | sed 's/.*results.csv_\([0-9]\{1,2\}\)/\1/')

# Replace the 17th column in the CSV file with the extracted number
tail -n +2 "$INPUT_FILE" | awk -F',' -v OFS=',' -v num="$NUMBER" '{if (NR>1) $17=num; print}' "$INPUT_FILE" > temp.csv && mv temp.csv "$INPUT_FILE"

echo "round $NUMBER result add_round 处理完成"