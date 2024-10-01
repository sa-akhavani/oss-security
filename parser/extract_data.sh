#!/bin/bash
NUM_ENTRIES=$(ls -l | wc -l)
for ((i = 0; i < $NUM_ENTRIES; i++)); do
  CURRENT_DIR=$(ls -t | head -n$i | tail -n1)
  # echo $CURRENT_DIR 
  FILE_NAME=$(ls $CURRENT_DIR -t | head -n1)
  # echo $FILE_NAME
  ./parse_report.sh $CURRENT_DIR/$FILE_NAME
done
