#!/bin/bash
NUM_DIRS=$(ls -l | wc -l)
for ((i = 0; i < NUM_DIRS; i++)); do
  CURRENT_BATCH=$(ls -t | head -n$i | tail -n1)
  # echo $CURRENT_BATCH
  NUM_ENTRIES=$(ls $CURRENT_BATCH -l | wc -l)
  for ((j = 0; j < $NUM_ENTRIES; j++)); do
    CURRENT_DIR=$(ls $CURRENT_BATCH -t | head -n$j | tail -n1)
    # echo $CURRENT_DIR 
    FILE_NAME=$(ls $CURRENT_BATCH/$CURRENT_DIR -t | head -n1)
    # echo $FILE_NAME
    python3 parser.py $CURRENT_BATCH/$CURRENT_DIR/$FILE_NAME
  done
done


# NUM_ENTRIES=$(ls -l | wc -l)
# for ((i = 0; i < $NUM_ENTRIES; i++)); do
#   CURRENT_DIR=$(ls -t | head -n$i | tail -n1)
#   # echo $CURRENT_DIR 
#   FILE_NAME=$(ls $CURRENT_DIR -t | head -n1)
#   # echo $FILE_NAME
#   python3 parser.py $CURRENT_DIR/$FILE_NAME
# done
