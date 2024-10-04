#!/bin/bash
# Get filename
INPUT_FILE=$1
# Parse the JSON file and extract the required fields using jq
ID=$(jq -r '.id' $INPUT_FILE)
SOURCE="Github"
REVIEWED=$(jq -r '.database_specific.github_reviewed' $INPUT_FILE)
PUBLISH_DATE=$(jq -r '.published' $INPUT_FILE)
CWE_IDS=$(jq -r '.database_specific.cwe_ids | @json' $INPUT_FILE)
ALIASES=$(jq -r '.aliases | @json' $INPUT_FILE)
SUMMARY=$(jq -r '.summary' $INPUT_FILE)
SEVERITY=$(jq -r '.database_specific.severity' $INPUT_FILE)
ECOSYSTEM=$(jq -r '.affected[0].package.ecosystem' $INPUT_FILE)
PACKAGE_NAME=$(jq -r '.affected[0].package.name' $INPUT_FILE)
# VERSION_INTRODUCE=$(jq -r '.affected[0].ranges[0].events[0].introduced' $INPUT_FILE)
# VERSION_LAST_AFFECTED=$(jq -r '.affected[0].ranges[0].events[0].last_affected' $INPUT_FILE)
VERSION_RANGE=$(jq -r '.affected[0].ranges[0].events | map(.introduced, .last_affected) | @json' $INPUT_FILE)
# VERSION_RANGE=$(echo $VERSION_RANGE | sed 's/null/"null"/g')

REFERENCES=$(jq -r '[.references[] | {type: .type, url: .url}] | @json' $INPUT_FILE)

# Echo parsed output
echo "\"$ID\", \"$SOURCE\", $REVIEWED, $CWE_IDS, $ALIASES, \"$SUMMARY\", \"$SEVERITY\", \"$ECOSYSTEM\", \"$PACKAGE_NAME\", $VERSION_RANGE, $REFERENCES"

