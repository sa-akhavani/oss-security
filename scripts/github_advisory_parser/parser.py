import json
import csv
import sys

# Read input filename from argc
input_file = sys.argv[1]
data = json.load(open(input_file))

# Prepare data for the CSV
id = data.get('id')
source = "Github"
reviewed = data['database_specific'].get('github_reviewed')
publish_date = data.get('published')
cwe_ids = ', '.join(data['database_specific'].get('cwe_ids', []))
aliases = ', '.join(data.get('aliases', []))
summary = data.get('summary')
severity = data['database_specific'].get('severity')
ecosystem = data['affected'][0]['package'].get('ecosystem')
package_name = data['affected'][0]['package'].get('name')

# Collect version ranges
version_ranges = []
for affected in data['affected']:
    for version_range in affected['ranges']:
        introduced = ""
        fixed = ""
        for event in version_range['events']:
            if 'introduced' in event:
                introduced = event['introduced']
            if 'fixed' in event:
                fixed = event['fixed']
        version_ranges.append(f"[{introduced},{fixed})")

version_range = ''.join(version_ranges)

# Collect references
references = ', '.join(ref['url'] for ref in data.get('references', []))

# CSV rows
row = {
    'ID': id,
    'SOURCE': source,
    'REVIEWED': reviewed,
    'PUBLISH_DATE': publish_date,
    'CWE_IDS': cwe_ids,
    'ALIASES': aliases,
    'SUMMARY': summary,
    'SEVERITY': severity,
    'ECOSYSTEM': ecosystem,
    'PACKAGE_NAME': package_name,
    'VERSION_RANGE': version_range,
    'REFERENCES': references
}

# Output to CSV format
csv_writer = csv.DictWriter(sys.stdout, fieldnames=row.keys(), quoting=csv.QUOTE_ALL)
csv_writer.writeheader()
csv_writer.writerow(row)

