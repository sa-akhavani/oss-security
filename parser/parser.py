import json
import csv
import sys
# read input filename from argc
input_file = sys.argv[1]
data = json.load(open(input_file))

# Prepare data for the CSV
id = data.get('id')
source = "Github"
reviewed = data['database_specific'].get('github_reviewed')
publish_date = data.get('published')
cwe_ids = str(data['database_specific'].get('cwe_ids'))
aliases = str(data.get('aliases'))
summary = data.get('summary')
severity = data['database_specific'].get('severity')
ecosystem = data['affected'][0]['package'].get('ecosystem')
package_name = data['affected'][0]['package'].get('name')
version_range = str([event.get('introduced', '') for event in data['affected'][0]['ranges'][0]['events']])
version_range += str([event.get('last_affected', '') for event in data['affected'][0]['ranges'][0]['events']])

# Collect references
references = str(data.get('references'))

# CSV header
# header = ['ID', 'SOURCE', 'REVIEWED', 'PUBLISH_DATE', 'CWE_IDS', 'ALIASES', 'SUMMARY', 'SEVERITY', 'ECOSYSTEM', 'PACKAGE_NAME', 'VERSION_RANGE', 'REFERENCES']

# CSV rows
# row = [id, source, reviewed, publish_date, cwe_ids, aliases, summary, severity, ecosystem, package_name, version_range, references]

# Prepare output rows
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

# Print header
# print(','.join(header))

# Print row (CSV values)
# print(','.join(f'"{item}"' if ',' in str(item) or '"' in str(item) else str(item) for item in row))

# print(header)
# print(row)
# # Write to CSV
# with open('output.csv', 'w', newline='') as file:
#     writer = csv.writer(file)
#     writer.writerow(header)
#     writer.writerows(rows)
# print("done")


# Output to CSV format
csv_writer = csv.DictWriter(sys.stdout, fieldnames=row.keys(), quoting=csv.QUOTE_ALL)

# Write the header
# csv_writer.writeheader()

# Write the row
csv_writer.writerow(row)
