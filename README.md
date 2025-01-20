# Open Source, Open Threats?

This repository contains datasets, scripts, and files for the
"Open Source, Open Threats? Investigating Security Challenges in Open-Source Software"
paper which is currently in submission to a security conference.


<!-- ### Citation -->
<!-- We hope this dataset helps future research on open-source software security research. -->
<!-- Please use the following format to cite this paper if you ended up using the dataset and codes in this repository. -->
<!---->
<!-- ```bibtex -->
<!---->
<!-- ``` -->


### Dataset
Here, we explain what each dataset folder contains and the CSV format we used to represent that data.

#### Github Advisory Parsed Data
Parsed data from the Github advisory database from 2017 to 2025 in a csv format.
`github_advisory_parsed_data`

```csv
ID,SOURCE,REVIEWED,PUBLISH_DATE,CWE_IDS,ALIASES,SUMMARY,SEVERITY,ECOSYSTEM,PACKAGE_NAME,VERSION_RANGE,REFERENCES
```

#### Libraries.io
This includes the status of total packages in each ecosystem from 2017 to 2025.
`libraries.io`

#### npm data
Some of the top downloaded npm packages and their metadata.
`npm-data`

#### Vulnerable Package Metadata
This is a detailed dataset that contains our extracted vulnrability and metadata information for each studied package.
`vulnerable_package_repository_info`

```csv
ID,Package,CWE,Date,Platform,GitHub URL,Stars,Contributors,Dependencies,Dependents
```

#### Contributor History
Includes the studied Github package contributor history.
`contributor_history`

```csv
REPO_NAME,GITHUB_URL,PERIOD_START,PERIOD_END,CONTRIBUTORS,CUMULATIVE_CONTRIBUTORS
```

### Scripts
Scripts folder contains the scripts we used to crawl
`github advisory` and `snyk.io` data,
and also the code we used to extract the contributor history from github packages.
