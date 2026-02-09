# Vulnerability Evolution and the Promise of Automated Gatekeeping in Open-Source Software

This repository contains datasets, scripts, and analysis code for the paper
"Vulnerability Evolution and the Promise of Automated Gatekeeping in Open-Source Software"
which is currently in submission to a security conference.


<!-- ### Citation -->
<!-- We hope this dataset helps future research on open-source software security research. -->
<!-- Please use the following format to cite this paper if you ended up using the dataset and codes in this repository. -->
<!---->
<!-- ```bibtex -->
<!---->
<!-- ``` -->


## Datasets

Here, we explain what each dataset folder contains and the CSV format we used to represent that data.

### Vulnerable Package Metadata
Detailed dataset containing extracted vulnerability and metadata information for each studied package.
`datasets/vulnerable_package_repository_info/`

```csv
ID,Package,CWE,Date,Platform,GitHub URL,Stars,Contributors,Dependencies,Dependents
```

### GitHub Advisory Parsed Data
Parsed data from the GitHub Advisory database from 2017 to 2025 in CSV format.
`datasets/github_advisory_parsed_data/`

```csv
ID,SOURCE,REVIEWED,PUBLISH_DATE,CWE_IDS,ALIASES,SUMMARY,SEVERITY,ECOSYSTEM,PACKAGE_NAME,VERSION_RANGE,REFERENCES
```

### Snyk Crawls
Vulnerability data crawled from Snyk.io, organized by ecosystem (npm, PyPI, Maven, etc.).
`datasets/snyk_crawls/`

### Libraries.io
Total package counts for each ecosystem from 2017 to 2025, with historical screenshots.
`datasets/libraries.io/`

### npm Data
Top downloaded npm packages and their metadata.
`datasets/npm-data/`

### Contributor History
GitHub package contributor history over time.
`datasets/contributor_history/`

```csv
REPO_NAME,GITHUB_URL,PERIOD_START,PERIOD_END,CONTRIBUTORS,CUMULATIVE_CONTRIBUTORS
```

### Version Crawls
Version information for packages across ecosystems (Composer, Crates, Go, Maven, NPM, NuGet, PyPI, RubyGems).
`datasets/version_crawls/`


## Scripts

Scripts used for data collection and processing:

- **GitHub Advisory Parser** (`scripts/github_advisory_parser/`): Parse GitHub Advisory database
- **Snyk Crawler** (`scripts/snyk_crawl.ipynb`): Crawl vulnerability data from Snyk.io
- **GitHub Contributor History** (`scripts/github_contributor_history/`): Extract contributor history from GitHub repositories
- **GitHub File Change Extractor** (`scripts/github_filechange_extractor/`): Extract file changes between vulnerable and patched versions
- **Data Merging** (`scripts/merge_data.ipynb`): Merge data from multiple sources into unified CSV format


## Analysis

Analysis notebooks for data exploration and visualization:

- `analysis/plots_and_stats.ipynb`: General statistics and plots
- `analysis/version_analysis.ipynb`: Version-related analysis
- `analysis/git_repo_attrbutes_analysis.ipynb`: Repository attributes analysis
- `analysis/total_pkgs_analysis.ipynb`: Total packages analysis


## LLM Analysis

LLM-based vulnerability detection analysis using code diffs:

- `llm_analysis/main.py`: Main pipeline for diff-based vulnerability analysis using LLMs
- `llm_analysis/diff_analysis_results/`: Results from LLM vulnerability detection experiments
- `llm_analysis/results_analysis.ipynb`: Analysis of LLM detection results
- `llm_analysis/cwe_classification_analysis.ipynb`: CWE classification analysis

### Diff Dataset

Code diffs between vulnerable and patched versions, organized by ecosystem. Each vulnerability folder contains:
- `diff.txt`: Unified diff between vulnerable and patched code
- `vulnerable.txt`: The vulnerable version of the code
- `patched.txt`: The patched version of the code

**Sample Dataset** (100 vulnerabilities): `llm_analysis/diff_dataset_sample/`

A representative sample of 100 vulnerabilities distributed across ecosystems:

**Full Dataset**: [Download from Google Drive](https://drive.google.com/file/d/1GLB_SqsQpMkdZ2lTBrU02Fq9_CZPXpwS/view?usp=sharing)

<!-- TODO: Upload diff_dataset.zip to Zenodo and update the link above -->