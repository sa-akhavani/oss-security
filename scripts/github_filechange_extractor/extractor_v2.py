import csv
import os
import re
import requests
import subprocess
import shutil
from pathlib import Path
import time
import ast


class VulnerabilityAnalyzer:
    def __init__(
        self, csv_file, output_dir="vulnerability_analysis", github_token=None
    ):
        self.csv_file = csv_file
        self.output_dir = output_dir
        self.github_token = github_token
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if github_token:
            self.headers["Authorization"] = f"token {github_token}"

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

    def parse_version_ranges(self, version_range_str):
        """
        Parse version range string which could be:
        - A single range: "[0,3.1.10)"
        - An array of ranges: "['[0,6.0.5)', '[6.1.0,6.1.8)', '[6.2.0,6.2.5)']"
        Returns a list of range strings
        """
        # Remove outer quotes if present
        version_range_str = version_range_str.strip().strip("\"'")

        # Check if it's an array format
        if version_range_str.startswith("[") and version_range_str.endswith("]"):
            try:
                # Try to parse as Python literal (array)
                ranges = ast.literal_eval(version_range_str)
                if isinstance(ranges, list):
                    return ranges
            except:
                pass

        # If not an array, treat as single range
        return [version_range_str]

    def is_unbounded_range(self, version_range):
        """
        Check if a version range has an unbounded lower bound.
        Examples:
            "[,2.3.1)" -> True (unbounded)
            "[0,2.3.1)" -> False (bounded, starts at 0)
            "[1.2.0,2.3.1)" -> False (bounded, starts at 1.2.0)
        """
        # Remove brackets and parentheses
        cleaned = version_range.strip("[]() ")

        # Check if it starts with a comma (unbounded lower bound)
        if cleaned.startswith(","):
            return True

        # Check if it starts with comparison operators without version
        if cleaned.startswith("<") or cleaned.startswith("<="):
            return True

        return False

    def extract_first_version_from_single_range(self, version_range):
        """
        Extract the FIRST (minimum) affected version from a single version range.
        Examples:
            "[0,3.1.10)" -> "0"
            "[1.2.0,1.5.0]" -> "1.2.0"
            ">=2.0.0,<2.5.1" -> "2.0.0"
            "<1.2.3" -> None (unbounded)
            "[,2.3.1)" -> None (unbounded)
        Returns None for unbounded ranges.
        """
        # Skip unbounded ranges
        if self.is_unbounded_range(version_range):
            return None

        # Remove brackets and parentheses
        cleaned = version_range.strip("[]() ")

        # Handle different formats
        # Format 1: [start,end) or [start,end]
        if "," in cleaned:
            first_part = cleaned.split(",")[0].strip()
            # Remove any comparison operators
            first_part = re.sub(r"^[><=]+", "", first_part)
            return first_part if first_part else None

        # Format 2: >=version or >version (first version is the one specified)
        if cleaned.startswith(">=") or cleaned.startswith(">"):
            version_match = re.search(r"[><=]+(.+)", cleaned)
            if version_match:
                return version_match.group(1).strip()

        # Format 3: <version or <=version (unbounded, already handled above)
        if cleaned.startswith("<=") or cleaned.startswith("<"):
            return None

        # Format 4: Just a version number
        version_pattern = r"\d+(?:\.\d+)*(?:[.-][a-zA-Z0-9]+)?"
        match = re.search(version_pattern, cleaned)
        if match:
            return match.group(0)

        return None

    def version_tuple(self, version_str):
        """
        Convert version string to tuple for comparison.
        Examples:
            "0" -> (0,)
            "1.2.3" -> (1, 2, 3)
            "6.1.0" -> (6, 1, 0)
        """
        try:
            # Split by dots and convert to integers
            parts = version_str.split(".")
            return tuple(int(p) if p.isdigit() else 0 for p in parts)
        except:
            return (0,)

    def extract_version_from_range(self, version_range_str):
        """
        Extract the SMALLEST first affected version from version range(s).
        Prefers bounded ranges over unbounded ones.

        Examples:
            "[0,3.1.10)" -> "0"
            "['[,2.3.1)', '[2.4.0,2.4.5)', '[3.0.0,3.1.0)']" -> "2.4.0" (skips unbounded)
            "['[0,6.0.5)', '[6.1.0,6.1.8)', '[6.2.0,6.2.5)']" -> "0"
            "['[,2.3.1)']" -> "0" (only unbounded, fallback to 0)
        """
        # Parse the version ranges
        ranges = self.parse_version_ranges(version_range_str)

        # Extract first version from each range, separating bounded and unbounded
        bounded_versions = []
        has_unbounded = False

        for range_str in ranges:
            if self.is_unbounded_range(range_str):
                has_unbounded = True
            else:
                version = self.extract_first_version_from_single_range(range_str)
                if version:
                    bounded_versions.append(version)

        # If we have bounded versions, use the minimum of those
        if bounded_versions:
            min_version = min(bounded_versions, key=self.version_tuple)
            return min_version

        # If only unbounded ranges exist, return "0" as fallback
        if has_unbounded:
            return "0"

        return None

    def parse_github_url(self, github_url):
        """
        Extract owner and repo from GitHub URL.
        Example: https://github.com/thorsten/phpmyfaq -> ('thorsten', 'phpmyfaq')
        """
        pattern = r"github\.com[/:]([^/]+)/([^/\.]+)"
        match = re.search(pattern, github_url)

        if match:
            return match.group(1), match.group(2)
        return None, None

    def get_changed_files(self, owner, repo, version):
        """Get files changed in a version compared to its parent commit"""
        try:
            # Try with 'v' prefix first (e.g., v3.1.10)
            for tag_format in [f"v{version}", version]:
                compare_url = f"https://api.github.com/repos/{owner}/{repo}/compare/{tag_format}^...{tag_format}"
                response = requests.get(compare_url, headers=self.headers)

                if response.status_code == 200:
                    data = response.json()
                    return [file["filename"] for file in data["files"]]
                elif response.status_code == 404:
                    continue  # Try next format
                else:
                    print(
                        f"  API Error {response.status_code} for {owner}/{repo}@{tag_format}"
                    )
                    return None

            print(f"  Tag not found for version {version}")
            return None

        except Exception as e:
            print(f"  Error getting changed files: {e}")
            return None

    def clone_and_extract_files(
        self, owner, repo, version, changed_files, package_name
    ):
        """Clone repo at specific version and copy only changed files"""

        # Create folder name
        folder_name = f"{package_name.replace('/', '_')}_{version}"
        folder_path = os.path.join(self.output_dir, folder_name)

        # Skip if already processed
        if os.path.exists(folder_path):
            print(f"  Folder already exists, skipping...")
            return folder_path

        os.makedirs(folder_path, exist_ok=True)

        # Create temporary directory for cloning
        temp_clone_dir = os.path.join(self.output_dir, f"_temp_{folder_name}")

        try:
            # Try both version formats
            for tag_format in [f"v{version}", version]:
                repo_url = f"https://github.com/{owner}/{repo}.git"

                print(f"  Cloning {owner}/{repo} at tag {tag_format}...")
                result = subprocess.run(
                    [
                        "git",
                        "clone",
                        "--depth",
                        "1",
                        "--branch",
                        tag_format,
                        repo_url,
                        temp_clone_dir,
                    ],
                    capture_output=True,
                    text=True,
                )

                if result.returncode == 0:
                    # Clone successful, now copy changed files
                    print(f"  Copying {len(changed_files)} changed files...")

                    for file_path in changed_files:
                        src = os.path.join(temp_clone_dir, file_path)
                        dst = os.path.join(folder_path, file_path)

                        if os.path.exists(src):
                            # Create directory structure
                            os.makedirs(os.path.dirname(dst), exist_ok=True)
                            shutil.copy2(src, dst)
                        else:
                            print(f"    Warning: File not found: {file_path}")

                    # Create metadata file
                    metadata = f"""Advisory Information:
Package: {package_name}
Version: {version}
Repository: {owner}/{repo}
Changed Files: {len(changed_files)}

Files:
"""
                    for f in changed_files:
                        metadata += f"  - {f}\n"

                    with open(
                        os.path.join(folder_path, "VULNERABILITY_INFO.txt"), "w"
                    ) as f:
                        f.write(metadata)

                    print(f"  ✓ Successfully created {folder_name}")
                    return folder_path

            print(f"  ✗ Failed to clone repository")
            return None

        except Exception as e:
            print(f"  Error during clone/copy: {e}")
            return None
        finally:
            # Clean up temporary clone directory
            if os.path.exists(temp_clone_dir):
                shutil.rmtree(temp_clone_dir, ignore_errors=True)

    def process_csv(self):
        """Main processing function"""
        results = []

        with open(self.csv_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for idx, row in enumerate(reader, 1):
                print(f"\n[{idx}] Processing {row['Package']}...")
                print(f"  Version Range: {row['Version Range']}")

                # Extract information
                version = self.extract_version_from_range(row["Version Range"])
                owner, repo = self.parse_github_url(row["GitHub URL"])

                if not version:
                    print(f"  ✗ Could not extract version from: {row['Version Range']}")
                    results.append(
                        {**row, "Status": "Failed - No version", "Folder": None}
                    )
                    continue

                if not owner or not repo:
                    print(f"  ✗ Could not parse GitHub URL: {row['GitHub URL']}")
                    results.append(
                        {**row, "Status": "Failed - Invalid URL", "Folder": None}
                    )
                    continue

                print(f"  Repository: {owner}/{repo}")
                print(f"  First affected version: {version}")

                # Get changed files
                changed_files = self.get_changed_files(owner, repo, version)

                if changed_files is None:
                    results.append(
                        {**row, "Status": "Failed - API Error", "Folder": None}
                    )
                    continue

                if not changed_files:
                    print(f"  No files changed (or tag not found)")
                    results.append(
                        {**row, "Status": "No changes found", "Folder": None}
                    )
                    continue

                print(f"  Found {len(changed_files)} changed files")

                # Clone and extract files
                folder_path = self.clone_and_extract_files(
                    owner, repo, version, changed_files, row["Package"]
                )

                if folder_path:
                    results.append(
                        {
                            **row,
                            "Status": "Success",
                            "Folder": folder_path,
                            "Files": len(changed_files),
                        }
                    )
                else:
                    results.append(
                        {**row, "Status": "Failed - Clone error", "Folder": None}
                    )

                # Rate limiting
                time.sleep(1)

        # Save summary
        self.save_summary(results)
        return results

    def save_summary(self, results):
        """Save processing summary to CSV"""
        summary_file = os.path.join(self.output_dir, "processing_summary.csv")

        fieldnames = [
            "ID",
            "Package",
            "CVE",
            "Version Range",
            "Extracted Version",
            "Files",
            "Status",
            "Folder",
        ]

        with open(summary_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for result in results:
                writer.writerow(
                    {
                        "ID": result.get("ID", ""),
                        "Package": result.get("Package", ""),
                        "CVE": result.get("CVE", ""),
                        "Version Range": result.get("Version Range", ""),
                        "Extracted Version": self.extract_version_from_range(
                            result.get("Version Range", "")
                        ),
                        "Files": result.get("Files", 0),
                        "Status": result.get("Status", ""),
                        "Folder": result.get("Folder", ""),
                    }
                )

        print(f"\n✓ Summary saved to {summary_file}")


# Usage
if __name__ == "__main__":
    # Configuration
    CSV_FILE = "vulnerabilities.csv"  # Your CSV file
    OUTPUT_DIR = "vulnerability_analysis"
    GITHUB_TOKEN = (
        "your_github_token_here"  # Get from https://github.com/settings/tokens
    )

    # Run the analyzer
    analyzer = VulnerabilityAnalyzer(CSV_FILE, OUTPUT_DIR, GITHUB_TOKEN)

    # Test version extraction with some examples
    print("Testing version extraction:")
    print("=" * 60)
    test_cases = [
        "[0,3.1.10)",
        "['[,2.3.1)', '[2.4.0,2.4.5)', '[3.0.0,3.1.0)']",
        "['[0,6.0.5)', '[6.1.0,6.1.8)', '[6.2.0,6.2.5)']",
        "[,2.3.1)",
        "['[,2.3.1)']",
        "[1.2.0,1.5.0]",
        "<5.0.0",
    ]
    for test in test_cases:
        result = analyzer.extract_version_from_range(test)
        print(f"{test[:60]:60} -> {result}")
    print("=" * 60)
    print()

    # Process the CSV
    results = analyzer.process_csv()

    # Print summary
    print("\n" + "=" * 60)
    print("PROCESSING COMPLETE")
    print("=" * 60)
    success = sum(1 for r in results if r["Status"] == "Success")
    print(f"Total entries: {len(results)}")
    print(f"Successful: {success}")
    print(f"Failed: {len(results) - success}")
    print(f"\nResults saved to: {OUTPUT_DIR}/")


## Test Output:
# Testing version extraction:
# ============================================================
# [0,3.1.10)                                                   -> 0
# ['[,2.3.1)', '[2.4.0,2.4.5)', '[3.0.0,3.1.0)']               -> 2.4.0
# ['[0,6.0.5)', '[6.1.0,6.1.8)', '[6.2.0,6.2.5)']              -> 0
# [,2.3.1)                                                     -> 0
# ['[,2.3.1)']                                                 -> 0
# [1.2.0,1.5.0]                                                -> 1.2.0
# <5.0.0                                                       -> 0
# ============================================================
#
