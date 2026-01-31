import csv
import os
import re
import requests
import subprocess
import shutil
from pathlib import Path
import time


class FourVersionExtractor:
    def __init__(
        self, csv_file, output_dir="vulnerability_analysis_4versions", github_token=None
    ):
        self.csv_file = csv_file
        self.output_dir = output_dir
        self.github_token = github_token
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if github_token:
            self.headers["Authorization"] = f"token {github_token}"

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

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

    def get_changed_files_between_versions(self, owner, repo, base_version, head_version):
        """Get files changed between two versions"""
        try:
            # Try different tag format combinations
            tag_combinations = [
                (f"v{base_version}", f"v{head_version}"),
                (base_version, head_version),
                (f"v{base_version}", head_version),
                (base_version, f"v{head_version}"),
            ]

            for base_tag, head_tag in tag_combinations:
                compare_url = f"https://api.github.com/repos/{owner}/{repo}/compare/{base_tag}...{head_tag}"
                response = requests.get(compare_url, headers=self.headers)

                if response.status_code == 200:
                    data = response.json()
                    files = [file["filename"] for file in data["files"]]
                    print(f"  Found {len(files)} changed files between {base_tag} and {head_tag}")
                    return files
                elif response.status_code == 404:
                    continue  # Try next format combination

            print(f"  Could not find comparison between {base_version} and {head_version}")
            return None

        except Exception as e:
            print(f"  Error getting changed files: {e}")
            return None

    def clone_and_extract_files(
        self, owner, repo, version, changed_files, package_name, platform, version_type
    ):
        """Clone repo at specific version and copy only changed files
        
        Args:
            version_type: One of 'Prev_Patched', 'First_Patched', 'Prev_Vulnerable', 'First_Vulnerable'
        """

        # Create directory structure: Platform/version_type/package_version
        platform_dir = os.path.join(self.output_dir, platform)
        version_type_dir = os.path.join(platform_dir, version_type)
        os.makedirs(version_type_dir, exist_ok=True)

        # Create folder name
        folder_name = f"{package_name.replace('/', '_')}_{version}"
        folder_path = os.path.join(version_type_dir, folder_name)

        # Skip if already processed
        if os.path.exists(folder_path):
            print(f"  Folder already exists, skipping...")
            return folder_path

        os.makedirs(folder_path, exist_ok=True)

        # Create temporary directory for cloning
        temp_clone_dir = os.path.join(self.output_dir, f"_temp_{version_type}_{folder_name}")

        try:
            # Try both version formats
            for tag_format in [f"v{version}", version]:
                repo_url = f"https://github.com/{owner}/{repo}.git"

                print(f"  Cloning {owner}/{repo} at tag {tag_format} ({version_type})...")
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
                    metadata = f"""Version Information:
Package: {package_name}
Platform: {platform}
Version Type: {version_type}
Version: {version}
Repository: {owner}/{repo}
Changed Files: {len(changed_files)}

Files:
"""
                    for f in changed_files:
                        metadata += f"  - {f}\n"

                    with open(
                        os.path.join(folder_path, "VERSION_INFO.txt"), "w"
                    ) as f:
                        f.write(metadata)

                    print(f"  ✓ Successfully created {platform}/{version_type}/{folder_name}")
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
        processed_count = 0
        skipped_count = 0

        with open(self.csv_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            original_fieldnames = reader.fieldnames

            for idx, row in enumerate(reader, 1):
                platform = row.get("Platform", "Unknown")
                package = row.get("Package", "Unknown")

                print(f"\n[{idx}] Processing {package} ({platform})...")

                # Extract all 4 versions
                prev_vulnerable = row.get("Prev Of First Vulnerable", "").strip()
                first_vulnerable = row.get("First Vulnerable Version", "").strip()
                prev_patched = row.get("Prev Of First Patched", "").strip()
                first_patched = row.get("First Patched Version", "").strip()

                # Check if all 4 versions exist
                if not all([prev_vulnerable, first_vulnerable, prev_patched, first_patched]):
                    print(f"  ⊘ Skipping - Not all 4 versions available")
                    print(f"     Prev Vulnerable: {'✓' if prev_vulnerable else '✗'}")
                    print(f"     First Vulnerable: {'✓' if first_vulnerable else '✗'}")
                    print(f"     Prev Patched: {'✓' if prev_patched else '✗'}")
                    print(f"     First Patched: {'✓' if first_patched else '✗'}")
                    skipped_count += 1
                    results.append({**row, "4Version Status": "Skipped - Missing versions"})
                    continue

                # Parse GitHub URL
                github_url = row.get("GitHub URL", "")
                owner, repo = self.parse_github_url(github_url)

                if not owner or not repo:
                    print(f"  ✗ Could not parse GitHub URL: {github_url}")
                    skipped_count += 1
                    results.append({**row, "4Version Status": "Failed - Invalid URL"})
                    continue

                print(f"  Repository: {owner}/{repo}")
                print(f"  Versions: PV={prev_vulnerable}, FV={first_vulnerable}, PP={prev_patched}, FP={first_patched}")

                # Get changed files for vulnerable comparison
                print("\n  === Getting vulnerable comparison ===")
                vulnerable_changed_files = self.get_changed_files_between_versions(
                    owner, repo, prev_vulnerable, first_vulnerable
                )

                if not vulnerable_changed_files:
                    print(f"  ✗ Could not get vulnerable comparison")
                    skipped_count += 1
                    results.append({**row, "4Version Status": "Failed - No vulnerable changes"})
                    continue

                # Get changed files for patched comparison
                print("\n  === Getting patched comparison ===")
                patched_changed_files = self.get_changed_files_between_versions(
                    owner, repo, prev_patched, first_patched
                )

                if not patched_changed_files:
                    print(f"  ✗ Could not get patched comparison")
                    skipped_count += 1
                    results.append({**row, "4Version Status": "Failed - No patched changes"})
                    continue

                # Now clone all 4 versions
                success = True

                print("\n  === Cloning 4 versions ===")

                # 1. Prev_Vulnerable
                prev_vulnerable_folder = self.clone_and_extract_files(
                    owner, repo, prev_vulnerable, vulnerable_changed_files, 
                    package, platform, "Prev_Vulnerable"
                )
                if not prev_vulnerable_folder:
                    success = False

                # 2. First_Vulnerable
                first_vulnerable_folder = self.clone_and_extract_files(
                    owner, repo, first_vulnerable, vulnerable_changed_files, 
                    package, platform, "First_Vulnerable"
                )
                if not first_vulnerable_folder:
                    success = False

                # 3. Prev_Patched
                prev_patched_folder = self.clone_and_extract_files(
                    owner, repo, prev_patched, patched_changed_files, 
                    package, platform, "Prev_Patched"
                )
                if not prev_patched_folder:
                    success = False

                # 4. First_Patched
                first_patched_folder = self.clone_and_extract_files(
                    owner, repo, first_patched, patched_changed_files, 
                    package, platform, "First_Patched"
                )
                if not first_patched_folder:
                    success = False

                if success:
                    processed_count += 1
                    results.append({**row, "4Version Status": "Success - All 4 versions"})
                    print(f"\n  ✓✓✓ Successfully processed all 4 versions")
                else:
                    skipped_count += 1
                    results.append({**row, "4Version Status": "Partial - Some versions failed"})
                    print(f"\n  ⚠ Some versions failed")

                # Rate limiting
                time.sleep(1)

        # Save summary
        self.save_summary(results, original_fieldnames)
        return results, processed_count, skipped_count

    def save_summary(self, results, original_fieldnames):
        """Save processing summary to CSV"""
        summary_file = os.path.join(self.output_dir, "4version_summary.csv")

        # Add new field
        new_fields = ["4Version Status"]
        all_fieldnames = list(original_fieldnames) + new_fields

        with open(summary_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=all_fieldnames)
            writer.writeheader()

            for result in results:
                row_data = {field: result.get(field, "") for field in all_fieldnames}
                writer.writerow(row_data)

        print(f"\n✓ Summary saved to {summary_file}")


# Usage
if __name__ == "__main__":
    # Configuration
    INPUT_CSV = "vulnerability_analysis/processing_summary.csv"  # From previous script
    OUTPUT_DIR = "vulnerability_analysis_4versions"

    # Get token from environment variable
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

    if not GITHUB_TOKEN:
        print("=" * 60)
        print("WARNING: No GitHub token found!")
        print("=" * 60)
        print("You can:")
        print("1. Set environment variable: export GITHUB_TOKEN='your_token'")
        print("2. Hardcode it (not recommended): GITHUB_TOKEN = 'ghp_...'")
        print("3. Continue without token (rate limited to 60 requests/hour)")
        print()
        response = input("Continue without token? (y/N): ")
        if response.lower() != "y":
            print("Get a token at: https://github.com/settings/tokens")
            exit(1)

    # Check if input file exists
    if not os.path.exists(INPUT_CSV):
        print(f"Error: Input file not found: {INPUT_CSV}")
        print("Please run the first extractor script to generate processing_summary.csv")
        exit(1)

    # Run the extractor
    extractor = FourVersionExtractor(INPUT_CSV, OUTPUT_DIR, GITHUB_TOKEN)

    # Test token if provided
    if GITHUB_TOKEN:
        print("\nTesting GitHub token...")
        test_url = "https://api.github.com/user"
        response = requests.get(test_url, headers=extractor.headers)

        if response.status_code == 200:
            user_data = response.json()
            print(f"✓ Authenticated as: {user_data['login']}")
            print(
                f"✓ Rate limit: {response.headers.get('X-RateLimit-Remaining')}/5000\n"
            )
        else:
            print(f"✗ Token validation failed: {response.status_code}")
            print("Get a new token at: https://github.com/settings/tokens")
            exit(1)

    # Process the CSV
    results, processed, skipped = extractor.process_csv()

    # Print summary
    print("\n" + "=" * 60)
    print("PROCESSING COMPLETE")
    print("=" * 60)
    print(f"Total entries: {len(results)}")
    print(f"Successfully processed (all 4 versions): {processed}")
    print(f"Skipped/Failed: {skipped}")
    print(f"\nResults saved to: {OUTPUT_DIR}/")

# **Output structure:**
# vulnerability_analysis_4versions/
# ├── NuGet/
# │   ├── Prev_Patched/
# │   │   └── Package.Name_1.2.3/
# │   │       ├── file1.cs
# │   │       └── VERSION_INFO.txt
# │   ├── First_Patched/
# │   │   └── Package.Name_1.2.5/
# │   ├── Prev_Vulnerable/
# │   │   └── Package.Name_1.2.2/
# │   └── First_Vulnerable/
# │       └── Package.Name_1.2.3/
# ├── Maven/
# │   ├── Prev_Patched/
# │   ├── First_Patched/
# │   ├── Prev_Vulnerable/
# │   └── First_Vulnerable/
# └── 4version_summary.csv
