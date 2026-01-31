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

        # Create output directory structure
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "Vulnerable"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "Patched"), exist_ok=True)

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
                    return files, base_tag, head_tag
                elif response.status_code == 404:
                    continue  # Try next format combination

            print(f"  Could not find comparison between {base_version} and {head_version}")
            return None, None, None

        except Exception as e:
            print(f"  Error getting changed files: {e}")
            return None, None, None

    def clone_and_extract_files(
        self, owner, repo, version, changed_files, package_name, platform, 
        comparison_info, version_type
    ):
        """Clone repo at specific version and copy only changed files
        
        Args:
            version_type: Either 'Vulnerable' or 'Patched'
        """

        # Create directory structure: output_dir/Vulnerable|Patched/Platform/package
        version_type_dir = os.path.join(self.output_dir, version_type)
        platform_dir = os.path.join(version_type_dir, platform)
        os.makedirs(platform_dir, exist_ok=True)

        # Create folder name without version type suffix
        folder_name = f"{package_name.replace('/', '_')}_{version}"
        folder_path = os.path.join(platform_dir, folder_name)

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
                    metadata = f"""Advisory Information:
Package: {package_name}
Platform: {platform}
Version Type: {version_type}
Cloned Version: {version}
Repository: {owner}/{repo}
Changed Files: {len(changed_files)}

{comparison_info}

Files:
"""
                    for f in changed_files:
                        metadata += f"  - {f}\n"

                    with open(
                        os.path.join(folder_path, "VULNERABILITY_INFO.txt"), "w"
                    ) as f:
                        f.write(metadata)

                    print(f"  ✓ Successfully created {version_type}/{platform}/{folder_name}")
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
            original_fieldnames = reader.fieldnames  # Capture original headers

            for idx, row in enumerate(reader, 1):
                platform = row.get("Platform", "Unknown")
                package = row.get("Package", "Unknown")

                print(f"\n[{idx}] Processing {package} ({platform})...")

                # Extract version information
                prev_vulnerable = row.get("Prev Of First Vulnerable", "").strip()
                first_vulnerable = row.get("First Vulnerable Version", "").strip()
                prev_patched = row.get("Prev Of First Patched", "").strip()
                first_patched = row.get("First Patched Version", "").strip()

                # Parse GitHub URL
                github_url = row.get("GitHub URL", "")
                owner, repo = self.parse_github_url(github_url)

                if not owner or not repo:
                    print(f"  ✗ Could not parse GitHub URL: {github_url}")
                    results.append(
                        {
                            **row,
                            "Vulnerable Comparison": "",
                            "Vulnerable Base": "",
                            "Vulnerable Head": "",
                            "Vulnerable Files": 0,
                            "Vulnerable Folder": "",
                            "Patched Comparison": "",
                            "Patched Base": "",
                            "Patched Head": "",
                            "Patched Files": 0,
                            "Patched Folder": "",
                            "Status": "Failed - Invalid URL",
                        }
                    )
                    continue

                print(f"  Repository: {owner}/{repo}")

                # Initialize result tracking
                vulnerable_files = None
                vulnerable_base_tag = None
                vulnerable_head_tag = None
                vulnerable_comparison_type = None
                vulnerable_cloned_version = None
                vulnerable_folder = None

                patched_files = None
                patched_base_tag = None
                patched_head_tag = None
                patched_comparison_type = None
                patched_cloned_version = None
                patched_folder = None

                # ===== VULNERABLE VERSION =====
                print("\n  === Processing Vulnerable Version ===")
                
                # Try primary comparison: Prev Of First Vulnerable -> First Vulnerable Version
                if prev_vulnerable and first_vulnerable:
                    print(f"  Trying primary: {prev_vulnerable} -> {first_vulnerable}")
                    vulnerable_files, vulnerable_base_tag, vulnerable_head_tag = \
                        self.get_changed_files_between_versions(
                            owner, repo, prev_vulnerable, first_vulnerable
                        )

                    if vulnerable_files:
                        vulnerable_comparison_type = "Primary"
                        vulnerable_cloned_version = first_vulnerable
                        vulnerable_comparison_info = f"""Comparison Type: Primary (Vulnerability Introduction)
Base Version: {vulnerable_base_tag} (Prev Of First Vulnerable)
Head Version: {vulnerable_head_tag} (First Vulnerable Version)
Note: This version contains the code where the vulnerability was INTRODUCED."""
                    else:
                        print(f"  ✗ Primary comparison failed")

                # Try fallback: Prev Of First Patched (if primary failed)
                if not vulnerable_files and prev_patched and first_patched:
                    print(f"  Trying fallback: {prev_patched} -> {first_patched}")
                    vulnerable_files, vulnerable_base_tag, vulnerable_head_tag = \
                        self.get_changed_files_between_versions(
                            owner, repo, prev_patched, first_patched
                        )

                    if vulnerable_files:
                        vulnerable_comparison_type = "Fallback"
                        vulnerable_cloned_version = prev_patched
                        vulnerable_comparison_info = f"""Comparison Type: Fallback (Using Pre-Patch Version)
Base Version: {vulnerable_base_tag} (Prev Of First Patched)
Head Version: {vulnerable_head_tag} (First Patched Version)
Note: Primary comparison failed. This version contains the VULNERABLE code before the patch."""
                    else:
                        print(f"  ✗ Fallback comparison also failed")

                # Clone vulnerable version if we found changes
                if vulnerable_files:
                    vulnerable_folder = self.clone_and_extract_files(
                        owner, repo, vulnerable_cloned_version, vulnerable_files, 
                        package, platform, vulnerable_comparison_info, "Vulnerable"
                    )

                # ===== PATCHED VERSION =====
                print("\n  === Processing Patched Version ===")
                
                if prev_patched and first_patched:
                    print(f"  Getting patched version: {prev_patched} -> {first_patched}")
                    patched_files, patched_base_tag, patched_head_tag = \
                        self.get_changed_files_between_versions(
                            owner, repo, prev_patched, first_patched
                        )

                    if patched_files:
                        patched_comparison_type = "Patch"
                        patched_cloned_version = first_patched
                        patched_comparison_info = f"""Comparison Type: Patch (Vulnerability Fix)
Base Version: {patched_base_tag} (Prev Of First Patched - VULNERABLE)
Head Version: {patched_head_tag} (First Patched Version)
Note: This version contains the code where the vulnerability was FIXED."""

                        # Clone patched version
                        patched_folder = self.clone_and_extract_files(
                            owner, repo, patched_cloned_version, patched_files, 
                            package, platform, patched_comparison_info, "Patched"
                        )
                    else:
                        print(f"  ✗ Could not get patched version comparison")
                else:
                    print(f"  ⊘ No patched version information available")

                # Determine overall status
                if vulnerable_folder or patched_folder:
                    status = "Success"
                    if vulnerable_folder and patched_folder:
                        status = "Success - Both versions"
                    elif vulnerable_folder:
                        status = "Success - Vulnerable only"
                    elif patched_folder:
                        status = "Success - Patched only"
                else:
                    status = "Failed - No versions processed"

                # Add result
                results.append(
                    {
                        **row,
                        "Vulnerable Comparison": vulnerable_comparison_type or "",
                        "Vulnerable Base": vulnerable_base_tag or "",
                        "Vulnerable Head": vulnerable_head_tag or "",
                        "Vulnerable Files": len(vulnerable_files) if vulnerable_files else 0,
                        "Vulnerable Folder": vulnerable_folder or "",
                        "Patched Comparison": patched_comparison_type or "",
                        "Patched Base": patched_base_tag or "",
                        "Patched Head": patched_head_tag or "",
                        "Patched Files": len(patched_files) if patched_files else 0,
                        "Patched Folder": patched_folder or "",
                        "Status": status,
                    }
                )

                # Rate limiting
                time.sleep(1)

        # Save summary with original fieldnames
        self.save_summary(results, original_fieldnames)
        return results

    def save_summary(self, results, original_fieldnames):
        """Save processing summary to CSV with all original headers plus new ones"""
        summary_file = os.path.join(self.output_dir, "processing_summary.csv")

        # Combine original fieldnames with new ones
        new_fields = [
            "Vulnerable Comparison", "Vulnerable Base", "Vulnerable Head", 
            "Vulnerable Files", "Vulnerable Folder",
            "Patched Comparison", "Patched Base", "Patched Head", 
            "Patched Files", "Patched Folder",
            "Status"
        ]
        all_fieldnames = list(original_fieldnames) + new_fields

        with open(summary_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=all_fieldnames)
            writer.writeheader()

            for result in results:
                # Create a row with all fields
                row_data = {field: result.get(field, "") for field in all_fieldnames}
                writer.writerow(row_data)

        print(f"\n✓ Summary saved to {summary_file}")


# Usage
if __name__ == "__main__":
    # Configuration
    CSV_FILE = "vulnerability_plan.csv"  # Input CSV file
    OUTPUT_DIR = "vulnerability_analysis"

    # Get token from environment variable (recommended) or hardcode
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

    # Run the analyzer
    analyzer = VulnerabilityAnalyzer(CSV_FILE, OUTPUT_DIR, GITHUB_TOKEN)

    # Test token if provided
    if GITHUB_TOKEN:
        print("\nTesting GitHub token...")
        test_url = "https://api.github.com/user"
        response = requests.get(test_url, headers=analyzer.headers)

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
    results = analyzer.process_csv()

    # Print summary
    print("\n" + "=" * 60)
    print("PROCESSING COMPLETE")
    print("=" * 60)
    
    both_versions = sum(1 for r in results if r["Status"] == "Success - Both versions")
    vulnerable_only = sum(1 for r in results if r["Status"] == "Success - Vulnerable only")
    patched_only = sum(1 for r in results if r["Status"] == "Success - Patched only")
    failed = sum(1 for r in results if "Failed" in r["Status"])
    
    print(f"Total entries: {len(results)}")
    print(f"Success - Both versions: {both_versions}")
    print(f"Success - Vulnerable only: {vulnerable_only}")
    print(f"Success - Patched only: {patched_only}")
    print(f"Failed: {failed}")
    print(f"\nResults saved to: {OUTPUT_DIR}/")
