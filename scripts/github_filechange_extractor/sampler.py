import csv
import random
from collections import defaultdict


def sample_vulnerabilities(input_file, output_file, sample_size=200):
    """
    Sample a specified number of entries per platform from vulnerabilities CSV.

    Args:
        input_file: Path to input CSV file
        output_file: Path to output CSV file
        sample_size: Number of entries to sample per platform (default: 200)
    """

    # Read all entries and group by platform
    platform_groups = defaultdict(list)
    fieldnames = None

    print(f"Reading {input_file}...")
    with open(input_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

        for row in reader:
            platform = row.get("Platform", "Unknown")
            platform_groups[platform].append(row)

    # Print statistics
    print(f"\nFound {len(platform_groups)} unique platforms:")
    print("=" * 60)
    for platform, entries in sorted(platform_groups.items()):
        print(f"  {platform:20} : {len(entries):5} entries")
    print("=" * 60)

    # Sample from each platform
    sampled_entries = []

    print(f"\nSampling up to {sample_size} entries per platform...")
    for platform, entries in sorted(platform_groups.items()):
        if len(entries) <= sample_size:
            # If platform has fewer entries than sample_size, take all
            sample = entries
            print(f"  {platform:20} : Taking all {len(sample)} entries")
        else:
            # Randomly sample
            sample = random.sample(entries, sample_size)
            print(f"  {platform:20} : Sampled {len(sample)} from {len(entries)}")

        sampled_entries.extend(sample)

    # Write sampled entries to new file
    print(f"\nWriting {len(sampled_entries)} sampled entries to {output_file}...")
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sampled_entries)

    print(f"✓ Successfully created {output_file}")
    print(f"\nSummary:")
    print(
        f"  Total input entries: {sum(len(entries) for entries in platform_groups.values())}"
    )
    print(f"  Total sampled entries: {len(sampled_entries)}")
    print(f"  Platforms: {len(platform_groups)}")


if __name__ == "__main__":
    # Configuration
    INPUT_FILE = "vulnerabilities.csv"
    OUTPUT_FILE = "vulnerabilities_sampled.csv"
    SAMPLE_SIZE = 1000  # Number of entries per platform

    # Set random seed for reproducibility (optional)
    random.seed(42)

    # Run sampling
    sample_vulnerabilities(INPUT_FILE, OUTPUT_FILE, SAMPLE_SIZE)

    print("\n" + "=" * 60)
    print("SAMPLING COMPLETE")
    print("=" * 60)
    print(f"Use '{OUTPUT_FILE}' as input for your vulnerability analyzer.")
