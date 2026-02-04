import pandas as pd
import numpy as np
import re

# Load the data
df = pd.read_csv('snyk_and_advisory.csv')

print("="*80)
print("DATASET OVERVIEW")
print("="*80)
print(f"Total entries: {len(df)}")
print()

# =============================================================================
# TABLE 2: VULNERABILITY REPORTS BY ECOSYSTEM
# =============================================================================
print("="*80)
print("TABLE 2: VULNERABILITY REPORTS BY ECOSYSTEM")
print("="*80)

platform_stats = df.groupby('Platform').agg({
    'Package': ['count', 'nunique']
})
platform_stats.columns = ['Total_Reports', 'Unique_Packages']
platform_stats = platform_stats.sort_values('Total_Reports', ascending=False)

print("\nPlatform\t\tTotal Reports\tUnique Packages")
print("-" * 70)
for platform, row in platform_stats.iterrows():
    print(f"{platform:15}\t{int(row['Total_Reports']):6}\t\t{int(row['Unique_Packages']):6}")

# CORRECTED TOTALS - sum of per-platform counts (no cross-platform deduplication)
total_reports = int(platform_stats['Total_Reports'].sum())
total_unique_packages = int(platform_stats['Unique_Packages'].sum())

print("-" * 70)
print(f"{'TOTAL':15}\t{total_reports:6}\t\t{total_unique_packages:6}")
print()

# =============================================================================
# TABLE 3: CWE-506 DISTRIBUTION
# =============================================================================
print("="*80)
print("TABLE 3: CWE-506 DISTRIBUTION ACROSS ECOSYSTEMS")
print("="*80)

cwe506_df = df[df['CWE'] == 'CWE-506']
total_cwe506_reports = len(cwe506_df)

# Count CWE-506 per platform (reports and unique packages)
cwe506_by_platform = cwe506_df.groupby('Platform').agg({
    'Package': ['count', 'nunique']
})
cwe506_by_platform.columns = ['CWE506_Reports', 'CWE506_Packages']

# Calculate totals for CWE-506 (sum per platform, no deduplication)
total_cwe506_packages = int(cwe506_by_platform['CWE506_Packages'].sum())

print(f"\nTotal CWE-506 reports: {total_cwe506_reports}")
print(f"Total CWE-506 packages (sum per platform): {total_cwe506_packages}")
print()

table3 = platform_stats.join(cwe506_by_platform, how='left').fillna(0)
table3['Pct_of_All_CWE506'] = (table3['CWE506_Reports'] / total_cwe506_reports * 100).round(2)
table3['Pct_of_Platform'] = (table3['CWE506_Reports'] / table3['Total_Reports'] * 100).round(2)
table3 = table3.sort_values('CWE506_Reports', ascending=False)

print("Platform\t\tCWE-506\t\t% of All\t% of Platform's")
print("\t\t\tCount\t\tCWE-506\t\tCWEs")
print("-" * 75)
for platform, row in table3.iterrows():
    print(f"{platform:15}\t{int(row['CWE506_Reports']):6}\t\t{row['Pct_of_All_CWE506']:6.2f}%\t\t{row['Pct_of_Platform']:6.2f}%")

print("-" * 75)
print(f"{'TOTAL':15}\t{total_cwe506_reports:6}\t\t100.00%\t\t{total_cwe506_reports/total_reports*100:.2f}%")
print()

# =============================================================================
# CWE-506 PACKAGE NAMING ANALYSIS
# =============================================================================
print("="*80)
print("CWE-506 PACKAGE NAMING ANALYSIS")
print("="*80)

# Use all CWE-506 rows (not unique packages) for naming analysis
cwe506_packages = cwe506_df['Package'].dropna()
total_cwe506_analyzed = len(cwe506_packages)

short_names = (cwe506_packages.str.len() <= 5).sum()
long_names = (cwe506_packages.str.len() > 10).sum()
scoped = (cwe506_packages.str.startswith('@') & cwe506_packages.str.contains('/')).sum()
with_dashes = cwe506_packages.str.contains('-', na=False).sum()

print(f"\nTotal CWE-506 entries analyzed: {total_cwe506_analyzed}")
print(f"Short names (≤5 chars): {short_names} ({short_names/total_cwe506_analyzed*100:.1f}%)")
print(f"Long names (>10 chars): {long_names} ({long_names/total_cwe506_analyzed*100:.1f}%)")
print(f"Scoped packages (@org/package): {scoped} ({scoped/total_cwe506_analyzed*100:.1f}%)")
print(f"Names with dashes: {with_dashes} ({with_dashes/total_cwe506_analyzed*100:.1f}%)")
print()


# =============================================================================
# VERSION TARGETING PATTERNS  
# =============================================================================
print("="*80)
print("CWE-506 VERSION TARGETING PATTERNS")
print("="*80)

version_ranges = cwe506_df['Version Range'].dropna().astype(str)

# Fixed detection - check for patterns like ['*'] or "*" or * 
all_versions = version_ranges.str.contains(r"\*", regex=True).sum()

# Has range operators - but exclude those that also have * (they're already counted)
has_range = (
    (~version_ranges.str.contains(r"\*", regex=True)) &  # NOT wildcard
    (version_ranges.str.contains('<') | 
     version_ranges.str.contains('>') | 
     version_ranges.str.contains('~') | 
     version_ranges.str.contains('\^') |
     version_ranges.str.contains(','))  # Comma often indicates ranges like [1.0.0, 2.0.0)
).sum()

# Specific versions are everything else
specific = len(version_ranges) - all_versions - has_range

print(f"\nTotal CWE-506 with version info: {len(version_ranges)}")
print(f"All versions (contains '*'): {all_versions} ({all_versions/len(version_ranges)*100:.1f}%)")
print(f"Version ranges (with <, >, ~, ^, comma): {has_range} ({has_range/len(version_ranges)*100:.1f}%)")
print(f"Specific versions: {specific} ({specific/len(version_ranges)*100:.1f}%)")
print()

print("Sample version range formats:")
print(version_ranges.head(10).tolist())
print()


# =============================================================================
# YEARLY DISTRIBUTION OF CWE-506
# =============================================================================
print("="*80)
print("CWE-506 YEARLY DISTRIBUTION")
print("="*80)

def extract_year(row):
    if pd.notna(row['Disclosed_Date']):
        try:
            return pd.to_datetime(row['Disclosed_Date']).year
        except:
            pass
    if pd.notna(row['Date']):
        try:
            return pd.to_datetime(row['Date']).year
        except:
            match = re.search(r'\d{4}', str(row['Date']))
            if match:
                return int(match.group())
    return None

cwe506_with_date = cwe506_df.copy()
cwe506_with_date['Year'] = cwe506_with_date.apply(extract_year, axis=1)
yearly_dist = cwe506_with_date['Year'].value_counts().sort_index()

print("\nYear\tCount")
print("-" * 30)
for year, count in yearly_dist.items():
    if year and 2017 <= year <= 2025:
        print(f"{int(year)}\t{count}")

total_yearly = sum([count for year, count in yearly_dist.items() if year and 2017 <= year <= 2025])
print("-" * 30)
print(f"TOTAL\t{total_yearly}")
print()

# =============================================================================
# TOP 5 CWEs PER ECOSYSTEM
# =============================================================================
print("="*80)
print("TOP 5 CWEs PER ECOSYSTEM")
print("="*80)

for platform in platform_stats.index:
    platform_df = df[df['Platform'] == platform]
    top_cwes = platform_df['CWE'].value_counts().head(5)
    
    print(f"\n{platform}:")
    print("-" * 40)
    for cwe, count in top_cwes.items():
        pct = count / len(platform_df) * 100
        print(f"  {cwe}: {count} ({pct:.2f}%)")

print("\n" + "="*80)
print("ANALYSIS COMPLETE")
print("="*80)
