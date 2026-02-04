import pandas as pd
import re

# Load CWE-506 data
df = pd.read_csv('snyk_and_advisory.csv')
cwe506_df = df[df['CWE'] == 'CWE-506']

# Comprehensive list of popular packages to check against
popular_packages = [
    'lodash', 'react', 'express', 'chalk', 'request', 'moment', 'axios', 'jquery',
    'bootstrap', 'webpack', 'babel', 'typescript', 'angular', 'vue', 'commander',
    'matplotlib', 'numpy', 'pandas', 'requests', 'flask', 'django', 'pygame',
    'tensorflow', 'pytorch', 'opencv', 'pillow', 'beautifulsoup', 'scikit',
    'selenium', 'pillow', 'colorama', 'discord', 'pycord', 'playwright'
]

def levenshtein_distance(s1, s2):
    """Calculate Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

# Method 1: Exact typosquatting using edit distance
typosquat_exact = set()
for idx, row in cwe506_df.iterrows():
    pkg = row['Package']
    if pd.isna(pkg):
        continue
    
    pkg_lower = pkg.lower()
    
    for popular in popular_packages:
        # Skip exact matches
        if pkg_lower == popular:
            continue
        
        distance = levenshtein_distance(pkg_lower, popular)
        
        # Threshold based on package name length
        threshold = 2 if len(popular) <= 8 else 3
        
        if 0 < distance <= threshold:
            typosquat_exact.add(pkg)
            break

# Method 2: Contains popular package name (but not exact match)
typosquat_contains = set()
for idx, row in cwe506_df.iterrows():
    pkg = row['Package']
    if pd.isna(pkg):
        continue
    
    pkg_lower = pkg.lower()
    
    for popular in popular_packages:
        # Check if package contains the popular name but isn't exactly it
        if popular in pkg_lower and pkg_lower != popular:
            typosquat_contains.add(pkg)
            break

# Method 3: Combined approach - packages that are EITHER similar OR contain popular names
typosquat_combined = typosquat_exact.union(typosquat_contains)

print("="*80)
print("TYPOSQUATTING DETECTION RESULTS")
print("="*80)
print(f"\nMethod 1 (Edit distance ≤2-3): {len(typosquat_exact)} packages")
print(f"Method 2 (Contains popular name): {len(typosquat_contains)} packages")
print(f"Method 3 (Combined): {len(typosquat_combined)} packages")
print()

# Show which method you should use based on your paper
print("RECOMMENDATION:")
print("-" * 80)
print(f"If you want STRICT typosquatting only: Use {len(typosquat_exact)} ({len(typosquat_exact)/len(cwe506_df)*100:.1f}%)")
print(f"If you want packages similar to popular: Use {len(typosquat_combined)} ({len(typosquat_combined)/len(cwe506_df)*100:.1f}%)")
print()

# Examples from each method
print("Examples from strict typosquatting (edit distance):")
for pkg in list(typosquat_exact)[:10]:
    print(f"  {pkg}")

print("\nExamples from contains method:")
for pkg in list(typosquat_contains - typosquat_exact)[:10]:
    print(f"  {pkg}")
