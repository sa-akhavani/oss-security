#!/usr/bin/env python3
"""
Diff-Based Analysis Pipeline

Analyzes the diff files from the changes dataset using LLMs.
For each vulnerability:
  1. Reads the unified diff file (reverse diff: patched → vulnerable)
  2. Asks the LLM to analyze the code for vulnerabilities

Diff format (reverse diff):
  - '+' lines = VULNERABLE code (code that introduces the vulnerability)
  - '-' lines = PATCHED code (code that fixes the vulnerability)

This tests the LLM's ability to identify vulnerabilities in the '+' lines.
"""

import os
import csv
import json
import random
import argparse
from pathlib import Path
from typing import List, Dict, Any, Literal, Tuple
from datetime import datetime
from dataclasses import dataclass

from openai import OpenAI


# Platform to file extension mapping
PLATFORM_EXTENSIONS = {
    "PyPI": ["*.py"],
    "NuGet": ["*.cs", "*.vb", "*.fs"],
    "npm": ["*.js", "*.ts", "*.jsx", "*.tsx"],
    "NPM": ["*.js", "*.ts", "*.jsx", "*.tsx"],
    "Maven": ["*.java"],
    "Composer": ["*.php"],
    "RubyGems": ["*.rb"],
    "Go": ["*.go"],
    "Cargo": ["*.rs"],
    "Crates": ["*.rs"],
    "C/C++": ["*.c", "*.cpp", "*.h", "*.hpp"],
}

# Platform to language mapping
PLATFORM_LANGUAGES = {
    "PyPI": "python",
    "NuGet": "csharp",
    "npm": "nodejs",
    "NPM": "nodejs",
    "Maven": "java",
    "Composer": "php",
    "RubyGems": "ruby",
    "Go": "go",
    "Cargo": "rust",
    "Crates": "rust",
    "C/C++": "c/c++",
}

# Top CWEs by platform (from original automated_pipeline.py)
PLATFORM_TOP_CWES = {
    "NPM": [
        "CWE-506",   # Embedded Malicious Code
        "CWE-79",    # Cross-site Scripting (XSS)
        "CWE-1321",  # Prototype Pollution
        "CWE-78",    # OS Command Injection
        "CWE-77",    # Command Injection
    ],
    "npm": [
        "CWE-506",   # Embedded Malicious Code
        "CWE-79",    # Cross-site Scripting (XSS)
        "CWE-1321",  # Prototype Pollution
        "CWE-78",    # OS Command Injection
        "CWE-77",    # Command Injection
    ],
    "Composer": [
        "CWE-79",    # Cross-site Scripting (XSS)
        "CWE-89",    # SQL Injection
        "CWE-352",   # Cross-Site Request Forgery (CSRF)
        "CWE-94",    # Code Injection
        "CWE-434",   # Unrestricted Upload of File with Dangerous Type
    ],
    "Maven": [
        "CWE-79",    # Cross-site Scripting (XSS)
        "CWE-352",   # Cross-Site Request Forgery (CSRF)
        "CWE-502",   # Deserialization of Untrusted Data
        "CWE-89",    # SQL Injection
        "CWE-862",   # Missing Authorization
    ],
    "NuGet": [
        "CWE-94",    # Code Injection
        "CWE-79",    # Cross-site Scripting (XSS)
        "CWE-122",   # Heap-based Buffer Overflow
        "CWE-416",   # Use After Free
        "CWE-22",    # Path Traversal
    ],
    "PyPI": [
        "CWE-79",    # Cross-site Scripting (XSS)
        "CWE-1333",  # Inefficient Regular Expression Complexity
        "CWE-94",    # Code Injection
        "CWE-22",    # Path Traversal
        "CWE-352",   # Cross-Site Request Forgery (CSRF)
    ],
    "RubyGems": [
        "CWE-79",    # Cross-site Scripting (XSS)
        "CWE-1333",  # Inefficient Regular Expression Complexity
        "CWE-94",    # Code Injection
        "CWE-22",    # Path Traversal
        "CWE-352",   # Cross-Site Request Forgery (CSRF)
    ],
    "Go": [
        "CWE-352",   # Cross-Site Request Forgery (CSRF)
        "CWE-79",    # Cross-site Scripting (XSS)
        "CWE-863",   # Incorrect Authorization
        "CWE-770",   # Allocation of Resources Without Limits
        "CWE-532",   # Information Exposure Through Log Files
    ],
    "C/C++": [
        "CWE-416",   # Use After Free
        "CWE-122",   # Heap-based Buffer Overflow
        "CWE-125",   # Out-of-bounds Read
        "CWE-787",   # Out-of-bounds Write
        "CWE-120",   # Buffer Copy without Checking Size of Input
    ],
    "Cargo": [
        "CWE-787",   # Out-of-bounds Write
        "CWE-125",   # Out-of-bounds Read
        "CWE-120",   # Buffer Copy without Checking Size of Input
        "CWE-770",   # Allocation of Resources Without Limits
        "CWE-476",   # NULL Pointer Dereference
    ],
    "Crates": [
        "CWE-787",   # Out-of-bounds Write
        "CWE-125",   # Out-of-bounds Read
        "CWE-120",   # Buffer Copy without Checking Size of Input
        "CWE-770",   # Allocation of Resources Without Limits
        "CWE-476",   # NULL Pointer Dereference
    ],
    "_default": [
        "CWE-79",    # Cross-site Scripting (XSS)
        "CWE-506",   # Embedded Malicious Code
        "CWE-352",   # Cross-Site Request Forgery (CSRF)
        "CWE-94",    # Code Injection
        "CWE-89",    # SQL Injection
    ]
}

# CWE Descriptions (comprehensive list from original automated_pipeline.py)
CWE_DESCRIPTIONS = {
    "CWE-506": "Embedded Malicious Code - Code that contains malicious functionality",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)",
    "CWE-79": "Cross-site Scripting (XSS) - Improper neutralization of input during web page generation",
    "CWE-77": "Command Injection - Improper neutralization of special elements used in a command",
    "CWE-476": "NULL Pointer Dereference - Dereferencing a NULL pointer",
    "CWE-89": "SQL Injection - Improper neutralization of SQL commands",
    "CWE-22": "Path Traversal - Improper limitation of pathname to a restricted directory",
    "CWE-78": "OS Command Injection - Improper neutralization of special elements in OS commands",
    "CWE-94": "Code Injection - Improper control of generation of code",
    "CWE-119": "Buffer Overflow - Improper restriction of operations within memory buffer bounds",
    "CWE-20": "Improper Input Validation",
    "CWE-200": "Information Exposure - Exposure of sensitive information to unauthorized actor",
    "CWE-287": "Improper Authentication",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-416": "Use After Free - Accessing memory after it has been freed",
    "CWE-787": "Out-of-bounds Write - Writing outside intended buffer boundaries",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-125": "Out-of-bounds Read - Reading outside intended buffer boundaries",
    "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-863": "Incorrect Authorization",
    "CWE-862": "Missing Authorization",
    "CWE-532": "Information Exposure Through Log Files",
    "CWE-1333": "Inefficient Regular Expression Complexity (ReDoS)",
}


@dataclass
class AnalysisEntry:
    """Represents a vulnerability entry to analyze"""
    vuln_id: str
    package: str
    platform: str
    cwe: str
    cve: str
    vulnerable_version: str
    patched_version: str
    directory: str
    total_changed_files: int
    range_index: int = 0
    
    def get_safe_id(self) -> str:
        """Get a safe filename-compatible ID including range index if > 0"""
        safe_id = self.vuln_id.replace('/', '_').replace('\\', '_')
        if self.range_index > 0:
            safe_id = f"{safe_id}_range{self.range_index}"
        return safe_id
    

class DiffAnalyzer:
    """Analyzes diff files using LLMs"""
    
    def __init__(
        self,
        model: str = "gpt-4o",
        provider: str = "auto",
        openai_api_key: str = None,
        ollama_url: str = "http://10.128.65.242:11444",
        novita_api_key: str = None,
        novita_url: str = "https://api.novita.ai/openai",
    ):
        self.model = model
        self.provider = self._detect_provider(model) if provider == "auto" else provider
        
        # Initialize client
        if self.provider == "openai":
            api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OpenAI API key required")
            self.client = OpenAI(api_key=api_key)
            
        elif self.provider == "ollama":
            ollama_base_url = f"{ollama_url.rstrip('/')}/v1"
            print(f"  Connecting to Ollama at: {ollama_base_url}")
            self.client = OpenAI(
                base_url=ollama_base_url,
                api_key="ollama"
            )
            
        elif self.provider == "novita":
            api_key = novita_api_key or os.getenv("NOVITA_API_KEY")
            if not api_key:
                raise ValueError("Novita API key required")
            self.client = OpenAI(
                base_url=novita_url.rstrip('/'),
                api_key=api_key
            )
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _detect_provider(self, model: str) -> str:
        """Auto-detect provider based on model name"""
        model_lower = model.lower()
        if 'gpt' in model_lower:
            return "openai"
        return "ollama"
    
    def create_diff_analysis_prompt(
        self,
        diff_content: str,
        platform: str,
        target_cwes: List[str],
        reverse_mode: bool = False,
    ) -> str:
        """Create prompt for diff-based vulnerability analysis
        
        Args:
            diff_content: The unified diff content (reverse diff format)
            platform: Platform/ecosystem name
            target_cwes: List of CWEs to check for
            reverse_mode: If False (default), asks if '+' code (VULNERABLE) is vulnerable.
                         If True, asks if '-' code (PATCHED) is vulnerable.
        
        Note: This uses REVERSE DIFF format where:
            - '+' lines = VULNERABLE code (what makes the code vulnerable)
            - '-' lines = PATCHED code (the security fix)
        """
        
        language = PLATFORM_LANGUAGES.get(platform, "unknown")
        
        # Build CWE list with descriptions
        cwe_details = "\n".join([
            f"- {cwe}: {CWE_DESCRIPTIONS.get(cwe, 'Security vulnerability')}"
            for cwe in target_cwes
        ])
        
        if reverse_mode:
            # Reverse mode: Ask if the PATCHED code (-) is vulnerable (it should NOT be)
            prompt = f"""You are a security code reviewer analyzing {language} code.

You are provided with a diff file that shows the changes between the OLD and NEW code.
This is the structure of a diff file:
- Lines starting with "+" are the NEW code
- Lines starting with "-" are the OLD code
- Lines without prefix are CONTEXT (unchanged code)

DIFF TO ANALYZE:
{diff_content}

TASK: Determine if adding the OLD code (lines marked with "-") and removing the NEW code (lines marked with "+") would introduce ANY of these vulnerabilities:
{cwe_details}

In other words: Was the OLD code vulnerable to any of the listed CWEs?

Respond with ONLY this JSON (no other text):
{{"vulnerable": true/false, "cwe_found": "CWE-XXX" or null, "evidence": "brief description of vulnerability in the OLD code, or null if OLD code is safe"}}

Set vulnerable=true if the OLD code (- lines) introduces ANY vulnerability from the list."""
        else:
            # Default mode: Ask if the VULNERABLE code (+) is vulnerable (it SHOULD be)
            prompt = f"""You are a security code reviewer analyzing {language} code.

You are provided with a diff file that shows the changes between the OLD and NEW code.

- 


TASK: Determine if adding the NEW code (lines marked with "+") and removing the OLD code (lines marked with "-") would introduce ANY of these vulnerabilities:

{cwe_details}

In other words: Is the NEW code vulnerable to any of the listed CWEs?

DIFF TO ANALYZE:
{diff_content}

Respond with ONLY this JSON (no other text):
{{"vulnerable": true/false, "cwe_found": "CWE-XXX" or null, "evidence": "brief description of the vulnerability in the NEW code, or null if safe"}}

Set vulnerable=true if the NEW code (+ lines) introduces ANY vulnerability from the list."""
        
        return prompt
    
    def analyze_diff(
        self,
        diff_content: str,
        platform: str,
        target_cwes: List[str],
        reverse_mode: bool = False,
    ) -> Dict[str, Any]:
        """Analyze diff and return results
        
        Args:
            diff_content: The unified diff content
            platform: Platform/ecosystem name
            target_cwes: List of CWEs to check for
            reverse_mode: If False (default), asks if NEW code is vulnerable.
                         If True (reverse), asks if OLD code is vulnerable.
        """
        import time
        
        start_time = time.time()
        prompt = self.create_diff_analysis_prompt(diff_content, platform, target_cwes, reverse_mode)
        # print(f"Prompt: {prompt}")
        # print('--------------------------------')
        try:
            if self.provider == "openai":
                content, token_usage = self._call_openai(prompt)
            elif self.provider == "ollama":
                content, token_usage = self._call_ollama(prompt)
            elif self.provider == "novita":
                content, token_usage = self._call_novita(prompt)
            else:
                raise ValueError(f"Unknown provider: {self.provider}")
            
            analysis_time = round(time.time() - start_time, 2)
            
            # Parse response
            result = self._parse_json_response(content)
            result["analysis_time_seconds"] = analysis_time
            result["token_usage"] = token_usage
            result["model"] = self.model
            result["provider"] = self.provider
            
            # Log if there was a parse issue
            if result.get("parse_error"):
                print(f"    ⚠ Parse issue - using fallback")
                if "raw_response" in result:
                    preview = result["raw_response"][:150].replace('\n', ' ')
                    print(f"    Response: {preview}...")
            
            return result
            
        except Exception as e:
            return {
                "error": str(e),
                "analysis_time_seconds": round(time.time() - start_time, 2),
                "model": self.model,
                "provider": self.provider
            }
    
    def _call_openai(self, prompt: str) -> Tuple[str, Dict]:
        """Call OpenAI API with proper handling for different model types"""
        # Models that support response_format json_object
        json_mode_models = ['gpt-4o', 'gpt-4-turbo', 'gpt-4-turbo-preview',
                           'gpt-3.5-turbo-1106', 'gpt-3.5-turbo-0125', 'gpt-4-0125-preview']
        
        # O1 and newer models have different API requirements
        is_o1_model = 'o1' in self.model.lower()
        
        # Models that use max_completion_tokens instead of max_tokens
        uses_completion_tokens = is_o1_model or 'gpt-5' in self.model.lower()
        
        system_content = "You are a security vulnerability analysis expert specializing in code review and patch analysis. Analyze diffs thoroughly and respond with valid JSON only."
        
        # Build API call parameters
        if is_o1_model:
            # O1 models don't support system messages, temperature, top_p, or frequency/presence penalties
            api_params = {
                "model": self.model,
                "messages": [
                    {"role": "user", "content": f"{system_content}\n\n{prompt}"}
                ],
                "max_completion_tokens": 4096
            }
        else:
            api_params = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0,
                "top_p": 0.1,
                "frequency_penalty": 0,
                "presence_penalty": 0
            }
            
            # Use appropriate token limit parameter based on model
            if uses_completion_tokens:
                api_params["max_completion_tokens"] = 4096
            else:
                api_params["max_tokens"] = 4096
            
            # Add response_format only for models that support it
            if any(model in self.model for model in json_mode_models):
                api_params["response_format"] = {"type": "json_object"}
        
        response = self.client.chat.completions.create(**api_params)
        
        token_usage = {
            "input_tokens": response.usage.prompt_tokens if hasattr(response, 'usage') and response.usage else 0,
            "output_tokens": response.usage.completion_tokens if hasattr(response, 'usage') and response.usage else 0,
            "total_tokens": response.usage.total_tokens if hasattr(response, 'usage') and response.usage else 0
        }
        
        return response.choices[0].message.content, token_usage
    
    def _call_ollama(self, prompt: str) -> Tuple[str, Dict]:
        """Call Ollama API (OpenAI-compatible) with optimized parameters"""
        system_content = "You are a security vulnerability analysis expert specializing in code review and patch analysis. Analyze diffs thoroughly and respond with valid JSON only."
        
        api_params = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": prompt}
            ],
            # "temperature": 0,
            # "top_p": 0.1
        }
        
        response = self.client.chat.completions.create(**api_params)
        
        token_usage = {
            "input_tokens": response.usage.prompt_tokens if hasattr(response, 'usage') and response.usage else 0,
            "output_tokens": response.usage.completion_tokens if hasattr(response, 'usage') and response.usage else 0,
            "total_tokens": response.usage.total_tokens if hasattr(response, 'usage') and response.usage else 0
        }
        
        return response.choices[0].message.content, token_usage
    
    def _call_novita(self, prompt: str) -> Tuple[str, Dict]:
        """Call Novita API (OpenAI-compatible) with optimized parameters"""
        system_content = "You are a security vulnerability analysis expert specializing in code review and patch analysis. Analyze diffs thoroughly and respond with valid JSON only."
        
        api_params = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0,
            "max_tokens": 4096,
            "top_p": 0.1,
            "frequency_penalty": 0,
            "presence_penalty": 0
        }
        
        response = self.client.chat.completions.create(**api_params)
        
        token_usage = {
            "input_tokens": response.usage.prompt_tokens if hasattr(response, 'usage') and response.usage else 0,
            "output_tokens": response.usage.completion_tokens if hasattr(response, 'usage') and response.usage else 0,
            "total_tokens": response.usage.total_tokens if hasattr(response, 'usage') and response.usage else 0
        }
        
        return response.choices[0].message.content, token_usage
    
    def _parse_json_response(self, content: str) -> Dict:
        """Parse JSON from response with multiple fallback strategies"""
        import re
        
        if not content or not content.strip():
            return {"vulnerable": None, "evidence": "Empty response", "parse_error": True}
        
        # Clean content
        cleaned = content.strip()
        
        # Strategy 1: Direct parse
        try:
            result = json.loads(cleaned)
            # Normalize: convert "safe" to "vulnerable" if present
            if "safe" in result and "vulnerable" not in result:
                result["vulnerable"] = not result["safe"]
            return result
        except json.JSONDecodeError:
            pass
        
        # Strategy 2: Extract from markdown code blocks
        json_match = re.search(r'```(?:json)?\s*(\{[^`]*\})\s*```', cleaned)
        if json_match:
            try:
                result = json.loads(json_match.group(1))
                if "safe" in result and "vulnerable" not in result:
                    result["vulnerable"] = not result["safe"]
                return result
            except json.JSONDecodeError:
                pass
        
        # Strategy 3: Find first { ... } pattern
        json_match = re.search(r'\{[^{}]*\}', cleaned)
        if json_match:
            try:
                result = json.loads(json_match.group(0))
                if "safe" in result and "vulnerable" not in result:
                    result["vulnerable"] = not result["safe"]
                return result
            except json.JSONDecodeError:
                pass
        
        # Strategy 4: Look for "vulnerable": true/false pattern directly
        vuln_match = re.search(r'"vulnerable"\s*:\s*(true|false)', cleaned.lower())
        if vuln_match:
            is_vulnerable = vuln_match.group(1) == 'true'
            evidence_match = re.search(r'"evidence"\s*:\s*"([^"]*)"', cleaned)
            evidence = evidence_match.group(1) if evidence_match else None
            return {"vulnerable": is_vulnerable, "evidence": evidence, "parse_note": "regex"}
        
        # Strategy 4b: Look for "safe": true/false pattern
        safe_match = re.search(r'"safe"\s*:\s*(true|false)', cleaned.lower())
        if safe_match:
            is_safe = safe_match.group(1) == 'true'
            return {"vulnerable": not is_safe, "evidence": None, "parse_note": "regex_safe"}
        
        # Strategy 5: Text analysis fallback
        content_lower = cleaned.lower()
        
        # Look for clear indicators
        if 'no vulnerabilit' in content_lower or 'code is safe' in content_lower or 'no issues found' in content_lower or 'not vulnerable' in content_lower:
            return {"vulnerable": False, "evidence": None, "parse_note": "text_analysis"}
        
        if 'is vulnerable' in content_lower or 'vulnerability found' in content_lower or 'contains vulnerab' in content_lower:
            return {"vulnerable": True, "evidence": "Detected from text", "parse_note": "text_analysis"}
        
        # Return unknown
        return {
            "vulnerable": None, 
            "evidence": "Could not parse response",
            "parse_error": True,
            "raw_response": cleaned[:300]
        }


def load_changes_summary(csv_path: str) -> List[AnalysisEntry]:
    """Load and parse changes_summary.csv"""
    entries = []
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Get range_index, default to 0
            try:
                range_index = int(row.get('Range_Index', 0))
            except (ValueError, TypeError):
                range_index = 0
            
            entries.append(AnalysisEntry(
                vuln_id=row.get('ID', ''),
                package=row.get('Package', ''),
                platform=row.get('Platform', ''),
                cwe=row.get('CWE', ''),
                cve=row.get('CVE', ''),
                vulnerable_version=row.get('Vulnerable_Version', ''),
                patched_version=row.get('Patched_Version', ''),
                directory=row.get('Directory', ''),
                total_changed_files=int(row.get('Total_Changed_Files', 0)),
                range_index=range_index
            ))
    
    return entries


def count_lines(filepath: str) -> int:
    """Count lines in a file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except:
        return 0


def run_diff_analysis_pipeline(
    changes_dataset_path: str,
    output_dir: str,
    model: str = "gpt-4o",
    provider: str = "auto",
    max_lines: int = 1000,
    samples_per_ecosystem: int = 10,
    seed: int = 42,
    reverse_mode: bool = False,
    dataset_version: str = "v3",
    unique_packages: bool = False,
    openai_api_key: str = None,
    ollama_url: str = "http://10.128.65.242:11444",
    novita_api_key: str = None,
    novita_url: str = "https://api.novita.ai/openai",
):
    """
    Run the diff analysis pipeline on the changes dataset.
    
    Uses REVERSE DIFF format where:
        - '+' lines = VULNERABLE code (what makes code vulnerable)
        - '-' lines = PATCHED code (the security fix)
    
    For each selected vulnerability:
    1. Read the diff file
    2. Ask LLM if the '+' lines (vulnerable code) contain vulnerabilities
       (or reverse: if '-' lines (patched code) contain vulnerabilities)
    3. Save results
    
    Args:
        reverse_mode: If False (default), checks '+' lines (VULNERABLE code) - should find vulns.
                     If True (reverse), checks '-' lines (PATCHED code) - should NOT find vulns.
        unique_packages: If True, ensures only one vulnerability per package is sampled per ecosystem.
    """
    
    mode_desc = "REVERSE (checking PATCHED code '-')" if reverse_mode else "DEFAULT (checking VULNERABLE code '+')"
    
    print(f"\n{'='*60}")
    print("DIFF ANALYSIS PIPELINE")
    print(f"{'='*60}")
    print(f"Dataset version: {dataset_version}")
    print(f"  Reverse diff format: '+' = VULNERABLE code, '-' = PATCHED code")
    print(f"Mode: {mode_desc}")
    print(f"Dataset: {changes_dataset_path}")
    print(f"Output: {output_dir}")
    print(f"Model: {model}")
    print(f"Provider: {provider}")
    if provider == "ollama" or (provider == "auto" and 'gpt' not in model.lower()):
        print(f"Ollama URL: {ollama_url}")
    print(f"Max lines per diff: {max_lines}")
    print(f"Samples per ecosystem: {samples_per_ecosystem}")
    print(f"Unique packages only: {unique_packages}")
    print(f"Random seed: {seed}")
    print(f"{'='*60}\n")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Load changes summary
    summary_path = os.path.join(changes_dataset_path, "changes_summary.csv")
    if not os.path.exists(summary_path):
        raise FileNotFoundError(f"changes_summary.csv not found at {summary_path}")
    
    entries = load_changes_summary(summary_path)
    print(f"Loaded {len(entries)} entries from changes_summary.csv")
    
    # Group by ecosystem (using directory prefix)
    from collections import defaultdict
    entries_by_ecosystem = defaultdict(list)
    
    for entry in entries:
        # Extract ecosystem from directory path (e.g., "go/SNYK-..." -> "go")
        ecosystem = entry.directory.split('/')[0] if '/' in entry.directory else "unknown"
        entries_by_ecosystem[ecosystem].append(entry)
    
    print(f"\nEntries by ecosystem:")
    for eco, eco_entries in sorted(entries_by_ecosystem.items()):
        print(f"  {eco}: {len(eco_entries)}")
    
    # Filter and sample entries
    random.seed(seed)
    selected_entries = []
    
    unique_str = ", unique packages" if unique_packages else ""
    print(f"\nFiltering and sampling (max {max_lines} lines, {samples_per_ecosystem} per ecosystem{unique_str})...")
    
    for ecosystem, eco_entries in sorted(entries_by_ecosystem.items()):
        # Filter by diff file line count
        valid_entries = []
        for entry in eco_entries:
            diff_file = os.path.join(changes_dataset_path, entry.directory, "diff.txt")
            
            diff_lines = count_lines(diff_file)
            
            if diff_lines > 0 and diff_lines <= max_lines:
                valid_entries.append((entry, diff_lines))
        
        # Optionally deduplicate by package (keep one random entry per package)
        if unique_packages and valid_entries:
            # Group by package
            by_package = {}
            for entry, lines in valid_entries:
                pkg = entry.package
                if pkg not in by_package:
                    by_package[pkg] = []
                by_package[pkg].append((entry, lines))
            
            # Select one random entry per package
            unique_valid = []
            for pkg, pkg_entries in by_package.items():
                unique_valid.append(random.choice(pkg_entries))
            valid_entries = unique_valid
            unique_count = len(by_package)
        else:
            unique_count = len(set(e.package for e, _ in valid_entries)) if valid_entries else 0
        
        # Sample
        sample_size = min(samples_per_ecosystem, len(valid_entries))
        sampled = random.sample(valid_entries, sample_size) if valid_entries else []
        
        selected_entries.extend(sampled)
        if unique_packages:
            print(f"  {ecosystem}: {unique_count} unique packages, {len(sampled)} sampled")
        else:
            print(f"  {ecosystem}: {len(valid_entries)} valid ({unique_count} unique packages), {len(sampled)} sampled")
    
    print(f"\nTotal selected for analysis: {len(selected_entries)}")
    
    # Initialize analyzer
    analyzer = DiffAnalyzer(
        model=model,
        provider=provider,
        openai_api_key=openai_api_key,
        ollama_url=ollama_url,
        novita_api_key=novita_api_key,
        novita_url=novita_url
    )
    
    # Process each entry
    results = []
    skipped_existing = 0
    
    for i, (entry, diff_lines) in enumerate(selected_entries, 1):
        # Check if output file already exists (use safe_id which includes range_index)
        safe_id = entry.get_safe_id()
        result_file = os.path.join(output_dir, f"{safe_id}.json")
        
        if os.path.exists(result_file):
            print(f"\n[{i}/{len(selected_entries)}] {safe_id}")
            print(f"  ⊗ Skipped: Result already exists - {safe_id}.json")
            # Load existing result to include in summary
            try:
                with open(result_file, 'r', encoding='utf-8') as f:
                    existing_result = json.load(f)
                results.append(existing_result)
            except Exception as e:
                print(f"  ⚠ Warning: Could not load existing result: {e}")
            skipped_existing += 1
            continue
        
        print(f"\n[{i}/{len(selected_entries)}] {safe_id}")
        print(f"  Package: {entry.package}")
        print(f"  Platform: {entry.platform}")
        print(f"  CWE: {entry.cwe}, CVE: {entry.cve}")
        if entry.range_index > 0:
            print(f"  Range index: {entry.range_index}")
        print(f"  Diff lines: {diff_lines}")
        
        # Get target CWEs
        target_cwes = PLATFORM_TOP_CWES.get(entry.platform, PLATFORM_TOP_CWES["_default"])
        # Include the actual CWE if known and not in list
        if entry.cwe and entry.cwe not in target_cwes:
            target_cwes = [entry.cwe] + target_cwes[:4]  # Keep top 5
        
        print(f"  Target CWEs: {', '.join(target_cwes)}")
        
        # Read diff file
        diff_file = os.path.join(changes_dataset_path, entry.directory, "diff.txt")
        
        with open(diff_file, 'r', encoding='utf-8', errors='ignore') as f:
            diff_content = f.read()
        
        # Analyze diff
        print(f"  Analyzing diff{'(reverse mode - checking PATCHED code)' if reverse_mode else ' (checking VULNERABLE code)'}...")
        diff_result = analyzer.analyze_diff(diff_content, entry.platform, target_cwes, reverse_mode)
        
        is_vulnerable = diff_result.get('vulnerable')
        analysis_time = diff_result.get('analysis_time_seconds', 'N/A')
        cwe_found = diff_result.get('cwe_found')
        
        if reverse_mode:
            print(f"    Patched code (-) vulnerable: {is_vulnerable} | CWE found: {cwe_found} | time={analysis_time}s")
        else:
            print(f"    Vulnerable code (+) detected: {is_vulnerable} | CWE found: {cwe_found} | time={analysis_time}s")
        if diff_result.get('evidence'):
            print(f"    Evidence: {str(diff_result.get('evidence', ''))[:100]}")
        
        # Determine if detection is correct based on mode
        # Reverse diff format: '+' = VULNERABLE, '-' = PATCHED
        if reverse_mode:
            # Reverse mode: checking PATCHED code (-) which should be SAFE
            # Correct if NOT vulnerable
            correct_detection = is_vulnerable == False
        else:
            # Normal mode: checking VULNERABLE code (+) which should have vulns
            # Correct if vulnerable
            correct_detection = is_vulnerable == True
        
        # Compile result
        result = {
            "vuln_id": entry.vuln_id,
            "range_index": entry.range_index,
            "safe_id": safe_id,
            "package": entry.package,
            "platform": entry.platform,
            "actual_cwe": entry.cwe,
            "actual_cve": entry.cve,
            "vulnerable_version": entry.vulnerable_version,
            "patched_version": entry.patched_version,
            "target_cwes": target_cwes,
            "diff_lines": diff_lines,
            "diff_analysis": diff_result,
            "dataset_version": dataset_version,
            "reverse_mode": reverse_mode,
            "code_checked": "patched (-)" if reverse_mode else "vulnerable (+)",
            "detected_vulnerable": is_vulnerable,
            "correct_detection": correct_detection,
            "analyzed_at": datetime.now().isoformat(),
            "model": model
        }
        
        results.append(result)
        
        # Save individual result
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)
        
        print(f"  ✓ Saved: {safe_id}.json")
    
    # Save summary
    summary = {
        "generated_at": datetime.now().isoformat(),
        "model": model,
        "provider": analyzer.provider,
        "dataset_version": dataset_version,
        "reverse_mode": reverse_mode,
        "code_checked": "patched (-)" if reverse_mode else "vulnerable (+)",
        "max_lines": max_lines,
        "samples_per_ecosystem": samples_per_ecosystem,
        "unique_packages": unique_packages,
        "total_analyzed": len(results),
        "results_summary": []
    }
    
    for r in results:
        summary["results_summary"].append({
            "vuln_id": r["vuln_id"],
            "package": r["package"],
            "platform": r["platform"],
            "actual_cwe": r["actual_cwe"],
            "code_checked": r.get("code_checked", "old"),
            "detected_vulnerable": r.get("detected_vulnerable"),
            "correct_detection": r.get("correct_detection"),
            "cwe_found": r.get("diff_analysis", {}).get("cwe_found"),
        })
    
    # Calculate metrics
    total = len(results)
    correct = sum(1 for s in summary["results_summary"] if s["correct_detection"])
    detected_vulnerable = sum(1 for s in summary["results_summary"] if s["detected_vulnerable"] == True)
    detected_safe = sum(1 for s in summary["results_summary"] if s["detected_vulnerable"] == False)
    unknown = sum(1 for s in summary["results_summary"] if s["detected_vulnerable"] is None)
    
    if reverse_mode:
        # Reverse mode: checking PATCHED code (-) which should be SAFE
        # Correct = detected_safe, False positive = detected_vulnerable
        summary["metrics"] = {
            "total": total,
            "correct_detection_count": correct,
            "correct_detection_rate": round(correct / total * 100, 2) if total else 0,
            "detected_safe_count": detected_safe,
            "detected_safe_rate": round(detected_safe / total * 100, 2) if total else 0,
            "false_positive_count": detected_vulnerable,  # Detected as vulnerable when should be safe
            "false_positive_rate": round(detected_vulnerable / total * 100, 2) if total else 0,
            "unknown_count": unknown,
        }
    else:
        # Default mode: checking VULNERABLE code (+) which should have vulns
        # Correct = detected_vulnerable, False negative = detected_safe
        summary["metrics"] = {
            "total": total,
            "correct_detection_count": correct,
            "correct_detection_rate": round(correct / total * 100, 2) if total else 0,
            "detected_vulnerable_count": detected_vulnerable,
            "detected_vulnerable_rate": round(detected_vulnerable / total * 100, 2) if total else 0,
            "false_negative_count": detected_safe,  # Detected as safe when should be vulnerable
            "false_negative_rate": round(detected_safe / total * 100, 2) if total else 0,
            "unknown_count": unknown,
        }
    
    summary_file = os.path.join(output_dir, "analysis_summary.json")
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    
    # Save CSV summary
    csv_summary_file = os.path.join(output_dir, "analysis_results.csv")
    with open(csv_summary_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'vuln_id', 'package', 'platform', 'actual_cwe',
            'code_checked', 'detected_vulnerable', 'correct_detection', 'cwe_found'
        ])
        writer.writeheader()
        for s in summary["results_summary"]:
            writer.writerow(s)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"DIFF ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Reverse diff format: '+' = VULNERABLE, '-' = PATCHED")
    print(f"Mode: {'Checking PATCHED code (-)' if reverse_mode else 'Checking VULNERABLE code (+)'}")
    print(f"Total analyzed: {total}")
    if skipped_existing > 0:
        print(f"  - Skipped (already exists): {skipped_existing}")
        print(f"  - Newly analyzed: {total - skipped_existing}")
    
    if reverse_mode:
        # Reverse: checking PATCHED code (-) which should be SAFE
        print(f"\nReverse mode: PATCHED code (-) should be SAFE")
        print(f"Correctly detected as safe: {detected_safe}/{total}")
        print(f"False positives (wrongly marked vulnerable): {detected_vulnerable}/{total}")
    else:
        # Normal: checking VULNERABLE code (+) which should have vulns
        print(f"\nNormal mode: VULNERABLE code (+) should have vulnerabilities")
        print(f"Correctly detected as vulnerable: {detected_vulnerable}/{total}")
        print(f"False negatives (wrongly marked safe): {detected_safe}/{total}")
    
    if unknown > 0:
        print(f"Unknown/parse errors: {unknown}/{total}")
    print(f"\n✓ Correct detection rate: {correct}/{total} ({summary['metrics']['correct_detection_rate']}%)")
    print(f"\nResults saved to: {output_dir}")
    print(f"  - Individual results: <vuln_id>.json")
    print(f"  - Summary: analysis_summary.json")
    print(f"  - CSV: analysis_results.csv")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Diff-Based Analysis Pipeline')
    parser.add_argument('--dataset', '-d', default='./datasets/changes_dataset',
                       help='Path to changes_dataset directory')
    parser.add_argument('--output', '-o', default='./results/diff_analysis',
                       help='Output directory for results')
    parser.add_argument('--model', '-m', default='gpt-4o',
                       help='LLM model to use')
    parser.add_argument('--provider', '-p', default='auto',
                       choices=['auto', 'openai', 'ollama', 'novita'],
                       help='LLM provider')
    parser.add_argument('--max-lines', type=int, default=1000,
                       help='Maximum lines per diff file (default: 1000)')
    parser.add_argument('--samples', '-s', type=int, default=10,
                       help='Samples per ecosystem (default: 10)')
    parser.add_argument('--seed', type=int, default=42,
                       help='Random seed for sampling')
    parser.add_argument('--reverse', '-r', action='store_true',
                       help='Reverse mode: check PATCHED code (-) instead of VULNERABLE code (+)')
    parser.add_argument('--unique-packages', '-u', action='store_true',
                       help='Ensure only one vulnerability per package is sampled per ecosystem')
    parser.add_argument('--dataset-version', default='v3', choices=['v2', 'v3'],
                       help='Dataset version (reverse diff: + = vulnerable, - = patched)')
    parser.add_argument('--openai-api-key', help='OpenAI API key')
    parser.add_argument('--ollama-url', default='http://10.128.65.242:11444',
                       help='Ollama server URL')
    parser.add_argument('--novita-api-key', help='Novita API key')
    parser.add_argument('--novita-url', default='https://api.novita.ai/openai',
                       help='Novita API URL')
    
    args = parser.parse_args()
    
    run_diff_analysis_pipeline(
        changes_dataset_path=args.dataset,
        output_dir=args.output,
        model=args.model,
        provider=args.provider,
        max_lines=args.max_lines,
        samples_per_ecosystem=args.samples,
        seed=args.seed,
        reverse_mode=args.reverse,
        dataset_version=args.dataset_version,
        unique_packages=args.unique_packages,
        openai_api_key=args.openai_api_key,
        ollama_url=args.ollama_url,
        novita_api_key=args.novita_api_key,
        novita_url=args.novita_url
    )
