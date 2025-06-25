#!/usr/bin/env python3
"""
WISP - Windows Audit & Security Profiler
CIS Excel to JSON Baseline Converter

This script converts CIS Excel benchmark files to JSON format for use with the WISP scanner.
It specifically extracts code blocks (enclosed in ```) from Remediation Procedure and Audit Procedure
columns and maps them to appropriate fields in the JSON structure.

Usage:
    python cis-excel-to-json.py <input_excel_file> <output_json_file>

Example:
    python cis-excel-to-json.py "CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.xlsx" "baseline.json"
"""

import sys
import os
import pandas as pd
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

if len(sys.argv) < 2:
    print("Usage: python cis-excel-to-json.py <input_excel_file> [output_json_file]")
    sys.exit(1)

input_excel = sys.argv[1]
output_json = None
if len(sys.argv) > 2:
    output_json = sys.argv[2]
else:
    base = os.path.splitext(os.path.basename(input_excel))[0]
    output_json = os.path.join(os.path.dirname(__file__), '..', 'baselines', f'{base}-member-server.json')

def extract_expected_value_from_remediation(remediation_procedure: str) -> str:
    """Extract expected value from Remediation Procedure text before the code block."""
    if not remediation_procedure:
        return ""
    
    # Pattern: "set the following UI path to `EXPECTED_VALUE`:"
    pattern = r"set the following UI path to `([^`]+)`:"
    match = re.search(pattern, remediation_procedure)
    if match:
        return match.group(1).strip()
    
    # Alternative pattern: "set to `EXPECTED_VALUE`"
    pattern2 = r"set to `([^`]+)`"
    match2 = re.search(pattern2, remediation_procedure)
    if match2:
        return match2.group(1).strip()
    
    # Alternative pattern: "is set to `EXPECTED_VALUE`"
    pattern3 = r"is set to `([^`]+)`"
    match3 = re.search(pattern3, remediation_procedure)
    if match3:
        return match3.group(1).strip()
    
    return ""

def extract_expected_value_from_default(default_value: str) -> str:
    """Extract expected value from Default Value column by removing parentheses and cleaning up."""
    if not default_value:
        return ""
    
    # Remove everything in parentheses and clean up
    cleaned = re.sub(r'\s*\([^)]*\)', '', default_value)
    cleaned = cleaned.strip()
    
    # Remove trailing period
    if cleaned.endswith('.'):
        cleaned = cleaned[:-1]
    
    return cleaned

def clean_text(text: str) -> str:
    """Clean and normalize text strings."""
    if pd.isna(text) or text is None:
        return ""
    
    text = str(text).strip()
    # Remove extra whitespace and normalize
    text = re.sub(r'\s+', ' ', text)
    return text

def extract_code_blocks(text: str) -> List[str]:
    """Extract code blocks enclosed in ``` from text."""
    if not text:
        return []
    
    # Pattern to match code blocks: ```\ncontent\n```
    pattern = r'```\n(.*?)\n```'
    matches = re.findall(pattern, text, re.DOTALL)
    
    # Clean up each code block
    code_blocks = []
    for match in matches:
        code_block = match.strip()
        if code_block:
            code_blocks.append(code_block)
    
    return code_blocks

def determine_check_type(title: str, audit_procedure: str, remediation_procedure: str) -> str:
    """Determine the check type based on title and procedures."""
    title_lower = title.lower()
    audit_lower = audit_procedure.lower()
    remediation_lower = remediation_procedure.lower()
    
    # User rights assignment rules (these should be secpol, not service)
    user_rights_keywords = [
        'adjust memory quotas', 'allow log on', 'back up files', 'change the system time',
        'change the time zone', 'create a pagefile', 'create a token object', 'create global objects',
        'create permanent shared objects', 'create symbolic links', 'debug programs', 'deny log on',
        'enable computer and user accounts', 'force shutdown', 'generate security audits',
        'impersonate a client', 'increase scheduling priority', 'load and unload device drivers',
        'lock pages in memory', 'manage auditing and security log', 'modify an object label',
        'modify firmware environment values', 'perform volume maintenance tasks', 'profile single process',
        'profile system performance', 'replace a process level token', 'restore files and directories',
        'shut down the system', 'take ownership of files'
    ]
    
    # Check if this is a user rights assignment rule
    if any(keyword in title_lower for keyword in user_rights_keywords):
        return "secpol"
    
    # Check if audit_procedure contains registry paths (indicating registry rule)
    if any(keyword in audit_lower for keyword in ['hklm\\', 'hkcu\\', 'hkey_local_machine', 'hkey_current_user', 'registry']):
        return "registry"
    
    # Actual Windows service rules (these should be service)
    # Only classify as service if the audit_procedure specifically mentions a Windows service
    service_keywords = [
        'background intelligent transfer service', 'bits', 'snmp service', 'device health attestation',
        'windows time service', 'activex installer service', 'event log service', 'internet information services',
        'remote desktop services', 'winrm service', 'windows server update service', 'print spooler',
        'telnet', 'tftp', 'peer-to-peer networking', 'locale services', 'service control manager',
        'trusted platform module', 'online speech recognition'
    ]
    
    # Only classify as service if both title contains service keywords AND audit_procedure contains Services\ path
    if (any(keyword in title_lower for keyword in service_keywords) and 
        'services\\' in audit_lower and 'currentcontrolset\\services\\' in audit_lower):
        return "service"
    
    # Audit policy checks
    if any(keyword in title_lower for keyword in ['audit', 'auditing', 'logon', 'logoff']):
        return "auditpol"
    
    # Security policy checks (default for most CIS checks)
    return "secpol"

def process_excel_file(file_path: str) -> List[Dict[str, Any]]:
    """Process CIS Excel file and extract rules."""
    print(f"Processing Excel file: {file_path}")
    
    # Read Level 1 and Level 2 Member Server sheets
    sheets_to_process = ['Level 1 - Member Server', 'Level 2 - Member Server']
    all_rules = []
    
    for sheet_name in sheets_to_process:
        print(f"Processing sheet: {sheet_name}")
        
        try:
            df = pd.read_excel(file_path, sheet_name=sheet_name)
            print(f"  Sheet '{sheet_name}' has {len(df)} rows")
            
            # Process each row
            for index, row in df.iterrows():
                recommendation_id = clean_text(str(row['Recommendation #']))
                title = clean_text(str(row['Title']))
                description = clean_text(str(row['Description']))
                rationale = clean_text(str(row['Rationale Statement']))
                impact = clean_text(str(row['Impact Statement']))
                audit_procedure = clean_text(str(row['Audit Procedure']))
                remediation_procedure = clean_text(str(row['Remediation Procedure']))
                default_value = clean_text(str(row['Default Value']))
                
                # Skip empty or header rows - only process rows with actual recommendation IDs
                if not recommendation_id or recommendation_id.lower() in ['title', 'recommendation', 'rule', 'na', 'nan'] or str(row['Recommendation #']).lower() == 'nan':
                    continue
                
                # Extract section from recommendation ID
                section = '.'.join(recommendation_id.split('.')[:2]) if '.' in recommendation_id else recommendation_id
                
                # Determine level from sheet name
                level = "Level 1" if "Level 1" in sheet_name else "Level 2"
                
                # Determine check type
                check_type = determine_check_type(title, audit_procedure, remediation_procedure)
                
                # Extract code blocks for remediation and audit procedures
                remediation_blocks = extract_code_blocks(str(row['Remediation Procedure']))
                audit_blocks = extract_code_blocks(str(row['Audit Procedure']))
                remediation_code = remediation_blocks[0].strip() if remediation_blocks else ''
                audit_code = audit_blocks[0].strip() if audit_blocks else ''
                
                # Extract expected value from remediation procedure first, fall back to default value
                remediation_expected = extract_expected_value_from_remediation(remediation_procedure)
                default_expected = extract_expected_value_from_default(default_value)
                expected_value = remediation_expected if remediation_expected else default_expected
                
                # Create base rule object with only necessary fields
                rule = {
                    'id': recommendation_id,
                    'title': title,
                    'level': level,
                    'check_type': check_type,
                    'expected_value': expected_value,
                    'remediation_procedure': remediation_code,
                    'default_value': default_value,
                    'skip': False
                }
                
                # Add audit_procedure only for registry rules
                if check_type == "registry":
                    rule['audit_procedure'] = audit_code
                
                all_rules.append(rule)
                
        except Exception as e:
            print(f"  Error processing sheet '{sheet_name}': {e}")
            continue
    
    print(f"Total rules extracted: {len(all_rules)}")
    return all_rules

def create_baseline(rules: List[Dict[str, Any]], file_path: str) -> Dict[str, Any]:
    """Create baseline object from rules."""
    # Count rules by level
    level_1_rules = len([r for r in rules if r['level'] == 'Level 1'])
    level_2_rules = len([r for r in rules if r['level'] == 'Level 2'])
    
    baseline = {
        'metadata': {
            'source_file': file_path,
            'sheets_processed': ['Level 1 - Member Server', 'Level 2 - Member Server'],
            'total_rules': len(rules),
            'level_1_rules': level_1_rules,
            'level_2_rules': level_2_rules,
            'generated_at': datetime.now().isoformat()
        },
        'rules': rules
    }
    
    return baseline

def main():
    """Main function."""
    if len(sys.argv) != 3:
        print("Usage: python cis-excel-to-json.py <input_excel_file> <output_json_file>")
        print("Example: python cis-excel-to-json.py 'CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.xlsx' 'baseline.json'")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Check if input file exists
    if not Path(input_file).exists():
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    
    try:
        # Process Excel file
        rules = process_excel_file(input_file)
        
        if not rules:
            print("Error: No rules extracted from Excel file")
            sys.exit(1)

        # Create baseline
        baseline = create_baseline(rules, input_file)

        # Write JSON file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(baseline, f, indent=2, ensure_ascii=False)
        
        print(f"Successfully created baseline with {len(rules)} rules")
        print(f"Output saved to: {output_file}")
        
        # Print summary
        check_types = {}
        for rule in rules:
            check_type = rule.get('check_type', 'unknown')
            check_types[check_type] = check_types.get(check_type, 0) + 1
        
        print("\nCheck type summary:")
        for check_type, count in check_types.items():
            print(f"  {check_type}: {count}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 