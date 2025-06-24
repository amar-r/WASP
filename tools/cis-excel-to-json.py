#!/usr/bin/env python3
"""
WASP - Windows Audit & Security Profiler
CIS Excel to JSON Baseline Converter

This script converts CIS Excel benchmark files to JSON format for use with the WASP scanner.
It extracts rule IDs, titles, check types, targets, and expected values from CIS Excel files.

Usage:
    python cis-excel-to-json.py <input_excel_file> <output_json_file>

Example:
    python cis-excel-to-json.py "CIS_Windows_Server_2022_Benchmark_v1.0.0.xlsx" "baseline.json"
"""

import sys
import os
import pandas as pd
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

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

def clean_text(text: str) -> str:
    """Clean and normalize text strings."""
    if pd.isna(text) or text is None:
        return ""
    
    text = str(text).strip()
    # Remove extra whitespace and normalize
    text = re.sub(r'\s+', ' ', text)
    return text

def extract_rule_id(title: str) -> Optional[str]:
    """Extract rule ID from title (e.g., '1.1.1' from '1.1.1 Ensure...')."""
    if not title:
        return None
    
    # Look for pattern like "1.1.1" at the beginning
    match = re.match(r'^(\d+\.\d+\.\d+)', title.strip())
    if match:
        return match.group(1)
    
    return None

def determine_check_type(title: str, check: str) -> str:
    """Determine the check type based on title and check content."""
    title_lower = title.lower()
    check_lower = check.lower()
    
    # Service checks
    if any(keyword in title_lower for keyword in ['service', 'spooler', 'telnet', 'tftp', 'snmp']):
        return "service"
    
    # Registry checks (most common)
    if any(keyword in check_lower for keyword in ['registry', 'regedit', 'hklm', 'hkcu', 'hkey']):
        return "registry"
    
    # Audit policy checks
    if any(keyword in title_lower for keyword in ['audit', 'auditing', 'logon', 'logoff']):
        return "audit_policy"
    
    # Security policy checks
    if any(keyword in title_lower for keyword in ['security policy', 'secedit', 'local policy']):
        return "security_policy"
    
    # Default to registry for most CIS checks
    return "registry"

def parse_registry_target(check: str) -> Optional[str]:
    """Extract registry path from check description."""
    # Look for registry paths
    registry_patterns = [
        r'HKLM\\[^,\s]+',
        r'HKCU\\[^,\s]+',
        r'HKEY_LOCAL_MACHINE\\[^,\s]+',
        r'HKEY_CURRENT_USER\\[^,\s]+',
        r'Registry Hive: HKEY_LOCAL_MACHINE\s+Registry Path: ([^,\s]+)',
        r'Registry Hive: HKEY_CURRENT_USER\s+Registry Path: ([^,\s]+)'
    ]
    
    for pattern in registry_patterns:
        match = re.search(pattern, check, re.IGNORECASE)
        if match:
            path = match.group(0) if match.groups() == () else match.group(1)
            # Normalize path format
            path = path.replace('HKEY_LOCAL_MACHINE', 'HKLM:')
            path = path.replace('HKEY_CURRENT_USER', 'HKCU:')
            if not path.endswith(':'):
                path = path.replace('HKLM\\', 'HKLM:\\')
                path = path.replace('HKCU\\', 'HKCU:\\')
            return path
    
    return None

def parse_registry_name(check: str) -> Optional[str]:
    """Extract registry value name from check description."""
    # Look for registry value names
    patterns = [
        r'Value Name: ([^,\s]+)',
        r'Registry Value: ([^,\s]+)',
        r'Value: ([^,\s]+)',
        r'Name: ([^,\s]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, check, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    return None

def parse_expected_value(check: str) -> Optional[str]:
    """Extract expected value from check description."""
    # Look for expected values
    patterns = [
        r'Expected: ([^,\s]+)',
        r'Value: ([^,\s]+)',
        r'Setting: ([^,\s]+)',
        r'Configured to: ([^,\s]+)',
        r'Set to: ([^,\s]+)',
        r'Should be: ([^,\s]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, check, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    return None

def parse_service_info(check: str) -> Dict[str, str]:
    """Extract service information from check description."""
    service_info = {}
    
    # Extract service name
    service_match = re.search(r'Service Name: ([^,\s]+)', check, re.IGNORECASE)
    if service_match:
        service_info['service_name'] = service_match.group(1).strip()
    
    # Extract expected status
    status_patterns = [
        r'Status: ([^,\s]+)',
        r'Service Status: ([^,\s]+)',
        r'Should be: ([^,\s]+)'
    ]
    
    for pattern in status_patterns:
        status_match = re.search(pattern, check, re.IGNORECASE)
        if status_match:
            service_info['expected_status'] = status_match.group(1).strip()
            break
    
    # Extract expected start type
    start_type_patterns = [
        r'Start Type: ([^,\s]+)',
        r'Startup Type: ([^,\s]+)',
        r'Start Mode: ([^,\s]+)'
    ]
    
    for pattern in start_type_patterns:
        start_type_match = re.search(pattern, check, re.IGNORECASE)
        if start_type_match:
            service_info['expected_start_type'] = start_type_match.group(1).strip()
            break
    
    return service_info

def parse_audit_policy_info(check: str) -> Dict[str, str]:
    """Extract audit policy information from check description."""
    audit_info = {}
    
    # Extract audit category
    category_match = re.search(r'Category: ([^,\s]+)', check, re.IGNORECASE)
    if category_match:
        audit_info['audit_category'] = category_match.group(1).strip()
    
    # Extract audit subcategory
    subcategory_match = re.search(r'Subcategory: ([^,\s]+)', check, re.IGNORECASE)
    if subcategory_match:
        audit_info['audit_subcategory'] = subcategory_match.group(1).strip()
    
    # Extract expected setting
    setting_patterns = [
        r'Setting: ([^,\s]+)',
        r'Should be: ([^,\s]+)',
        r'Expected: ([^,\s]+)'
    ]
    
    for pattern in setting_patterns:
        setting_match = re.search(pattern, check, re.IGNORECASE)
        if setting_match:
            audit_info['expected_setting'] = setting_match.group(1).strip()
            break
    
    return audit_info

def process_excel_file(file_path: str) -> List[Dict[str, Any]]:
    """Process CIS Excel file and extract rules."""
    print(f"Processing Excel file: {file_path}")
    
    # Read all sheets
    excel_file = pd.ExcelFile(file_path)
    print(f"Found sheets: {excel_file.sheet_names}")
    
    all_rules = []
    
    for sheet_name in excel_file.sheet_names:
        print(f"Processing sheet: {sheet_name}")
        
        # Skip non-rule sheets
        if any(keyword in sheet_name.lower() for keyword in ['summary', 'overview', 'introduction', 'glossary']):
            continue
        
        try:
            df = pd.read_excel(file_path, sheet_name=sheet_name)
            print(f"  Sheet '{sheet_name}' has {len(df)} rows and {len(df.columns)} columns")
            
            # Find relevant columns
            title_col = None
            check_col = None
            level_col = None
            
            for col in df.columns:
                col_lower = str(col).lower()
                if any(keyword in col_lower for keyword in ['title', 'recommendation', 'rule']):
                    title_col = col
                elif any(keyword in col_lower for keyword in ['check', 'audit', 'procedure']):
                    check_col = col
                elif any(keyword in col_lower for keyword in ['level', 'profile']):
                    level_col = col
            
            if not title_col or not check_col:
                print(f"  Skipping sheet '{sheet_name}' - missing required columns")
                continue
            
            print(f"  Using columns: Title='{title_col}', Check='{check_col}'")
            
            # Process each row
            for index, row in df.iterrows():
                title = clean_text(row[title_col])
                check = clean_text(row[check_col])
                
                # Skip empty or header rows
                if not title or title.lower() in ['title', 'recommendation', 'rule', 'na']:
                    continue
                
                # Extract rule ID
                rule_id = extract_rule_id(title)
                if not rule_id:
                    continue
                
                # Determine check type
                check_type = determine_check_type(title, check)
                
                # Create rule object
                rule = {
                    'id': rule_id,
                    'title': title,
                    'check_type': check_type,
                    'skip': False
                }
                
                # Add check-specific information
                if check_type == "registry":
                    target = parse_registry_target(check)
                    registry_name = parse_registry_name(check)
                    expected_value = parse_expected_value(check)
                    
                    if target:
                        rule['target'] = target
                    if registry_name:
                        rule['registry_name'] = registry_name
                    if expected_value:
                        rule['expected_value'] = expected_value
                
                elif check_type == "service":
                    service_info = parse_service_info(check)
                    rule.update(service_info)
                
                elif check_type == "audit_policy":
                    audit_info = parse_audit_policy_info(check)
                    rule.update(audit_info)
                
                # Add level information if available
                if level_col and level_col in row:
                    level = clean_text(row[level_col])
                    if level:
                        rule['level'] = level
                
                all_rules.append(rule)
                
        except Exception as e:
            print(f"  Error processing sheet '{sheet_name}': {e}")
            continue
    
    print(f"Total rules extracted: {len(all_rules)}")
    return all_rules

def create_baseline(rules: List[Dict[str, Any]], file_path: str) -> Dict[str, Any]:
    """Create baseline object from rules."""
    # Extract filename for baseline name
    file_name = Path(file_path).stem
    baseline_name = f"CIS {file_name.replace('_', ' ').replace('-', ' ')}"
    
    baseline = {
        'name': baseline_name,
        'version': '1.0.0',
        'description': f'CIS benchmark converted from {file_name}',
        'source_file': file_path,
        'total_rules': len(rules),
        'rules': rules
    }
    
    return baseline

def main():
    """Main function."""
    if len(sys.argv) != 3:
        print("Usage: python cis-excel-to-json.py <input_excel_file> <output_json_file>")
        print("Example: python cis-excel-to-json.py 'CIS_Windows_Server_2022_Benchmark.xlsx' 'baseline.json'")
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