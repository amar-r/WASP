#!/usr/bin/env python3
"""
Validate Check Types in CIS JSON Baseline
Analyzes the JSON baseline to ensure check_type assignments are correct.
"""

import json
import re
from typing import Dict, List, Tuple

def load_baseline(file_path: str) -> Dict:
    """Load the JSON baseline file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def analyze_rule(rule: Dict) -> Tuple[str | None, str, List[str]]:
    """
    Analyze a rule to determine what check_type it should have.
    Returns: (suggested_type, confidence, reasons)
    """
    title = rule.get('title', '').lower()
    description = rule.get('description', '').lower()
    remediation = rule.get('remediation_procedure', '').lower()
    audit_procedure = rule.get('audit_procedure', '').lower()
    target = rule.get('target', '').lower()
    
    reasons = []
    suggested_type = None
    confidence = "low"
    
    # Keywords for each check type
    secpol_keywords = [
        'password', 'account lockout', 'user rights', 'security options',
        'audit policy', 'event log', 'system services', 'registry',
        'file system', 'wireless network', 'public key', 'ipsec',
        'administrative templates', 'windows settings', 'security settings',
        'local policies', 'account policies', 'kerberos', 'domain controller',
        'domain member', 'stand-alone', 'domain', 'local computer'
    ]
    
    registry_keywords = [
        'registry', 'regedit', 'hklm', 'hkcu', 'hkcr', 'hku',
        'currentcontrolset', 'software\\', 'system\\', 'windows\\',
        'microsoft\\', 'policies\\', 'explorer\\', 'internet settings',
        'network\\', 'services\\', 'drivers\\', 'control\\'
    ]
    
    auditpol_keywords = [
        'audit', 'auditing', 'audit policy', 'audit settings',
        'success and failure', 'success', 'failure', 'no auditing',
        'auditpol', 'audit policy change', 'logon audit', 'object access audit'
    ]
    
    # Check title patterns
    if any(keyword in title for keyword in auditpol_keywords):
        if 'audit' in title and ('policy' in title or 'auditing' in title):
            suggested_type = "auditpol"
            confidence = "high"
            reasons.append("Title contains audit policy keywords")
    
    # Check description patterns
    if any(keyword in description for keyword in registry_keywords):
        if 'registry' in description and ('key' in description or 'value' in description):
            suggested_type = "registry"
            confidence = "high"
            reasons.append("Description mentions registry keys/values")
    
    # Check remediation procedure
    if remediation:
        if 'registry' in remediation and ('hklm' in remediation or 'hkcu' in remediation):
            suggested_type = "registry"
            confidence = "high"
            reasons.append("Remediation mentions registry paths")
        elif 'security settings' in remediation or 'policies' in remediation:
            if 'audit' in remediation:
                suggested_type = "auditpol"
                confidence = "medium"
                reasons.append("Remediation mentions audit policy settings")
            else:
                suggested_type = "secpol"
                confidence = "medium"
                reasons.append("Remediation mentions security policy settings")
    
    # Check audit procedure
    if audit_procedure:
        if audit_procedure.startswith('hklm') or audit_procedure.startswith('hkcu'):
            suggested_type = "registry"
            confidence = "high"
            reasons.append("Audit procedure specifies registry path")
        elif 'auditpol' in audit_procedure:
            suggested_type = "auditpol"
            confidence = "high"
            reasons.append("Audit procedure mentions auditpol")
        elif 'secedit' in audit_procedure or 'security policy' in audit_procedure:
            suggested_type = "secpol"
            confidence = "high"
            reasons.append("Audit procedure mentions security policy")
    
    # Check target field
    if target:
        if 'registry' in target:
            suggested_type = "registry"
            confidence = "high"
            reasons.append("Target field specifies Registry")
        elif 'audit policy' in target:
            suggested_type = "auditpol"
            confidence = "high"
            reasons.append("Target field specifies Audit Policy")
        elif 'security' in target or 'policies' in target:
            suggested_type = "secpol"
            confidence = "medium"
            reasons.append("Target field mentions security/policies")
    
    # Special cases based on rule content
    if 'password' in title or 'account lockout' in title:
        if 'audit' not in title and 'audit' not in description:
            suggested_type = "secpol"
            confidence = "high"
            reasons.append("Password/account lockout settings are security policy")
    
    if 'user rights' in title or 'user right' in title:
        suggested_type = "secpol"
        confidence = "high"
        reasons.append("User rights are security policy settings")
    
    if 'system services' in title or 'service' in title:
        suggested_type = "secpol"
        confidence = "high"
        reasons.append("System services are security policy settings")
    
    if 'file system' in title or 'ntfs' in title:
        suggested_type = "secpol"
        confidence = "high"
        reasons.append("File system settings are security policy")
    
    # If no specific indicators found, default to secpol for security-related rules
    if not suggested_type:
        if any(keyword in title for keyword in secpol_keywords):
            suggested_type = "secpol"
            confidence = "low"
            reasons.append("Default to secpol for security-related rules")
    
    return suggested_type, confidence, reasons

def validate_baseline(baseline_path: str) -> Dict:
    """Validate all rules in the baseline."""
    baseline = load_baseline(baseline_path)
    rules = baseline.get('rules', [])
    
    results = {
        'total_rules': len(rules),
        'correct': 0,
        'incorrect': 0,
        'uncertain': 0,
        'issues': [],
        'summary': {
            'secpol': {'correct': 0, 'incorrect': 0, 'uncertain': 0},
            'registry': {'correct': 0, 'incorrect': 0, 'uncertain': 0},
            'auditpol': {'correct': 0, 'incorrect': 0, 'uncertain': 0}
        }
    }
    
    for rule in rules:
        rule_id = rule.get('id', 'Unknown')
        current_type = rule.get('check_type', 'Unknown')
        title = rule.get('title', 'No title')
        
        suggested_type, confidence, reasons = analyze_rule(rule)
        
        if suggested_type:
            if suggested_type == current_type:
                results['correct'] += 1
                results['summary'][current_type]['correct'] += 1
                status = "CORRECT"
            else:
                results['incorrect'] += 1
                results['summary'][current_type]['incorrect'] += 1
                status = "INCORRECT"
                
                results['issues'].append({
                    'rule_id': rule_id,
                    'title': title,
                    'current_type': current_type,
                    'suggested_type': suggested_type,
                    'confidence': confidence,
                    'reasons': reasons
                })
        else:
            results['uncertain'] += 1
            results['summary'][current_type]['uncertain'] += 1
            status = "UNCERTAIN"
            
            results['issues'].append({
                'rule_id': rule_id,
                'title': title,
                'current_type': current_type,
                'suggested_type': 'Unknown',
                'confidence': 'low',
                'reasons': ['Could not determine appropriate check type']
            })
    
    return results

def print_results(results: Dict):
    """Print validation results."""
    print("=" * 80)
    print("CIS JSON BASELINE CHECK_TYPE VALIDATION")
    print("=" * 80)
    
    print(f"\nSUMMARY:")
    print(f"Total Rules: {results['total_rules']}")
    print(f"Correct: {results['correct']}")
    print(f"Incorrect: {results['incorrect']}")
    print(f"Uncertain: {results['uncertain']}")
    
    print(f"\nBREAKDOWN BY TYPE:")
    for check_type, counts in results['summary'].items():
        total = counts['correct'] + counts['incorrect'] + counts['uncertain']
        if total > 0:
            print(f"  {check_type.upper()}: {total} total")
            print(f"    Correct: {counts['correct']}")
            print(f"    Incorrect: {counts['incorrect']}")
            print(f"    Uncertain: {counts['uncertain']}")
    
    if results['issues']:
        print(f"\nISSUES FOUND ({len(results['issues'])}):")
        print("-" * 80)
        
        for issue in results['issues']:
            print(f"Rule ID: {issue['rule_id']}")
            print(f"Title: {issue['title']}")
            print(f"Current Type: {issue['current_type']}")
            print(f"Suggested Type: {issue['suggested_type']}")
            print(f"Confidence: {issue['confidence']}")
            print(f"Reasons: {', '.join(issue['reasons'])}")
            print("-" * 40)
    else:
        print(f"\n✅ No issues found! All check_type assignments appear correct.")

def main():
    """Main function."""
    baseline_path = "baselines/cis-windows-server-2022-member-server.json"
    
    try:
        results = validate_baseline(baseline_path)
        print_results(results)
        
        # Save detailed results to file
        output_file = "reports/check_type_validation.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\nDetailed results saved to: {output_file}")
        
    except FileNotFoundError:
        print(f"Error: Baseline file not found at {baseline_path}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main() 