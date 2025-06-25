#!/usr/bin/env python3
"""
Fix Check Types in CIS JSON Baseline
Updates incorrect check_type assignments based on validation results.
"""

import json
import shutil
from datetime import datetime

def load_baseline(file_path: str) -> dict:
    """Load the JSON baseline file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_baseline(baseline: dict, file_path: str):
    """Save the JSON baseline file."""
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(baseline, f, indent=2, ensure_ascii=False)

def fix_check_types(baseline: dict) -> tuple[dict, list[str]]:
    """Fix incorrect check_type assignments."""
    
    # Rules that need to be changed from registry to secpol
    registry_to_secpol = [
        "1.1.6",   # Relax minimum password length limits
        "2.3.1.2", # Accounts: Limit local account use of blank passwords
        "2.3.6.4", # Domain member: Disable machine account password changes
        "2.3.6.5", # Domain member: Maximum machine account password age
        "2.3.7.7", # Interactive logon: Prompt user to change password
        "2.3.8.3", # Microsoft network client: Send unencrypted password
        "2.3.10.4", # Network access: Do not allow storage of passwords
        "2.3.11.5", # Network security: Do not store LAN Manager hash
        "18.1.2.2", # Allow users to enable online speech recognition
        "18.9.25.1", # Configure password backup directory
        "18.9.25.2", # Do not allow password expiration time longer
        "18.9.25.3", # Enable password encryption
        "18.9.25.4", # Password Settings: Password Complexity
        "18.9.25.5", # Password Settings: Password Length
        "18.9.25.6", # Password Settings: Password Age (Days)
        "18.9.25.8", # Post-authentication actions: Actions
        "18.9.28.6", # Turn off picture password sign-in
        "18.9.33.6.3", # Require a password when a computer wakes (battery)
        "18.9.33.6.4", # Require a password when a computer wakes (plugged in)
        "18.10.15.1", # Do not display the password reveal button
        "18.10.57.2.2", # Do not allow passwords to be saved
        "18.10.57.3.9.1", # Always prompt for password upon connection
        "18.10.82.1", # Configure transmission of user's password
        "18.6.10.2", # Turn off Microsoft Peer-to-Peer Networking Services
        "18.10.16.2", # Configure Authenticated Proxy usage
        "18.10.41.1", # Allow Message Service Cloud Sync
        "18.10.56.1", # Turn off Push To Install service
        "18.10.57.3.2.1", # Restrict Remote Desktop Services users
        "18.10.57.3.10.1", # Set time limit for active but idle RDS sessions
    ]
    
    # Rules that need to be changed from auditpol to secpol
    auditpol_to_secpol = [
        "1.2.2",   # Account lockout threshold
    ]
    
    changes_made = []
    
    for rule in baseline['rules']:
        rule_id = rule.get('id')
        current_type = rule.get('check_type')
        
        if rule_id in registry_to_secpol and current_type == 'registry':
            rule['check_type'] = 'secpol'
            changes_made.append(f"Rule {rule_id}: registry → secpol")
            
        elif rule_id in auditpol_to_secpol and current_type == 'auditpol':
            rule['check_type'] = 'secpol'
            changes_made.append(f"Rule {rule_id}: auditpol → secpol")
    
    return baseline, changes_made

def count_check_types(baseline: dict) -> dict:
    """Count check types in the baseline."""
    counts = {'registry': 0, 'secpol': 0, 'auditpol': 0}
    
    for rule in baseline['rules']:
        check_type = rule.get('check_type')
        if check_type in counts:
            counts[check_type] += 1
    
    return counts

def main():
    """Main function."""
    baseline_path = "baselines/cis-windows-server-2022-member-server.json"
    backup_path = f"baselines/cis-windows-server-2022-member-server.json.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        # Load baseline
        print("Loading baseline...")
        baseline = load_baseline(baseline_path)
        
        # Show original counts
        original_counts = count_check_types(baseline)
        print(f"\nOriginal counts:")
        for check_type, count in original_counts.items():
            print(f"  {check_type}: {count}")
        
        # Create backup
        print(f"\nCreating backup: {backup_path}")
        shutil.copy2(baseline_path, backup_path)
        
        # Fix check types
        print("\nFixing check types...")
        baseline, changes_made = fix_check_types(baseline)
        
        if changes_made:
            print(f"\nChanges made ({len(changes_made)}):")
            for change in changes_made:
                print(f"  {change}")
            
            # Show new counts
            new_counts = count_check_types(baseline)
            print(f"\nNew counts:")
            for check_type, count in new_counts.items():
                print(f"  {check_type}: {count}")
            
            # Update metadata
            baseline['metadata']['last_modified'] = datetime.now().isoformat()
            baseline['metadata']['check_type_fixes'] = len(changes_made)
            
            # Save updated baseline
            print(f"\nSaving updated baseline...")
            save_baseline(baseline, baseline_path)
            
            print(f"\n✅ Successfully fixed {len(changes_made)} check type assignments!")
            print(f"Backup saved to: {backup_path}")
            
        else:
            print("\n✅ No changes needed - all check types are correct!")
            
    except FileNotFoundError:
        print(f"Error: Baseline file not found at {baseline_path}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main() 