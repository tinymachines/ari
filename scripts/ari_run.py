#!/usr/bin/env python3
"""
ARI - AWS Resource Inventory and Service Mapper
Terminal wrapper with account selection menu
"""

import os
import sys
import configparser
import argparse
from typing import Dict, List, Tuple, Optional
import logging
import traceback

# Enable importing from parent directory when running script directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from ari.aws_inventory import AWSInventory
    from ari.aws_cli_mapper import AWSCLIMapper
except ImportError:
    print("Error: ARI package not found. Please install it with 'pip install -e .'")
    sys.exit(1)

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def setup_logging():
    """Set up logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('ari_run.log')
        ]
    )
    return logging.getLogger(__name__)

def read_aws_credentials() -> Dict[str, Dict[str, str]]:
    """Read AWS credentials from ~/.aws/credentials file"""
    credentials_path = os.path.expanduser("~/.aws/credentials")
    
    if not os.path.exists(credentials_path):
        print(f"{Colors.RED}Error: AWS credentials file not found at {credentials_path}{Colors.ENDC}")
        print(f"{Colors.YELLOW}Please make sure you have AWS CLI configured.{Colors.ENDC}")
        print(f"Run {Colors.BOLD}aws configure{Colors.ENDC} to set up your credentials.")
        sys.exit(1)
    
    config = configparser.ConfigParser()
    config.read(credentials_path)
    
    credentials = {}
    for profile in config.sections():
        if 'aws_access_key_id' in config[profile] and 'aws_secret_access_key' in config[profile]:
            credentials[profile] = {
                'access_key': config[profile]['aws_access_key_id'],
                'secret_key': config[profile]['aws_secret_access_key'],
                'region': config[profile].get('region', 'us-east-1')
            }
    
    return credentials

def display_menu(profiles: List[str]) -> int:
    """Display a menu to select an AWS profile and return the chosen index"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}AWS Resource Inventory and Service Mapper{Colors.ENDC}")
    print(f"{Colors.CYAN}Select an AWS profile to scan:{Colors.ENDC}\n")
    
    for i, profile in enumerate(profiles, 1):
        print(f"{Colors.GREEN}{i}.{Colors.ENDC} {Colors.BOLD}{profile}{Colors.ENDC}")
    
    print(f"\n{Colors.YELLOW}0. Exit{Colors.ENDC}")
    
    while True:
        try:
            choice = int(input(f"\n{Colors.BOLD}Enter your choice [1-{len(profiles)}]: {Colors.ENDC}"))
            if 0 <= choice <= len(profiles):
                return choice
            print(f"{Colors.RED}Invalid choice. Please select a number between 0 and {len(profiles)}.{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.RED}Invalid input. Please enter a number.{Colors.ENDC}")

def display_operation_menu() -> Tuple[bool, bool]:
    """Display menu to select which operations to perform"""
    print(f"\n{Colors.CYAN}Select operations to perform:{Colors.ENDC}\n")
    print(f"{Colors.GREEN}1.{Colors.ENDC} Full scan (inventory + CLI mapping)")
    print(f"{Colors.GREEN}2.{Colors.ENDC} Resource inventory only")
    print(f"{Colors.GREEN}3.{Colors.ENDC} CLI mapping only")
    
    while True:
        try:
            choice = int(input(f"\n{Colors.BOLD}Enter your choice [1-3]: {Colors.ENDC}"))
            if choice == 1:
                return True, True
            elif choice == 2:
                return True, False
            elif choice == 3:
                return False, True
            print(f"{Colors.RED}Invalid choice. Please select a number between 1 and 3.{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.RED}Invalid input. Please enter a number.{Colors.ENDC}")

def display_progress(message: str):
    """Display a progress message"""
    print(f"{Colors.BLUE}[+] {message}{Colors.ENDC}")

def run_inventory(credentials: Dict[str, str], db_path: str):
    """Run the inventory collection"""
    display_progress("Starting AWS resource inventory collection...")
    
    inventory = AWSInventory(
        access_key=credentials['access_key'],
        secret_key=credentials['secret_key'],
        region=credentials['region'],
        db_path=db_path
    )
    inventory.collect_inventory()
    
    display_progress("Inventory collection completed!")

def run_cli_mapping(credentials: Dict[str, str], db_path: str):
    """Run the AWS CLI mapping"""
    display_progress("Starting AWS CLI service mapping...")
    
    mapper = AWSCLIMapper(
        access_key=credentials['access_key'],
        secret_key=credentials['secret_key'],
        region=credentials['region'],
        db_path=db_path
    )
    mapper.map_aws_cli()
    
    display_progress("CLI mapping completed!")

def main():
    """Main function"""
    logger = setup_logging()
    
    parser = argparse.ArgumentParser(description='ARI - AWS Resource Inventory and Service Mapper')
    parser.add_argument('--db-path', default='aws_inventory.db', help='SQLite database path')
    parser.add_argument('--profile', help='AWS profile name to use (skips menu)')
    args = parser.parse_args()
    
    try:
        # Read AWS credentials
        credentials = read_aws_credentials()
        
        if not credentials:
            print(f"{Colors.RED}No valid AWS profiles found in credentials file.{Colors.ENDC}")
            sys.exit(1)
        
        profiles = list(credentials.keys())
        selected_profile = None
        
        # Use specified profile or show menu
        if args.profile:
            if args.profile in credentials:
                selected_profile = args.profile
                print(f"{Colors.GREEN}Using profile: {selected_profile}{Colors.ENDC}")
            else:
                print(f"{Colors.RED}Profile '{args.profile}' not found in credentials file.{Colors.ENDC}")
                print(f"{Colors.YELLOW}Available profiles: {', '.join(profiles)}{Colors.ENDC}")
                sys.exit(1)
        else:
            # Display menu for profile selection
            choice = display_menu(profiles)
            
            if choice == 0:
                print(f"{Colors.YELLOW}Exiting...{Colors.ENDC}")
                sys.exit(0)
            
            selected_profile = profiles[choice - 1]
        
        # Select operations to perform
        run_inventory_flag, run_mapping_flag = display_operation_menu()
        
        profile_creds = credentials[selected_profile]
        db_path = args.db_path
        
        # Run selected operations
        print(f"\n{Colors.HEADER}{Colors.BOLD}Starting scan with profile: {selected_profile}{Colors.ENDC}\n")
        
        if run_inventory_flag:
            run_inventory(profile_creds, db_path)
        
        if run_mapping_flag:
            run_cli_mapping(profile_creds, db_path)
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}Scan completed successfully!{Colors.ENDC}")
        print(f"{Colors.CYAN}Database saved to: {os.path.abspath(db_path)}{Colors.ENDC}\n")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Operation cancelled by user.{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        print(f"\n{Colors.RED}Error: {str(e)}{Colors.ENDC}")
        print(f"{Colors.YELLOW}Check ari_run.log for details.{Colors.ENDC}")
        traceback.print_exc(file=open('ari_run.log', 'a'))
        sys.exit(1)

if __name__ == "__main__":
    main()