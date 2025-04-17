#!/usr/bin/env python3

import argparse
import logging
from ari.aws_inventory import AWSInventory
from ari.aws_cli_mapper import AWSCLIMapper

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Main entry point for the CLI"""
    parser = argparse.ArgumentParser(description='AWS Resource and Cost Inventory Tool with Service Mapper')
    parser.add_argument('--access-key', required=True, help='AWS Access Key')
    parser.add_argument('--secret-key', required=True, help='AWS Secret Key')
    parser.add_argument('--region', default='us-east-1', help='AWS Region (default: us-east-1)')
    parser.add_argument('--db-path', default='aws_inventory.db', help='SQLite database path (default: aws_inventory.db)')
    parser.add_argument('--map-only', action='store_true', help='Only map services without collecting inventory')
    parser.add_argument('--inventory-only', action='store_true', help='Only collect inventory without mapping services')
    
    args = parser.parse_args()
    
    # If neither flag is set, do both
    do_mapping = not args.inventory_only
    do_inventory = not args.map_only
    
    if do_mapping:
        logger.info("Starting AWS CLI service mapping...")
        mapper = AWSCLIMapper(
            access_key=args.access_key,
            secret_key=args.secret_key,
            region=args.region,
            db_path=args.db_path
        )
        mapper.map_aws_cli()
    
    if do_inventory:
        logger.info("Starting AWS resource inventory collection...")
        inventory = AWSInventory(
            access_key=args.access_key,
            secret_key=args.secret_key,
            region=args.region,
            db_path=args.db_path
        )
        inventory.collect_inventory()
    
    logger.info("Operations completed successfully")


if __name__ == '__main__':
    main()