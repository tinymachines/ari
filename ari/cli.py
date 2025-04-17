#!/usr/bin/env python3

import argparse
import logging
import sys
from typing import List, Optional

from ari.aws_inventory import AWSInventory
from ari.aws_cli_mapper import AWSCLIMapper
from ari.config import get_config

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main(args: Optional[List[str]] = None):
    """Main entry point for the CLI"""
    try:
        # Get configuration from environment and command line
        config = get_config(args)
        
        # Validate configuration
        errors = config.validate()
        if errors:
            for error in errors:
                logger.error(error)
            sys.exit(1)
        
        # Log the configuration (with masked secrets)
        logger.info(f"Using configuration: {config}")
        
        # If neither flag is set, do both
        do_mapping = not config.inventory_only
        do_inventory = not config.map_only
        
        if do_mapping:
            logger.info("Starting AWS CLI service mapping...")
            mapper = AWSCLIMapper(
                access_key=config.access_key,
                secret_key=config.secret_key,
                region=config.region,
                db_path=config.db_path
            )
            mapper.map_aws_cli()
        
        if do_inventory:
            logger.info("Starting AWS resource inventory collection...")
            inventory = AWSInventory(
                access_key=config.access_key,
                secret_key=config.secret_key,
                profile=config.profile,
                region=config.region,
                regions=config.regions,
                db_path=config.db_path,
                services=config.services,
                max_resources=config.max_resources,
                max_threads=config.max_threads
            )
            inventory.collect_inventory()
        
        logger.info("Operations completed successfully")
        return 0
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())