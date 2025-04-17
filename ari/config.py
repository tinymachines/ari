"""
Configuration management for ARI
Handles loading configuration from environment variables and command line arguments
"""

import os
import sys
import argparse
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from dataclasses import dataclass, field
import logging

# Try to import dotenv for environment variables
try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class ARIConfig:
    """Configuration for ARI"""
    # AWS credentials
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    profile: Optional[str] = None
    
    # AWS regions
    region: str = "us-east-1"
    regions: List[str] = field(default_factory=list)
    
    # Database
    db_path: str = "aws_inventory.db"
    
    # Execution options
    map_only: bool = False
    inventory_only: bool = False
    
    # Resource scanning options
    services: List[str] = field(default_factory=list)
    max_resources: int = 0
    max_threads: int = 5
    
    def __post_init__(self):
        """Set regions list if not already populated"""
        if not self.regions and self.region:
            self.regions = [self.region]

    @classmethod
    def from_env(cls) -> "ARIConfig":
        """Load configuration from environment variables"""
        # Load .env file if available
        if DOTENV_AVAILABLE:
            env_file = Path(".env")
            if env_file.exists():
                load_dotenv(env_file)
                logger.info(f"Loaded configuration from {env_file.absolute()}")
        
        config = cls(
            access_key=os.environ.get("AWS_ACCESS_KEY"),
            secret_key=os.environ.get("AWS_SECRET_KEY"),
            profile=os.environ.get("AWS_PROFILE"),
            region=os.environ.get("AWS_REGION", "us-east-1"),
            db_path=os.environ.get("DB_PATH", "aws_inventory.db"),
            map_only=os.environ.get("MAP_ONLY", "").lower() == "true",
            inventory_only=os.environ.get("INVENTORY_ONLY", "").lower() == "true",
            max_resources=int(os.environ.get("MAX_RESOURCES", "0")),
            max_threads=int(os.environ.get("MAX_THREADS", "5"))
        )
        
        # Process regions
        regions_str = os.environ.get("AWS_REGIONS", "")
        if regions_str:
            config.regions = [r.strip() for r in regions_str.split(",") if r.strip()]
            if not config.regions and config.region:
                config.regions = [config.region]
        
        # Process services
        services_str = os.environ.get("SERVICES", "")
        if services_str:
            config.services = [s.strip() for s in services_str.split(",") if s.strip()]
        
        return config
    
    @classmethod
    def from_args(cls, args: Optional[List[str]] = None) -> "ARIConfig":
        """Load configuration from command line arguments"""
        parser = argparse.ArgumentParser(description="AWS Resource Inventory and Service Mapper")
        
        # AWS credentials
        cred_group = parser.add_argument_group("AWS Credentials")
        cred_group.add_argument("--access-key", help="AWS Access Key")
        cred_group.add_argument("--secret-key", help="AWS Secret Key")
        cred_group.add_argument("--profile", help="AWS Profile name")
        
        # AWS regions
        region_group = parser.add_argument_group("AWS Regions")
        region_group.add_argument("--region", default="us-east-1", help="AWS Region (default: us-east-1)")
        region_group.add_argument("--regions", help="Comma-separated list of AWS regions")
        
        # Database
        parser.add_argument("--db-path", help="SQLite database path")
        
        # Execution options
        exec_group = parser.add_argument_group("Execution Options")
        exec_group.add_argument("--map-only", action="store_true", help="Only map services without collecting inventory")
        exec_group.add_argument("--inventory-only", action="store_true", help="Only collect inventory without mapping services")
        
        # Resource scanning options
        scan_group = parser.add_argument_group("Resource Scanning Options")
        scan_group.add_argument("--services", help="Comma-separated list of services to scan")
        scan_group.add_argument("--max-resources", type=int, help="Maximum number of resources to collect per service")
        scan_group.add_argument("--max-threads", type=int, help="Maximum threads for concurrent resource collection")
        
        # Parse arguments
        parsed_args = parser.parse_args(args)
        
        # Convert to dictionary and filter None values
        args_dict = {k: v for k, v in vars(parsed_args).items() if v is not None}
        
        # Start with config from environment
        config = cls.from_env()
        
        # Update with command line arguments
        if "access_key" in args_dict:
            config.access_key = args_dict["access_key"]
        if "secret_key" in args_dict:
            config.secret_key = args_dict["secret_key"]
        if "profile" in args_dict:
            config.profile = args_dict["profile"]
        if "region" in args_dict:
            config.region = args_dict["region"]
        if "db_path" in args_dict:
            config.db_path = args_dict["db_path"]
        if "map_only" in args_dict:
            config.map_only = args_dict["map_only"]
        if "inventory_only" in args_dict:
            config.inventory_only = args_dict["inventory_only"]
        if "max_resources" in args_dict:
            config.max_resources = args_dict["max_resources"]
        if "max_threads" in args_dict:
            config.max_threads = args_dict["max_threads"]
        
        # Process regions
        if "regions" in args_dict and args_dict["regions"]:
            config.regions = [r.strip() for r in args_dict["regions"].split(",") if r.strip()]
        if not config.regions and config.region:
            config.regions = [config.region]
        
        # Process services
        if "services" in args_dict and args_dict["services"]:
            config.services = [s.strip() for s in args_dict["services"].split(",") if s.strip()]
        
        return config
    
    def validate(self) -> List[str]:
        """Validate the configuration and return a list of errors"""
        errors = []
        
        # Check for credentials
        if not self.access_key and not self.secret_key and not self.profile:
            errors.append("No AWS credentials provided. Use --access-key and --secret-key, --profile, or set in .env file")
        
        # Check for regions
        if not self.regions:
            errors.append("No AWS regions specified")
        
        # Check for incompatible options
        if self.map_only and self.inventory_only:
            errors.append("Cannot use both --map-only and --inventory-only together")
        
        return errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "access_key": self.access_key,
            "secret_key": self.secret_key,
            "profile": self.profile,
            "region": self.region,
            "regions": self.regions,
            "db_path": self.db_path,
            "map_only": self.map_only,
            "inventory_only": self.inventory_only,
            "services": self.services,
            "max_resources": self.max_resources,
            "max_threads": self.max_threads
        }
    
    def __str__(self) -> str:
        """String representation with masked secrets"""
        config_dict = self.to_dict()
        if config_dict["access_key"]:
            config_dict["access_key"] = f"{config_dict['access_key'][:4]}...{config_dict['access_key'][-4:]}"
        if config_dict["secret_key"]:
            config_dict["secret_key"] = "********"
        
        return str(config_dict)


def get_config(args: Optional[List[str]] = None) -> ARIConfig:
    """Get configuration from environment and command line"""
    return ARIConfig.from_args(args)