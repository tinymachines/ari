#!/usr/bin/env python3

import sqlite3
import datetime
import sys
import logging
import json
import subprocess
import re

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Resource listing command patterns
RESOURCE_LIST_PATTERNS = [
    'list-', 'describe-', 'get-', '-list', 'search-'
]

class AWSCLIMapper:
    def __init__(self, access_key, secret_key, region='us-east-1', db_path='aws_inventory.db'):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        
        # Set AWS credentials as environment variables for CLI
        self.env = {
            'AWS_ACCESS_KEY_ID': self.access_key,
            'AWS_SECRET_ACCESS_KEY': self.secret_key,
            'AWS_DEFAULT_REGION': self.region
        }
    
    def initialize_database(self):
        """Create the command mapping tables if they don't exist"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()
            
            # Create command mapping table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS aws_commands (
                id INTEGER PRIMARY KEY,
                service TEXT,
                command TEXT,
                full_path TEXT UNIQUE,
                is_resource_lister BOOLEAN,
                command_type TEXT,
                help_text TEXT,
                output_example TEXT,
                last_updated TEXT
            )
            ''')
            
            # Create command arguments table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_arguments (
                id INTEGER PRIMARY KEY,
                command_id INTEGER,
                argument_name TEXT,
                argument_type TEXT,
                is_required BOOLEAN,
                description TEXT,
                FOREIGN KEY (command_id) REFERENCES aws_commands(id)
            )
            ''')
            
            self.conn.commit()
            logger.info("Command mapping database tables initialized successfully")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            sys.exit(1)
    
    def execute_aws_command(self, command):
        """Execute an AWS CLI command and return its output"""
        try:
            full_command = ['aws'] + command + ['--output', 'json']
            logger.debug(f"Executing command: {' '.join(full_command)}")
            
            result = subprocess.run(
                full_command,
                env=self.env,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return result.stdout
            else:
                logger.debug(f"Command failed: {result.stderr}")
                return None
        except Exception as e:
            logger.error(f"Error executing AWS command {' '.join(command)}: {e}")
            return None
    
    def get_help_text(self, command):
        """Get help text for a command"""
        try:
            full_command = ['aws'] + command + ['help']
            result = subprocess.run(
                full_command,
                env=self.env,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                return ""
        except Exception as e:
            logger.error(f"Error getting help for command {' '.join(command)}: {e}")
            return ""
    
    def save_command(self, service, command, full_path, is_resource_lister, command_type, help_text, output_example=None):
        """Save a command to the database"""
        now = datetime.datetime.now().isoformat()
        full_path_str = ' '.join(full_path)
        
        try:
            self.cursor.execute('''
            INSERT INTO aws_commands (
                service, command, full_path, is_resource_lister, command_type, help_text, output_example, last_updated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(full_path) DO UPDATE SET
                is_resource_lister = ?,
                command_type = ?,
                help_text = ?,
                output_example = ?,
                last_updated = ?
            ''', (
                service, command, full_path_str, is_resource_lister, command_type, help_text, 
                json.dumps(output_example) if output_example else None, now,
                is_resource_lister, command_type, help_text, 
                json.dumps(output_example) if output_example else None, now
            ))
            self.conn.commit()
            
            # Get the command ID
            self.cursor.execute("SELECT id FROM aws_commands WHERE full_path = ?", (full_path_str,))
            return self.cursor.fetchone()[0]
        except sqlite3.Error as e:
            logger.error(f"Error saving command {full_path_str}: {e}")
            return None
    
    def save_argument(self, command_id, argument_name, argument_type, is_required, description):
        """Save a command argument to the database"""
        try:
            self.cursor.execute('''
            INSERT INTO command_arguments (
                command_id, argument_name, argument_type, is_required, description
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(command_id, argument_name) DO UPDATE SET
                argument_type = ?,
                is_required = ?,
                description = ?
            ''', (
                command_id, argument_name, argument_type, is_required, description,
                argument_type, is_required, description
            ))
            self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error saving argument {argument_name} for command {command_id}: {e}")
    
    def extract_arguments_from_help(self, command_id, help_text):
        """Extract command arguments from help text"""
        # This is a simplified example - AWS CLI help text parsing is complex
        # You might need to adjust this based on the exact format
        
        # Look for sections like "Options:" or "Arguments:"
        options_section = re.search(r'(Options:|Arguments:)(.*?)(\n\n|\Z)', help_text, re.DOTALL)
        
        if not options_section:
            return
        
        options_text = options_section.group(2)
        
        # Look for argument patterns like "--argument-name (string)" or "--flag"
        argument_pattern = r'--([a-zA-Z0-9-]+)(?:\s+\(([a-zA-Z0-9-]+)\))?(?:\s+\[([a-zA-Z0-9-]+)\])?(?:\s+(.+?)(?=\n\s+--|\Z))?'
        arguments = re.finditer(argument_pattern, options_text, re.DOTALL)
        
        for match in arguments:
            arg_name = match.group(1)
            arg_type = match.group(2) or "flag"
            is_required = "required" in (match.group(3) or "").lower()
            description = (match.group(4) or "").strip()
            
            self.save_argument(command_id, arg_name, arg_type, is_required, description)
    
    def is_resource_lister(self, command_name):
        """Check if a command is likely to list resources"""
        for pattern in RESOURCE_LIST_PATTERNS:
            if pattern in command_name:
                return True
        return False
    
    def explore_command(self, path_so_far=None, depth=0, max_depth=4):
        """Recursively explore AWS CLI commands"""
        if path_so_far is None:
            path_so_far = []
        
        if depth > max_depth:
            return
        
        # Get help output for the current command path
        help_text = self.get_help_text(path_so_far)
        
        # If we're at the root, get all services
        if not path_so_far:
            service_pattern = r'\n\s*o\s+([a-z0-9-]+)\s*\n'
            services = re.findall(service_pattern, help_text)
            
            for service in services:
                logger.info(f"Exploring service: {service}")
                self.explore_command([service], depth + 1, max_depth)
            
            return
        
        # We have a service, get its subcommands
        service = path_so_far[0]
        current_command = path_so_far[-1] if len(path_so_far) > 0 else None
        
        # Different patterns depending on depth
        if len(path_so_far) == 1:  # Service level
            # Check if this is a valid service with commands
            subcmd_pattern = r'\n\s*o\s+([a-z0-9-]+)\s*\n'
            subcommands = re.findall(subcmd_pattern, help_text)
            
            command_type = "service"
        else:  # Subcommand level
            # Look for subcommands or operations
            subcmd_pattern = r'\n\s*o\s+([a-z0-9-]+)\s*\n'
            subcommands = re.findall(subcmd_pattern, help_text)
            
            # If no subcommands found, this might be a leaf command
            if not subcommands:
                # Check if this is a command that can take arguments
                if "Options:" in help_text or "Arguments:" in help_text:
                    command_type = "operation"
                    is_resource_lister = self.is_resource_lister(current_command)
                    
                    # For resource listers, get an example output
                    output_example = None
                    if is_resource_lister:
                        # Try to execute with skeleton to get the output structure
                        output_example = self.execute_aws_command(path_so_far + ['--generate-cli-skeleton', 'output'])
                    
                    # Save this command
                    command_id = self.save_command(
                        service, current_command, path_so_far, 
                        is_resource_lister, command_type, help_text, output_example
                    )
                    
                    # Extract and save arguments
                    if command_id:
                        self.extract_arguments_from_help(command_id, help_text)
                    
                    return
                else:
                    command_type = "group"
            else:
                command_type = "group"
        
        # Save this command/group
        command_id = self.save_command(
            service, current_command, path_so_far, 
            False, command_type, help_text
        )
        
        # Extract and save arguments
        if command_id:
            self.extract_arguments_from_help(command_id, help_text)
        
        # Recursively explore subcommands
        for subcmd in subcommands:
            new_path = path_so_far + [subcmd]
            self.explore_command(new_path, depth + 1, max_depth)
    
    def map_aws_cli(self):
        """Map all AWS CLI commands"""
        try:
            self.initialize_database()
            logger.info("Starting recursive AWS CLI command mapping...")
            self.explore_command()
            logger.info("AWS CLI command mapping completed")
        except Exception as e:
            logger.error(f"Error mapping AWS CLI commands: {e}")
        finally:
            if self.conn:
                self.conn.close()


def execute_command_with_mapped_resources(db_path, command_path):
    """Execute a command identified as a resource lister and save the results"""
    # This function would integrate with the service mapper and inventory
    # For now, this is a placeholder showing how we would connect the two
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get the command details
    full_path_str = ' '.join(command_path)
    cursor.execute("SELECT id, service FROM aws_commands WHERE full_path = ?", (full_path_str,))
    result = cursor.fetchone()
    
    if not result:
        logger.error(f"Command path not found in database: {full_path_str}")
        conn.close()
        return
    
    command_id, service = result
    
    # Execute the command
    # The implementation would depend on your needs
    
    conn.close()