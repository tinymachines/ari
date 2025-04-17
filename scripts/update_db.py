#!/usr/bin/env python3
"""
ARI - Database Update Script

This script handles database schema migrations and rebuilding for ARI.
It can detect and update old database schemas to match the current version.
"""

import os
import sys
import argparse
import sqlite3
import logging
import shutil
from datetime import datetime
import glob

# Enable importing from parent directory when running script directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('update_db.log')
    ]
)
logger = logging.getLogger(__name__)

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

def print_colored(text, color):
    """Print text with color"""
    print(f"{color}{text}{Colors.ENDC}")

def backup_database(db_path):
    """Create a backup of the database"""
    if not os.path.exists(db_path):
        logger.warning(f"Database file {db_path} does not exist, no backup needed")
        return None
    
    backup_dir = os.path.join(os.path.dirname(db_path), 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(backup_dir, f"{os.path.basename(db_path)}.{timestamp}.bak")
    
    try:
        shutil.copy2(db_path, backup_path)
        logger.info(f"Created database backup at {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create database backup: {e}")
        return None

def get_current_schema(db_path):
    """Get the current schema version from the database"""
    if not os.path.exists(db_path):
        return None
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if schema_version table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
        if not cursor.fetchone():
            # No schema_version table, so this is an old version
            return "0.0.0"
        
        # Get the current schema version
        cursor.execute("SELECT version FROM schema_version ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else "0.0.0"
    except sqlite3.Error as e:
        logger.error(f"Error getting database schema version: {e}")
        return None

def check_column_exists(cursor, table, column):
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table})")
    return any(col[1] == column for col in cursor.fetchall())

def create_schema_version_table(cursor):
    """Create the schema_version table"""
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS schema_version (
        id INTEGER PRIMARY KEY,
        version TEXT,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

def update_schema_version(cursor, version):
    """Update the schema version in the database"""
    create_schema_version_table(cursor)
    cursor.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))

def upgrade_to_v0_2_0(conn, cursor):
    """Upgrade schema to version 0.2.0"""
    logger.info("Upgrading database schema to v0.2.0...")
    
    try:
        # Check if the resources table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='resources'")
        if not cursor.fetchone():
            logger.error("Resources table does not exist, cannot upgrade")
            return False
        
        # Create a temporary table with the new schema
        cursor.execute('''
        CREATE TABLE resources_new (
            id INTEGER PRIMARY KEY,
            service_id INTEGER,
            resource_id TEXT UNIQUE,
            arn TEXT,
            resource_name TEXT,
            resource_type TEXT,
            region TEXT,
            creation_date TEXT,
            tags TEXT,
            properties TEXT,
            security_groups TEXT,
            relationships TEXT,
            metadata TEXT,
            last_updated TEXT,
            FOREIGN KEY (service_id) REFERENCES services(id)
        )
        ''')
        
        # Copy data from the old table to the new table
        try:
            # Check which columns exist in the old table
            cursor.execute("PRAGMA table_info(resources)")
            old_columns = [col[1] for col in cursor.fetchall()]
            
            # Prepare data migration SQL
            select_cols = ", ".join(old_columns)
            target_cols = select_cols
            
            # Add NULL values for new columns
            if "arn" not in old_columns:
                target_cols += ", NULL as arn"
            if "security_groups" not in old_columns:
                target_cols += ", NULL as security_groups"
            if "relationships" not in old_columns:
                target_cols += ", NULL as relationships"
            if "metadata" not in old_columns:
                target_cols += ", NULL as metadata"
            
            # Copy data from old table to new table
            cursor.execute(f"INSERT INTO resources_new ({target_cols}) SELECT {select_cols} FROM resources")
            
            # Drop old table and rename new table
            cursor.execute("DROP TABLE resources")
            cursor.execute("ALTER TABLE resources_new RENAME TO resources")
            
            logger.info("Successfully migrated resources table to new schema")
        except sqlite3.Error as e:
            logger.error(f"Error migrating data to new schema: {e}")
            conn.rollback()
            return False
        
        # Update schema version
        update_schema_version(cursor, "0.2.0")
        conn.commit()
        return True
        
    except sqlite3.Error as e:
        logger.error(f"Error upgrading database schema: {e}")
        conn.rollback()
        return False

def rebuild_database(db_path):
    """Completely rebuild the database"""
    logger.info("Rebuilding database from scratch...")
    
    try:
        # Remove existing database
        if os.path.exists(db_path):
            os.remove(db_path)
            logger.info(f"Removed existing database at {db_path}")
        
        # Import database initialization code from aws_inventory
        from ari.aws_inventory import AWSInventory
        
        # Create a dummy inventory instance to initialize the database
        dummy_inventory = AWSInventory(
            access_key="dummy",
            secret_key="dummy",
            db_path=db_path
        )
        
        # Initialize the database with the current schema
        dummy_inventory.initialize_database()
        
        # Add schema version
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        update_schema_version(cursor, "0.2.0")
        conn.commit()
        conn.close()
        
        logger.info(f"Successfully rebuilt database at {db_path}")
        return True
    except Exception as e:
        logger.error(f"Error rebuilding database: {e}")
        return False

def clean_old_backups(db_path, keep=5):
    """Clean up old database backups, keeping only the most recent ones"""
    backup_dir = os.path.join(os.path.dirname(db_path), 'backups')
    if not os.path.exists(backup_dir):
        return
    
    basename = os.path.basename(db_path)
    backups = glob.glob(os.path.join(backup_dir, f"{basename}.*.bak"))
    
    # Sort backups by modification time (newest first)
    backups.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    # Keep the most recent 'keep' backups, delete the rest
    if len(backups) > keep:
        for old_backup in backups[keep:]:
            try:
                os.remove(old_backup)
                logger.info(f"Removed old backup: {old_backup}")
            except Exception as e:
                logger.warning(f"Could not remove old backup {old_backup}: {e}")

def process_database(db_path, args):
    """Process the database according to the provided arguments"""
    current_version = get_current_schema(db_path)
    
    if args.rebuild:
        print_colored("Rebuilding database from scratch...", Colors.YELLOW)
        backup_database(db_path)
        if rebuild_database(db_path):
            print_colored("Database successfully rebuilt!", Colors.GREEN)
            return True
        else:
            print_colored("Failed to rebuild database.", Colors.RED)
            return False
    
    if not current_version:
        if not os.path.exists(db_path):
            print_colored(f"Database file {db_path} does not exist.", Colors.YELLOW)
            if args.create:
                print_colored("Creating new database...", Colors.BLUE)
                if rebuild_database(db_path):
                    print_colored("Database successfully created!", Colors.GREEN)
                    return True
                else:
                    print_colored("Failed to create database.", Colors.RED)
                    return False
            else:
                print_colored("Use --create to create a new database.", Colors.CYAN)
                return False
        else:
            print_colored(f"Could not determine schema version for {db_path}", Colors.RED)
            return False
    
    if current_version == "0.0.0":
        print_colored(f"Found database with old schema (pre-versioning)", Colors.YELLOW)
        if args.migrate:
            print_colored("Migrating database schema...", Colors.BLUE)
            backup_path = backup_database(db_path)
            if not backup_path:
                print_colored("Failed to create backup, aborting migration.", Colors.RED)
                return False
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            if upgrade_to_v0_2_0(conn, cursor):
                print_colored("Database migration to v0.2.0 completed successfully!", Colors.GREEN)
                conn.close()
                return True
            else:
                conn.close()
                print_colored("Migration failed, consider using --rebuild option.", Colors.RED)
                print_colored(f"Your original database was backed up to {backup_path}", Colors.YELLOW)
                return False
        else:
            print_colored("Use --migrate to update the schema or --rebuild to recreate the database.", Colors.CYAN)
            return False
    
    if current_version == "0.2.0":
        print_colored(f"Database is already at the latest version (v0.2.0).", Colors.GREEN)
        return True
    
    print_colored(f"Unknown database version: {current_version}", Colors.RED)
    return False

def main():
    parser = argparse.ArgumentParser(description='ARI Database Update Script')
    parser.add_argument('--db-path', default='aws_inventory.db', help='SQLite database path')
    parser.add_argument('--rebuild', action='store_true', help='Completely rebuild the database (will delete all data)')
    parser.add_argument('--migrate', action='store_true', help='Migrate the database schema to the latest version')
    parser.add_argument('--create', action='store_true', help='Create a new database if it does not exist')
    parser.add_argument('--clean-backups', action='store_true', help='Clean up old database backups')
    parser.add_argument('--keep', type=int, default=5, help='Number of backups to keep when cleaning')
    args = parser.parse_args()
    
    db_path = os.path.abspath(args.db_path)
    
    print_colored(f"ARI Database Update Script", Colors.HEADER + Colors.BOLD)
    print_colored(f"{'=' * 50}", Colors.HEADER)
    print_colored(f"Target database: {db_path}", Colors.BLUE)
    
    success = process_database(db_path, args)
    
    if success and args.clean_backups:
        print_colored(f"Cleaning old database backups, keeping {args.keep} most recent...", Colors.YELLOW)
        clean_old_backups(db_path, args.keep)
    
    if success:
        print_colored("\nDatabase update completed successfully!", Colors.GREEN + Colors.BOLD)
    else:
        print_colored("\nDatabase update encountered issues. Check the logs for details.", Colors.RED + Colors.BOLD)

if __name__ == "__main__":
    main()