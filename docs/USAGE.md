# ARI Usage Guide

## Installation

Install ARI from PyPI:

```bash
pip install ari
```

For development installation:

```bash
git clone https://github.com/yourusername/ari.git
cd ari
pip install -e .
```

## Basic Usage

### Running ARI with default settings

```bash
ari --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY
```

### Optional parameters

- `--region`: Specify a default AWS region (default: us-east-1)
- `--db-path`: Specify a custom SQLite database path (default: aws_inventory.db)
- `--map-only`: Only map the AWS CLI command structure
- `--inventory-only`: Only collect the resource inventory

Examples:
```bash
# Run ARI in a specific region
ari --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --region us-west-2

# Use a custom database path
ari --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --db-path my_inventory.db

# Only map AWS CLI commands
ari --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --map-only

# Only collect resource inventory
ari --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --inventory-only
```

## What the Service Mapper Does

The service mapper component:

1. Recursively explores the entire AWS CLI command structure
2. Identifies commands that likely list resources (using patterns like "list-", "describe-", etc.)
3. Captures command help text and argument information
4. For resource-listing commands, captures example output formats
5. Stores all this information in SQLite tables:
   - `aws_commands`: Stores command paths and metadata
   - `command_arguments`: Stores command parameters and options

This service mapper provides a comprehensive map of AWS CLI commands that can later be used to:
- Discover additional resource types not explicitly handled in the inventory code
- Automatically generate code to inventory resources for services not yet implemented
- Provide a reference for AWS service capabilities and API endpoints

## What the Resource Inventory Does

The resource inventory component:

1. Connects to various AWS services across all regions
2. Collects detailed information about resources
3. Retrieves cost data from AWS Cost Explorer
4. Stores everything in a SQLite database with the following tables:
   - `services`: Records each AWS service and its resource count
   - `resources`: Stores detailed information about individual resources
   - `costs`: Tracks cost data associated with services and resources

## Working with the Database

The SQLite database can be queried using standard SQL tools:

```bash
# Example SQLite query
sqlite3 aws_inventory.db "SELECT resource_name, region, properties FROM resources WHERE service_id = 1 LIMIT 10;"
```

For Python scripts:

```python
import sqlite3

# Connect to the database
conn = sqlite3.connect('aws_inventory.db')
cursor = conn.cursor()

# Example query
cursor.execute("SELECT s.name, COUNT(r.id) FROM services s JOIN resources r ON s.id = r.service_id GROUP BY s.name")
results = cursor.fetchall()

# Print results
for service, count in results:
    print(f"{service}: {count} resources")

# Close connection
conn.close()
```

The service mapper complements the resource inventory to give you a complete picture of your AWS environment and its costs.