# AWS Resource Inventory and Service Mapper

[![PyPI version](https://img.shields.io/pypi/v/ari.svg)](https://pypi.org/project/ari/)
[![Python versions](https://img.shields.io/pypi/pyversions/ari.svg)](https://pypi.org/project/ari/)
[![License](https://img.shields.io/pypi/l/ari.svg)](https://pypi.org/project/ari/)

## Project Overview

This project provides a comprehensive solution for AWS account assessment, enabling organizations to gain visibility into their AWS resources and associated costs. It combines two powerful components: a resource inventory collector and a service mapper that automatically discovers AWS service commands and their capabilities.

## Installation

```bash
pip install ari
```

For development installation:

```bash
git clone https://github.com/yourusername/ari.git
cd ari
pip install -e .
```

## Quick Start

### Using the Terminal Wrapper (Recommended)

The easiest way to run ARI is with the terminal wrapper, which detects your AWS profiles automatically:

```bash
# Run with the wrapper script
./scripts/ari_wrapper.sh

# Alternatively, run the Python script directly
python scripts/ari_run.py
```

The wrapper provides a colorful menu interface that:
1. Reads accounts from ~/.aws/credentials
2. Lets you select which account to scan
3. Offers options for full scan, inventory only, or CLI mapping only
4. Displays progress and results

### Command Line Usage

```bash
# Run with both inventory collection and CLI mapping
ari --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY

# Only perform CLI mapping
ari --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --map-only

# Only collect resource inventory
ari --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --inventory-only

# Use a custom database path
ari --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --db-path my_inventory.db
```

## Key Components

### 1. AWS Resource Inventory Collector

The inventory collector performs a thorough scan of an AWS account to identify and catalog all resources that have associated costs. It connects to the AWS API using boto3 and methodically gathers data about various services including:

- EC2 instances and related resources
- S3 buckets
- RDS databases
- Lambda functions
- DynamoDB tables
- And many other service types

For each resource, the collector captures detailed metadata including:
- Resource identifiers
- Names and descriptions
- Region information
- Tags
- Creation dates
- Service-specific properties

Additionally, the collector integrates with AWS Cost Explorer to retrieve cost data for each service, providing financial visibility alongside technical inventory.

### 2. AWS CLI Service Mapper

The service mapper component performs a recursive exploration of the AWS CLI command structure to build a comprehensive map of available AWS services and their capabilities. It:

- Automatically discovers all AWS services accessible via the CLI
- Recursively traverses the command hierarchy for each service
- Identifies commands that list or describe resources
- Captures command parameters, options, and help text
- Documents command output formats for resource-listing operations

This mapping creates a valuable reference of AWS service capabilities and provides a foundation for extending the inventory collector to new services.

## Technical Requirements

- Python 3.6+
- boto3 library for AWS API access
- AWS credentials with appropriate permissions
- AWS CLI v2 installed (for service mapping component)

## Development

To contribute to this project:

1. Clone the repository
2. Install development dependencies: `pip install -e ".[dev]"`
3. Run tests: `pytest`

## License

This project is licensed under the MIT License - see the LICENSE file for details.