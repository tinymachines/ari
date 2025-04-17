#!/usr/bin/env python3

import boto3
import sqlite3
import datetime
import sys
import logging
import json
from botocore.exceptions import ClientError

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of AWS services to check (these have resources that can incur costs)
SERVICES_TO_CHECK = [
    'ec2', 'rds', 's3', 'lambda', 'dynamodb', 'elasticache', 'elb', 'elbv2', 'es',
    'cloudfront', 'route53', 'ebs', 'ecr', 'ecs', 'eks', 'eip', 'vpc', 'iam',
    'sqs', 'sns', 'kinesis', 'firehose', 'glacier', 'api-gateway', 'kms',
    'cloudwatch', 'cloudtrail', 'redshift', 'elasticbeanstalk', 'batch'
]


class AWSInventory:
    def __init__(self, access_key, secret_key, region='us-east-1', db_path='aws_inventory.db'):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.db_path = db_path
        self.session = boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region
        )
        self.conn = None
        self.cursor = None
        
    def initialize_database(self):
        """Create the database and tables if they don't exist"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()
            
            # Create services table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                resource_count INTEGER DEFAULT 0,
                last_updated TEXT
            )
            ''')
            
            # Create resources table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY,
                service_id INTEGER,
                resource_id TEXT UNIQUE,
                resource_name TEXT,
                resource_type TEXT,
                region TEXT,
                creation_date TEXT,
                tags TEXT,
                properties TEXT,
                last_updated TEXT,
                FOREIGN KEY (service_id) REFERENCES services(id)
            )
            ''')
            
            # Create costs table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS costs (
                id INTEGER PRIMARY KEY,
                service_id INTEGER,
                resource_id INTEGER,
                cost_period TEXT,
                amount REAL,
                currency TEXT,
                unit TEXT,
                last_updated TEXT,
                UNIQUE(service_id, resource_id, cost_period),
                FOREIGN KEY (service_id) REFERENCES services(id),
                FOREIGN KEY (resource_id) REFERENCES resources(id)
            )
            ''')
            
            self.conn.commit()
            logger.info("Database initialized successfully")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            sys.exit(1)
    
    def update_service_record(self, service_name, resource_count):
        """Update or insert a service record"""
        now = datetime.datetime.now().isoformat()
        try:
            self.cursor.execute('''
            INSERT INTO services (name, resource_count, last_updated)
            VALUES (?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
            resource_count = ?,
            last_updated = ?
            ''', (service_name, resource_count, now, resource_count, now))
            self.conn.commit()
            
            # Get the service ID
            self.cursor.execute("SELECT id FROM services WHERE name = ?", (service_name,))
            return self.cursor.fetchone()[0]
        except sqlite3.Error as e:
            logger.error(f"Error updating service record for {service_name}: {e}")
            return None
            
    def save_resource(self, service_id, resource_data):
        """Save a resource to the database"""
        now = datetime.datetime.now().isoformat()
        
        # Extract resource data or use default values
        resource_id = resource_data.get('resource_id', 'unknown')
        resource_name = resource_data.get('resource_name', 'unnamed')
        resource_type = resource_data.get('resource_type', 'unknown')
        region = resource_data.get('region', self.region)
        creation_date = resource_data.get('creation_date', None)
        tags = json.dumps(resource_data.get('tags', {}))
        properties = json.dumps(resource_data.get('properties', {}))
        
        try:
            self.cursor.execute('''
            INSERT INTO resources (
                service_id, resource_id, resource_name, resource_type, 
                region, creation_date, tags, properties, last_updated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(resource_id) DO UPDATE SET
                resource_name = ?,
                resource_type = ?,
                region = ?,
                creation_date = ?,
                tags = ?,
                properties = ?,
                last_updated = ?
            ''', (
                service_id, resource_id, resource_name, resource_type,
                region, creation_date, tags, properties, now,
                resource_name, resource_type, region, creation_date,
                tags, properties, now
            ))
            self.conn.commit()
            
            # Get the resource ID
            self.cursor.execute("SELECT id FROM resources WHERE resource_id = ?", (resource_id,))
            return self.cursor.fetchone()[0]
        except sqlite3.Error as e:
            logger.error(f"Error saving resource {resource_id}: {e}")
            return None
    
    def save_cost_data(self, service_id, resource_id, cost_data):
        """Save cost data to the database"""
        now = datetime.datetime.now().isoformat()
        
        # Extract cost data or use default values
        cost_period = cost_data.get('period', 'monthly')
        amount = cost_data.get('amount', 0.0)
        currency = cost_data.get('currency', 'USD')
        unit = cost_data.get('unit', 'USD')
        
        try:
            self.cursor.execute('''
            INSERT INTO costs (
                service_id, resource_id, cost_period, amount, currency, unit, last_updated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(service_id, resource_id, cost_period) DO UPDATE SET
                amount = ?,
                currency = ?,
                unit = ?,
                last_updated = ?
            ''', (
                service_id, resource_id, cost_period, amount, currency, unit, now,
                amount, currency, unit, now
            ))
            self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error saving cost data for resource {resource_id}: {e}")

    def get_ec2_resources(self):
        """Get all EC2 instances"""
        resources = []
        try:
            ec2 = self.session.client('ec2')
            regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
            
            for region in regions:
                ec2_regional = self.session.client('ec2', region_name=region)
                response = ec2_regional.describe_instances()
                
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        # Process tags
                        tags = {}
                        if 'Tags' in instance:
                            for tag in instance['Tags']:
                                tags[tag['Key']] = tag['Value']
                        
                        # Format creation date
                        launch_time = instance['LaunchTime'].isoformat() if 'LaunchTime' in instance else None
                        
                        # Get resource name from tags or use instance ID
                        name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['InstanceId'])
                        
                        resources.append({
                            'resource_id': instance['InstanceId'],
                            'resource_name': name,
                            'resource_type': 'EC2 Instance',
                            'region': region,
                            'creation_date': launch_time,
                            'tags': tags,
                            'properties': {
                                'instance_type': instance.get('InstanceType', ''),
                                'state': instance.get('State', {}).get('Name', ''),
                                'vpc_id': instance.get('VpcId', ''),
                                'private_ip': instance.get('PrivateIpAddress', ''),
                                'public_ip': instance.get('PublicIpAddress', '')
                            }
                        })
            
            return resources
        except ClientError as e:
            logger.error(f"Error getting EC2 resources: {e}")
            return resources

    def get_s3_resources(self):
        """Get all S3 buckets"""
        resources = []
        try:
            s3 = self.session.client('s3')
            response = s3.list_buckets()
            
            for bucket in response['Buckets']:
                # Get bucket region
                bucket_region_response = s3.get_bucket_location(Bucket=bucket['Name'])
                region = bucket_region_response.get('LocationConstraint', self.region)
                if region is None:
                    region = 'us-east-1'  # Default region if None
                
                # Get bucket tags
                tags = {}
                try:
                    tags_response = s3.get_bucket_tagging(Bucket=bucket['Name'])
                    for tag in tags_response.get('TagSet', []):
                        tags[tag['Key']] = tag['Value']
                except ClientError:
                    # Bucket might not have tags
                    pass
                
                resources.append({
                    'resource_id': bucket['Name'],
                    'resource_name': bucket['Name'],
                    'resource_type': 'S3 Bucket',
                    'region': region,
                    'creation_date': bucket['CreationDate'].isoformat() if 'CreationDate' in bucket else None,
                    'tags': tags,
                    'properties': {
                        'creation_date': bucket['CreationDate'].isoformat() if 'CreationDate' in bucket else None
                    }
                })
            
            return resources
        except ClientError as e:
            logger.error(f"Error getting S3 resources: {e}")
            return resources

    def get_rds_resources(self):
        """Get all RDS instances"""
        resources = []
        try:
            rds = self.session.client('rds')
            regions = [region['RegionName'] for region in self.session.client('ec2').describe_regions()['Regions']]
            
            for region in regions:
                rds_regional = self.session.client('rds', region_name=region)
                response = rds_regional.describe_db_instances()
                
                for instance in response['DBInstances']:
                    # Process ARN to get identifier
                    db_id = instance['DBInstanceIdentifier']
                    
                    # Get instance tags
                    tags = {}
                    try:
                        tags_response = rds_regional.list_tags_for_resource(ResourceName=instance['DBInstanceArn'])
                        for tag in tags_response.get('TagList', []):
                            tags[tag['Key']] = tag['Value']
                    except ClientError:
                        # Instance might not have tags
                        pass
                    
                    resources.append({
                        'resource_id': db_id,
                        'resource_name': db_id,
                        'resource_type': 'RDS Instance',
                        'region': region,
                        'creation_date': instance['InstanceCreateTime'].isoformat() if 'InstanceCreateTime' in instance else None,
                        'tags': tags,
                        'properties': {
                            'engine': instance.get('Engine', ''),
                            'instance_class': instance.get('DBInstanceClass', ''),
                            'storage': instance.get('AllocatedStorage', 0),
                            'multi_az': instance.get('MultiAZ', False),
                            'endpoint': instance.get('Endpoint', {}).get('Address', '')
                        }
                    })
            
            return resources
        except ClientError as e:
            logger.error(f"Error getting RDS resources: {e}")
            return resources

    def get_lambda_resources(self):
        """Get all Lambda functions"""
        resources = []
        try:
            regions = [region['RegionName'] for region in self.session.client('ec2').describe_regions()['Regions']]
            
            for region in regions:
                lambda_client = self.session.client('lambda', region_name=region)
                response = lambda_client.list_functions()
                
                for function in response['Functions']:
                    # Get function tags
                    tags = {}
                    try:
                        tags_response = lambda_client.list_tags(Resource=function['FunctionArn'])
                        tags = tags_response.get('Tags', {})
                    except ClientError:
                        # Function might not have tags
                        pass
                    
                    resources.append({
                        'resource_id': function['FunctionArn'],
                        'resource_name': function['FunctionName'],
                        'resource_type': 'Lambda Function',
                        'region': region,
                        'creation_date': None,  # Lambda doesn't provide creation date
                        'tags': tags,
                        'properties': {
                            'runtime': function.get('Runtime', ''),
                            'memory': function.get('MemorySize', 0),
                            'timeout': function.get('Timeout', 0),
                            'last_modified': function.get('LastModified', '')
                        }
                    })
            
            return resources
        except ClientError as e:
            logger.error(f"Error getting Lambda resources: {e}")
            return resources

    def get_dynamodb_resources(self):
        """Get all DynamoDB tables"""
        resources = []
        try:
            regions = [region['RegionName'] for region in self.session.client('ec2').describe_regions()['Regions']]
            
            for region in regions:
                dynamodb = self.session.client('dynamodb', region_name=region)
                response = dynamodb.list_tables()
                
                for table_name in response['TableNames']:
                    # Get table details
                    table = dynamodb.describe_table(TableName=table_name)['Table']
                    
                    # Get table tags
                    tags = {}
                    try:
                        tags_response = dynamodb.list_tags_of_resource(ResourceArn=table['TableArn'])
                        for tag in tags_response.get('Tags', []):
                            tags[tag['Key']] = tag['Value']
                    except ClientError:
                        # Table might not have tags
                        pass
                    
                    resources.append({
                        'resource_id': table['TableArn'],
                        'resource_name': table['TableName'],
                        'resource_type': 'DynamoDB Table',
                        'region': region,
                        'creation_date': table['CreationDateTime'].isoformat() if 'CreationDateTime' in table else None,
                        'tags': tags,
                        'properties': {
                            'status': table.get('TableStatus', ''),
                            'read_capacity': table.get('ProvisionedThroughput', {}).get('ReadCapacityUnits', 0),
                            'write_capacity': table.get('ProvisionedThroughput', {}).get('WriteCapacityUnits', 0),
                            'item_count': table.get('ItemCount', 0),
                            'size_bytes': table.get('TableSizeBytes', 0)
                        }
                    })
            
            return resources
        except ClientError as e:
            logger.error(f"Error getting DynamoDB resources: {e}")
            return resources

    def get_cost_data(self):
        """Get cost data for all services using Cost Explorer API"""
        try:
            cost_explorer = self.session.client('ce')
            
            # Get costs for the last month
            end_date = datetime.datetime.now()
            start_date = end_date - datetime.timedelta(days=30)
            
            response = cost_explorer.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    }
                ]
            )
            
            # Process and return cost data
            cost_data = {}
            for result in response['ResultsByTime']:
                for group in result['Groups']:
                    service_name = group['Keys'][0]
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    unit = group['Metrics']['UnblendedCost']['Unit']
                    
                    cost_data[service_name] = {
                        'period': f"{result['TimePeriod']['Start']} to {result['TimePeriod']['End']}",
                        'amount': amount,
                        'currency': unit,
                        'unit': unit
                    }
            
            return cost_data
        except ClientError as e:
            logger.error(f"Error getting cost data: {e}")
            return {}

    def get_resources_by_service(self, service_name):
        """Get resources for a specific service"""
        if service_name == 'ec2':
            return self.get_ec2_resources()
        elif service_name == 's3':
            return self.get_s3_resources()
        elif service_name == 'rds':
            return self.get_rds_resources()
        elif service_name == 'lambda':
            return self.get_lambda_resources()
        elif service_name == 'dynamodb':
            return self.get_dynamodb_resources()
        else:
            logger.warning(f"Resource gathering not implemented for service: {service_name}")
            return []

    def collect_inventory(self):
        """Collect inventory of all AWS resources and their costs"""
        try:
            # Initialize the database
            self.initialize_database()
            
            # Get all services that have costs associated
            logger.info("Getting cost data from AWS Cost Explorer...")
            cost_data = self.get_cost_data()
            
            # Iterate through all services to check
            for service_name in SERVICES_TO_CHECK:
                logger.info(f"Collecting inventory for service: {service_name}")
                
                # Get resources for this service
                resources = self.get_resources_by_service(service_name)
                
                # Update service record
                service_id = self.update_service_record(service_name, len(resources))
                
                if service_id:
                    # Save each resource
                    for resource in resources:
                        db_resource_id = self.save_resource(service_id, resource)
                        
                        # If we have cost data for this service, save it
                        if service_name in cost_data and db_resource_id:
                            self.save_cost_data(service_id, db_resource_id, cost_data[service_name])
            
            logger.info("Inventory collection completed successfully")
            
        except Exception as e:
            logger.error(f"Error collecting inventory: {e}")
        finally:
            if self.conn:
                self.conn.close()