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
        self._account_id = None  # Cached account ID value
        
    def get_account_id(self):
        """Get the AWS account ID associated with the credentials"""
        if self._account_id:
            return self._account_id
            
        try:
            sts = self.session.client('sts')
            response = sts.get_caller_identity()
            self._account_id = response['Account']
            return self._account_id
        except ClientError as e:
            logger.error(f"Error getting AWS account ID: {e}")
            return "unknown"
        
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
        arn = resource_data.get('arn', '')
        resource_name = resource_data.get('resource_name', 'unnamed')
        resource_type = resource_data.get('resource_type', 'unknown')
        region = resource_data.get('region', self.region)
        creation_date = resource_data.get('creation_date', None)
        tags = json.dumps(resource_data.get('tags', {}))
        properties = json.dumps(resource_data.get('properties', {}))
        security_groups = json.dumps(resource_data.get('security_groups', []))
        relationships = json.dumps(resource_data.get('relationships', {}))
        metadata = json.dumps(resource_data.get('metadata', {}))
        
        try:
            self.cursor.execute('''
            INSERT INTO resources (
                service_id, resource_id, arn, resource_name, resource_type, 
                region, creation_date, tags, properties, security_groups,
                relationships, metadata, last_updated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(resource_id) DO UPDATE SET
                arn = ?,
                resource_name = ?,
                resource_type = ?,
                region = ?,
                creation_date = ?,
                tags = ?,
                properties = ?,
                security_groups = ?,
                relationships = ?,
                metadata = ?,
                last_updated = ?
            ''', (
                service_id, resource_id, arn, resource_name, resource_type,
                region, creation_date, tags, properties, security_groups,
                relationships, metadata, now,
                arn, resource_name, resource_type, region, creation_date,
                tags, properties, security_groups, relationships, metadata, now
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
                        instance_id = instance['InstanceId']
                        
                        # Construct ARN
                        # Format: arn:aws:ec2:region:account-id:instance/instance-id
                        account_id = self.get_account_id()
                        arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
                        
                        # Process tags
                        tags = {}
                        if 'Tags' in instance:
                            for tag in instance['Tags']:
                                tags[tag['Key']] = tag['Value']
                        
                        # Format creation date
                        launch_time = instance['LaunchTime'].isoformat() if 'LaunchTime' in instance else None
                        
                        # Get resource name from tags or use instance ID
                        name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                        
                        # Get security groups
                        security_groups = []
                        if 'SecurityGroups' in instance:
                            security_groups = [{
                                'id': sg['GroupId'],
                                'name': sg['GroupName']
                            } for sg in instance['SecurityGroups']]
                        
                        # Get volume information
                        volumes = []
                        if 'BlockDeviceMappings' in instance:
                            for block_device in instance['BlockDeviceMappings']:
                                if 'Ebs' in block_device:
                                    volume_id = block_device['Ebs']['VolumeId']
                                    # Get volume details
                                    try:
                                        volume_info = ec2_regional.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]
                                        volumes.append({
                                            'id': volume_id,
                                            'size': volume_info.get('Size', 0),
                                            'type': volume_info.get('VolumeType', ''),
                                            'device': block_device.get('DeviceName', ''),
                                            'encrypted': volume_info.get('Encrypted', False)
                                        })
                                    except ClientError:
                                        # If we can't get volume details, just add basic info
                                        volumes.append({
                                            'id': volume_id,
                                            'device': block_device.get('DeviceName', '')
                                        })
                        
                        # Get network interfaces
                        network_interfaces = []
                        if 'NetworkInterfaces' in instance:
                            for nic in instance['NetworkInterfaces']:
                                network_interfaces.append({
                                    'id': nic.get('NetworkInterfaceId', ''),
                                    'private_ip': nic.get('PrivateIpAddress', ''),
                                    'mac': nic.get('MacAddress', ''),
                                    'private_dns': nic.get('PrivateDnsName', ''),
                                    'public_ip': nic.get('Association', {}).get('PublicIp', ''),
                                    'public_dns': nic.get('Association', {}).get('PublicDnsName', '')
                                })
                        
                        # Track relationships with other resources
                        relationships = {
                            'vpc': instance.get('VpcId', ''),
                            'subnet': instance.get('SubnetId', ''),
                            'security_groups': [sg['id'] for sg in security_groups],
                            'volumes': [vol['id'] for vol in volumes],
                            'network_interfaces': [nic['id'] for nic in network_interfaces]
                        }
                        
                        # Additional metadata
                        metadata = {
                            'ami_id': instance.get('ImageId', ''),
                            'architecture': instance.get('Architecture', ''),
                            'hypervisor': instance.get('Hypervisor', ''),
                            'virtualization_type': instance.get('VirtualizationType', ''),
                            'root_device_type': instance.get('RootDeviceType', ''),
                            'root_device_name': instance.get('RootDeviceName', ''),
                            'iam_instance_profile': instance.get('IamInstanceProfile', {}).get('Arn', ''),
                            'key_name': instance.get('KeyName', ''),
                            'placement': {
                                'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', ''),
                                'tenancy': instance.get('Placement', {}).get('Tenancy', '')
                            },
                            'reservation_id': reservation.get('ReservationId', '')
                        }
                        
                        resources.append({
                            'resource_id': instance_id,
                            'arn': arn,
                            'resource_name': name,
                            'resource_type': 'EC2 Instance',
                            'region': region,
                            'creation_date': launch_time,
                            'tags': tags,
                            'security_groups': security_groups,
                            'relationships': relationships,
                            'metadata': metadata,
                            'properties': {
                                'instance_type': instance.get('InstanceType', ''),
                                'state': instance.get('State', {}).get('Name', ''),
                                'vpc_id': instance.get('VpcId', ''),
                                'subnet_id': instance.get('SubnetId', ''),
                                'private_ip': instance.get('PrivateIpAddress', ''),
                                'public_ip': instance.get('PublicIpAddress', ''),
                                'private_dns': instance.get('PrivateDnsName', ''),
                                'public_dns': instance.get('PublicDnsName', ''),
                                'volumes': volumes,
                                'network_interfaces': network_interfaces,
                                'ebs_optimized': instance.get('EbsOptimized', False),
                                'monitoring': instance.get('Monitoring', {}).get('State', '')
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
            
            account_id = self.get_account_id()
            
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                # Get bucket region
                bucket_region_response = s3.get_bucket_location(Bucket=bucket_name)
                region = bucket_region_response.get('LocationConstraint', self.region)
                if region is None:
                    region = 'us-east-1'  # Default region if None
                
                # Construct ARN
                arn = f"arn:aws:s3:::{bucket_name}"
                
                # Get bucket tags
                tags = {}
                try:
                    tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
                    for tag in tags_response.get('TagSet', []):
                        tags[tag['Key']] = tag['Value']
                except ClientError:
                    # Bucket might not have tags
                    pass
                
                # Get bucket policy
                policy = None
                try:
                    policy_response = s3.get_bucket_policy(Bucket=bucket_name)
                    policy = policy_response.get('Policy', None)
                except ClientError:
                    # Bucket might not have a policy
                    pass
                
                # Get bucket encryption
                encryption = None
                try:
                    encryption_response = s3.get_bucket_encryption(Bucket=bucket_name)
                    encryption = encryption_response.get('ServerSideEncryptionConfiguration', {})
                except ClientError:
                    # Bucket might not have encryption configured
                    pass
                
                # Get bucket versioning
                versioning = None
                try:
                    versioning_response = s3.get_bucket_versioning(Bucket=bucket_name)
                    versioning = versioning_response.get('Status', 'Disabled')
                except ClientError:
                    versioning = 'Unknown'
                
                # Get bucket website configuration
                website = None
                try:
                    website_response = s3.get_bucket_website(Bucket=bucket_name)
                    website = {
                        'index_document': website_response.get('IndexDocument', {}).get('Suffix', ''),
                        'error_document': website_response.get('ErrorDocument', {}).get('Key', '')
                    }
                except ClientError:
                    # Bucket might not have website configuration
                    pass
                
                # Get bucket ACL
                acl = None
                try:
                    acl_response = s3.get_bucket_acl(Bucket=bucket_name)
                    acl = {
                        'owner': acl_response.get('Owner', {}).get('DisplayName', ''),
                        'grants': [{
                            'grantee': grant.get('Grantee', {}).get('DisplayName', 
                                     grant.get('Grantee', {}).get('URI', '')),
                            'permission': grant.get('Permission', '')
                        } for grant in acl_response.get('Grants', [])]
                    }
                except ClientError:
                    # Might not be able to get ACL info
                    pass
                
                # Get bucket size and object count
                size = 0
                object_count = 0
                try:
                    # This requires cloudwatch metrics, which might not be available
                    cloudwatch = self.session.client('cloudwatch', region_name=region)
                    
                    # Get bucket size
                    size_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/S3',
                        MetricName='BucketSizeBytes',
                        Dimensions=[
                            {'Name': 'BucketName', 'Value': bucket_name},
                            {'Name': 'StorageType', 'Value': 'StandardStorage'}
                        ],
                        StartTime=datetime.datetime.now() - datetime.timedelta(days=2),
                        EndTime=datetime.datetime.now(),
                        Period=86400,
                        Statistics=['Average']
                    )
                    
                    if size_response['Datapoints']:
                        size = size_response['Datapoints'][-1]['Average']
                    
                    # Get object count
                    count_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/S3',
                        MetricName='NumberOfObjects',
                        Dimensions=[
                            {'Name': 'BucketName', 'Value': bucket_name},
                            {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
                        ],
                        StartTime=datetime.datetime.now() - datetime.timedelta(days=2),
                        EndTime=datetime.datetime.now(),
                        Period=86400,
                        Statistics=['Average']
                    )
                    
                    if count_response['Datapoints']:
                        object_count = count_response['Datapoints'][-1]['Average']
                except ClientError:
                    # Metrics might not be available
                    pass
                
                # Collect all metadata
                metadata = {
                    'owner': account_id,
                    'policy': policy,
                    'encryption': encryption,
                    'versioning': versioning,
                    'website': website,
                    'acl': acl,
                    'size_bytes': size,
                    'object_count': object_count
                }
                
                resources.append({
                    'resource_id': bucket_name,
                    'arn': arn,
                    'resource_name': bucket_name,
                    'resource_type': 'S3 Bucket',
                    'region': region,
                    'creation_date': bucket['CreationDate'].isoformat() if 'CreationDate' in bucket else None,
                    'tags': tags,
                    'metadata': metadata,
                    'properties': {
                        'creation_date': bucket['CreationDate'].isoformat() if 'CreationDate' in bucket else None,
                        'versioning_enabled': versioning == 'Enabled',
                        'encryption_enabled': encryption is not None,
                        'website_enabled': website is not None,
                        'size_bytes': size,
                        'object_count': object_count
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
            ec2 = self.session.client('ec2')
            regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
            
            for region in regions:
                rds_regional = self.session.client('rds', region_name=region)
                response = rds_regional.describe_db_instances()
                
                for instance in response['DBInstances']:
                    # Get instance identifier and ARN
                    db_id = instance['DBInstanceIdentifier']
                    arn = instance['DBInstanceArn']
                    
                    # Get instance tags
                    tags = {}
                    try:
                        tags_response = rds_regional.list_tags_for_resource(ResourceName=arn)
                        for tag in tags_response.get('TagList', []):
                            tags[tag['Key']] = tag['Value']
                    except ClientError:
                        # Instance might not have tags
                        pass
                    
                    # Get security groups
                    security_groups = []
                    vpc_security_groups = instance.get('VpcSecurityGroups', [])
                    for sg in vpc_security_groups:
                        security_groups.append({
                            'id': sg.get('VpcSecurityGroupId', ''),
                            'status': sg.get('Status', '')
                        })
                    
                    # Get parameter groups
                    parameter_groups = []
                    for pg in instance.get('DBParameterGroups', []):
                        parameter_groups.append({
                            'name': pg.get('DBParameterGroupName', ''),
                            'status': pg.get('ParameterApplyStatus', '')
                        })
                    
                    # Get option groups
                    option_groups = []
                    for og in instance.get('OptionGroupMemberships', []):
                        option_groups.append({
                            'name': og.get('OptionGroupName', ''),
                            'status': og.get('Status', '')
                        })
                    
                    # Get subnet group
                    subnet_group = None
                    if 'DBSubnetGroup' in instance:
                        subnet_group = {
                            'name': instance['DBSubnetGroup'].get('DBSubnetGroupName', ''),
                            'description': instance['DBSubnetGroup'].get('DBSubnetGroupDescription', ''),
                            'vpc_id': instance['DBSubnetGroup'].get('VpcId', ''),
                            'status': instance['DBSubnetGroup'].get('SubnetGroupStatus', ''),
                            'subnets': [
                                {
                                    'id': subnet.get('SubnetIdentifier', ''),
                                    'availability_zone': subnet.get('SubnetAvailabilityZone', {}).get('Name', ''),
                                    'status': subnet.get('SubnetStatus', '')
                                }
                                for subnet in instance['DBSubnetGroup'].get('Subnets', [])
                            ]
                        }
                    
                    # Get enhanced monitoring info
                    enhanced_monitoring = None
                    if instance.get('EnhancedMonitoringResourceArn'):
                        enhanced_monitoring = {
                            'role_arn': instance.get('MonitoringRoleArn', ''),
                            'interval': instance.get('MonitoringInterval', 0)
                        }
                    
                    # Get performance insights info
                    performance_insights = None
                    if instance.get('PerformanceInsightsEnabled', False):
                        performance_insights = {
                            'enabled': True,
                            'kms_key_id': instance.get('PerformanceInsightsKMSKeyId', ''),
                            'retention_period': instance.get('PerformanceInsightsRetentionPeriod', 0)
                        }
                    
                    # Get endpoint details
                    endpoint = None
                    if 'Endpoint' in instance:
                        endpoint = {
                            'address': instance['Endpoint'].get('Address', ''),
                            'port': instance['Endpoint'].get('Port', 0),
                            'hosted_zone_id': instance['Endpoint'].get('HostedZoneId', '')
                        }
                    
                    # Get storage details
                    storage = {
                        'allocated': instance.get('AllocatedStorage', 0),
                        'type': instance.get('StorageType', ''),
                        'encrypted': instance.get('StorageEncrypted', False),
                        'iops': instance.get('Iops', 0),
                        'throughput': instance.get('StorageThroughput', 0)
                    }
                    
                    # Track relationships
                    relationships = {
                        'vpc_id': instance.get('DBSubnetGroup', {}).get('VpcId', ''),
                        'parameter_groups': [pg['name'] for pg in parameter_groups],
                        'option_groups': [og['name'] for og in option_groups],
                        'security_groups': [sg['id'] for sg in security_groups],
                        'subnet_group': instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName', ''),
                        'replica_of': instance.get('ReadReplicaSourceDBInstanceIdentifier', ''),
                        'replicas': instance.get('ReadReplicaDBInstanceIdentifiers', [])
                    }
                    
                    # Additional metadata
                    metadata = {
                        'license_model': instance.get('LicenseModel', ''),
                        'engine_version': instance.get('EngineVersion', ''),
                        'auto_minor_version_upgrade': instance.get('AutoMinorVersionUpgrade', False),
                        'preferred_maintenance_window': instance.get('PreferredMaintenanceWindow', ''),
                        'preferred_backup_window': instance.get('PreferredBackupWindow', ''),
                        'backup_retention_period': instance.get('BackupRetentionPeriod', 0),
                        'latest_restorable_time': instance.get('LatestRestorableTime', ''),
                        'master_username': instance.get('MasterUsername', ''),
                        'db_name': instance.get('DBName', ''),
                        'character_set_name': instance.get('CharacterSetName', ''),
                        'availability_zone': instance.get('AvailabilityZone', ''),
                        'secondary_availability_zone': instance.get('SecondaryAvailabilityZone', ''),
                        'status': instance.get('DBInstanceStatus', ''),
                        'publicly_accessible': instance.get('PubliclyAccessible', False),
                        'ca_certificate_identifier': instance.get('CACertificateIdentifier', ''),
                        'automated_backups': {
                            'status': instance.get('BackupRetentionPeriod', 0) > 0,
                            'retention_period': instance.get('BackupRetentionPeriod', 0)
                        },
                        'deletion_protection': instance.get('DeletionProtection', False),
                        'performance_insights': performance_insights,
                        'enhanced_monitoring': enhanced_monitoring
                    }
                    
                    resources.append({
                        'resource_id': db_id,
                        'arn': arn,
                        'resource_name': db_id,
                        'resource_type': 'RDS Instance',
                        'region': region,
                        'creation_date': instance['InstanceCreateTime'].isoformat() if 'InstanceCreateTime' in instance else None,
                        'tags': tags,
                        'security_groups': security_groups,
                        'relationships': relationships,
                        'metadata': metadata,
                        'properties': {
                            'engine': instance.get('Engine', ''),
                            'engine_version': instance.get('EngineVersion', ''),
                            'instance_class': instance.get('DBInstanceClass', ''),
                            'storage': storage,
                            'multi_az': instance.get('MultiAZ', False),
                            'endpoint': endpoint,
                            'parameter_groups': parameter_groups,
                            'option_groups': option_groups,
                            'subnet_group': subnet_group,
                            'vpc_id': instance.get('DBSubnetGroup', {}).get('VpcId', ''),
                            'status': instance.get('DBInstanceStatus', ''),
                            'publicly_accessible': instance.get('PubliclyAccessible', False)
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
                    function_name = function['FunctionName']
                    function_arn = function['FunctionArn']
                    
                    # Get function tags
                    tags = {}
                    try:
                        tags_response = lambda_client.list_tags(Resource=function_arn)
                        tags = tags_response.get('Tags', {})
                    except ClientError:
                        # Function might not have tags
                        pass
                    
                    # Get function configuration
                    function_config = None
                    try:
                        config_response = lambda_client.get_function_configuration(FunctionName=function_name)
                        function_config = config_response
                    except ClientError:
                        # Might not be able to get config
                        pass
                    
                    # Get function code
                    code_info = None
                    try:
                        code_response = lambda_client.get_function(FunctionName=function_name)
                        if 'Code' in code_response:
                            code_info = {
                                'repository_type': code_response['Code'].get('RepositoryType', ''),
                                'location': code_response['Code'].get('Location', ''),
                                'code_sha256': function.get('CodeSha256', '')
                            }
                    except ClientError:
                        # Might not be able to get code info
                        pass
                    
                    # Get function policy
                    policy = None
                    try:
                        policy_response = lambda_client.get_policy(FunctionName=function_name)
                        policy = policy_response.get('Policy', '')
                    except ClientError:
                        # Function might not have a policy
                        pass
                    
                    # Get function aliases
                    aliases = []
                    try:
                        aliases_response = lambda_client.list_aliases(FunctionName=function_name)
                        aliases = [{
                            'name': alias.get('Name', ''),
                            'arn': alias.get('AliasArn', ''),
                            'description': alias.get('Description', ''),
                            'function_version': alias.get('FunctionVersion', '')
                        } for alias in aliases_response.get('Aliases', [])]
                    except ClientError:
                        # Function might not have aliases
                        pass
                    
                    # Get function versions
                    versions = []
                    try:
                        versions_response = lambda_client.list_versions_by_function(FunctionName=function_name)
                        versions = [{
                            'version': version.get('Version', ''),
                            'description': version.get('Description', ''),
                            'last_modified': version.get('LastModified', ''),
                            'code_sha256': version.get('CodeSha256', '')
                        } for version in versions_response.get('Versions', [])]
                    except ClientError:
                        # Might not be able to get versions
                        pass
                    
                    # Get function event sources
                    event_sources = []
                    try:
                        sources_response = lambda_client.list_event_source_mappings(FunctionName=function_name)
                        event_sources = [{
                            'uuid': source.get('UUID', ''),
                            'event_source_arn': source.get('EventSourceArn', ''),
                            'state': source.get('State', ''),
                            'starting_position': source.get('StartingPosition', '')
                        } for source in sources_response.get('EventSourceMappings', [])]
                    except ClientError:
                        # Function might not have event sources
                        pass
                    
                    # Extract creation date from last modified timestamp if possible
                    creation_date = None
                    last_modified = function.get('LastModified', '')
                    if last_modified:
                        try:
                            # Try to convert ISO 8601 string to datetime
                            last_modified_dt = datetime.datetime.strptime(
                                last_modified, "%Y-%m-%dT%H:%M:%S.%f%z"
                            )
                            creation_date = last_modified_dt.isoformat()
                        except (ValueError, TypeError):
                            # Handle other date formats or parsing errors
                            creation_date = last_modified
                    
                    # Get VPC config
                    vpc_config = None
                    if 'VpcConfig' in function and function['VpcConfig'].get('VpcId'):
                        vpc_config = {
                            'vpc_id': function['VpcConfig'].get('VpcId', ''),
                            'subnet_ids': function['VpcConfig'].get('SubnetIds', []),
                            'security_group_ids': function['VpcConfig'].get('SecurityGroupIds', [])
                        }
                    
                    # Get environment variables
                    env_vars = {}
                    if 'Environment' in function and 'Variables' in function['Environment']:
                        env_vars = function['Environment']['Variables']
                    
                    # Track relationships
                    relationships = {
                        'vpc': function.get('VpcConfig', {}).get('VpcId', ''),
                        'subnets': function.get('VpcConfig', {}).get('SubnetIds', []),
                        'security_groups': function.get('VpcConfig', {}).get('SecurityGroupIds', []),
                        'event_sources': [source['event_source_arn'] for source in event_sources if 'event_source_arn' in source],
                        'execution_role': function.get('Role', ''),
                        'aliases': [alias['name'] for alias in aliases]
                    }
                    
                    # Collect security groups
                    security_groups = []
                    for sg_id in function.get('VpcConfig', {}).get('SecurityGroupIds', []):
                        security_groups.append({
                            'id': sg_id,
                            'name': sg_id  # We don't have the name without an additional EC2 call
                        })
                    
                    # Collect metadata
                    metadata = {
                        'description': function.get('Description', ''),
                        'runtime': function.get('Runtime', ''),
                        'role': function.get('Role', ''),
                        'handler': function.get('Handler', ''),
                        'code_size': function.get('CodeSize', 0),
                        'code_sha256': function.get('CodeSha256', ''),
                        'revision_id': function.get('RevisionId', ''),
                        'kms_key_arn': function.get('KMSKeyArn', ''),
                        'tracing_config': function.get('TracingConfig', {}).get('Mode', 'PassThrough'),
                        'versions': versions,
                        'aliases': aliases,
                        'layers': [layer.get('Arn', '') for layer in function.get('Layers', [])],
                        'event_sources': event_sources,
                        'environment_variables': env_vars,
                        'policy': policy,
                        'code_info': code_info
                    }
                    
                    resources.append({
                        'resource_id': function_arn,
                        'arn': function_arn,
                        'resource_name': function_name,
                        'resource_type': 'Lambda Function',
                        'region': region,
                        'creation_date': creation_date,
                        'tags': tags,
                        'security_groups': security_groups,
                        'relationships': relationships,
                        'metadata': metadata,
                        'properties': {
                            'runtime': function.get('Runtime', ''),
                            'memory_size': function.get('MemorySize', 0),
                            'timeout': function.get('Timeout', 0),
                            'last_modified': function.get('LastModified', ''),
                            'code_size': function.get('CodeSize', 0),
                            'handler': function.get('Handler', ''),
                            'description': function.get('Description', ''),
                            'environment': env_vars,
                            'vpc_config': vpc_config,
                            'dead_letter_config': function.get('DeadLetterConfig', {}).get('TargetArn', ''),
                            'package_type': function.get('PackageType', 'Zip'),
                            'state': function.get('State', ''),
                            'state_reason': function.get('StateReason', ''),
                            'state_reason_code': function.get('StateReasonCode', ''),
                            'last_update_status': function.get('LastUpdateStatus', '')
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
                    table_response = dynamodb.describe_table(TableName=table_name)
                    table = table_response['Table']
                    table_arn = table['TableArn']
                    
                    # Get table tags
                    tags = {}
                    try:
                        tags_response = dynamodb.list_tags_of_resource(ResourceArn=table_arn)
                        for tag in tags_response.get('Tags', []):
                            tags[tag['Key']] = tag['Value']
                    except ClientError:
                        # Table might not have tags
                        pass
                    
                    # Get billing mode (provisioned or on-demand)
                    billing_mode = 'PROVISIONED'
                    if 'BillingModeSummary' in table:
                        billing_mode = table['BillingModeSummary'].get('BillingMode', 'PROVISIONED')
                    elif table.get('ProvisionedThroughput', {}).get('ReadCapacityUnits', 0) == 0:
                        billing_mode = 'PAY_PER_REQUEST'
                    
                    # Get table's key schema
                    key_schema = []
                    if 'KeySchema' in table:
                        key_schema = [{
                            'attribute_name': key.get('AttributeName', ''),
                            'key_type': key.get('KeyType', '')  # HASH or RANGE
                        } for key in table['KeySchema']]
                    
                    # Get attribute definitions
                    attribute_definitions = []
                    if 'AttributeDefinitions' in table:
                        attribute_definitions = [{
                            'name': attr.get('AttributeName', ''),
                            'type': attr.get('AttributeType', '')  # S, N, or B
                        } for attr in table['AttributeDefinitions']]
                    
                    # Get global secondary indexes
                    global_secondary_indexes = []
                    if 'GlobalSecondaryIndexes' in table:
                        global_secondary_indexes = [{
                            'name': idx.get('IndexName', ''),
                            'status': idx.get('IndexStatus', ''),
                            'key_schema': [{
                                'attribute_name': key.get('AttributeName', ''),
                                'key_type': key.get('KeyType', '')
                            } for key in idx.get('KeySchema', [])],
                            'projection': {
                                'type': idx.get('Projection', {}).get('ProjectionType', ''),
                                'non_key_attributes': idx.get('Projection', {}).get('NonKeyAttributes', [])
                            },
                            'provisioned_throughput': {
                                'read_capacity_units': idx.get('ProvisionedThroughput', {}).get('ReadCapacityUnits', 0),
                                'write_capacity_units': idx.get('ProvisionedThroughput', {}).get('WriteCapacityUnits', 0)
                            },
                            'size_bytes': idx.get('IndexSizeBytes', 0),
                            'item_count': idx.get('ItemCount', 0)
                        } for idx in table['GlobalSecondaryIndexes']]
                    
                    # Get local secondary indexes
                    local_secondary_indexes = []
                    if 'LocalSecondaryIndexes' in table:
                        local_secondary_indexes = [{
                            'name': idx.get('IndexName', ''),
                            'key_schema': [{
                                'attribute_name': key.get('AttributeName', ''),
                                'key_type': key.get('KeyType', '')
                            } for key in idx.get('KeySchema', [])],
                            'projection': {
                                'type': idx.get('Projection', {}).get('ProjectionType', ''),
                                'non_key_attributes': idx.get('Projection', {}).get('NonKeyAttributes', [])
                            },
                            'size_bytes': idx.get('IndexSizeBytes', 0),
                            'item_count': idx.get('ItemCount', 0)
                        } for idx in table['LocalSecondaryIndexes']]
                    
                    # Get streams information
                    streams_info = None
                    try:
                        streams_response = dynamodb.describe_table(TableName=table_name)
                        if 'StreamSpecification' in table:
                            stream_spec = table['StreamSpecification']
                            streams_info = {
                                'stream_enabled': stream_spec.get('StreamEnabled', False),
                                'stream_view_type': stream_spec.get('StreamViewType', '')
                            }
                            
                            if streams_info['stream_enabled']:
                                # Get stream ARN
                                streams_info['stream_arn'] = table.get('LatestStreamArn', '')
                                
                                # Try to get stream details
                                try:
                                    dynamodb_streams = self.session.client('dynamodbstreams', region_name=region)
                                    streams_desc_response = dynamodb_streams.describe_stream(
                                        StreamArn=streams_info['stream_arn']
                                    )
                                    stream_desc = streams_desc_response.get('StreamDescription', {})
                                    streams_info['stream_status'] = stream_desc.get('StreamStatus', '')
                                    streams_info['stream_label'] = stream_desc.get('StreamLabel', '')
                                    streams_info['shards'] = len(stream_desc.get('Shards', []))
                                except ClientError:
                                    # Might not have permissions for streams
                                    pass
                    except ClientError:
                        # Table might not have streams
                        pass
                    
                    # Try to get table's TTL information
                    ttl_info = None
                    try:
                        ttl_response = dynamodb.describe_time_to_live(TableName=table_name)
                        ttl_desc = ttl_response.get('TimeToLiveDescription', {})
                        ttl_info = {
                            'status': ttl_desc.get('TimeToLiveStatus', 'DISABLED'),
                            'attribute_name': ttl_desc.get('AttributeName', '')
                        }
                    except ClientError:
                        # TTL might not be enabled
                        pass
                    
                    # Try to get continuous backups configuration
                    backup_info = None
                    try:
                        backup_response = dynamodb.describe_continuous_backups(TableName=table_name)
                        backup_desc = backup_response.get('ContinuousBackupsDescription', {})
                        point_in_time = backup_desc.get('PointInTimeRecoveryDescription', {})
                        backup_info = {
                            'continuous_backups_status': backup_desc.get('ContinuousBackupsStatus', 'DISABLED'),
                            'point_in_time_recovery': {
                                'status': point_in_time.get('PointInTimeRecoveryStatus', 'DISABLED'),
                                'earliest_restorable_time': point_in_time.get('EarliestRestorableDateTime', ''),
                                'latest_restorable_time': point_in_time.get('LatestRestorableDateTime', '')
                            }
                        }
                    except ClientError:
                        # Might not have continuous backups
                        pass
                    
                    # Collect relationships
                    relationships = {
                        'streams': streams_info['stream_arn'] if streams_info and 'stream_arn' in streams_info else None,
                        'replicas': [replica.get('RegionName', '') for replica in table.get('Replicas', [])]
                    }
                    
                    # Collect metadata
                    metadata = {
                        'billing_mode': billing_mode,
                        'creation_date': table['CreationDateTime'].isoformat() if 'CreationDateTime' in table else None,
                        'key_schema': key_schema,
                        'attribute_definitions': attribute_definitions,
                        'global_secondary_indexes': global_secondary_indexes,
                        'local_secondary_indexes': local_secondary_indexes,
                        'streams': streams_info,
                        'ttl': ttl_info,
                        'backups': backup_info,
                        'table_id': table.get('TableId', ''),
                        'sse_description': table.get('SSEDescription', {})
                    }
                    
                    # Build resource object
                    resource = {
                        'resource_id': table_arn,
                        'arn': table_arn,
                        'resource_name': table['TableName'],
                        'resource_type': 'DynamoDB Table',
                        'region': region,
                        'creation_date': table['CreationDateTime'].isoformat() if 'CreationDateTime' in table else None,
                        'tags': tags,
                        'relationships': relationships,
                        'metadata': metadata,
                        'properties': {
                            'status': table.get('TableStatus', ''),
                            'read_capacity': table.get('ProvisionedThroughput', {}).get('ReadCapacityUnits', 0),
                            'write_capacity': table.get('ProvisionedThroughput', {}).get('WriteCapacityUnits', 0),
                            'item_count': table.get('ItemCount', 0),
                            'size_bytes': table.get('TableSizeBytes', 0),
                            'billing_mode': billing_mode,
                            'key_schema': key_schema,
                            'global_secondary_indexes_count': len(global_secondary_indexes),
                            'local_secondary_indexes_count': len(local_secondary_indexes),
                            'stream_enabled': streams_info['stream_enabled'] if streams_info else False,
                            'ttl_enabled': ttl_info['status'] == 'ENABLED' if ttl_info else False,
                            'point_in_time_recovery': backup_info['point_in_time_recovery']['status'] == 'ENABLED' if backup_info else False
                        }
                    }
                    
                    resources.append(resource)
            
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