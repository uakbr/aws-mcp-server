"""
Enhanced AWS Resource Discovery with Real AWS Integration.

This module provides real AWS resource discovery capabilities with support for
multiple services, regions, and accounts.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set
from datetime import datetime
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from concurrent.futures import ThreadPoolExecutor
import json

logger = logging.getLogger(__name__)


class AWSResourceDiscovery:
    """Enhanced AWS resource discovery with real AWS API integration."""
    
    def __init__(self, regions: Optional[List[str]] = None, 
                 assume_role_arn: Optional[str] = None,
                 external_id: Optional[str] = None):
        """
        Initialize AWS resource discovery.
        
        Args:
            regions: List of regions to scan, or None for all regions
            assume_role_arn: ARN of role to assume for cross-account access
            external_id: External ID for role assumption
        """
        self.regions = regions or self._get_all_regions()
        self.assume_role_arn = assume_role_arn
        self.external_id = external_id
        self._clients: Dict[str, Dict[str, Any]] = {}
        self._executor = ThreadPoolExecutor(max_workers=10)
        
    def _get_all_regions(self) -> List[str]:
        """Get all available AWS regions."""
        ec2 = boto3.client('ec2', region_name='us-east-1')
        try:
            response = ec2.describe_regions()
            return [region['RegionName'] for region in response['Regions']]
        except Exception as e:
            logger.error(f"Error fetching regions: {e}")
            # Fallback to common regions
            return ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-northeast-1']
    
    def _get_client(self, service: str, region: str) -> Any:
        """Get or create a boto3 client for the specified service and region."""
        key = f"{service}_{region}"
        
        if key not in self._clients:
            try:
                if self.assume_role_arn:
                    # Assume role for cross-account access
                    sts = boto3.client('sts')
                    assumed_role = sts.assume_role(
                        RoleArn=self.assume_role_arn,
                        RoleSessionName=f'ResourceDiscovery-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}',
                        ExternalId=self.external_id
                    ) if self.external_id else sts.assume_role(
                        RoleArn=self.assume_role_arn,
                        RoleSessionName=f'ResourceDiscovery-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}'
                    )
                    
                    credentials = assumed_role['Credentials']
                    self._clients[key] = boto3.client(
                        service,
                        region_name=region,
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                    )
                else:
                    self._clients[key] = boto3.client(service, region_name=region)
            except Exception as e:
                logger.error(f"Error creating client for {service} in {region}: {e}")
                raise
                
        return self._clients[key]
    
    async def discover_ec2_instances(self, regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Discover EC2 instances across specified regions."""
        regions = regions or self.regions
        results = {"ec2_instances": {}}
        
        async def discover_in_region(region: str) -> Dict[str, Any]:
            try:
                ec2 = self._get_client('ec2', region)
                
                # Get all instances
                paginator = ec2.get_paginator('describe_instances')
                instances = []
                
                for page in paginator.paginate():
                    for reservation in page['Reservations']:
                        for instance in reservation['Instances']:
                            # Extract relevant instance information
                            instance_data = {
                                'InstanceId': instance['InstanceId'],
                                'InstanceType': instance['InstanceType'],
                                'State': instance['State']['Name'],
                                'LaunchTime': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None,
                                'PublicIpAddress': instance.get('PublicIpAddress'),
                                'PrivateIpAddress': instance.get('PrivateIpAddress'),
                                'VpcId': instance.get('VpcId'),
                                'SubnetId': instance.get('SubnetId'),
                                'SecurityGroups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                                'Tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                                'Platform': instance.get('Platform', 'linux'),
                                'Architecture': instance.get('Architecture'),
                                'RootDeviceType': instance.get('RootDeviceType'),
                                'IamInstanceProfile': instance.get('IamInstanceProfile', {}).get('Arn')
                            }
                            instances.append(instance_data)
                
                return {region: {"instances": instances, "count": len(instances)}}
                
            except ClientError as e:
                logger.error(f"Error discovering EC2 instances in {region}: {e}")
                return {region: {"error": str(e), "instances": [], "count": 0}}
        
        # Run discovery in parallel across regions
        tasks = [discover_in_region(region) for region in regions]
        region_results = await asyncio.gather(*tasks)
        
        # Combine results
        for result in region_results:
            results["ec2_instances"].update(result)
        
        results["summary"] = {
            "total_instances": sum(r.get("count", 0) for r in results["ec2_instances"].values()),
            "regions_scanned": len(regions),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return results
    
    async def discover_s3_buckets(self) -> Dict[str, Any]:
        """Discover S3 buckets (global service)."""
        results = {"s3_buckets": {"global": {"buckets": [], "count": 0}}}
        
        try:
            s3 = self._get_client('s3', 'us-east-1')  # S3 is global
            
            # List all buckets
            response = s3.list_buckets()
            buckets = []
            
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                bucket_data = {
                    'Name': bucket_name,
                    'CreationDate': bucket['CreationDate'].isoformat()
                }
                
                try:
                    # Get bucket location
                    location_response = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_data['Region'] = location_response.get('LocationConstraint') or 'us-east-1'
                    
                    # Get bucket versioning
                    versioning_response = s3.get_bucket_versioning(Bucket=bucket_name)
                    bucket_data['Versioning'] = versioning_response.get('Status', 'Disabled')
                    
                    # Get bucket encryption
                    try:
                        encryption_response = s3.get_bucket_encryption(Bucket=bucket_name)
                        bucket_data['Encryption'] = True
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                            bucket_data['Encryption'] = False
                        else:
                            raise
                    
                    # Get bucket tags
                    try:
                        tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
                        bucket_data['Tags'] = {tag['Key']: tag['Value'] for tag in tags_response.get('TagSet', [])}
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchTagSet':
                            bucket_data['Tags'] = {}
                        else:
                            raise
                            
                except Exception as e:
                    logger.error(f"Error getting details for bucket {bucket_name}: {e}")
                    bucket_data['Error'] = str(e)
                
                buckets.append(bucket_data)
            
            results["s3_buckets"]["global"]["buckets"] = buckets
            results["s3_buckets"]["global"]["count"] = len(buckets)
            
        except Exception as e:
            logger.error(f"Error discovering S3 buckets: {e}")
            results["s3_buckets"]["global"]["error"] = str(e)
        
        results["summary"] = {
            "total_buckets": results["s3_buckets"]["global"]["count"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return results
    
    async def discover_rds_instances(self, regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Discover RDS instances across regions."""
        regions = regions or self.regions
        results = {"rds_instances": {}}
        
        async def discover_in_region(region: str) -> Dict[str, Any]:
            try:
                rds = self._get_client('rds', region)
                
                # Get all DB instances
                paginator = rds.get_paginator('describe_db_instances')
                instances = []
                
                for page in paginator.paginate():
                    for db_instance in page['DBInstances']:
                        instance_data = {
                            'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'],
                            'DBInstanceClass': db_instance['DBInstanceClass'],
                            'Engine': db_instance['Engine'],
                            'EngineVersion': db_instance['EngineVersion'],
                            'DBInstanceStatus': db_instance['DBInstanceStatus'],
                            'AllocatedStorage': db_instance['AllocatedStorage'],
                            'StorageType': db_instance['StorageType'],
                            'StorageEncrypted': db_instance.get('StorageEncrypted', False),
                            'MultiAZ': db_instance['MultiAZ'],
                            'VpcId': db_instance.get('DBSubnetGroup', {}).get('VpcId'),
                            'DBSubnetGroup': db_instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName'),
                            'VpcSecurityGroups': [sg['VpcSecurityGroupId'] for sg in db_instance.get('VpcSecurityGroups', [])],
                            'Endpoint': db_instance.get('Endpoint', {}).get('Address'),
                            'Port': db_instance.get('Endpoint', {}).get('Port'),
                            'BackupRetentionPeriod': db_instance['BackupRetentionPeriod'],
                            'PreferredBackupWindow': db_instance.get('PreferredBackupWindow'),
                            'PreferredMaintenanceWindow': db_instance.get('PreferredMaintenanceWindow'),
                            'Tags': {tag['Key']: tag['Value'] for tag in db_instance.get('TagList', [])}
                        }
                        instances.append(instance_data)
                
                return {region: {"instances": instances, "count": len(instances)}}
                
            except ClientError as e:
                logger.error(f"Error discovering RDS instances in {region}: {e}")
                return {region: {"error": str(e), "instances": [], "count": 0}}
        
        # Run discovery in parallel across regions
        tasks = [discover_in_region(region) for region in regions]
        region_results = await asyncio.gather(*tasks)
        
        # Combine results
        for result in region_results:
            results["rds_instances"].update(result)
        
        results["summary"] = {
            "total_instances": sum(r.get("count", 0) for r in results["rds_instances"].values()),
            "regions_scanned": len(regions),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return results
    
    async def discover_lambda_functions(self, regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Discover Lambda functions across regions."""
        regions = regions or self.regions
        results = {"lambda_functions": {}}
        
        async def discover_in_region(region: str) -> Dict[str, Any]:
            try:
                lambda_client = self._get_client('lambda', region)
                
                # Get all functions
                paginator = lambda_client.get_paginator('list_functions')
                functions = []
                
                for page in paginator.paginate():
                    for function in page['Functions']:
                        function_data = {
                            'FunctionName': function['FunctionName'],
                            'FunctionArn': function['FunctionArn'],
                            'Runtime': function.get('Runtime'),
                            'Handler': function.get('Handler'),
                            'CodeSize': function['CodeSize'],
                            'Description': function.get('Description'),
                            'Timeout': function['Timeout'],
                            'MemorySize': function['MemorySize'],
                            'LastModified': function['LastModified'],
                            'Role': function['Role'],
                            'VpcConfig': {
                                'VpcId': function.get('VpcConfig', {}).get('VpcId'),
                                'SubnetIds': function.get('VpcConfig', {}).get('SubnetIds', []),
                                'SecurityGroupIds': function.get('VpcConfig', {}).get('SecurityGroupIds', [])
                            } if function.get('VpcConfig') else None,
                            'Environment': list(function.get('Environment', {}).get('Variables', {}).keys()),
                            'TracingConfig': function.get('TracingConfig', {}).get('Mode')
                        }
                        
                        # Get function tags
                        try:
                            tags_response = lambda_client.list_tags(Resource=function['FunctionArn'])
                            function_data['Tags'] = tags_response.get('Tags', {})
                        except Exception as e:
                            logger.debug(f"Error getting tags for function {function['FunctionName']}: {e}")
                            function_data['Tags'] = {}
                        
                        functions.append(function_data)
                
                return {region: {"functions": functions, "count": len(functions)}}
                
            except ClientError as e:
                logger.error(f"Error discovering Lambda functions in {region}: {e}")
                return {region: {"error": str(e), "functions": [], "count": 0}}
        
        # Run discovery in parallel across regions
        tasks = [discover_in_region(region) for region in regions]
        region_results = await asyncio.gather(*tasks)
        
        # Combine results
        for result in region_results:
            results["lambda_functions"].update(result)
        
        results["summary"] = {
            "total_functions": sum(r.get("count", 0) for r in results["lambda_functions"].values()),
            "regions_scanned": len(regions),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return results
    
    async def discover_all_resources(self, resource_types: Optional[List[str]] = None,
                                   regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Discover all specified AWS resources across regions.
        
        Args:
            resource_types: List of resource types to discover
            regions: List of regions to scan
            
        Returns:
            Dictionary of all discovered resources
        """
        if not resource_types:
            resource_types = ['ec2', 's3', 'rds', 'lambda']
        
        regions = regions or self.regions
        all_results = {}
        
        # Map resource types to discovery methods
        discovery_methods = {
            'ec2': lambda: self.discover_ec2_instances(regions),
            's3': lambda: self.discover_s3_buckets(),  # S3 is global
            'rds': lambda: self.discover_rds_instances(regions),
            'lambda': lambda: self.discover_lambda_functions(regions)
        }
        
        # Run discovery for each resource type
        tasks = []
        for resource_type in resource_types:
            if resource_type in discovery_methods:
                tasks.append(discovery_methods[resource_type]())
            else:
                logger.warning(f"Unknown resource type: {resource_type}")
        
        # Gather all results
        results = await asyncio.gather(*tasks)
        
        # Combine results
        for result in results:
            all_results.update(result)
        
        # Add overall summary
        all_results["discovery_summary"] = {
            "resource_types_scanned": resource_types,
            "regions_scanned": regions,
            "timestamp": datetime.utcnow().isoformat(),
            "total_resources": sum(
                sum(region_data.get("count", 0) for region_data in resource_data.values() if isinstance(region_data, dict))
                for resource_type, resource_data in all_results.items()
                if isinstance(resource_data, dict) and resource_type != "discovery_summary"
            )
        }
        
        return all_results
    
    def get_resource_relationships(self, resources: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
        """
        Analyze and return relationships between discovered resources.
        
        Args:
            resources: Dictionary of discovered resources
            
        Returns:
            Dictionary mapping resource IDs to their relationships
        """
        relationships = {}
        
        # Extract EC2 instances for relationship mapping
        ec2_instances = []
        if "ec2_instances" in resources:
            for region_data in resources["ec2_instances"].values():
                if isinstance(region_data, dict) and "instances" in region_data:
                    ec2_instances.extend(region_data["instances"])
        
        # Extract RDS instances
        rds_instances = []
        if "rds_instances" in resources:
            for region_data in resources["rds_instances"].values():
                if isinstance(region_data, dict) and "instances" in region_data:
                    rds_instances.extend(region_data["instances"])
        
        # Extract Lambda functions
        lambda_functions = []
        if "lambda_functions" in resources:
            for region_data in resources["lambda_functions"].values():
                if isinstance(region_data, dict) and "functions" in region_data:
                    lambda_functions.extend(region_data["functions"])
        
        # Map EC2 instances to their VPCs and security groups
        for instance in ec2_instances:
            instance_id = instance['InstanceId']
            relationships[instance_id] = []
            
            # VPC relationship
            if instance.get('VpcId'):
                relationships[instance_id].append({
                    'type': 'vpc',
                    'id': instance['VpcId'],
                    'relationship': 'belongs_to'
                })
            
            # Security group relationships
            for sg_id in instance.get('SecurityGroups', []):
                relationships[instance_id].append({
                    'type': 'security_group',
                    'id': sg_id,
                    'relationship': 'uses'
                })
            
            # IAM role relationship
            if instance.get('IamInstanceProfile'):
                relationships[instance_id].append({
                    'type': 'iam_role',
                    'arn': instance['IamInstanceProfile'],
                    'relationship': 'assumes'
                })
        
        # Map RDS instances to their VPCs and security groups
        for db_instance in rds_instances:
            db_id = db_instance['DBInstanceIdentifier']
            relationships[db_id] = []
            
            # VPC relationship
            if db_instance.get('VpcId'):
                relationships[db_id].append({
                    'type': 'vpc',
                    'id': db_instance['VpcId'],
                    'relationship': 'belongs_to'
                })
            
            # Security group relationships
            for sg_id in db_instance.get('VpcSecurityGroups', []):
                relationships[db_id].append({
                    'type': 'security_group',
                    'id': sg_id,
                    'relationship': 'uses'
                })
        
        # Map Lambda functions to their VPCs and roles
        for function in lambda_functions:
            function_name = function['FunctionName']
            relationships[function_name] = []
            
            # VPC relationship
            if function.get('VpcConfig') and function['VpcConfig'].get('VpcId'):
                relationships[function_name].append({
                    'type': 'vpc',
                    'id': function['VpcConfig']['VpcId'],
                    'relationship': 'deployed_in'
                })
            
            # IAM role relationship
            if function.get('Role'):
                relationships[function_name].append({
                    'type': 'iam_role',
                    'arn': function['Role'],
                    'relationship': 'assumes'
                })
        
        return relationships