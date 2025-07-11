"""
MCP Resources for exposing AWS data as queryable resources.

This module implements the MCP Resources feature to provide real-time access
to AWS resources like EC2 instances, S3 buckets, CloudWatch metrics, etc.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError
from mcp import Resource
import logging

logger = logging.getLogger(__name__)


class AWSResourceProvider:
    """Base class for AWS resource providers."""
    
    def __init__(self, region: Optional[str] = None):
        self.region = region or 'us-east-1'
        self._clients: Dict[str, Any] = {}
    
    def get_client(self, service: str) -> Any:
        """Get or create a boto3 client for the specified service."""
        if service not in self._clients:
            self._clients[service] = boto3.client(service, region_name=self.region)
        return self._clients[service]
    
    async def fetch_resources(self) -> Dict[str, Any]:
        """Fetch resources from AWS. To be implemented by subclasses."""
        raise NotImplementedError


class EC2ResourceProvider(AWSResourceProvider):
    """Provider for EC2 instance resources."""
    
    async def fetch_resources(self, instance_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Fetch EC2 instance information."""
        ec2 = self.get_client('ec2')
        
        try:
            params = {}
            if instance_ids:
                params['InstanceIds'] = instance_ids
            
            response = await asyncio.get_event_loop().run_in_executor(
                None, lambda: ec2.describe_instances(**params)
            )
            
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append({
                        'instanceId': instance['InstanceId'],
                        'instanceType': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'launchTime': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None,
                        'publicIp': instance.get('PublicIpAddress'),
                        'privateIp': instance.get('PrivateIpAddress'),
                        'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                        'vpcId': instance.get('VpcId'),
                        'subnetId': instance.get('SubnetId'),
                        'securityGroups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    })
            
            return {
                'instances': instances,
                'count': len(instances),
                'region': self.region,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            logger.error(f"Error fetching EC2 instances: {e}")
            return {
                'error': str(e),
                'instances': [],
                'count': 0,
                'region': self.region,
                'timestamp': datetime.utcnow().isoformat()
            }


class S3ResourceProvider(AWSResourceProvider):
    """Provider for S3 bucket and object resources."""
    
    async def fetch_buckets(self) -> Dict[str, Any]:
        """Fetch S3 bucket information."""
        s3 = self.get_client('s3')
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None, s3.list_buckets
            )
            
            buckets = []
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                # Get bucket location
                try:
                    location_response = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: s3.get_bucket_location(Bucket=bucket_name)
                    )
                    region = location_response.get('LocationConstraint') or 'us-east-1'
                except:
                    region = 'unknown'
                
                # Get bucket size and object count (first 1000 objects for performance)
                try:
                    objects_response = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1000)
                    )
                    object_count = objects_response.get('KeyCount', 0)
                    total_size = sum(obj.get('Size', 0) for obj in objects_response.get('Contents', []))
                except:
                    object_count = 0
                    total_size = 0
                
                buckets.append({
                    'name': bucket_name,
                    'creationDate': bucket['CreationDate'].isoformat(),
                    'region': region,
                    'objectCount': object_count,
                    'totalSize': total_size,
                    'sizeHuman': self._human_readable_size(total_size)
                })
            
            return {
                'buckets': buckets,
                'count': len(buckets),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            logger.error(f"Error fetching S3 buckets: {e}")
            return {
                'error': str(e),
                'buckets': [],
                'count': 0,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    async def fetch_objects(self, bucket_name: str, prefix: str = '', max_keys: int = 100) -> Dict[str, Any]:
        """Fetch objects from an S3 bucket."""
        s3 = self.get_client('s3')
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None, lambda: s3.list_objects_v2(
                    Bucket=bucket_name,
                    Prefix=prefix,
                    MaxKeys=max_keys
                )
            )
            
            objects = []
            for obj in response.get('Contents', []):
                objects.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'sizeHuman': self._human_readable_size(obj['Size']),
                    'lastModified': obj['LastModified'].isoformat(),
                    'storageClass': obj.get('StorageClass', 'STANDARD'),
                    'etag': obj.get('ETag', '').strip('"')
                })
            
            return {
                'bucket': bucket_name,
                'prefix': prefix,
                'objects': objects,
                'count': len(objects),
                'isTruncated': response.get('IsTruncated', False),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            logger.error(f"Error fetching S3 objects: {e}")
            return {
                'error': str(e),
                'bucket': bucket_name,
                'objects': [],
                'count': 0,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _human_readable_size(self, size: int) -> str:
        """Convert bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


class CloudWatchResourceProvider(AWSResourceProvider):
    """Provider for CloudWatch metrics resources."""
    
    async def fetch_metrics(self, namespace: str, metric_name: Optional[str] = None,
                          dimensions: Optional[Dict[str, str]] = None,
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None,
                          period: int = 300) -> Dict[str, Any]:
        """Fetch CloudWatch metrics."""
        cloudwatch = self.get_client('cloudwatch')
        
        if not end_time:
            end_time = datetime.utcnow()
        if not start_time:
            start_time = end_time - timedelta(hours=1)
        
        try:
            # List available metrics if no specific metric requested
            if not metric_name:
                list_params = {'Namespace': namespace}
                if dimensions:
                    list_params['Dimensions'] = [
                        {'Name': k, 'Value': v} for k, v in dimensions.items()
                    ]
                
                response = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: cloudwatch.list_metrics(**list_params)
                )
                
                metrics = []
                for metric in response['Metrics']:
                    metrics.append({
                        'metricName': metric['MetricName'],
                        'namespace': metric['Namespace'],
                        'dimensions': {d['Name']: d['Value'] for d in metric.get('Dimensions', [])}
                    })
                
                return {
                    'namespace': namespace,
                    'metrics': metrics,
                    'count': len(metrics),
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Get metric statistics for specific metric
            params = {
                'Namespace': namespace,
                'MetricName': metric_name,
                'StartTime': start_time,
                'EndTime': end_time,
                'Period': period,
                'Statistics': ['Average', 'Minimum', 'Maximum', 'Sum', 'SampleCount']
            }
            
            if dimensions:
                params['Dimensions'] = [
                    {'Name': k, 'Value': v} for k, v in dimensions.items()
                ]
            
            response = await asyncio.get_event_loop().run_in_executor(
                None, lambda: cloudwatch.get_metric_statistics(**params)
            )
            
            datapoints = []
            for dp in sorted(response['Datapoints'], key=lambda x: x['Timestamp']):
                datapoints.append({
                    'timestamp': dp['Timestamp'].isoformat(),
                    'average': dp.get('Average'),
                    'minimum': dp.get('Minimum'),
                    'maximum': dp.get('Maximum'),
                    'sum': dp.get('Sum'),
                    'sampleCount': dp.get('SampleCount'),
                    'unit': dp.get('Unit')
                })
            
            return {
                'namespace': namespace,
                'metricName': metric_name,
                'dimensions': dimensions or {},
                'datapoints': datapoints,
                'period': period,
                'startTime': start_time.isoformat(),
                'endTime': end_time.isoformat(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            logger.error(f"Error fetching CloudWatch metrics: {e}")
            return {
                'error': str(e),
                'namespace': namespace,
                'timestamp': datetime.utcnow().isoformat()
            }


class CloudFormationResourceProvider(AWSResourceProvider):
    """Provider for CloudFormation stack resources."""
    
    async def fetch_stacks(self, stack_name: Optional[str] = None) -> Dict[str, Any]:
        """Fetch CloudFormation stack information."""
        cf = self.get_client('cloudformation')
        
        try:
            params = {}
            if stack_name:
                params['StackName'] = stack_name
            
            response = await asyncio.get_event_loop().run_in_executor(
                None, lambda: cf.describe_stacks(**params)
            )
            
            stacks = []
            for stack in response['Stacks']:
                # Get stack resources
                resources_response = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: cf.describe_stack_resources(StackName=stack['StackName'])
                )
                
                resources = []
                for resource in resources_response['StackResources']:
                    resources.append({
                        'logicalId': resource['LogicalResourceId'],
                        'physicalId': resource.get('PhysicalResourceId'),
                        'type': resource['ResourceType'],
                        'status': resource['ResourceStatus'],
                        'timestamp': resource['Timestamp'].isoformat()
                    })
                
                stacks.append({
                    'stackName': stack['StackName'],
                    'stackId': stack['StackId'],
                    'status': stack['StackStatus'],
                    'creationTime': stack['CreationTime'].isoformat(),
                    'lastUpdatedTime': stack.get('LastUpdatedTime', stack['CreationTime']).isoformat(),
                    'description': stack.get('Description'),
                    'parameters': {p['ParameterKey']: p['ParameterValue'] for p in stack.get('Parameters', [])},
                    'outputs': {o['OutputKey']: o['OutputValue'] for o in stack.get('Outputs', [])},
                    'resources': resources,
                    'resourceCount': len(resources),
                    'tags': {tag['Key']: tag['Value'] for tag in stack.get('Tags', [])}
                })
            
            return {
                'stacks': stacks,
                'count': len(stacks),
                'region': self.region,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            logger.error(f"Error fetching CloudFormation stacks: {e}")
            return {
                'error': str(e),
                'stacks': [],
                'count': 0,
                'region': self.region,
                'timestamp': datetime.utcnow().isoformat()
            }


class IAMResourceProvider(AWSResourceProvider):
    """Provider for IAM resources."""
    
    async def fetch_policies(self, scope: str = 'All') -> Dict[str, Any]:
        """Fetch IAM policies. Scope can be 'All', 'AWS', or 'Local'."""
        iam = self.get_client('iam')
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None, lambda: iam.list_policies(Scope=scope, MaxItems=100)
            )
            
            policies = []
            for policy in response['Policies']:
                # Get policy version details
                version_response = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: iam.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                )
                
                policies.append({
                    'policyName': policy['PolicyName'],
                    'policyId': policy['PolicyId'],
                    'arn': policy['Arn'],
                    'description': policy.get('Description'),
                    'createDate': policy['CreateDate'].isoformat(),
                    'updateDate': policy['UpdateDate'].isoformat(),
                    'attachmentCount': policy.get('AttachmentCount', 0),
                    'document': version_response['PolicyVersion']['Document']
                })
            
            return {
                'policies': policies,
                'count': len(policies),
                'scope': scope,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            logger.error(f"Error fetching IAM policies: {e}")
            return {
                'error': str(e),
                'policies': [],
                'count': 0,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    async def fetch_roles(self) -> Dict[str, Any]:
        """Fetch IAM roles."""
        iam = self.get_client('iam')
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None, iam.list_roles
            )
            
            roles = []
            for role in response['Roles']:
                roles.append({
                    'roleName': role['RoleName'],
                    'roleId': role['RoleId'],
                    'arn': role['Arn'],
                    'description': role.get('Description'),
                    'createDate': role['CreateDate'].isoformat(),
                    'maxSessionDuration': role.get('MaxSessionDuration'),
                    'assumeRolePolicyDocument': role['AssumeRolePolicyDocument']
                })
            
            return {
                'roles': roles,
                'count': len(roles),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            logger.error(f"Error fetching IAM roles: {e}")
            return {
                'error': str(e),
                'roles': [],
                'count': 0,
                'timestamp': datetime.utcnow().isoformat()
            }


# Resource registration functions for MCP server
async def get_ec2_instances(region: str, instance_ids: Optional[str] = None) -> Resource:
    """MCP resource for EC2 instances."""
    provider = EC2ResourceProvider(region)
    instance_list = instance_ids.split(',') if instance_ids else None
    data = await provider.fetch_resources(instance_list)
    
    return Resource(
        uri=f"ec2://instances/{region}",
        name=f"EC2 Instances in {region}",
        description=f"Real-time EC2 instance information for region {region}",
        mimeType="application/json",
        text=json.dumps(data, indent=2)
    )


async def get_s3_buckets() -> Resource:
    """MCP resource for S3 buckets."""
    provider = S3ResourceProvider()
    data = await provider.fetch_buckets()
    
    return Resource(
        uri="s3://buckets",
        name="S3 Buckets",
        description="List of all S3 buckets in the account",
        mimeType="application/json",
        text=json.dumps(data, indent=2)
    )


async def get_s3_objects(bucket_name: str, prefix: str = '') -> Resource:
    """MCP resource for S3 bucket objects."""
    provider = S3ResourceProvider()
    data = await provider.fetch_objects(bucket_name, prefix)
    
    return Resource(
        uri=f"s3://buckets/{bucket_name}/objects",
        name=f"Objects in {bucket_name}",
        description=f"List of objects in S3 bucket {bucket_name}",
        mimeType="application/json",
        text=json.dumps(data, indent=2)
    )


async def get_cloudwatch_metrics(namespace: str, metric_name: Optional[str] = None) -> Resource:
    """MCP resource for CloudWatch metrics."""
    provider = CloudWatchResourceProvider()
    data = await provider.fetch_metrics(namespace, metric_name)
    
    return Resource(
        uri=f"cloudwatch://metrics/{namespace}",
        name=f"CloudWatch Metrics - {namespace}",
        description=f"CloudWatch metrics for namespace {namespace}",
        mimeType="application/json",
        text=json.dumps(data, indent=2)
    )


async def get_cloudformation_stacks(region: str, stack_name: Optional[str] = None) -> Resource:
    """MCP resource for CloudFormation stacks."""
    provider = CloudFormationResourceProvider(region)
    data = await provider.fetch_stacks(stack_name)
    
    return Resource(
        uri=f"cloudformation://stacks/{region}",
        name=f"CloudFormation Stacks in {region}",
        description=f"CloudFormation stacks and their resources in {region}",
        mimeType="application/json",
        text=json.dumps(data, indent=2)
    )


async def get_iam_policies(scope: str = 'Local') -> Resource:
    """MCP resource for IAM policies."""
    provider = IAMResourceProvider()
    data = await provider.fetch_policies(scope)
    
    return Resource(
        uri=f"iam://policies",
        name="IAM Policies",
        description=f"IAM policies with scope {scope}",
        mimeType="application/json",
        text=json.dumps(data, indent=2)
    )


async def get_iam_roles() -> Resource:
    """MCP resource for IAM roles."""
    provider = IAMResourceProvider()
    data = await provider.fetch_roles()
    
    return Resource(
        uri="iam://roles",
        name="IAM Roles",
        description="List of all IAM roles in the account",
        mimeType="application/json",
        text=json.dumps(data, indent=2)
    )