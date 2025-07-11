"""
Machine Learning and AI capabilities for AWS MCP Server.

This module provides comprehensive ML/AI features including:
- SageMaker integration for model training and deployment
- Bedrock integration for foundation models
- TimeStream DB for time series data and ML
- S3 integration for datasets and model artifacts
- Automated ML pipeline management
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import json
import boto3
from botocore.exceptions import ClientError
from dataclasses import dataclass, field
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class MLPipeline:
    """Represents an ML training pipeline."""
    pipeline_id: str
    name: str
    pipeline_type: str  # "sagemaker", "bedrock_finetune", "timestream_forecast"
    status: str  # "created", "running", "completed", "failed"
    config: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    artifacts: Dict[str, str] = field(default_factory=dict)


class MLAIEngine:
    """Main engine for ML/AI operations on AWS."""
    
    def __init__(self):
        self._clients: Dict[str, Any] = {}
        self.pipelines: Dict[str, MLPipeline] = {}
        
    def _get_client(self, service: str, region: str = 'us-east-1') -> Any:
        """Get or create a boto3 client."""
        key = f"{service}_{region}"
        if key not in self._clients:
            self._clients[key] = boto3.client(service, region_name=region)
        return self._clients[key]
    
    # TimeStream Integration
    async def create_timestream_database(
        self,
        database_name: str,
        region: str = 'us-east-1',
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a TimeStream database for ML time series data."""
        timestream = self._get_client('timestream-write', region)
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: timestream.create_database(
                    DatabaseName=database_name,
                    Tags=[{'Key': k, 'Value': v} for k, v in (tags or {}).items()]
                )
            )
            
            return {
                "status": "success",
                "database_name": database_name,
                "arn": response['Database']['Arn'],
                "creation_time": response['Database']['CreationTime'].isoformat()
            }
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConflictException':
                return {
                    "status": "exists",
                    "database_name": database_name,
                    "message": "Database already exists"
                }
            raise
    
    async def create_timestream_table(
        self,
        database_name: str,
        table_name: str,
        memory_retention_hours: int = 12,
        magnetic_retention_days: int = 365,
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """Create a TimeStream table for ML data storage."""
        timestream = self._get_client('timestream-write', region)
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: timestream.create_table(
                    DatabaseName=database_name,
                    TableName=table_name,
                    RetentionProperties={
                        'MemoryStoreRetentionPeriodInHours': memory_retention_hours,
                        'MagneticStoreRetentionPeriodInDays': magnetic_retention_days
                    }
                )
            )
            
            return {
                "status": "success",
                "table_name": table_name,
                "database_name": database_name,
                "arn": response['Table']['Arn']
            }
            
        except ClientError as e:
            logger.error(f"Error creating TimeStream table: {e}")
            raise
    
    async def write_ml_metrics_to_timestream(
        self,
        database_name: str,
        table_name: str,
        metrics: List[Dict[str, Any]],
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """Write ML training metrics to TimeStream for analysis."""
        timestream = self._get_client('timestream-write', region)
        
        records = []
        for metric in metrics:
            record = {
                'Time': str(int(metric.get('timestamp', datetime.utcnow()).timestamp() * 1000)),
                'TimeUnit': 'MILLISECONDS',
                'MeasureName': metric['metric_name'],
                'MeasureValue': str(metric['value']),
                'MeasureValueType': 'DOUBLE',
                'Dimensions': [
                    {'Name': k, 'Value': str(v)}
                    for k, v in metric.get('dimensions', {}).items()
                ]
            }
            records.append(record)
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: timestream.write_records(
                    DatabaseName=database_name,
                    TableName=table_name,
                    Records=records
                )
            )
            
            return {
                "status": "success",
                "records_written": len(records),
                "failed_records": response.get('RecordsIngested', {}).get('Total', 0) - len(records)
            }
            
        except ClientError as e:
            logger.error(f"Error writing to TimeStream: {e}")
            raise
    
    async def query_timestream_for_ml_insights(
        self,
        database_name: str,
        table_name: str,
        query: str,
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """Query TimeStream for ML model performance insights."""
        timestream_query = self._get_client('timestream-query', region)
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: timestream_query.query(QueryString=query)
            )
            
            # Parse results
            rows = []
            for row in response['Rows']:
                parsed_row = {}
                for i, col in enumerate(response['ColumnInfo']):
                    parsed_row[col['Name']] = row['Data'][i].get('ScalarValue')
                rows.append(parsed_row)
            
            return {
                "status": "success",
                "row_count": len(rows),
                "data": rows,
                "query_id": response['QueryId']
            }
            
        except ClientError as e:
            logger.error(f"Error querying TimeStream: {e}")
            raise
    
    # SageMaker Integration
    async def create_sagemaker_training_job(
        self,
        job_name: str,
        algorithm_image: str,
        input_data_s3: str,
        output_data_s3: str,
        instance_type: str = 'ml.m5.xlarge',
        instance_count: int = 1,
        hyperparameters: Optional[Dict[str, str]] = None,
        role_arn: Optional[str] = None,
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """Create and start a SageMaker training job."""
        sagemaker = self._get_client('sagemaker', region)
        
        # Use default SageMaker execution role if not provided
        if not role_arn:
            # This would need to be configured based on your setup
            role_arn = f"arn:aws:iam::123456789012:role/SageMakerExecutionRole"
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sagemaker.create_training_job(
                    TrainingJobName=job_name,
                    RoleArn=role_arn,
                    AlgorithmSpecification={
                        'TrainingImage': algorithm_image,
                        'TrainingInputMode': 'File'
                    },
                    InputDataConfig=[{
                        'ChannelName': 'training',
                        'DataSource': {
                            'S3DataSource': {
                                'S3DataType': 'S3Prefix',
                                'S3Uri': input_data_s3,
                                'S3DataDistributionType': 'FullyReplicated'
                            }
                        }
                    }],
                    OutputDataConfig={
                        'S3OutputPath': output_data_s3
                    },
                    ResourceConfig={
                        'InstanceType': instance_type,
                        'InstanceCount': instance_count,
                        'VolumeSizeInGB': 30
                    },
                    StoppingCondition={
                        'MaxRuntimeInSeconds': 86400  # 24 hours
                    },
                    HyperParameters=hyperparameters or {}
                )
            )
            
            # Create pipeline record
            pipeline = MLPipeline(
                pipeline_id=f"sagemaker_{job_name}",
                name=job_name,
                pipeline_type="sagemaker",
                status="running",
                config={
                    "training_job_arn": response['TrainingJobArn'],
                    "algorithm": algorithm_image,
                    "instance_type": instance_type,
                    "input_s3": input_data_s3,
                    "output_s3": output_data_s3
                }
            )
            self.pipelines[pipeline.pipeline_id] = pipeline
            
            return {
                "status": "success",
                "training_job_name": job_name,
                "training_job_arn": response['TrainingJobArn'],
                "pipeline_id": pipeline.pipeline_id
            }
            
        except ClientError as e:
            logger.error(f"Error creating SageMaker training job: {e}")
            raise
    
    async def deploy_sagemaker_model(
        self,
        model_name: str,
        model_data_s3: str,
        container_image: str,
        instance_type: str = 'ml.m5.large',
        initial_instance_count: int = 1,
        role_arn: Optional[str] = None,
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """Deploy a trained model to SageMaker endpoint."""
        sagemaker = self._get_client('sagemaker', region)
        
        if not role_arn:
            role_arn = f"arn:aws:iam::123456789012:role/SageMakerExecutionRole"
        
        try:
            # Create model
            model_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sagemaker.create_model(
                    ModelName=model_name,
                    PrimaryContainer={
                        'Image': container_image,
                        'ModelDataUrl': model_data_s3
                    },
                    ExecutionRoleArn=role_arn
                )
            )
            
            # Create endpoint configuration
            endpoint_config_name = f"{model_name}-config"
            config_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sagemaker.create_endpoint_config(
                    EndpointConfigName=endpoint_config_name,
                    ProductionVariants=[{
                        'VariantName': 'primary',
                        'ModelName': model_name,
                        'InitialInstanceCount': initial_instance_count,
                        'InstanceType': instance_type
                    }]
                )
            )
            
            # Create endpoint
            endpoint_name = f"{model_name}-endpoint"
            endpoint_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sagemaker.create_endpoint(
                    EndpointName=endpoint_name,
                    EndpointConfigName=endpoint_config_name
                )
            )
            
            return {
                "status": "success",
                "model_name": model_name,
                "endpoint_name": endpoint_name,
                "endpoint_arn": endpoint_response['EndpointArn'],
                "deployment_status": "creating"
            }
            
        except ClientError as e:
            logger.error(f"Error deploying SageMaker model: {e}")
            raise
    
    async def invoke_sagemaker_endpoint(
        self,
        endpoint_name: str,
        payload: Dict[str, Any],
        content_type: str = 'application/json',
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """Invoke a SageMaker endpoint for inference."""
        runtime = self._get_client('sagemaker-runtime', region)
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: runtime.invoke_endpoint(
                    EndpointName=endpoint_name,
                    Body=json.dumps(payload),
                    ContentType=content_type
                )
            )
            
            result = json.loads(response['Body'].read().decode())
            
            return {
                "status": "success",
                "endpoint_name": endpoint_name,
                "prediction": result,
                "model_version": response.get('InvokedProductionVariant')
            }
            
        except ClientError as e:
            logger.error(f"Error invoking SageMaker endpoint: {e}")
            raise
    
    # Bedrock Integration
    async def list_bedrock_models(self, region: str = 'us-east-1') -> Dict[str, Any]:
        """List available Bedrock foundation models."""
        bedrock = self._get_client('bedrock', region)
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: bedrock.list_foundation_models()
            )
            
            models = []
            for model in response['modelSummaries']:
                models.append({
                    'model_id': model['modelId'],
                    'model_name': model['modelName'],
                    'provider': model['providerName'],
                    'input_modalities': model.get('inputModalities', []),
                    'output_modalities': model.get('outputModalities', []),
                    'customization_supported': model.get('customizationsSupported', [])
                })
            
            return {
                "status": "success",
                "model_count": len(models),
                "models": models
            }
            
        except ClientError as e:
            logger.error(f"Error listing Bedrock models: {e}")
            raise
    
    async def create_bedrock_fine_tuning_job(
        self,
        job_name: str,
        base_model_id: str,
        training_data_s3: str,
        output_s3: str,
        hyperparameters: Optional[Dict[str, Any]] = None,
        role_arn: Optional[str] = None,
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """Create a fine-tuning job for Bedrock models."""
        bedrock = self._get_client('bedrock', region)
        
        if not role_arn:
            role_arn = f"arn:aws:iam::123456789012:role/BedrockExecutionRole"
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: bedrock.create_model_customization_job(
                    jobName=job_name,
                    customModelName=f"{job_name}-model",
                    roleArn=role_arn,
                    baseModelIdentifier=base_model_id,
                    trainingDataConfig={
                        's3Uri': training_data_s3
                    },
                    outputDataConfig={
                        's3Uri': output_s3
                    },
                    hyperParameters=hyperparameters or {}
                )
            )
            
            # Create pipeline record
            pipeline = MLPipeline(
                pipeline_id=f"bedrock_{job_name}",
                name=job_name,
                pipeline_type="bedrock_finetune",
                status="running",
                config={
                    "job_arn": response['jobArn'],
                    "base_model": base_model_id,
                    "training_data": training_data_s3,
                    "output_s3": output_s3
                }
            )
            self.pipelines[pipeline.pipeline_id] = pipeline
            
            return {
                "status": "success",
                "job_name": job_name,
                "job_arn": response['jobArn'],
                "pipeline_id": pipeline.pipeline_id
            }
            
        except ClientError as e:
            logger.error(f"Error creating Bedrock fine-tuning job: {e}")
            raise
    
    async def invoke_bedrock_model(
        self,
        model_id: str,
        prompt: str,
        max_tokens: int = 512,
        temperature: float = 0.7,
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """Invoke a Bedrock model for inference."""
        bedrock_runtime = self._get_client('bedrock-runtime', region)
        
        # Format request based on model provider
        if 'anthropic' in model_id:
            body = {
                "prompt": f"\n\nHuman: {prompt}\n\nAssistant:",
                "max_tokens_to_sample": max_tokens,
                "temperature": temperature
            }
        elif 'meta' in model_id:
            body = {
                "prompt": prompt,
                "max_gen_len": max_tokens,
                "temperature": temperature
            }
        else:
            body = {
                "prompt": prompt,
                "maxTokens": max_tokens,
                "temperature": temperature
            }
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: bedrock_runtime.invoke_model(
                    modelId=model_id,
                    body=json.dumps(body),
                    contentType='application/json'
                )
            )
            
            result = json.loads(response['body'].read())
            
            # Extract completion based on model
            if 'anthropic' in model_id:
                completion = result.get('completion', '')
            elif 'meta' in model_id:
                completion = result.get('generation', '')
            else:
                completion = result.get('results', [{}])[0].get('outputText', '')
            
            return {
                "status": "success",
                "model_id": model_id,
                "completion": completion,
                "usage": {
                    "prompt_tokens": result.get('prompt_token_count'),
                    "completion_tokens": result.get('completion_token_count')
                }
            }
            
        except ClientError as e:
            logger.error(f"Error invoking Bedrock model: {e}")
            raise
    
    # S3 Data Management for ML
    async def prepare_ml_dataset(
        self,
        source_bucket: str,
        source_prefix: str,
        dest_bucket: str,
        dest_prefix: str,
        split_ratio: Tuple[float, float, float] = (0.7, 0.2, 0.1),
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """
        Prepare ML dataset by organizing data into train/validation/test splits.
        
        Args:
            source_bucket: Source S3 bucket
            source_prefix: Source prefix for data files
            dest_bucket: Destination bucket for organized data
            dest_prefix: Destination prefix
            split_ratio: (train, validation, test) split ratios
        """
        s3 = self._get_client('s3', region)
        
        try:
            # List all files in source
            paginator = s3.get_paginator('list_objects_v2')
            files = []
            
            for page in paginator.paginate(Bucket=source_bucket, Prefix=source_prefix):
                for obj in page.get('Contents', []):
                    files.append(obj['Key'])
            
            # Shuffle and split files
            import random
            random.shuffle(files)
            
            total_files = len(files)
            train_count = int(total_files * split_ratio[0])
            val_count = int(total_files * split_ratio[1])
            
            train_files = files[:train_count]
            val_files = files[train_count:train_count + val_count]
            test_files = files[train_count + val_count:]
            
            # Copy files to organized structure
            copy_tasks = []
            
            for file_list, split_name in [
                (train_files, 'train'),
                (val_files, 'validation'),
                (test_files, 'test')
            ]:
                for file_key in file_list:
                    file_name = file_key.split('/')[-1]
                    dest_key = f"{dest_prefix}/{split_name}/{file_name}"
                    
                    copy_task = asyncio.create_task(
                        asyncio.get_event_loop().run_in_executor(
                            None,
                            lambda src=file_key, dst=dest_key: s3.copy_object(
                                CopySource={'Bucket': source_bucket, 'Key': src},
                                Bucket=dest_bucket,
                                Key=dst
                            )
                        )
                    )
                    copy_tasks.append(copy_task)
            
            # Wait for all copies to complete
            await asyncio.gather(*copy_tasks)
            
            return {
                "status": "success",
                "total_files": total_files,
                "train_files": len(train_files),
                "validation_files": len(val_files),
                "test_files": len(test_files),
                "destination": f"s3://{dest_bucket}/{dest_prefix}/"
            }
            
        except ClientError as e:
            logger.error(f"Error preparing ML dataset: {e}")
            raise
    
    async def create_feature_store(
        self,
        feature_group_name: str,
        s3_uri: str,
        record_identifier: str,
        event_time_feature: str,
        features: List[Dict[str, str]],
        role_arn: Optional[str] = None,
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """Create a SageMaker Feature Store for ML features."""
        sagemaker = self._get_client('sagemaker', region)
        
        if not role_arn:
            role_arn = f"arn:aws:iam::123456789012:role/SageMakerExecutionRole"
        
        try:
            # Define feature definitions
            feature_definitions = []
            for feature in features:
                feature_definitions.append({
                    'FeatureName': feature['name'],
                    'FeatureType': feature.get('type', 'String')
                })
            
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sagemaker.create_feature_group(
                    FeatureGroupName=feature_group_name,
                    RecordIdentifierFeatureName=record_identifier,
                    EventTimeFeatureName=event_time_feature,
                    FeatureDefinitions=feature_definitions,
                    OnlineStoreConfig={
                        'EnableOnlineStore': True
                    },
                    OfflineStoreConfig={
                        'S3StorageConfig': {
                            'S3Uri': s3_uri
                        }
                    },
                    RoleArn=role_arn
                )
            )
            
            return {
                "status": "success",
                "feature_group_name": feature_group_name,
                "feature_group_arn": response['FeatureGroupArn'],
                "feature_count": len(feature_definitions)
            }
            
        except ClientError as e:
            logger.error(f"Error creating feature store: {e}")
            raise
    
    # Automated ML Pipeline
    async def create_automl_pipeline(
        self,
        pipeline_name: str,
        data_s3_uri: str,
        target_column: str,
        problem_type: str = 'BinaryClassification',
        objective_metric: str = 'F1',
        max_candidates: int = 10,
        instance_type: str = 'ml.m5.xlarge',
        role_arn: Optional[str] = None,
        region: str = 'us-east-1'
    ) -> Dict[str, Any]:
        """Create an AutoML pipeline using SageMaker Autopilot."""
        sagemaker = self._get_client('sagemaker', region)
        
        if not role_arn:
            role_arn = f"arn:aws:iam::123456789012:role/SageMakerExecutionRole"
        
        job_name = f"automl-{pipeline_name}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sagemaker.create_auto_ml_job(
                    AutoMLJobName=job_name,
                    InputDataConfig=[{
                        'DataSource': {
                            'S3DataSource': {
                                'S3DataType': 'S3Prefix',
                                'S3Uri': data_s3_uri
                            }
                        },
                        'TargetAttributeName': target_column
                    }],
                    OutputDataConfig={
                        'S3OutputPath': f"{data_s3_uri.rsplit('/', 1)[0]}/automl-output"
                    },
                    ProblemType=problem_type,
                    AutoMLJobObjective={
                        'MetricName': objective_metric
                    },
                    AutoMLJobConfig={
                        'CompletionCriteria': {
                            'MaxCandidates': max_candidates
                        }
                    },
                    RoleArn=role_arn
                )
            )
            
            # Create pipeline record
            pipeline = MLPipeline(
                pipeline_id=f"automl_{job_name}",
                name=pipeline_name,
                pipeline_type="sagemaker_automl",
                status="running",
                config={
                    "job_name": job_name,
                    "job_arn": response['AutoMLJobArn'],
                    "problem_type": problem_type,
                    "target_column": target_column,
                    "objective_metric": objective_metric
                }
            )
            self.pipelines[pipeline.pipeline_id] = pipeline
            
            return {
                "status": "success",
                "job_name": job_name,
                "job_arn": response['AutoMLJobArn'],
                "pipeline_id": pipeline.pipeline_id,
                "estimated_completion_time": "2-4 hours"
            }
            
        except ClientError as e:
            logger.error(f"Error creating AutoML pipeline: {e}")
            raise
    
    async def get_ml_pipeline_status(self, pipeline_id: str) -> Dict[str, Any]:
        """Get the status of an ML pipeline."""
        if pipeline_id not in self.pipelines:
            return {"error": f"Pipeline {pipeline_id} not found"}
        
        pipeline = self.pipelines[pipeline_id]
        
        # Update status based on pipeline type
        if pipeline.pipeline_type == "sagemaker":
            sagemaker = self._get_client('sagemaker')
            job_name = pipeline.config.get('training_job_arn', '').split('/')[-1]
            
            try:
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: sagemaker.describe_training_job(TrainingJobName=job_name)
                )
                
                pipeline.status = response['TrainingJobStatus'].lower()
                pipeline.updated_at = datetime.utcnow()
                
                if response['TrainingJobStatus'] == 'Completed':
                    pipeline.artifacts['model_artifacts'] = response['ModelArtifacts']['S3ModelArtifacts']
                
            except Exception as e:
                logger.error(f"Error getting training job status: {e}")
        
        return {
            "pipeline_id": pipeline_id,
            "name": pipeline.name,
            "type": pipeline.pipeline_type,
            "status": pipeline.status,
            "created_at": pipeline.created_at.isoformat(),
            "updated_at": pipeline.updated_at.isoformat() if pipeline.updated_at else None,
            "artifacts": pipeline.artifacts
        }