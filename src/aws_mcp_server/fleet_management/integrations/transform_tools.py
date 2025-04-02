"""
Transform Tools for AWS MCP Server.

This module provides tools for managing data transformation pipelines.
"""

import json
import logging
from typing import Dict, List, Any, Optional

from ..tools import Tool, ToolSchema
from .transform import (
    TransformRegistry, TransformPipeline, TransformStep, TransformPipelineConfig,
    TransformStepConfig, TransformOperation, DataFormat
)

logger = logging.getLogger(__name__)


class CreateTransformPipelineTool(Tool):
    """Tool for creating a new transformation pipeline."""
    
    def __init__(self, transform_registry: TransformRegistry):
        """
        Initialize the tool.
        
        Args:
            transform_registry: Registry for managing transformation pipelines
        """
        super().__init__(
            name="create_transform_pipeline",
            schema=ToolSchema(
                description="Create a new data transformation pipeline",
                parameters={
                    "name": {
                        "description": "Name of the pipeline",
                        "type": "string"
                    },
                    "description": {
                        "description": "Description of the pipeline",
                        "type": "string"
                    },
                    "input_format": {
                        "description": "Input data format",
                        "type": "string",
                        "enum": [f.value for f in DataFormat],
                        "default": "json"
                    },
                    "output_format": {
                        "description": "Output data format",
                        "type": "string",
                        "enum": [f.value for f in DataFormat],
                        "default": "json"
                    },
                    "steps": {
                        "description": "Transformation steps",
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "operation": {
                                    "type": "string",
                                    "enum": [o.value for o in TransformOperation]
                                },
                                "config": {"type": "object"},
                                "enabled": {"type": "boolean"},
                                "description": {"type": "string"},
                                "is_conditional": {"type": "boolean"},
                                "condition": {"type": "string"},
                                "error_behavior": {
                                    "type": "string",
                                    "enum": ["fail", "skip", "continue"]
                                },
                                "timeout_seconds": {"type": "integer"},
                                "retry_count": {"type": "integer"}
                            },
                            "required": ["name", "operation"]
                        }
                    },
                    "source_schema": {
                        "description": "Schema of the input data",
                        "type": "object"
                    },
                    "target_schema": {
                        "description": "Schema of the output data",
                        "type": "object"
                    },
                    "tags": {
                        "description": "Tags for the pipeline",
                        "type": "object",
                        "default": {}
                    },
                    "metadata": {
                        "description": "Additional metadata",
                        "type": "object",
                        "default": {}
                    }
                },
                returns={
                    "description": "Result of pipeline creation",
                    "type": "object",
                    "properties": {
                        "pipeline_id": {"type": "string"},
                        "name": {"type": "string"},
                        "step_count": {"type": "integer"}
                    }
                }
            )
        )
        self.transform_registry = transform_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            name = parameters.get("name")
            description = parameters.get("description")
            
            if not name:
                return {"error": "Pipeline name is required"}
                
            if not description:
                return {"error": "Pipeline description is required"}
            
            # Parse and create step configs
            step_configs = []
            for step_data in parameters.get("steps", []):
                step_config = TransformStepConfig(
                    name=step_data.get("name"),
                    operation=TransformOperation(step_data.get("operation")),
                    config=step_data.get("config", {}),
                    enabled=step_data.get("enabled", True),
                    description=step_data.get("description", ""),
                    is_conditional=step_data.get("is_conditional", False),
                    condition=step_data.get("condition"),
                    error_behavior=step_data.get("error_behavior", "fail"),
                    timeout_seconds=step_data.get("timeout_seconds", 30),
                    retry_count=step_data.get("retry_count", 0)
                )
                step_configs.append(step_config)
            
            # Create pipeline config
            pipeline_config = TransformPipelineConfig(
                name=name,
                description=description,
                steps=step_configs,
                input_format=DataFormat(parameters.get("input_format", "json")),
                output_format=DataFormat(parameters.get("output_format", "json")),
                source_schema=parameters.get("source_schema"),
                target_schema=parameters.get("target_schema"),
                tags=parameters.get("tags", {}),
                metadata=parameters.get("metadata", {})
            )
            
            # Register pipeline
            pipeline_id = await self.transform_registry.register_pipeline(pipeline_config)
            
            return {
                "pipeline_id": pipeline_id,
                "name": name,
                "step_count": len(step_configs)
            }
        except Exception as e:
            logger.error(f"Error creating transform pipeline: {str(e)}")
            return {"error": str(e)}


class DeleteTransformPipelineTool(Tool):
    """Tool for deleting a transformation pipeline."""
    
    def __init__(self, transform_registry: TransformRegistry):
        """
        Initialize the tool.
        
        Args:
            transform_registry: Registry for managing transformation pipelines
        """
        super().__init__(
            name="delete_transform_pipeline",
            schema=ToolSchema(
                description="Delete a transformation pipeline",
                parameters={
                    "pipeline_id": {
                        "description": "ID of the pipeline to delete",
                        "type": "string"
                    }
                },
                returns={
                    "description": "Result of pipeline deletion",
                    "type": "object",
                    "properties": {
                        "pipeline_id": {"type": "string"},
                        "success": {"type": "boolean"},
                        "message": {"type": "string"}
                    }
                }
            )
        )
        self.transform_registry = transform_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            pipeline_id = parameters.get("pipeline_id")
            
            if not pipeline_id:
                return {"error": "Pipeline ID is required"}
            
            # Delete pipeline
            success = await self.transform_registry.delete_pipeline(pipeline_id)
            
            if success:
                return {
                    "pipeline_id": pipeline_id,
                    "success": True,
                    "message": f"Pipeline deleted successfully"
                }
            else:
                return {
                    "pipeline_id": pipeline_id,
                    "success": False,
                    "message": f"Failed to delete pipeline {pipeline_id}"
                }
        except Exception as e:
            logger.error(f"Error deleting transform pipeline: {str(e)}")
            return {"error": str(e)}


class ListTransformPipelinesTool(Tool):
    """Tool for listing transformation pipelines."""
    
    def __init__(self, transform_registry: TransformRegistry):
        """
        Initialize the tool.
        
        Args:
            transform_registry: Registry for managing transformation pipelines
        """
        super().__init__(
            name="list_transform_pipelines",
            schema=ToolSchema(
                description="List all transformation pipelines",
                parameters={},
                returns={
                    "description": "List of transformation pipelines",
                    "type": "array"
                }
            )
        )
        self.transform_registry = transform_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            # Get all pipelines
            pipelines = await self.transform_registry.get_pipelines()
            
            # Convert to dictionaries
            result = []
            for pipeline in pipelines:
                pipeline_dict = {
                    "id": pipeline.id,
                    "name": pipeline.config.name,
                    "description": pipeline.config.description,
                    "input_format": pipeline.config.input_format.value,
                    "output_format": pipeline.config.output_format.value,
                    "step_count": len(pipeline.steps),
                    "active": pipeline.active,
                    "execution_count": pipeline.execution_count,
                    "success_count": pipeline.success_count,
                    "failure_count": pipeline.failure_count,
                    "created_at": pipeline.created_at.isoformat(),
                    "updated_at": pipeline.updated_at.isoformat()
                }
                
                if pipeline.last_execution:
                    pipeline_dict["last_execution"] = pipeline.last_execution.isoformat()
                    
                result.append(pipeline_dict)
            
            return result
        except Exception as e:
            logger.error(f"Error listing transform pipelines: {str(e)}")
            return [{"error": str(e)}]


class GetTransformPipelineTool(Tool):
    """Tool for getting details of a transformation pipeline."""
    
    def __init__(self, transform_registry: TransformRegistry):
        """
        Initialize the tool.
        
        Args:
            transform_registry: Registry for managing transformation pipelines
        """
        super().__init__(
            name="get_transform_pipeline",
            schema=ToolSchema(
                description="Get details of a transformation pipeline",
                parameters={
                    "pipeline_id": {
                        "description": "ID of the pipeline",
                        "type": "string"
                    }
                },
                returns={
                    "description": "Pipeline details",
                    "type": "object"
                }
            )
        )
        self.transform_registry = transform_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            pipeline_id = parameters.get("pipeline_id")
            
            if not pipeline_id:
                return {"error": "Pipeline ID is required"}
            
            # Get pipeline
            pipeline = await self.transform_registry.get_pipeline(pipeline_id)
            
            if not pipeline:
                return {"error": f"Pipeline with ID {pipeline_id} not found"}
            
            # Convert to dictionary
            steps = []
            for step in pipeline.steps:
                step_dict = {
                    "name": step.config.name,
                    "operation": step.config.operation.value,
                    "enabled": step.config.enabled,
                    "description": step.config.description,
                    "is_conditional": step.config.is_conditional,
                    "condition": step.config.condition,
                    "error_behavior": step.config.error_behavior,
                    "timeout_seconds": step.config.timeout_seconds,
                    "retry_count": step.config.retry_count,
                    "config": step.config.config
                }
                steps.append(step_dict)
            
            result = {
                "id": pipeline.id,
                "name": pipeline.config.name,
                "description": pipeline.config.description,
                "input_format": pipeline.config.input_format.value,
                "output_format": pipeline.config.output_format.value,
                "steps": steps,
                "source_schema": pipeline.config.source_schema,
                "target_schema": pipeline.config.target_schema,
                "tags": pipeline.config.tags,
                "metadata": pipeline.config.metadata,
                "active": pipeline.active,
                "execution_count": pipeline.execution_count,
                "success_count": pipeline.success_count,
                "failure_count": pipeline.failure_count,
                "created_at": pipeline.created_at.isoformat(),
                "updated_at": pipeline.updated_at.isoformat()
            }
            
            if pipeline.last_execution:
                result["last_execution"] = pipeline.last_execution.isoformat()
                
            if pipeline.last_success:
                result["last_success"] = pipeline.last_success.isoformat()
                
            if pipeline.last_failure:
                result["last_failure"] = pipeline.last_failure.isoformat()
            
            return result
        except Exception as e:
            logger.error(f"Error getting transform pipeline: {str(e)}")
            return {"error": str(e)}


class ExecuteTransformPipelineTool(Tool):
    """Tool for executing a transformation pipeline."""
    
    def __init__(self, transform_registry: TransformRegistry):
        """
        Initialize the tool.
        
        Args:
            transform_registry: Registry for managing transformation pipelines
        """
        super().__init__(
            name="execute_transform_pipeline",
            schema=ToolSchema(
                description="Execute a transformation pipeline on input data",
                parameters={
                    "pipeline_id": {
                        "description": "ID of the pipeline to execute",
                        "type": "string"
                    },
                    "data": {
                        "description": "Input data to transform",
                        "type": ["object", "array", "string"]
                    },
                    "timeout_seconds": {
                        "description": "Timeout in seconds",
                        "type": "integer"
                    }
                },
                returns={
                    "description": "Result of pipeline execution",
                    "type": "object",
                    "properties": {
                        "success": {"type": "boolean"},
                        "data": {"type": ["object", "array", "string"]},
                        "execution_time_ms": {"type": "number"},
                        "error_message": {"type": "string"}
                    }
                }
            )
        )
        self.transform_registry = transform_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            pipeline_id = parameters.get("pipeline_id")
            data = parameters.get("data")
            timeout_seconds = parameters.get("timeout_seconds")
            
            if not pipeline_id:
                return {"error": "Pipeline ID is required"}
                
            if data is None:
                return {"error": "Input data is required"}
            
            # Execute pipeline
            result = await self.transform_registry.execute_pipeline(
                pipeline_id,
                data,
                timeout_seconds
            )
            
            if not result:
                return {"error": f"Pipeline with ID {pipeline_id} not found"}
            
            # Create result dictionary
            return {
                "success": result.success,
                "data": result.data,
                "execution_time_ms": result.execution_time_ms,
                "error_message": result.error_message
            }
        except Exception as e:
            logger.error(f"Error executing transform pipeline: {str(e)}")
            return {"error": str(e)}


# Create transform registry
transform_registry = TransformRegistry()

# Define list of transform tools
transform_tools = [
    CreateTransformPipelineTool(transform_registry),
    DeleteTransformPipelineTool(transform_registry),
    ListTransformPipelinesTool(transform_registry),
    GetTransformPipelineTool(transform_registry),
    ExecuteTransformPipelineTool(transform_registry)
] 