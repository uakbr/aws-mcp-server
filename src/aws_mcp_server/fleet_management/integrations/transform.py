"""
Data Transformation Pipeline for AWS Fleet Management.

This module provides capabilities for transforming data between
different formats and schemas for integration purposes.
"""

import json
import logging
import asyncio
import importlib
import inspect
from enum import Enum
from typing import Dict, List, Any, Optional, Union, Callable, Type, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class DataFormat(Enum):
    """Supported data formats for transformation."""
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    YAML = "yaml"
    AVRO = "avro"
    PARQUET = "parquet"
    PROTOBUF = "protobuf"
    BINARY = "binary"
    TEXT = "text"
    CUSTOM = "custom"


class TransformOperation(Enum):
    """Types of transform operations."""
    MAP = "map"
    FILTER = "filter"
    AGGREGATE = "aggregate"
    SPLIT = "split"
    JOIN = "join"
    ENRICH = "enrich"
    VALIDATE = "validate"
    FORMAT_CONVERT = "format_convert"
    CUSTOM = "custom"


@dataclass
class TransformStepConfig:
    """Configuration for a transformation step."""
    name: str
    operation: TransformOperation
    config: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    description: str = ""
    is_conditional: bool = False
    condition: Optional[str] = None
    error_behavior: str = "fail"  # fail, skip, continue
    timeout_seconds: int = 30
    retry_count: int = 0


@dataclass
class TransformPipelineConfig:
    """Configuration for a transformation pipeline."""
    name: str
    description: str
    steps: List[TransformStepConfig] = field(default_factory=list)
    input_format: DataFormat = DataFormat.JSON
    output_format: DataFormat = DataFormat.JSON
    source_schema: Optional[Dict[str, Any]] = None
    target_schema: Optional[Dict[str, Any]] = None
    enabled: bool = True
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TransformContext:
    """Context for transformation execution."""
    data: Any
    pipeline: 'TransformPipeline'
    step: Optional[TransformStepConfig] = None
    step_index: int = -1
    started_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class TransformResult:
    """Result of a transformation."""
    success: bool
    data: Any
    context: TransformContext
    error_message: Optional[str] = None
    execution_time_ms: float = 0


class TransformStep:
    """
    Base class for transformation steps.
    
    This class defines the interface for transformation steps that
    process and transform data within a pipeline.
    """
    
    def __init__(self, config: TransformStepConfig):
        """
        Initialize the transformation step.
        
        Args:
            config: Step configuration
        """
        self.config = config
    
    async def execute(self, context: TransformContext) -> TransformResult:
        """
        Execute the transformation step.
        
        Args:
            context: Transformation context
            
        Returns:
            Result of the transformation
        """
        # Default implementation does nothing
        return TransformResult(
            success=True,
            data=context.data,
            context=context
        )
    
    async def validate(self, data: Any) -> bool:
        """
        Validate the input data for this step.
        
        Args:
            data: Input data to validate
            
        Returns:
            True if data is valid, False otherwise
        """
        # Default implementation accepts any data
        return True


class TransformPipeline:
    """
    Transformation pipeline for processing data.
    
    This class manages a sequence of transformation steps that process
    data in a defined order, with support for conditional execution,
    error handling, and timeouts.
    """
    
    def __init__(self, config: TransformPipelineConfig, steps: Optional[List[TransformStep]] = None):
        """
        Initialize the transformation pipeline.
        
        Args:
            config: Pipeline configuration
            steps: Optional list of transformation steps
        """
        self.config = config
        self.steps = steps or []
        self.id = f"{config.name.lower().replace(' ', '_')}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.execution_count = 0
        self.success_count = 0
        self.failure_count = 0
        self.last_execution: Optional[datetime] = None
        self.last_success: Optional[datetime] = None
        self.last_failure: Optional[datetime] = None
        self.active = self.config.enabled
    
    async def execute(self, data: Any, timeout_seconds: Optional[int] = None) -> TransformResult:
        """
        Execute the transformation pipeline on the given data.
        
        Args:
            data: Input data to transform
            timeout_seconds: Optional timeout in seconds
            
        Returns:
            Result of the transformation
        """
        self.execution_count += 1
        self.last_execution = datetime.utcnow()
        
        # Create context
        context = TransformContext(
            data=data,
            pipeline=self
        )
        
        # Validate input format
        if not await self._validate_input(data):
            self.failure_count += 1
            self.last_failure = datetime.utcnow()
            
            return TransformResult(
                success=False,
                data=data,
                context=context,
                error_message="Invalid input format"
            )
        
        # Set up timeout
        timeout = timeout_seconds or sum(step.config.timeout_seconds for step in self.steps)
        
        # Execute pipeline
        try:
            start_time = datetime.utcnow()
            
            # Execute steps with timeout
            result = await asyncio.wait_for(self._execute_steps(context), timeout)
            
            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            # Update metrics
            if result.success:
                self.success_count += 1
                self.last_success = datetime.utcnow()
            else:
                self.failure_count += 1
                self.last_failure = datetime.utcnow()
            
            # Set execution time
            result.execution_time_ms = execution_time
            
            return result
        except asyncio.TimeoutError:
            self.failure_count += 1
            self.last_failure = datetime.utcnow()
            
            return TransformResult(
                success=False,
                data=data,
                context=context,
                error_message=f"Pipeline execution timed out after {timeout} seconds"
            )
        except Exception as e:
            self.failure_count += 1
            self.last_failure = datetime.utcnow()
            
            logger.error(f"Unexpected error executing pipeline {self.id}: {str(e)}")
            
            return TransformResult(
                success=False,
                data=data,
                context=context,
                error_message=f"Unexpected error: {str(e)}"
            )
    
    async def _execute_steps(self, context: TransformContext) -> TransformResult:
        """
        Execute all steps in the pipeline.
        
        Args:
            context: Transformation context
            
        Returns:
            Result of the transformation
        """
        # Execute each step
        for i, step in enumerate(self.steps):
            # Skip disabled steps
            if not step.config.enabled:
                continue
                
            # Check condition if this is a conditional step
            if step.config.is_conditional and step.config.condition:
                condition_result = await self._evaluate_condition(step.config.condition, context)
                if not condition_result:
                    logger.debug(f"Skipping step {step.config.name} due to condition")
                    continue
            
            # Update context for this step
            context.step = step.config
            context.step_index = i
            
            # Execute step with retries
            result = await self._execute_step_with_retry(step, context)
            
            # Handle errors
            if not result.success:
                # Update failure metrics
                self.failure_count += 1
                self.last_failure = datetime.utcnow()
                
                error_behavior = step.config.error_behavior.lower()
                
                if error_behavior == "fail":
                    # Fail pipeline
                    return result
                elif error_behavior == "skip":
                    # Skip this step but continue with original data
                    context.errors.append(result.error_message or "Unknown error")
                    continue
                elif error_behavior == "continue":
                    # Continue with the result data despite error
                    context.errors.append(result.error_message or "Unknown error")
                    context.data = result.data
                    continue
            else:
                # Update context with result data
                context.data = result.data
        
        # All steps completed successfully
        return TransformResult(
            success=len(context.errors) == 0,
            data=context.data,
            context=context,
            error_message=context.errors[0] if context.errors else None
        )
    
    async def _execute_step_with_retry(self, step: TransformStep, context: TransformContext) -> TransformResult:
        """
        Execute a step with retry logic.
        
        Args:
            step: Step to execute
            context: Transformation context
            
        Returns:
            Result of the step execution
        """
        max_attempts = step.config.retry_count + 1
        attempt = 0
        
        while attempt < max_attempts:
            attempt += 1
            
            try:
                # Execute step with timeout
                return await asyncio.wait_for(
                    step.execute(context),
                    step.config.timeout_seconds
                )
            except asyncio.TimeoutError:
                if attempt < max_attempts:
                    logger.warning(f"Step {step.config.name} timed out, retrying ({attempt}/{max_attempts})")
                    continue
                else:
                    return TransformResult(
                        success=False,
                        data=context.data,
                        context=context,
                        error_message=f"Step timed out after {step.config.timeout_seconds} seconds"
                    )
            except Exception as e:
                if attempt < max_attempts:
                    logger.warning(f"Step {step.config.name} failed with error: {str(e)}, retrying ({attempt}/{max_attempts})")
                    continue
                else:
                    return TransformResult(
                        success=False,
                        data=context.data,
                        context=context,
                        error_message=f"Step failed with error: {str(e)}"
                    )
    
    async def _validate_input(self, data: Any) -> bool:
        """
        Validate the input data format.
        
        Args:
            data: Input data to validate
            
        Returns:
            True if data format is valid, False otherwise
        """
        input_format = self.config.input_format
        
        if input_format == DataFormat.JSON:
            if isinstance(data, dict) or isinstance(data, list):
                return True
            elif isinstance(data, str):
                try:
                    json.loads(data)
                    return True
                except json.JSONDecodeError:
                    return False
            else:
                return False
        elif input_format == DataFormat.XML:
            # Basic XML validation
            if isinstance(data, str) and data.strip().startswith("<?xml"):
                return True
            else:
                return False
        elif input_format == DataFormat.CSV:
            # Basic CSV validation
            if isinstance(data, str) and "," in data:
                return True
            elif isinstance(data, list) and all(isinstance(row, list) for row in data):
                return True
            else:
                return False
        elif input_format == DataFormat.TEXT:
            return isinstance(data, str)
        elif input_format == DataFormat.BINARY:
            return isinstance(data, bytes)
        else:
            # For other formats, assume valid
            return True
    
    async def _evaluate_condition(self, condition: str, context: TransformContext) -> bool:
        """
        Evaluate a condition string.
        
        Args:
            condition: Condition to evaluate
            context: Transformation context
            
        Returns:
            True if condition is met, False otherwise
        """
        try:
            # Create a safe evaluation environment
            env = {
                "data": context.data,
                "metadata": context.metadata,
                "errors": context.errors,
                "step_index": context.step_index,
                "datetime": datetime,
                "len": len,
                "str": str,
                "int": int,
                "float": float,
                "bool": bool,
                "list": list,
                "dict": dict,
                "isinstance": isinstance,
            }
            
            # Evaluate the condition
            return bool(eval(condition, {"__builtins__": {}}, env))
        except Exception as e:
            logger.error(f"Error evaluating condition '{condition}': {str(e)}")
            return False


class MapStep(TransformStep):
    """
    Transformation step that maps data from one schema to another.
    
    This step applies a mapping function to transform the input data
    according to defined field mappings.
    """
    
    async def execute(self, context: TransformContext) -> TransformResult:
        """
        Execute the mapping transformation.
        
        Args:
            context: Transformation context
            
        Returns:
            Result of the transformation
        """
        try:
            # Get mapping configuration
            field_mappings = self.config.config.get("mappings", {})
            default_values = self.config.config.get("defaults", {})
            
            # Get input data
            input_data = context.data
            
            # Create output data structure
            if isinstance(input_data, list):
                # Map each item in the list
                output_data = []
                for item in input_data:
                    mapped_item = await self._map_item(item, field_mappings, default_values)
                    output_data.append(mapped_item)
            else:
                # Map single item
                output_data = await self._map_item(input_data, field_mappings, default_values)
            
            return TransformResult(
                success=True,
                data=output_data,
                context=context
            )
        except Exception as e:
            logger.error(f"Error in map step: {str(e)}")
            return TransformResult(
                success=False,
                data=context.data,
                context=context,
                error_message=f"Mapping error: {str(e)}"
            )
    
    async def _map_item(self, item: Dict[str, Any], mappings: Dict[str, str], defaults: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map a single data item.
        
        Args:
            item: Item to map
            mappings: Field mappings
            defaults: Default values
            
        Returns:
            Mapped item
        """
        result = {}
        
        # Apply field mappings
        for target_field, source_expr in mappings.items():
            try:
                # Simple field mapping
                if "." not in source_expr and "[" not in source_expr:
                    result[target_field] = item.get(source_expr, defaults.get(target_field))
                else:
                    # Nested field access
                    value = await self._resolve_path(item, source_expr)
                    if value is None and target_field in defaults:
                        value = defaults[target_field]
                    result[target_field] = value
            except Exception as e:
                logger.warning(f"Error mapping field '{target_field}': {str(e)}")
                if target_field in defaults:
                    result[target_field] = defaults[target_field]
        
        return result
    
    async def _resolve_path(self, data: Dict[str, Any], path: str) -> Any:
        """
        Resolve a path expression to get a value from nested data.
        
        Args:
            data: Data to get value from
            path: Path expression (e.g., "user.address.city" or "items[0].name")
            
        Returns:
            Value at the specified path, or None if not found
        """
        current = data
        parts = path.replace("][", "].[").split(".")
        
        for part in parts:
            if not current:
                return None
                
            # Handle array indexing
            if "[" in part and part.endswith("]"):
                field_name, index_str = part.split("[", 1)
                index = int(index_str[:-1])  # Remove closing bracket
                
                if field_name:
                    # Get the array field first
                    if field_name not in current:
                        return None
                    array_field = current[field_name]
                else:
                    # Direct array indexing
                    array_field = current
                
                # Check if it's actually an array
                if not isinstance(array_field, list):
                    return None
                    
                # Check if index is valid
                if index < 0 or index >= len(array_field):
                    return None
                    
                current = array_field[index]
            else:
                # Simple field access
                if part not in current:
                    return None
                current = current[part]
        
        return current


class FilterStep(TransformStep):
    """
    Transformation step that filters data based on criteria.
    
    This step applies filtering criteria to include or exclude elements
    from the input data.
    """
    
    async def execute(self, context: TransformContext) -> TransformResult:
        """
        Execute the filtering transformation.
        
        Args:
            context: Transformation context
            
        Returns:
            Result of the transformation
        """
        try:
            # Get filter configuration
            include_condition = self.config.config.get("include_condition")
            exclude_condition = self.config.config.get("exclude_condition")
            filter_fields = self.config.config.get("fields", [])
            
            # Get input data
            input_data = context.data
            
            # Apply filtering
            if isinstance(input_data, list):
                # Filter a list of items
                output_data = []
                for item in input_data:
                    should_include = await self._check_include(item, include_condition, exclude_condition)
                    if should_include:
                        # Apply field filtering if needed
                        filtered_item = await self._filter_fields(item, filter_fields)
                        output_data.append(filtered_item)
            else:
                # Filter a single item (fields only)
                should_include = await self._check_include(input_data, include_condition, exclude_condition)
                if should_include:
                    output_data = await self._filter_fields(input_data, filter_fields)
                else:
                    output_data = {}
            
            return TransformResult(
                success=True,
                data=output_data,
                context=context
            )
        except Exception as e:
            logger.error(f"Error in filter step: {str(e)}")
            return TransformResult(
                success=False,
                data=context.data,
                context=context,
                error_message=f"Filtering error: {str(e)}"
            )
    
    async def _check_include(self, item: Dict[str, Any], include_condition: Optional[str], exclude_condition: Optional[str]) -> bool:
        """
        Check if an item should be included based on conditions.
        
        Args:
            item: Item to check
            include_condition: Condition for inclusion
            exclude_condition: Condition for exclusion
            
        Returns:
            True if item should be included, False otherwise
        """
        # Default to include if no conditions specified
        if not include_condition and not exclude_condition:
            return True
            
        # Create evaluation environment
        env = {
            "item": item,
            "datetime": datetime,
            "len": len,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "list": list,
            "dict": dict,
            "isinstance": isinstance,
        }
        
        # Check exclude condition first
        if exclude_condition:
            try:
                exclude_result = bool(eval(exclude_condition, {"__builtins__": {}}, env))
                if exclude_result:
                    return False
            except Exception as e:
                logger.warning(f"Error evaluating exclude condition: {str(e)}")
        
        # Check include condition
        if include_condition:
            try:
                return bool(eval(include_condition, {"__builtins__": {}}, env))
            except Exception as e:
                logger.warning(f"Error evaluating include condition: {str(e)}")
                return False
        
        # Include by default if only exclude condition was specified and it wasn't met
        return True
    
    async def _filter_fields(self, item: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """
        Extract only specified fields from the data.
        
        Args:
            item: Data item to filter
            fields: List of field names to keep
            
        Returns:
            Filtered data containing only specified fields
        """
        # If no fields specified, return the original item
        if not fields:
            return item
            
        # Create a new item with only the specified fields
        result = {}
        for field_name in fields:
            if field_name in item:
                result[field_name] = item[field_name]
        
        return result


class FormatConvertStep(TransformStep):
    """
    Transformation step that converts data between formats.
    
    This step converts data from one format to another, such as
    JSON to XML, CSV to JSON, etc.
    """
    
    async def execute(self, context: TransformContext) -> TransformResult:
        """
        Execute the format conversion.
        
        Args:
            context: Transformation context
            
        Returns:
            Result of the transformation
        """
        try:
            # Get conversion configuration
            source_format = DataFormat(self.config.config.get("source_format", "json"))
            target_format = DataFormat(self.config.config.get("target_format", "json"))
            config = self.config.config.get("conversion_config", {})
            
            # Get input data
            input_data = context.data
            
            # Convert format
            if source_format == target_format:
                # No conversion needed
                return TransformResult(
                    success=True,
                    data=input_data,
                    context=context
                )
            
            if source_format == DataFormat.JSON and target_format == DataFormat.XML:
                output_data = await self._json_to_xml(input_data, config)
            elif source_format == DataFormat.XML and target_format == DataFormat.JSON:
                output_data = await self._xml_to_json(input_data, config)
            elif source_format == DataFormat.JSON and target_format == DataFormat.CSV:
                output_data = await self._json_to_csv(input_data, config)
            elif source_format == DataFormat.CSV and target_format == DataFormat.JSON:
                output_data = await self._csv_to_json(input_data, config)
            elif source_format == DataFormat.JSON and target_format == DataFormat.TEXT:
                output_data = json.dumps(input_data)
            elif source_format == DataFormat.TEXT and target_format == DataFormat.JSON:
                output_data = json.loads(input_data)
            else:
                raise ValueError(f"Unsupported format conversion: {source_format.value} to {target_format.value}")
            
            return TransformResult(
                success=True,
                data=output_data,
                context=context
            )
        except Exception as e:
            logger.error(f"Error in format conversion step: {str(e)}")
            return TransformResult(
                success=False,
                data=context.data,
                context=context,
                error_message=f"Format conversion error: {str(e)}"
            )
    
    async def _json_to_xml(self, data: Any, config: Dict[str, Any]) -> str:
        """
        Convert JSON to XML.
        
        Args:
            data: JSON data to convert
            config: Conversion configuration
            
        Returns:
            XML string
        """
        root_element = config.get("root_element", "root")
        item_element = config.get("item_element", "item")
        
        # Simple XML conversion (for more complex needs, use a specialized library)
        xml_parts = [f'<?xml version="1.0" encoding="UTF-8"?>\n<{root_element}>']
        
        if isinstance(data, list):
            for item in data:
                xml_parts.append(f"<{item_element}>")
                xml_parts.append(await self._dict_to_xml(item))
                xml_parts.append(f"</{item_element}>")
        else:
            xml_parts.append(await self._dict_to_xml(data))
        
        xml_parts.append(f"</{root_element}>")
        
        return "\n".join(xml_parts)
    
    async def _dict_to_xml(self, data: Dict[str, Any]) -> str:
        """
        Convert a dictionary to XML elements.
        
        Args:
            data: Dictionary to convert
            
        Returns:
            XML elements as string
        """
        xml_parts = []
        
        for key, value in data.items():
            if isinstance(value, dict):
                xml_parts.append(f"<{key}>")
                xml_parts.append(await self._dict_to_xml(value))
                xml_parts.append(f"</{key}>")
            elif isinstance(value, list):
                xml_parts.append(f"<{key}>")
                for item in value:
                    if isinstance(item, dict):
                        xml_parts.append("<item>")
                        xml_parts.append(await self._dict_to_xml(item))
                        xml_parts.append("</item>")
                    else:
                        xml_parts.append(f"<item>{self._escape_xml(str(item))}</item>")
                xml_parts.append(f"</{key}>")
            else:
                xml_parts.append(f"<{key}>{self._escape_xml(str(value))}</{key}>")
        
        return "\n".join(xml_parts)
    
    def _escape_xml(self, text: str) -> str:
        """
        Escape special characters in XML.
        
        Args:
            text: Text to escape
            
        Returns:
            Escaped text
        """
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;")
    
    async def _xml_to_json(self, data: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert XML to JSON.
        
        Args:
            data: XML string to convert
            config: Conversion configuration
            
        Returns:
            JSON data
        """
        # Import xml.etree.ElementTree here to avoid dependency on entire module
        import xml.etree.ElementTree as ET
        
        # Parse XML
        root = ET.fromstring(data)
        
        # Convert to JSON
        return await self._element_to_dict(root)
    
    async def _element_to_dict(self, element) -> Dict[str, Any]:
        """
        Convert an XML element to a dictionary.
        
        Args:
            element: XML element
            
        Returns:
            Dictionary representation
        """
        result = {}
        
        # Add attributes
        for key, value in element.attrib.items():
            result[f"@{key}"] = value
        
        # Add children
        for child in element:
            child_dict = await self._element_to_dict(child)
            
            if child.tag in result:
                # If this tag already exists, convert to list or append to existing list
                if isinstance(result[child.tag], list):
                    result[child.tag].append(child_dict)
                else:
                    result[child.tag] = [result[child.tag], child_dict]
            else:
                result[child.tag] = child_dict
        
        # Add text content
        text = element.text
        if text is not None and text.strip():
            if len(result) > 0:
                result["#text"] = text.strip()
            else:
                return text.strip()
        
        return result
    
    async def _json_to_csv(self, data: Any, config: Dict[str, Any]) -> str:
        """
        Convert JSON to CSV.
        
        Args:
            data: JSON data to convert
            config: Conversion configuration
            
        Returns:
            CSV string
        """
        # Handle different input formats
        if not isinstance(data, list):
            if isinstance(data, dict):
                data = [data]
            else:
                raise ValueError("Cannot convert to CSV: Input data must be a list or dict")
        
        if not data:
            return ""
            
        # Get field names
        fields = config.get("fields")
        if not fields:
            # Determine fields from first item
            fields = list(data[0].keys())
        
        # Generate CSV
        csv_rows = [",".join(fields)]
        
        for item in data:
            row_values = []
            for field_name in fields:
                value = item.get(field_name, "")
                # Escape commas and quotes
                if isinstance(value, str):
                    if "," in value or "\"" in value:
                        value = f"\"{value.replace('\"', '\"\"')}\""
                row_values.append(str(value))
            csv_rows.append(",".join(row_values))
        
        return "\n".join(csv_rows)
    
    async def _csv_to_json(self, data: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert CSV to JSON.
        
        Args:
            data: CSV string to convert
            config: Conversion configuration
            
        Returns:
            JSON data as list of dictionaries
        """
        # Split into rows
        rows = data.strip().split("\n")
        if not rows:
            return []
            
        # Get headers
        headers = config.get("headers")
        if not headers:
            # Use first row as headers
            header_row = rows[0]
            headers = await self._parse_csv_row(header_row)
            data_rows = rows[1:]
        else:
            data_rows = rows
        
        # Parse rows
        result = []
        for row in data_rows:
            if not row.strip():
                continue
                
            values = await self._parse_csv_row(row)
            item = {}
            
            for i, value in enumerate(values):
                if i < len(headers):
                    item[headers[i]] = value
            
            result.append(item)
        
        return result
    
    async def _parse_csv_row(self, row: str) -> List[str]:
        """
        Parse a CSV row into values.
        
        Args:
            row: CSV row to parse
            
        Returns:
            List of values
        """
        # Simple CSV parsing (for more complex needs, use csv module)
        values = []
        current_value = ""
        in_quotes = False
        
        for char in row:
            if char == "\"":
                # Handle quotes
                if in_quotes and len(current_value) > 0 and current_value[-1] == "\"":
                    # Escaped quote
                    current_value = current_value[:-1] + "\""
                else:
                    # Start or end quote
                    in_quotes = not in_quotes
            elif char == "," and not in_quotes:
                # End of value
                values.append(current_value)
                current_value = ""
            else:
                current_value += char
        
        # Add last value
        values.append(current_value)
        
        return values


class TransformRegistry:
    """
    Registry for transformation pipelines.
    
    This class handles registration, lookup, and execution of
    transformation pipelines.
    """
    
    def __init__(self, data_dir: Optional[str] = None):
        """
        Initialize the transform registry.
        
        Args:
            data_dir: Optional directory for persisting pipeline data
        """
        self.pipelines: Dict[str, TransformPipeline] = {}
        self.data_dir = Path(data_dir) if data_dir else None
        
        # Register standard step types
        self.step_types: Dict[TransformOperation, Type[TransformStep]] = {
            TransformOperation.MAP: MapStep,
            TransformOperation.FILTER: FilterStep,
            TransformOperation.FORMAT_CONVERT: FormatConvertStep,
            # Add more built-in step types here
        }
    
    async def initialize(self) -> None:
        """Initialize the registry and load existing pipelines."""
        logger.info("Initializing transform registry")
        
        if self.data_dir:
            self.data_dir.mkdir(exist_ok=True, parents=True)
            await self._load_pipelines()
    
    async def register_pipeline(self, config: TransformPipelineConfig) -> str:
        """
        Register a new transformation pipeline.
        
        Args:
            config: Pipeline configuration
            
        Returns:
            ID of the registered pipeline
            
        Raises:
            ValueError: If a pipeline with the same name already exists
        """
        # Check if pipeline with the same name already exists
        for pipeline in self.pipelines.values():
            if pipeline.config.name == config.name:
                raise ValueError(f"Pipeline with name '{config.name}' already exists")
        
        # Create steps
        steps = []
        for step_config in config.steps:
            step_type = self.step_types.get(step_config.operation)
            if not step_type:
                logger.warning(f"Unsupported transform operation: {step_config.operation.value}, using default implementation")
                step_type = TransformStep
            
            steps.append(step_type(step_config))
        
        # Create pipeline
        pipeline = TransformPipeline(config, steps)
        
        # Add to registry
        self.pipelines[pipeline.id] = pipeline
        
        # Save pipeline data
        if self.data_dir:
            await self._save_pipeline(pipeline)
        
        logger.info(f"Registered transform pipeline: {config.name} ({pipeline.id})")
        return pipeline.id
    
    async def get_pipeline(self, pipeline_id: str) -> Optional[TransformPipeline]:
        """
        Get a transformation pipeline by ID.
        
        Args:
            pipeline_id: ID of the pipeline to get
            
        Returns:
            Pipeline if found, None otherwise
        """
        return self.pipelines.get(pipeline_id)
    
    async def get_pipelines(self) -> List[TransformPipeline]:
        """
        Get all registered transformation pipelines.
        
        Returns:
            List of pipelines
        """
        return list(self.pipelines.values())
    
    async def delete_pipeline(self, pipeline_id: str) -> bool:
        """
        Delete a transformation pipeline.
        
        Args:
            pipeline_id: ID of the pipeline to delete
            
        Returns:
            True if successful, False if pipeline not found
        """
        if pipeline_id not in self.pipelines:
            return False
        
        # Remove from registry
        del self.pipelines[pipeline_id]
        
        # Delete pipeline data
        if self.data_dir:
            data_file = self.data_dir / f"{pipeline_id}.json"
            if data_file.exists():
                data_file.unlink()
        
        logger.info(f"Deleted transform pipeline: {pipeline_id}")
        return True
    
    async def execute_pipeline(self, pipeline_id: str, data: Any) -> Optional[TransformResult]:
        """
        Execute a transformation pipeline.
        
        Args:
            pipeline_id: ID of the pipeline to execute
            data: Input data for the transformation
            
        Returns:
            Result of the transformation if successful, None if pipeline not found
        """
        pipeline = await self.get_pipeline(pipeline_id)
        if not pipeline:
            return None
        
        result = await pipeline.execute(data)
        
        # Save updated pipeline data
        if self.data_dir:
            await self._save_pipeline(pipeline)
        
        return result
    
    async def register_step_type(self, operation: TransformOperation, step_class: Type[TransformStep]) -> None:
        """
        Register a custom step type.
        
        Args:
            operation: Operation type
            step_class: Step implementation class
            
        Raises:
            ValueError: If the step class is not a subclass of TransformStep
        """
        if not issubclass(step_class, TransformStep):
            raise ValueError(f"Step class must be a subclass of TransformStep: {step_class.__name__}")
        
        self.step_types[operation] = step_class
        logger.info(f"Registered transform step type: {operation.value} -> {step_class.__name__}")
    
    async def _load_pipelines(self) -> None:
        """Load pipelines from the data directory."""
        if not self.data_dir or not self.data_dir.exists():
            return
        
        for data_file in self.data_dir.glob("*.json"):
            try:
                with open(data_file, "r") as f:
                    pipeline_data = json.load(f)
                
                # Load pipeline
                pipeline_config = await self._create_pipeline_config(pipeline_data.get("config", {}))
                
                # Create steps
                steps = []
                for step_data in pipeline_data.get("steps", []):
                    step_config = await self._create_step_config(step_data)
                    
                    step_type = self.step_types.get(step_config.operation)
                    if not step_type:
                        step_type = TransformStep
                    
                    steps.append(step_type(step_config))
                
                # Create pipeline
                pipeline = TransformPipeline(pipeline_config, steps)
                
                # Set pipeline properties
                pipeline.id = pipeline_data.get("id", pipeline.id)
                pipeline.created_at = datetime.fromisoformat(pipeline_data.get("created_at", pipeline.created_at.isoformat()))
                pipeline.updated_at = datetime.fromisoformat(pipeline_data.get("updated_at", pipeline.updated_at.isoformat()))
                pipeline.execution_count = pipeline_data.get("execution_count", 0)
                pipeline.success_count = pipeline_data.get("success_count", 0)
                pipeline.failure_count = pipeline_data.get("failure_count", 0)
                
                if pipeline_data.get("last_execution"):
                    pipeline.last_execution = datetime.fromisoformat(pipeline_data["last_execution"])
                
                if pipeline_data.get("last_success"):
                    pipeline.last_success = datetime.fromisoformat(pipeline_data["last_success"])
                
                if pipeline_data.get("last_failure"):
                    pipeline.last_failure = datetime.fromisoformat(pipeline_data["last_failure"])
                
                pipeline.active = pipeline_data.get("active", True)
                
                # Add to registry
                self.pipelines[pipeline.id] = pipeline
                logger.info(f"Loaded transform pipeline: {pipeline.config.name} ({pipeline.id})")
            except Exception as e:
                logger.error(f"Error loading transform pipeline from {data_file}: {str(e)}")
    
    async def _save_pipelines(self) -> None:
        """Save all pipelines to the data directory."""
        if not self.data_dir:
            return
        
        self.data_dir.mkdir(exist_ok=True, parents=True)
        
        for pipeline in self.pipelines.values():
            await self._save_pipeline(pipeline)
    
    async def _save_pipeline(self, pipeline: TransformPipeline) -> None:
        """
        Save a pipeline to the data directory.
        
        Args:
            pipeline: Pipeline to save
        """
        if not self.data_dir:
            return
        
        self.data_dir.mkdir(exist_ok=True, parents=True)
        
        try:
            # Convert pipeline config to dictionary
            config_dict = {
                "name": pipeline.config.name,
                "description": pipeline.config.description,
                "input_format": pipeline.config.input_format.value,
                "output_format": pipeline.config.output_format.value,
                "source_schema": pipeline.config.source_schema,
                "target_schema": pipeline.config.target_schema,
                "enabled": pipeline.config.enabled,
                "tags": pipeline.config.tags,
                "metadata": pipeline.config.metadata
            }
            
            # Convert steps to dictionaries
            steps_dict = []
            for step in pipeline.steps:
                steps_dict.append({
                    "name": step.config.name,
                    "operation": step.config.operation.value,
                    "config": step.config.config,
                    "enabled": step.config.enabled,
                    "description": step.config.description,
                    "is_conditional": step.config.is_conditional,
                    "condition": step.config.condition,
                    "error_behavior": step.config.error_behavior,
                    "timeout_seconds": step.config.timeout_seconds,
                    "retry_count": step.config.retry_count
                })
            
            # Create pipeline data
            pipeline_data = {
                "id": pipeline.id,
                "config": config_dict,
                "steps": steps_dict,
                "created_at": pipeline.created_at.isoformat(),
                "updated_at": pipeline.updated_at.isoformat(),
                "execution_count": pipeline.execution_count,
                "success_count": pipeline.success_count,
                "failure_count": pipeline.failure_count,
                "active": pipeline.active
            }
            
            if pipeline.last_execution:
                pipeline_data["last_execution"] = pipeline.last_execution.isoformat()
            
            if pipeline.last_success:
                pipeline_data["last_success"] = pipeline.last_success.isoformat()
            
            if pipeline.last_failure:
                pipeline_data["last_failure"] = pipeline.last_failure.isoformat()
            
            # Save to file
            with open(self.data_dir / f"{pipeline.id}.json", "w") as f:
                json.dump(pipeline_data, f, indent=2)
            
            logger.debug(f"Saved transform pipeline: {pipeline.id}")
        except Exception as e:
            logger.error(f"Error saving transform pipeline {pipeline.id}: {str(e)}")
    
    async def _create_pipeline_config(self, config_data: Dict[str, Any]) -> TransformPipelineConfig:
        """
        Create a pipeline configuration from data.
        
        Args:
            config_data: Configuration data
            
        Returns:
            TransformPipelineConfig instance
        """
        try:
            input_format = DataFormat(config_data.get("input_format", "json"))
        except ValueError:
            logger.warning(f"Invalid input format: {config_data.get('input_format')}, using JSON")
            input_format = DataFormat.JSON
        
        try:
            output_format = DataFormat(config_data.get("output_format", "json"))
        except ValueError:
            logger.warning(f"Invalid output format: {config_data.get('output_format')}, using JSON")
            output_format = DataFormat.JSON
        
        return TransformPipelineConfig(
            name=config_data.get("name", "unnamed"),
            description=config_data.get("description", ""),
            steps=[],  # Will be populated separately
            input_format=input_format,
            output_format=output_format,
            source_schema=config_data.get("source_schema"),
            target_schema=config_data.get("target_schema"),
            enabled=config_data.get("enabled", True),
            tags=config_data.get("tags", {}),
            metadata=config_data.get("metadata", {})
        )
    
    async def _create_step_config(self, step_data: Dict[str, Any]) -> TransformStepConfig:
        """
        Create a step configuration from data.
        
        Args:
            step_data: Step data
            
        Returns:
            TransformStepConfig instance
        """
        try:
            operation = TransformOperation(step_data.get("operation", "custom"))
        except ValueError:
            logger.warning(f"Invalid transform operation: {step_data.get('operation')}, using CUSTOM")
            operation = TransformOperation.CUSTOM
        
        return TransformStepConfig(
            name=step_data.get("name", "unnamed"),
            operation=operation,
            config=step_data.get("config", {}),
            enabled=step_data.get("enabled", True),
            description=step_data.get("description", ""),
            is_conditional=step_data.get("is_conditional", False),
            condition=step_data.get("condition"),
            error_behavior=step_data.get("error_behavior", "fail"),
            timeout_seconds=step_data.get("timeout_seconds", 30),
            retry_count=step_data.get("retry_count", 0)
        )

    def filter_fields(self, item: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """
        Extract only specified fields from the data.
        
        Args:
            item: Data item to filter
            fields: List of field names to keep
            
        Returns:
            Filtered data containing only specified fields
        """
        # Create a new item with only the specified fields
        result = {}
        for field_name in fields:
            if field_name in item:
                result[field_name] = item[field_name]
        
        return result

    def convert_to_csv(self, data: List[Dict[str, Any]], fields: List[str]) -> str:
        """
        Convert data to CSV format.
        
        Args:
            data: List of data items to convert
            fields: List of field names to include in CSV
            
        Returns:
            CSV formatted string
        """
        if not data:
            return ""
        
        # Generate CSV header
        csv_lines = [",".join(fields)]
        
        # Generate rows
        for item in data:
            row_values = []
            for field_name in fields:
                value = item.get(field_name, "")
                # Escape commas and quotes
                if isinstance(value, str):
                    # Double quotes to escape quotes
                    value = value.replace('"', '""')
                    # Quote if contains comma, newline, or quotes
                    if "," in value or "\n" in value or '"' in value:
                        value = f'"{value}"'
                elif value is None:
                    value = ""
                else:
                    value = str(value)
                row_values.append(value)
            csv_lines.append(",".join(row_values))
        
        return "\n".join(csv_lines) 