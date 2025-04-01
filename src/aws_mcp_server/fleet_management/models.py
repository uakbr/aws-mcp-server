"""
Resource Data Models for AWS Fleet Management.

This module defines data models for representing AWS resources
in a standardized way for the fleet management system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
import json
import uuid


@dataclass
class ResourceTag:
    """Model representing a resource tag."""
    key: str
    value: str


@dataclass
class BaseResource:
    """Base model for all AWS resources."""
    
    # Common fields for all resources
    id: str
    name: Optional[str] = None
    resource_type: str = ""
    arn: Optional[str] = None
    region: str = ""
    account_id: str = ""
    tags: List[ResourceTag] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    state: str = ""
    
    # Metadata and dynamic properties
    metadata: Dict[str, Any] = field(default_factory=dict)
    properties: Dict[str, Any] = field(default_factory=dict)
    
    # Related resources
    related_resources: Dict[str, List[str]] = field(default_factory=dict)
    
    # Internal tracking
    _version: int = 1
    _last_discovery: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert resource to dictionary representation."""
        result = {
            "id": self.id,
            "resource_type": self.resource_type,
            "region": self.region,
            "account_id": self.account_id,
            "state": self.state,
            "_version": self._version,
        }
        
        # Add optional fields if they exist
        if self.name:
            result["name"] = self.name
        if self.arn:
            result["arn"] = self.arn
        if self.created_at:
            result["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            result["updated_at"] = self.updated_at.isoformat()
        if self._last_discovery:
            result["_last_discovery"] = self._last_discovery.isoformat()
        
        # Add collection fields
        if self.tags:
            result["tags"] = [{"key": tag.key, "value": tag.value} for tag in self.tags]
        if self.metadata:
            result["metadata"] = self.metadata
        if self.properties:
            result["properties"] = self.properties
        if self.related_resources:
            result["related_resources"] = self.related_resources
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BaseResource':
        """Create resource from dictionary representation."""
        # Handle datetime fields
        for date_field in ['created_at', 'updated_at', '_last_discovery']:
            if date_field in data and data[date_field]:
                data[date_field] = datetime.fromisoformat(data[date_field])
        
        # Handle tags
        if 'tags' in data:
            data['tags'] = [
                ResourceTag(tag['key'], tag['value']) 
                for tag in data['tags']
            ]
        
        return cls(**data)
    
    def update_from_dict(self, data: Dict[str, Any]) -> None:
        """Update resource from dictionary representation."""
        # Track version
        self._version += 1
        self._last_discovery = datetime.now()
        
        # Update fields
        for key, value in data.items():
            if key == 'tags' and value:
                self.tags = [ResourceTag(tag['key'], tag['value']) for tag in value]
            elif hasattr(self, key):
                setattr(self, key, value)


@dataclass
class EC2Instance(BaseResource):
    """Model representing an EC2 instance."""
    
    resource_type: str = "ec2:instance"
    
    # EC2-specific fields
    instance_type: str = ""
    private_ip: Optional[str] = None
    public_ip: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    security_groups: List[str] = field(default_factory=list)
    iam_role: Optional[str] = None
    availability_zone: Optional[str] = None
    root_volume_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert EC2 instance to dictionary representation."""
        result = super().to_dict()
        
        # Add EC2-specific fields
        ec2_fields = [
            'instance_type', 'private_ip', 'public_ip', 'vpc_id', 
            'subnet_id', 'iam_role', 'availability_zone', 'root_volume_id'
        ]
        
        for field in ec2_fields:
            value = getattr(self, field)
            if value:
                result[field] = value
                
        if self.security_groups:
            result['security_groups'] = self.security_groups
            
        return result


class ResourceRegistry:
    """Registry for managing resource models."""
    
    _models = {}
    _instances = {}
    
    @classmethod
    def register_model(cls, resource_type: str, model_class) -> None:
        """Register a model class for a resource type."""
        cls._models[resource_type] = model_class
    
    @classmethod
    def get_model_class(cls, resource_type: str):
        """Get the model class for a resource type."""
        if resource_type in cls._models:
            return cls._models[resource_type]
        return BaseResource
    
    @classmethod
    def create_resource(cls, resource_type: str, data: Dict[str, Any]):
        """Create a resource instance of the appropriate type."""
        model_class = cls.get_model_class(resource_type)
        resource = model_class.from_dict(data)
        
        # Store in registry
        cls._instances[resource.id] = resource
        return resource
    
    @classmethod
    def get_resource(cls, resource_id: str):
        """Get a resource by ID."""
        return cls._instances.get(resource_id)
    
    @classmethod
    def update_resource(cls, resource_id: str, data: Dict[str, Any]):
        """Update a resource by ID."""
        resource = cls.get_resource(resource_id)
        if resource:
            resource.update_from_dict(data)
            return resource
        return None
    
    @classmethod
    def get_resources_by_type(cls, resource_type: str) -> List[BaseResource]:
        """Get all resources of a specific type."""
        return [
            resource for resource in cls._instances.values()
            if resource.resource_type == resource_type
        ]


# Register models
ResourceRegistry.register_model("ec2:instance", EC2Instance) 