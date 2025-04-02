
# AWS MCP Server

## Fleet Management and Integration Framework

---

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [Core Components](#core-components)
4. [Integration Framework](#integration-framework)
   - [Integration Types](#integration-types)
   - [Configuration](#integration-configuration)
   - [Authentication](#authentication)
   - [Health Checks](#health-checks)
   - [Retry Mechanisms](#retry-mechanisms)
5. [API Layer](#api-layer)
6. [Getting Started](#getting-started)
7. [Development Guide](#development-guide)
8. [Deployment](#deployment)
9. [Advanced Topics](#advanced-topics)
10. [Troubleshooting](#troubleshooting)

---

## Introduction

AWS MCP Server is a comprehensive fleet management solution for AWS resources. It provides a centralized platform for managing resources across multiple AWS accounts, regions, and services. The server includes an extensive integration framework that allows for seamless connectivity with external systems, APIs, and data sources.

The platform is designed with a focus on:
- **Scalability**: Support for thousands of AWS resources across multiple accounts
- **Extensibility**: Pluggable integration framework
- **Resilience**: Fault-tolerant architecture with health checks and retry mechanisms
- **Security**: Comprehensive authentication and authorization
- **Observability**: Built-in monitoring and logging

---

## Architecture Overview

The AWS MCP Server follows a layered architecture pattern:

```
┌───────────────────────────────────────────────────────────────┐
│                         Presentation Layer                     │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐  │
│  │ Web Console │   │    CLI      │   │  Programmatic API   │  │
│  └─────────────┘   └─────────────┘   └─────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
                             │
┌───────────────────────────┼───────────────────────────────────┐
│                       API Layer                                │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐  │
│  │  REST API   │   │ GraphQL API │   │    WebSockets       │  │
│  └─────────────┘   └─────────────┘   └─────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
                             │
┌───────────────────────────┼───────────────────────────────────┐
│                     Service Layer                              │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐  │
│  │Resource Mgmt│   │Fleet Control│   │Integration Services │  │
│  └─────────────┘   └─────────────┘   └─────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
                             │
┌───────────────────────────┼───────────────────────────────────┐
│                    Integration Layer                           │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐  │
│  │ AWS Services│   │External APIs│   │  Data Sources       │  │
│  └─────────────┘   └─────────────┘   └─────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

### Key Architecture Principles

1. **Asynchronous Design**: The server uses Python's asyncio for non-blocking operations
2. **Domain-Driven Design**: Components are organized around business domains
3. **Configuration-Driven**: Behavior is controlled through structured configuration
4. **Stateless Services**: Where possible, services are designed to be stateless
5. **Event-Driven Communication**: Services communicate through events when appropriate

---

## Core Components

### CLI Executor (`src/aws_mcp_server/cli_executor.py`)
Provides a unified interface for executing AWS CLI commands across accounts and regions.

### Resource Registry (`src/aws_mcp_server/fleet_management/models.py`)
Manages the inventory of AWS resources, providing a centralized registry for lookup and reference.

### Integration Framework (`src/aws_mcp_server/fleet_management/integrations/integration.py`)
Provides the foundation for integrating with external systems, APIs, and data sources.

### API Server
RESTful API endpoints for controlling and monitoring the fleet and integrations.

---

## Integration Framework

The integration framework is a core component that enables the MCP Server to connect with external systems. It provides a pluggable architecture for adding new integration types.

### Integration Types

The framework supports the following integration types:

1. **WEBHOOK**: HTTP callbacks for event notifications
2. **REST_API**: Standard RESTful API integrations
3. **GRAPHQL**: GraphQL API integrations
4. **GRPC**: gRPC service integrations
5. **EVENT_BUS**: Integration with event bus systems (e.g., Kafka, RabbitMQ)
6. **MESSAGE_QUEUE**: Message queue integrations (e.g., SQS, ActiveMQ)
7. **DATABASE**: Direct database integrations
8. **FILE**: File system integrations
9. **CUSTOM**: Custom integration types for specialized needs

### Data Flow Directions

Each integration can operate in one of three directions:

1. **INBOUND**: External systems sending data to MCP Server
2. **OUTBOUND**: MCP Server sending data to external systems
3. **BIDIRECTIONAL**: Two-way communication between MCP Server and external systems

### Integration Configuration

Integrations are configured using a structured configuration model:

```python
@dataclass
class IntegrationConfig:
    name: str
    description: str
    type: IntegrationType
    direction: Direction
    version: str = "1.0.0"
    auth: AuthConfig = field(default_factory=AuthConfig)
    health_check: HealthCheckConfig = field(default_factory=HealthCheckConfig)
    retry: RetryConfig = field(default_factory=RetryConfig)
    timeout_seconds: int = 30
    rate_limit_per_minute: int = 60
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
```

### Authentication

The framework supports multiple authentication mechanisms:

1. **NONE**: No authentication
2. **API_KEY**: API key authentication
3. **BASIC**: HTTP Basic authentication
4. **BEARER_TOKEN**: Bearer token authentication
5. **OAUTH2**: OAuth 2.0 authentication
6. **OAUTH1**: OAuth 1.0a authentication
7. **AWS_SIG_V4**: AWS Signature Version 4
8. **CERTIFICATE**: Client certificate authentication
9. **CUSTOM**: Custom authentication mechanisms

### Health Checks

Integrations include configurable health checks:

```python
@dataclass
class HealthCheckConfig:
    enabled: bool = True
    interval_seconds: int = 300
    timeout_seconds: int = 30
    failure_threshold: int = 3
    success_threshold: int = 1
    endpoint: Optional[str] = None
    method: str = "GET"
    expected_status_code: int = 200
    body: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
```

Health checks are automatically executed in the background to monitor the status of integrations. The system manages:

- Regular interval-based checks
- Automatic marking of failed integrations
- Recovery detection and status updates
- Persistence of health check results

### Retry Mechanisms

The framework includes sophisticated retry handling:

```python
@dataclass
class RetryConfig:
    enabled: bool = True
    max_attempts: int = 3
    initial_backoff_seconds: float = 1.0
    max_backoff_seconds: float = 60.0
    backoff_multiplier: float = 2.0
    retry_on_status_codes: List[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])
```

Key retry features:
- Exponential backoff with jitter
- Configurable retry conditions
- Maximum attempt limits
- Status code-based retry decisions

### Integration Registry

The `IntegrationRegistry` class manages the lifecycle of integrations:

- Registration of new integrations
- Updates to existing integrations
- Deletion of integrations
- Lookup of integrations by ID, type, or status
- Persistence of integration configurations
- Automatic health check scheduling

### Integration Lifecycle

```
┌─────────────┐
│ CONFIGURING │
└──────┬──────┘
       │
       ▼
┌─────────────┐    ┌─────────────┐
│   ACTIVE    │◄───┤   TESTING   │
└──────┬──────┘    └─────────────┘
       │
       ▼
┌─────────────┐    ┌─────────────┐
│    ERROR    │◄───┤  INACTIVE   │
└──────┬──────┘    └─────────────┘
       │
       ▼
┌─────────────┐
│ DEPRECATED  │
└─────────────┘
```

---

## API Layer

The API layer provides RESTful endpoints for managing the fleet and integrations.

### Integration Management API

#### List Integrations
```
GET /api/v1/integrations
```

#### Get Integration
```
GET /api/v1/integrations/{integration_id}
```

#### Create Integration
```
POST /api/v1/integrations
```

#### Update Integration
```
PUT /api/v1/integrations/{integration_id}
```

#### Delete Integration
```
DELETE /api/v1/integrations/{integration_id}
```

#### Integration Health
```
GET /api/v1/integrations/{integration_id}/health
```

### Authentication and Authorization

The API implements:
- JWT-based authentication
- Role-based access control
- API key authentication for service-to-service communication
- Rate limiting to prevent abuse

---

## Getting Started

### Prerequisites

- Python 3.9+
- AWS CLI configured with appropriate credentials
- Access to target AWS accounts
- Docker (for containerized deployment)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/aws-mcp-server.git
cd aws-mcp-server

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e ".[dev]"
```

### Configuration

1. Create a configuration file:

```yaml
# config.yaml
aws:
  default_region: us-west-2
  
server:
  host: 0.0.0.0
  port: 8000
  
integrations:
  data_dir: /path/to/integration/data
  
logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

2. Set environment variables:

```bash
export MCP_CONFIG_PATH=/path/to/config.yaml
export AWS_PROFILE=your-profile  # Optional
```

### Running the Server

```bash
# Start the server
python -m aws_mcp_server.server

# Or with specific config file
python -m aws_mcp_server.server --config /path/to/config.yaml
```

---

## Development Guide

### Project Structure

```
aws-mcp-server/
├── src/
│   └── aws_mcp_server/
│       ├── __init__.py
│       ├── cli_executor.py
│       ├── server.py
│       ├── config.py
│       ├── fleet_management/
│       │   ├── __init__.py
│       │   ├── models.py
│       │   ├── api/
│       │   │   ├── __init__.py
│       │   │   ├── router.py
│       │   │   └── endpoints/
│       │   └── integrations/
│       │       ├── __init__.py
│       │       ├── integration.py
│       │       ├── rest.py
│       │       ├── webhook.py
│       │       └── ...
├── tests/
│   ├── __init__.py
│   ├── test_cli_executor.py
│   └── ...
├── docs/
│   ├── api.md
│   ├── integrations.md
│   └── ...
├── pyproject.toml
├── setup.py
└── README.md
```

### Adding a New Integration Type

1. Create a new module in `src/aws_mcp_server/fleet_management/integrations/`
2. Subclass the `Integration` base class
3. Implement required methods
4. Register the integration type with the registry

Example:

```python
# src/aws_mcp_server/fleet_management/integrations/custom_type.py
from .integration import Integration, IntegrationType

class CustomIntegration(Integration):
    async def initialize(self) -> bool:
        # Custom initialization logic
        return await super().initialize()
    
    async def health_check(self) -> bool:
        # Custom health check logic
        return await super().health_check()

# Register with the registry
async def register(registry):
    await registry.register_plugin_type(
        IntegrationType.CUSTOM,
        CustomIntegration
    )
```

### Testing

```bash
# Run all tests
pytest

# Run specific test module
pytest tests/test_integrations.py

# Run with coverage
pytest --cov=aws_mcp_server
```

---

## Deployment

### Docker Deployment

```bash
# Build the Docker image
docker build -t aws-mcp-server .

# Run the container
docker run -p 8000:8000 -v /path/to/config.yaml:/app/config.yaml aws-mcp-server
```

### AWS Deployment

#### EC2 Deployment

1. Launch an EC2 instance with appropriate IAM role
2. Install dependencies and copy the application
3. Configure the application
4. Start the server with systemd or a similar service manager

#### ECS Deployment

1. Create an ECS cluster
2. Create a task definition using the Docker image
3. Configure environment variables and volumes
4. Deploy the task as a service

#### Lambda Deployment (API Components)

1. Package the application for Lambda deployment
2. Create Lambda functions for API endpoints
3. Configure API Gateway integration
4. Set up appropriate IAM roles and permissions

---

## Advanced Topics

### Custom Authentication Providers

The system allows custom authentication providers:

```python
from aws_mcp_server.fleet_management.integrations.integration import AuthType, AuthConfig

class CustomAuthProvider:
    def __init__(self, config: AuthConfig):
        self.config = config
    
    async def authenticate(self, request):
        # Custom authentication logic
        pass

# Register with auth providers
async def register_auth_provider(registry):
    registry.auth_providers[AuthType.CUSTOM] = CustomAuthProvider
```

### Event-Driven Integrations

For event-driven integrations, the system provides specialized handling:

```python
from aws_mcp_server.fleet_management.integrations.integration import Integration

class EventDrivenIntegration(Integration):
    async def start_listening(self):
        # Set up event listeners
        pass
    
    async def process_event(self, event):
        # Process incoming events
        pass
    
    async def stop_listening(self):
        # Clean up event listeners
        pass
```

### Bulk Operations

The system supports bulk operations for efficiency:

```python
# Bulk registration
async def register_bulk(registry, configs):
    results = {}
    for config in configs:
        try:
            integration_id = await registry.register_integration(config)
            results[config.name] = {
                "success": True,
                "id": integration_id
            }
        except Exception as e:
            results[config.name] = {
                "success": False,
                "error": str(e)
            }
    return results
```

---

## Troubleshooting

### Common Issues

#### Integration Initialization Failures

**Symptoms:**
- Integration status shows as ERROR
- Initialization logs show connection failures

**Solutions:**
1. Check network connectivity to the external system
2. Verify authentication credentials
3. Ensure the external system is available
4. Review configuration parameters for accuracy

#### Health Check Failures

**Symptoms:**
- Integration transitions from ACTIVE to ERROR
- Health check logs show repeated failures

**Solutions:**
1. Check the health check endpoint configuration
2. Verify network connectivity
3. Adjust health check parameters (interval, timeout)
4. Check external system status

#### Performance Issues

**Symptoms:**
- Slow response times
- High CPU or memory usage

**Solutions:**
1. Adjust rate limiting parameters
2. Optimize integration implementations
3. Scale the server horizontally
4. Implement caching where appropriate

### Logging and Debugging

The system uses Python's logging module with configurable levels:

```python
import logging

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Get a logger for a specific component
logger = logging.getLogger("aws_mcp_server.fleet_management.integrations")
```

### Support and Resources

- **Documentation**: Comprehensive documentation is available in the `docs/` directory
- **Issue Tracker**: Report issues on GitHub
- **Community Forums**: Discuss questions and share experiences
- **Commercial Support**: Available for enterprise customers

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

*This README was last updated on 2023-11-01.*
