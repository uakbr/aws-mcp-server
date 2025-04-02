
# AWS MCP Server

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/aws/aws-mcp-server)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

> *A comprehensive fleet management and integration solution for AWS resources*

---

<div align="center">
  <img src="https://via.placeholder.com/800x200?text=AWS+MCP+Server" alt="AWS MCP Server" width="800"/>
</div>

---

## Table of Contents

<table>
  <tr>
    <td width="33%" valign="top">
      <ul>
        <li><a href="#introduction">Introduction</a></li>
        <li><a href="#architecture-overview">Architecture Overview</a></li>
        <li><a href="#core-components">Core Components</a></li>
        <li><a href="#integration-framework">Integration Framework</a>
          <ul>
            <li><a href="#integration-types">Integration Types</a></li>
            <li><a href="#integration-configuration">Configuration</a></li>
          </ul>
        </li>
      </ul>
    </td>
    <td width="33%" valign="top">
      <ul>
        <li><a href="#api-layer">API Layer</a></li>
        <li><a href="#getting-started">Getting Started</a>
          <ul>
            <li><a href="#prerequisites">Prerequisites</a></li>
            <li><a href="#installation">Installation</a></li>
            <li><a href="#configuration">Configuration</a></li>
          </ul>
        </li>
        <li><a href="#development-guide">Development Guide</a></li>
      </ul>
    </td>
    <td width="33%" valign="top">
      <ul>
        <li><a href="#deployment">Deployment</a>
          <ul>
            <li><a href="#docker-deployment">Docker</a></li>
            <li><a href="#aws-deployment">AWS</a></li>
          </ul>
        </li>
        <li><a href="#advanced-topics">Advanced Topics</a></li>
        <li><a href="#troubleshooting">Troubleshooting</a></li>
        <li><a href="#license">License</a></li>
      </ul>
    </td>
  </tr>
</table>

---

## Introduction

**AWS MCP Server** is a comprehensive fleet management solution for AWS resources. It provides a centralized platform for managing resources across multiple AWS accounts, regions, and services with an extensive integration framework for seamless connectivity with external systems, APIs, and data sources.

| Key Focus Areas | Description |
| --- | --- |
| **Scalability** | Support for thousands of AWS resources across multiple accounts |
| **Extensibility** | Pluggable integration framework with multiple integration types |
| **Resilience** | Fault-tolerant architecture with health checks and retry mechanisms |
| **Security** | Comprehensive authentication and authorization mechanisms |
| **Observability** | Built-in monitoring and logging for system health analysis |

---

## Architecture Overview

The AWS MCP Server follows a modular, layered architecture pattern designed for flexibility and maintainability.

<div align="center">
  <pre style="text-align: center; background-color: #f8f8f8; padding: 15px; border-radius: 5px;">
┌─────────────────────────────────────────────────────────────┐
│                     Presentation Layer                       │
│  ┌───────────┐   ┌───────────┐   ┌─────────────────────┐    │
│  │Web Console│   │    CLI    │   │  Programmatic API   │    │
│  └───────────┘   └───────────┘   └─────────────────────┘    │
└──────────────────────────┬──────────────────────────────────┘
                          │
┌──────────────────────────┼──────────────────────────────────┐
│                      API Layer                               │
│  ┌───────────┐   ┌───────────┐   ┌─────────────────────┐    │
│  │ REST API  │   │GraphQL API│   │    WebSockets       │    │
│  └───────────┘   └───────────┘   └─────────────────────┘    │
└──────────────────────────┬──────────────────────────────────┘
                          │
┌──────────────────────────┼──────────────────────────────────┐
│                    Service Layer                             │
│  ┌───────────┐   ┌───────────┐   ┌─────────────────────┐    │
│  │Resource   │   │Fleet      │   │Integration          │    │
│  │Management │   │Control    │   │Services             │    │
│  └───────────┘   └───────────┘   └─────────────────────┘    │
└──────────────────────────┬──────────────────────────────────┘
                          │
┌──────────────────────────┼──────────────────────────────────┐
│                  Integration Layer                           │
│  ┌───────────┐   ┌───────────┐   ┌─────────────────────┐    │
│  │AWS        │   │External   │   │Data                 │    │
│  │Services   │   │APIs       │   │Sources              │    │
│  └───────────┘   └───────────┘   └─────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
  </pre>
</div>

### Key Architecture Principles

<table>
  <tr>
    <th width="25%">Principle</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><strong>Asynchronous Design</strong></td>
    <td>Leverages Python's asyncio for non-blocking operations, enabling high throughput and efficient resource utilization</td>
  </tr>
  <tr>
    <td><strong>Domain-Driven Design</strong></td>
    <td>Components organized around business domains for better separation of concerns and maintainability</td>
  </tr>
  <tr>
    <td><strong>Configuration-Driven</strong></td>
    <td>System behavior controlled through structured configuration, minimizing code changes for behavioral adjustments</td>
  </tr>
  <tr>
    <td><strong>Stateless Services</strong></td>
    <td>Services designed to be stateless where possible, enabling horizontal scaling and improved reliability</td>
  </tr>
  <tr>
    <td><strong>Event-Driven Communication</strong></td>
    <td>Services communicate through events when appropriate, promoting loose coupling</td>
  </tr>
</table>

---

## Core Components

### CLI Executor

<kbd>src/aws_mcp_server/cli_executor.py</kbd>

Provides a unified interface for executing AWS CLI commands across accounts and regions.

```python
# Example usage
from aws_mcp_server.cli_executor import CliExecutor

executor = CliExecutor(region="us-west-2", profile="prod")
result = await executor.run("ec2 describe-instances")
```

### Resource Registry

<kbd>src/aws_mcp_server/fleet_management/models.py</kbd>

Manages the inventory of AWS resources, providing a centralized registry for lookup and reference.

### Integration Framework

<kbd>src/aws_mcp_server/fleet_management/integrations/integration.py</kbd>

Provides the foundation for integrating with external systems, APIs, and data sources.

---

## Integration Framework

The integration framework is a core component enabling the MCP Server to connect with external systems through a pluggable architecture.

### Integration Types

<div style="background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
  <table>
    <tr>
      <th width="20%">Type</th>
      <th>Description</th>
      <th width="25%">Use Cases</th>
    </tr>
    <tr>
      <td><code>WEBHOOK</code></td>
      <td>HTTP callbacks for event notifications</td>
      <td>Notification delivery, event triggers</td>
    </tr>
    <tr>
      <td><code>REST_API</code></td>
      <td>Standard RESTful API integrations</td>
      <td>Resource management, data synchronization</td>
    </tr>
    <tr>
      <td><code>GRAPHQL</code></td>
      <td>GraphQL API integrations</td>
      <td>Complex data queries, flexible data retrieval</td>
    </tr>
    <tr>
      <td><code>GRPC</code></td>
      <td>gRPC service integrations</td>
      <td>High-performance microservice communication</td>
    </tr>
    <tr>
      <td><code>EVENT_BUS</code></td>
      <td>Integration with event bus systems</td>
      <td>Pub/sub patterns, event distribution</td>
    </tr>
    <tr>
      <td><code>MESSAGE_QUEUE</code></td>
      <td>Message queue integrations</td>
      <td>Asynchronous processing, workload distribution</td>
    </tr>
    <tr>
      <td><code>DATABASE</code></td>
      <td>Direct database integrations</td>
      <td>Data persistence, querying external data stores</td>
    </tr>
    <tr>
      <td><code>FILE</code></td>
      <td>File system integrations</td>
      <td>File-based data exchange, report generation</td>
    </tr>
    <tr>
      <td><code>CUSTOM</code></td>
      <td>Custom integration types</td>
      <td>Specialized protocols, legacy systems</td>
    </tr>
  </table>
</div>

### Data Flow Directions

Each integration operates in one of three directions:

- **`INBOUND`**: External systems sending data to MCP Server
- **`OUTBOUND`**: MCP Server sending data to external systems
- **`BIDIRECTIONAL`**: Two-way communication between MCP Server and external systems

### Integration Configuration

<details>
<summary><strong>Click to expand configuration model</strong></summary>

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
</details>

### Authentication

<div style="background-color: #f0f7ff; padding: 15px; border-radius: 5px; border-left: 5px solid #0066cc; margin-bottom: 20px;">
  <p><strong>Authentication Mechanisms</strong></p>
  <ul>
    <li><code>NONE</code>: No authentication</li>
    <li><code>API_KEY</code>: API key authentication</li>
    <li><code>BASIC</code>: HTTP Basic authentication</li>
    <li><code>BEARER_TOKEN</code>: Bearer token authentication</li>
    <li><code>OAUTH2</code>: OAuth 2.0 authentication</li>
    <li><code>OAUTH1</code>: OAuth 1.0a authentication</li>
    <li><code>AWS_SIG_V4</code>: AWS Signature Version 4</li>
    <li><code>CERTIFICATE</code>: Client certificate authentication</li>
    <li><code>CUSTOM</code>: Custom authentication mechanisms</li>
  </ul>
</div>

### Health Checks

The framework includes sophisticated health monitoring capabilities:

<details>
<summary><strong>Health Check Configuration</strong></summary>

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
</details>

Health checks are automatically executed in the background, monitoring integration status with:

- Regular interval-based checks
- Automatic marking of failed integrations
- Recovery detection and status updates
- Persistence of health check results

### Retry Mechanisms

<details>
<summary><strong>Retry Configuration</strong></summary>

```python
@dataclass
class RetryConfig:
    enabled: bool = True
    max_attempts: int = 3
    initial_backoff_seconds: float = 1.0
    max_backoff_seconds: float = 60.0
    backoff_multiplier: float = 2.0
    retry_on_status_codes: List[int] = field(
        default_factory=lambda: [429, 500, 502, 503, 504]
    )
```
</details>

Key retry features include:
- Exponential backoff with jitter
- Configurable retry conditions
- Maximum attempt limits
- Status code-based retry decisions

### Integration Lifecycle

<div align="center">
  <img src="https://via.placeholder.com/600x300?text=Integration+Lifecycle+Diagram" alt="Integration Lifecycle" width="600"/>
</div>

The integration lifecycle flows through the following states:

1. **`CONFIGURING`**: Initial setup state
2. **`TESTING`**: Validation and testing state
3. **`ACTIVE`**: Normal operational state
4. **`ERROR`**: Failure state after health check failures
5. **`INACTIVE`**: Manually disabled state
6. **`DEPRECATED`**: End-of-life state

---

## API Layer

The API layer provides RESTful endpoints for managing the fleet and integrations.

### Integration Management API

<div style="background-color: #f8f8f8; padding: 15px; border-radius: 5px;">
  <table>
    <tr>
      <th>Endpoint</th>
      <th>Method</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>/api/v1/integrations</code></td>
      <td>GET</td>
      <td>List all integrations</td>
    </tr>
    <tr>
      <td><code>/api/v1/integrations/{integration_id}</code></td>
      <td>GET</td>
      <td>Get integration details</td>
    </tr>
    <tr>
      <td><code>/api/v1/integrations</code></td>
      <td>POST</td>
      <td>Create a new integration</td>
    </tr>
    <tr>
      <td><code>/api/v1/integrations/{integration_id}</code></td>
      <td>PUT</td>
      <td>Update an integration</td>
    </tr>
    <tr>
      <td><code>/api/v1/integrations/{integration_id}</code></td>
      <td>DELETE</td>
      <td>Delete an integration</td>
    </tr>
    <tr>
      <td><code>/api/v1/integrations/{integration_id}/health</code></td>
      <td>GET</td>
      <td>Get integration health status</td>
    </tr>
  </table>
</div>

### Authentication and Authorization

The API implements:
- JWT-based authentication
- Role-based access control
- API key authentication for service-to-service communication
- Rate limiting to prevent abuse

---

## Getting Started

### Prerequisites

<div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
  <ul>
    <li>Python 3.9+</li>
    <li>AWS CLI configured with appropriate credentials</li>
    <li>Access to target AWS accounts</li>
    <li>Docker (for containerized deployment)</li>
  </ul>
</div>

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

<details>
<summary><strong>Configuration File (YAML)</strong></summary>

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
</details>

Set environment variables:

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

<details>
<summary><strong>View Project Structure</strong></summary>

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
</details>

### Adding a New Integration Type

<div style="background-color: #f0fff0; padding: 15px; border-radius: 5px; border-left: 5px solid #006600; margin-bottom: 20px;">
  <p><strong>Implementation Steps:</strong></p>
  <ol>
    <li>Create a new module in <code>src/aws_mcp_server/fleet_management/integrations/</code></li>
    <li>Subclass the <code>Integration</code> base class</li>
    <li>Implement required methods</li>
    <li>Register the integration type with the registry</li>
  </ol>
</div>

<details>
<summary><strong>Example Implementation</strong></summary>

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
</details>

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

<details>
<summary><strong>Dockerfile</strong></summary>

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY pyproject.toml setup.py README.md /app/
COPY src/ /app/src/

RUN pip install --no-cache-dir -e ".[prod]"

EXPOSE 8000

CMD ["python", "-m", "aws_mcp_server.server"]
```
</details>

Build and run:

```bash
# Build the Docker image
docker build -t aws-mcp-server .

# Run the container
docker run -p 8000:8000 -v /path/to/config.yaml:/app/config.yaml aws-mcp-server
```

### AWS Deployment

<table>
  <tr>
    <th width="25%">Deployment Option</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><strong>EC2</strong></td>
    <td>
      <ol>
        <li>Launch an EC2 instance with appropriate IAM role</li>
        <li>Install dependencies and copy the application</li>
        <li>Configure the application</li>
        <li>Start the server with systemd or similar</li>
      </ol>
    </td>
  </tr>
  <tr>
    <td><strong>ECS</strong></td>
    <td>
      <ol>
        <li>Create an ECS cluster</li>
        <li>Create a task definition using the Docker image</li>
        <li>Configure environment variables and volumes</li>
        <li>Deploy the task as a service</li>
      </ol>
    </td>
  </tr>
  <tr>
    <td><strong>Lambda (API Components)</strong></td>
    <td>
      <ol>
        <li>Package the application for Lambda deployment</li>
        <li>Create Lambda functions for API endpoints</li>
        <li>Configure API Gateway integration</li>
        <li>Set up appropriate IAM roles and permissions</li>
      </ol>
    </td>
  </tr>
</table>

---

## Advanced Topics

### Custom Authentication Providers

<details>
<summary><strong>Implementation Example</strong></summary>

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
</details>

### Event-Driven Integrations

<details>
<summary><strong>Implementation Example</strong></summary>

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
</details>

### Bulk Operations

<details>
<summary><strong>Implementation Example</strong></summary>

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
</details>

---

## Troubleshooting

### Common Issues

<div style="background-color: #fff6f6; padding: 15px; border-radius: 5px; border-left: 5px solid #cc0000; margin-bottom: 20px;">
  <p><strong>Integration Initialization Failures</strong></p>
  <p><em>Symptoms:</em></p>
  <ul>
    <li>Integration status shows as ERROR</li>
    <li>Initialization logs show connection failures</li>
  </ul>
  <p><em>Solutions:</em></p>
  <ol>
    <li>Check network connectivity to the external system</li>
    <li>Verify authentication credentials</li>
    <li>Ensure the external system is available</li>
    <li>Review configuration parameters for accuracy</li>
  </ol>
</div>

<div style="background-color: #fff6f6; padding: 15px; border-radius: 5px; border-left: 5px solid #cc0000; margin-bottom: 20px;">
  <p><strong>Health Check Failures</strong></p>
  <p><em>Symptoms:</em></p>
  <ul>
    <li>Integration transitions from ACTIVE to ERROR</li>
    <li>Health check logs show repeated failures</li>
  </ul>
  <p><em>Solutions:</em></p>
  <ol>
    <li>Check the health check endpoint configuration</li>
    <li>Verify network connectivity</li>
    <li>Adjust health check parameters (interval, timeout)</li>
    <li>Check external system status</li>
  </ol>
</div>

### Logging and Debugging

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

<table>
  <tr>
    <th width="30%">Resource</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><strong>Documentation</strong></td>
    <td>Comprehensive documentation is available in the <code>docs/</code> directory</td>
  </tr>
  <tr>
    <td><strong>Issue Tracker</strong></td>
    <td>Report issues on <a href="https://github.com/aws/aws-mcp-server/issues">GitHub</a></td>
  </tr>
  <tr>
    <td><strong>Community Forums</strong></td>
    <td>Discuss questions and share experiences on our community platform</td>
  </tr>
  <tr>
    <td><strong>Commercial Support</strong></td>
    <td>Available for enterprise customers</td>
  </tr>
</table>

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <p><em>Copyright © 2023 AWS MCP Server Team. All rights reserved.</em></p>
  <p>Documentation last updated: November 1, 2023</p>
</div>
