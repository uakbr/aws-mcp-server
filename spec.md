# AWS Model Context Protocol (MCP) Server Specification

## Project Overview

The **AWS MCP Server** is a lightweight service that enables users to execute AWS CLI commands through an MCP (Model Context Protocol) interface. It integrates with MCP-aware AI assistants (e.g., Claude Desktop, Cursor, Windsurf) via the [Model Context Protocol](https://modelcontextprotocol.io/), which is based on JSON-RPC 2.0. The server facilitates AWS CLI command documentation and execution, returning human-readable output optimized for AI consumption.

### Key Objectives

- **Command Documentation**: Provide detailed help information for AWS CLI commands.
- **Command Execution**: Execute AWS CLI commands and return formatted results.
- **MCP Compliance**: Fully implement the standard MCP protocol.
- **Human-Readable Output**: Ensure command output is optimized for AI assistants.
- **Easy Deployment**: Prioritize Docker-based deployment for environment consistency.
- **Open Source**: Release under MIT license with GitHub repository and CI/CD.

## Core Features

### 1. Command Documentation Tool

The `describe_command` tool retrieves and formats AWS CLI help information:

- Use `aws  help` and `aws   help` to access documentation.
- Present results in a structured, readable format optimized for AI consumption.
- Support parameter exploration to help understand command options.

**Examples:**

```
describe_command({"service": "s3"})
// Returns high-level AWS S3 service documentation

describe_command({"service": "s3", "command": "ls"})
// Returns specific documentation for the S3 ls command
```

### 2. Command Execution Tool

The `execute_command` tool runs AWS CLI commands:

- Accept complete AWS CLI command strings.
- Execute commands using the OS's AWS CLI installation.
- Format output for readability.
- Support optional parameters (region, profile, output format).

**Examples:**

```
execute_command({"command": "aws s3 ls"})
// Lists all S3 buckets

execute_command({"command": "aws ec2 describe-instances --region us-west-2"})
// Lists EC2 instances in the Oregon region
```

### 3. Output Formatting

Transform raw AWS CLI output into human-readable formats:

- Default to AWS CLI's `--output text` for simplicity.
- Format complex outputs (e.g., tables, lists) for better readability.
- Handle JSON, YAML, and text output formats.

### 4. Authentication Management

- Leverage existing AWS CLI authentication on the host machine.
- Support AWS profiles through command parameters.
- Provide clear error messages for authentication issues.

## MCP Protocol Implementation

The server implements the MCP protocol with the following components:

### 1. Initialization Workflow

**Client Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "DRAFT-2025-v1",
    "capabilities": {
      "experimental": {}
    },
    "clientInfo": {
      "name": "Claude Desktop",
      "version": "1.0.0"
    }
  }
}
```

**Server Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "DRAFT-2025-v1",
    "capabilities": {
      "tools": {}
    },
    "serverInfo": {
      "name": "AWS MCP Server",
      "version": "1.0.0"
    },
    "instructions": "Use this server to retrieve AWS CLI documentation and execute AWS CLI commands."
  }
}
```

**Client Notification:**
```json
{
  "jsonrpc": "2.0",
  "method": "notifications/initialized"
}
```

### 2. Tool Definitions

The server defines two primary tools:

#### describe_command

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/describe_command",
  "params": {
    "service": "s3",
    "command": "ls"  // Optional
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "help_text": "Description: Lists all your buckets or all the objects in a bucket.\n\nUsage: aws s3 ls [bucket] [options]\n\nOptions:\n  --bucket TEXT        The bucket name\n  --prefix TEXT        Prefix to filter objects\n  --delimiter TEXT     Delimiter to use for grouping\n  --max-items INTEGER  Maximum number of items to return\n  --page-size INTEGER  Number of items to return per page\n  --starting-token TEXT Starting token for pagination\n  --request-payer TEXT  Confirms that the requester knows they will be charged for the request\n\nExamples:\n  aws s3 ls\n  aws s3 ls my-bucket\n  aws s3 ls my-bucket --prefix folder/\n"
  }
}
```

#### execute_command

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/execute_command",
  "params": {
    "command": "aws s3 ls --region us-west-2"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "output": "2023-10-15 14:30:45 my-bucket-1\n2023-11-20 09:15:32 my-bucket-2",
    "status": "success"
  }
}
```

### 3. Error Handling

The server returns standardized JSON-RPC error responses:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "error": {
    "code": -32603,
    "message": "Internal error",
    "data": "AWS CLI command failed: Unable to locate credentials"
  }
}
```

**Standard Error Codes:**
- `-32600`: Invalid Request
- `-32601`: Method Not Found
- `-32602`: Invalid Parameters
- `-32603`: Internal Error

## Architecture

### Simplified Component Architecture

```
+-------------------+          +-------------------+
|   MCP Client      ||   MCP Interface   |
|   (Claude/Cursor) |          |   (JSON-RPC)      |
+-------------------+          +-------------------+
                                        |
                                        v
                              +-------------------+
                              |   Tool Handler    |
                              | (describe/execute)|
                              +-------------------+
                                        |
                                        v
                              +-------------------+
                              | AWS CLI Executor  |
                              | (subprocess)      |
                              +-------------------+
                                        |
                                        v
                              +-------------------+
                              | Output Formatter  |
                              | (text/tables)     |
                              +-------------------+
```

### Components

1. **MCP Interface**
   - Implements JSON-RPC 2.0 protocol endpoints
   - Handles MCP initialization and notifications
   - Routes tool requests to appropriate handlers

2. **Tool Handler**
   - Processes `describe_command` requests
   - Processes `execute_command` requests
   - Validates parameters

3. **AWS CLI Executor**
   - Executes AWS CLI commands via subprocess
   - Captures standard output and error streams
   - Handles command timing and timeout

4. **Output Formatter**
   - Processes raw AWS CLI output
   - Formats complex responses for readability
   - Handles errors and exceptions

## Implementation Details

### 1. Server Implementation

**Python Implementation using MCP SDK:**

```python
from modelcontextprotocol.server import Server, StdioServerTransport
import subprocess
import json

# Create MCP server
server = Server(
    {"name": "aws-mcp-server", "version": "1.0.0"},
    {"capabilities": {"tools": {}}}
)

# Define describe_command tool
@server.tool({
    "name": "describe_command",
    "description": "Get AWS CLI command documentation",
    "parameters": {
        "type": "object",
        "properties": {
            "service": {
                "type": "string",
                "description": "AWS service (e.g., s3, ec2)"
            },
            "command": {
                "type": "string",
                "description": "Command within the service (optional)"
            }
        },
        "required": ["service"]
    }
})
async def describe_command(params):
    service = params["service"]
    command = params.get("command")
    
    aws_cmd = ["aws", service]
    if command:
        aws_cmd.append(command)
    aws_cmd.append("help")
    
    try:
        result = subprocess.run(aws_cmd, capture_output=True, text=True, check=True)
        return {"help_text": result.stdout}
    except subprocess.CalledProcessError as e:
        return {"error": e.stderr}

# Define execute_command tool
@server.tool({
    "name": "execute_command",
    "description": "Execute an AWS CLI command",
    "parameters": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Complete AWS CLI command to execute"
            }
        },
        "required": ["command"]
    }
})
async def execute_command(params):
    command = params["command"]
    cmd_parts = command.split()
    
    if cmd_parts[0] != "aws":
        return {"error": "Commands must start with 'aws'"}
    
    try:
        result = subprocess.run(cmd_parts, capture_output=True, text=True, check=True)
        return {
            "output": result.stdout,
            "status": "success"
        }
    except subprocess.CalledProcessError as e:
        return {
            "output": e.stderr,
            "status": "error"
        }

# Connect transport and start the server
transport = StdioServerTransport()
server.connect(transport)
```

### 2. Directory Structure

```
aws-mcp-server/
├── src/
│   ├── main.py                # Server entry point
│   ├── tools/
│   │   ├── describe.py        # Command documentation tool
│   │   └── execute.py         # Command execution tool
│   ├── utils/
│   │   ├── cli_executor.py    # AWS CLI subprocess wrapper
│   │   └── formatter.py       # Output formatting utilities
│   └── config.py              # Configuration settings
├── tests/
│   ├── unit/                  # Unit tests
│   └── integration/           # Integration tests
├── Dockerfile                 # Docker configuration
├── docker-compose.yml         # Docker Compose for dev/test
├── requirements.txt           # Python dependencies
├── README.md                  # Usage documentation
└── LICENSE                    # MIT license
```

### 3. Error Handling Strategy

Implement comprehensive error handling for common scenarios:

- **AWS CLI Not Installed**: Check for AWS CLI presence at startup
- **Authentication Failures**: Return clear error messages with resolution steps
- **Permission Issues**: Clarify required AWS permissions
- **Invalid Commands**: Validate commands before execution
- **Timeout Handling**: Set reasonable command timeouts (30-60 seconds default)

## Deployment Strategy

### 1. Docker Deployment (Primary Method)

**Dockerfile:**
```dockerfile
FROM python:3.9-slim

# Install AWS CLI v2
RUN apt-get update && apt-get install -y \
    unzip \
    curl \
    less \
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy application files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Command to run the MCP server
ENTRYPOINT ["python", "src/main.py"]
```

**Docker Compose:**
```yaml
version: '3'
services:
  aws-mcp-server:
    build: .
    volumes:
      - ~/.aws:/root/.aws:ro  # Mount AWS credentials as read-only
    environment:
      - AWS_PROFILE=default   # Optional: specify AWS profile
```

**Usage:**
```bash
# Build and run
docker-compose up -d

# In MCP client (e.g., Claude Desktop)
# Connect to server at port 8000
```

### 2. Alternative: Python Virtual Environment

For users who prefer direct Python installation:

```bash
# Clone repository
git clone https://github.com/username/aws-mcp-server.git
cd aws-mcp-server

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run server
python src/main.py
```

## Testing Strategy

### 1. Unit Tests

Test individual components in isolation:

- **CLI Executor Tests**: Mock subprocess calls to verify command construction
- **Formatter Tests**: Verify output formatting for various AWS CLI responses
- **Tool Parameter Validation**: Test parameter validation for both tools

### 2. Integration Tests

Test end-to-end functionality:

- **MCP Protocol Tests**: Verify proper protocol implementation
- **AWS CLI Integration**: Test with actual AWS CLI using mock credentials
- **Error Handling**: Verify appropriate error responses

### 3. Test Automation

Implement CI/CD with GitHub Actions:

```yaml
name: Test and Build

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install pytest pytest-cov moto
      - name: Test with pytest
        run: |
          pytest --cov=src tests/

  build-docker:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build Docker image
        run: docker build -t aws-mcp-server .
      - name: Test Docker image
        run: |
          docker run --rm aws-mcp-server python -c "import sys; sys.exit(0)"
```

## Security Considerations

### Authentication Handling

- Use AWS credentials on the host machine
- Support profile specification through environment variables
- Never store or log AWS credentials

### Command Validation

- Verify all commands begin with "aws" prefix
- Consider implementing a simple allow/deny pattern for certain services or commands
- Rely on MCP host's approval mechanism for command execution

### Resource Limitations

- Set reasonable timeouts for command execution (default: 30 seconds)
- Limit output size to prevent memory issues
- Implement rate limiting for multiple rapid commands

## Conclusion

This simplified AWS MCP Server specification provides a clear, focused approach for building a server that integrates with the Model Context Protocol to execute AWS CLI commands. By removing unnecessary components like NLP and custom approval systems, the specification creates a more maintainable and purpose-driven implementation that leverages existing MCP host capabilities.

The specification provides detailed guidance on implementing the two core tools (`describe_command` and `execute_command`), MCP protocol compliance, and deployment strategies with Docker as the primary method. The structured approach, along with comprehensive code examples, provides the necessary detail for AI code generation systems to implement the server effectively.
