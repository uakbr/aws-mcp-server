# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# AWS MCP Server Development Guide

## Build & Test Commands

- Install dependencies: `pip install -e .`
- Install dev dependencies: `pip install -e ".[dev]"`
- Run server: `python -m aws_mcp_server`
- Run server with SSE transport: `AWS_MCP_TRANSPORT=sse python -m aws_mcp_server`
- Run with MCP CLI: `mcp run src/aws_mcp_server/server.py`
- Run tests: `pytest`
- Run single test: `pytest tests/path/to/test_file.py::test_function_name -v`
- Run unit tests only: `pytest tests/unit/`
- Run integration tests: `pytest --run-integration` (requires AWS credentials)
- Run linter: `ruff check src/ tests/`
- Format code: `ruff format src/ tests/`
- Build Docker image: `docker build -t aws-mcp-server .`
- Run Docker container: `docker run -e AWS_PROFILE=your-profile -v ~/.aws:/root/.aws:ro aws-mcp-server`

## Technical Stack

- **Python version**: Python 3.13+
- **Project config**: `pyproject.toml` for configuration and dependency management
- **Environment**: Use virtual environment in `.venv` for dependency isolation
- **Dependencies**: Separate production and dev dependencies in `pyproject.toml`
- **Linting**: `ruff` for style and error checking (E, F, I, B rules enabled)
- **Type checking**: Use VS Code with Pylance for static type checking
- **Testing**: `pytest` with `moto` for AWS service mocking
- **Project layout**: Organize code with `src/` layout
- **Test markers**: `integration` (requires AWS), `asyncio` (async tests)

## Code Style Guidelines

- **Formatting**: Black-compatible formatting via `ruff format`
- **Line length**: 160 characters maximum
- **Imports**: Sort imports with `ruff` (stdlib, third-party, local)
- **Type hints**: Use native Python type hints (e.g., `list[str]` not `List[str]`)
- **Documentation**: Google-style docstrings for all modules, classes, functions
- **Naming**: snake_case for variables/functions, PascalCase for classes
- **Function length**: Keep functions short (< 30 lines) and single-purpose
- **PEP 8**: Follow PEP 8 style guide (enforced via `ruff`)

## Python Best Practices

- **File handling**: Prefer `pathlib.Path` over `os.path`
- **Debugging**: Use `logging` module instead of `print`
- **Error handling**: Use specific exceptions with context messages and proper logging
- **Data structures**: Use list/dict comprehensions for concise, readable code
- **Function arguments**: Avoid mutable default arguments
- **Data containers**: Leverage `dataclasses` to reduce boilerplate
- **Configuration**: Use environment variables (via `python-dotenv`) for configuration
- **AWS CLI**: Validate all commands before execution (must start with "aws")
- **Security**: Never store/log AWS credentials, set command timeouts

## Development Patterns & Best Practices

- **Favor simplicity**: Choose the simplest solution that meets requirements
- **DRY principle**: Avoid code duplication; reuse existing functionality
- **Configuration management**: Use environment variables for different environments
- **Focused changes**: Only implement explicitly requested or fully understood changes
- **Preserve patterns**: Follow existing code patterns when fixing bugs
- **File size**: Keep files under 300 lines; refactor when exceeding this limit
- **Test coverage**: Write comprehensive unit and integration tests with `pytest`; include fixtures
- **Modular design**: Create reusable, modular components
- **Logging**: Implement appropriate logging levels (debug, info, error)
- **Error handling**: Implement robust error handling for production reliability
- **Security best practices**: Follow input validation and data protection practices
- **Performance**: Optimize critical code sections when necessary
- **Dependency management**: Add libraries only when essential

## Development Workflow

- **Version control**: Commit frequently with clear messages
- **Impact assessment**: Evaluate how changes affect other codebase areas
- **Documentation**: Keep documentation up-to-date for complex logic and features

## Codebase Architecture

### Core MCP Server (`src/aws_mcp_server/`)
- **server.py**: Main MCP server implementation with FastMCP
- **cli_executor.py**: AWS CLI command execution with validation and security
- **tools.py**: MCP tool definitions for AWS operations
- **config.py**: Configuration management using environment variables
- **prompts.py**: User-facing prompt templates

### Fleet Management Module (`src/aws_mcp_server/fleet_management/`)
Advanced features for multi-account AWS resource management:
- **api/**: REST API server with authentication and rate limiting
- **integrations/**: External system integration framework (REST, webhook, GraphQL, gRPC)
- **monitoring/**: CloudWatch metrics and alerting
- **config/**: Hierarchical configuration with inheritance
- **deployment/**: Template-based deployment automation
- **logging/**: Centralized log collection and analysis

### Testing Structure
- **tests/unit/**: Unit tests using mocks (run by default)
- **tests/integration/**: Integration tests requiring AWS credentials (use `--run-integration`)
- **tests/conftest.py**: Shared pytest fixtures and configuration

### Key Design Patterns
- **Asynchronous-first**: All server operations use async/await
- **Layered architecture**: Presentation → API → Service → Integration layers
- **Domain-driven design**: Organized around business capabilities
- **Security by default**: Input validation, credential protection, audit logging
