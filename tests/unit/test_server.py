"""Tests for the FastMCP server implementation."""

from unittest.mock import ANY, AsyncMock, patch

import pytest

from aws_mcp_server.cli_executor import CommandExecutionError, CommandValidationError
from aws_mcp_server.server import describe_command, execute_command, mcp, run_startup_checks


def test_run_startup_checks():
    """Test the run_startup_checks function."""
    # Test when AWS CLI is installed
    with patch("aws_mcp_server.server.check_aws_cli_installed") as mock_check:
        # Return a Future-like object that resolves to True
        future_true = AsyncMock()
        future_true.__await__ = lambda: (yield True)
        mock_check.return_value = future_true

        with patch("asyncio.run", lambda x: True):
            with patch("sys.exit") as mock_exit:
                run_startup_checks()
                mock_exit.assert_not_called()

    # Test when AWS CLI is not installed
    with patch("aws_mcp_server.server.check_aws_cli_installed") as mock_check:
        # Return a Future-like object that resolves to False
        future_false = AsyncMock()
        future_false.__await__ = lambda: (yield False)
        mock_check.return_value = future_false

        with patch("asyncio.run", lambda x: False):
            with patch("sys.exit") as mock_exit:
                run_startup_checks()
                mock_exit.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_describe_command():
    """Test the describe_command tool."""
    # Mock the get_command_help function instead of execute_aws_command
    with patch("aws_mcp_server.server.get_command_help", new_callable=AsyncMock) as mock_get_help:
        mock_get_help.return_value = {"help_text": "Test help text"}

        # Call the tool with service only
        result = await describe_command(service="s3")
        assert result == {"help_text": "Test help text"}
        mock_get_help.assert_called_with("s3", ANY)

        # Call the tool with service and command
        result = await describe_command(service="s3", command="ls")
        assert result == {"help_text": "Test help text"}
        mock_get_help.assert_called_with("s3", "ls")


@pytest.mark.asyncio
async def test_describe_command_with_context():
    """Test the describe_command tool with context."""
    mock_ctx = AsyncMock()

    with patch("aws_mcp_server.server.get_command_help", new_callable=AsyncMock) as mock_get_help:
        mock_get_help.return_value = {"help_text": "Test help text"}

        result = await describe_command(service="s3", command="ls", ctx=mock_ctx)

        assert result == {"help_text": "Test help text"}
        mock_ctx.info.assert_called_once()
        assert "Fetching help for AWS s3 ls" in mock_ctx.info.call_args[0][0]


@pytest.mark.asyncio
async def test_describe_command_exception_handling():
    """Test exception handling in describe_command."""
    with patch("aws_mcp_server.server.get_command_help", side_effect=Exception("Test exception")):
        result = await describe_command(service="s3")

        assert "help_text" in result
        assert "Error retrieving help" in result["help_text"]
        assert "Test exception" in result["help_text"]


@pytest.mark.asyncio
async def test_execute_command_success():
    """Test the execute_command tool with successful execution."""
    # Mock the execute_aws_command function
    with patch("aws_mcp_server.server.execute_aws_command", new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = {"status": "success", "output": "Test output"}
        result = await execute_command(command="aws s3 ls")
        assert result["status"] == "success"
        assert result["output"] == "Test output"
        mock_execute.assert_called_with("aws s3 ls", ANY)


@pytest.mark.asyncio
async def test_execute_command_with_timeout():
    """Test the execute_command tool with custom timeout."""
    # Mock the execute_aws_command function
    with patch("aws_mcp_server.server.execute_aws_command", new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = {"status": "success", "output": "Test output"}
        result = await execute_command(command="aws s3 ls", timeout=60)
        assert result["status"] == "success"
        assert result["output"] == "Test output"
        mock_execute.assert_called_with("aws s3 ls", 60)


@pytest.mark.asyncio
async def test_execute_command_with_context():
    """Test the execute_command tool with context."""
    mock_ctx = AsyncMock()

    # Test successful command with context
    with patch("aws_mcp_server.server.execute_aws_command", new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = {"status": "success", "output": "Test output"}

        result = await execute_command(command="aws s3 ls", ctx=mock_ctx)

        assert result["status"] == "success"
        assert result["output"] == "Test output"

        # Verify context was used correctly
        assert mock_ctx.info.call_count == 2
        assert "Executing AWS CLI command" in mock_ctx.info.call_args_list[0][0][0]
        assert "Command executed successfully" in mock_ctx.info.call_args_list[1][0][0]

    # Test failed command with context
    mock_ctx.reset_mock()
    with patch("aws_mcp_server.server.execute_aws_command", new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = {"status": "error", "output": "Error output"}

        result = await execute_command(command="aws s3 ls", ctx=mock_ctx)

        assert result["status"] == "error"
        assert result["output"] == "Error output"

        # Verify context was used correctly
        assert mock_ctx.info.call_count == 1
        assert mock_ctx.warning.call_count == 1
        assert "Command failed" in mock_ctx.warning.call_args[0][0]


@pytest.mark.asyncio
async def test_execute_command_with_context_and_timeout():
    """Test the execute_command tool with context and timeout."""
    mock_ctx = AsyncMock()

    with patch("aws_mcp_server.server.execute_aws_command", new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = {"status": "success", "output": "Test output"}

        await execute_command(command="aws s3 ls", timeout=60, ctx=mock_ctx)

        # Verify timeout was mentioned in the context message
        message = mock_ctx.info.call_args_list[0][0][0]
        assert "with timeout: 60s" in message


@pytest.mark.asyncio
async def test_execute_command_validation_error():
    """Test the execute_command tool with validation error."""
    # Mock the execute_aws_command function to raise validation error
    with patch("aws_mcp_server.server.execute_aws_command", side_effect=CommandValidationError("Invalid command")) as mock_execute:
        # Call the tool
        result = await execute_command(command="not aws")

        assert result["status"] == "error"
        assert "Command validation error" in result["output"]
        mock_execute.assert_called_with("not aws", ANY)


@pytest.mark.asyncio
async def test_execute_command_execution_error():
    """Test the execute_command tool with execution error."""
    # Mock the execute_aws_command function to raise execution error
    with patch("aws_mcp_server.server.execute_aws_command", side_effect=CommandExecutionError("Execution failed")) as mock_execute:
        # Call the tool
        result = await execute_command(command="aws s3 ls")

        assert result["status"] == "error"
        assert "Command execution error" in result["output"]
        assert "Execution failed" in result["output"]
        mock_execute.assert_called_with("aws s3 ls", ANY)


@pytest.mark.asyncio
async def test_execute_command_unexpected_error():
    """Test the execute_command tool with unexpected errors."""
    # Mock the execute_aws_command function to raise a generic exception
    with patch("aws_mcp_server.server.execute_aws_command", side_effect=Exception("Unexpected error")) as mock_execute:
        # Call the tool
        result = await execute_command(command="aws s3 ls")

        assert result["status"] == "error"
        assert "Unexpected error" in result["output"]
        mock_execute.assert_called_with("aws s3 ls", ANY)


@pytest.mark.asyncio
async def test_mcp_server_initialization():
    """Test that the MCP server initializes correctly."""
    # Verify server was created with correct name
    assert mcp.name == "AWS MCP Server"

    # Verify tools are registered by calling them
    # This ensures the tools exist without depending on FastMCP's internal structure
    assert callable(describe_command)
    assert callable(execute_command)
