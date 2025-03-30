"""Tests for the CLI executor module."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aws_mcp_server.cli_executor import (
    CommandExecutionError,
    CommandValidationError,
    check_aws_cli_installed,
    execute_aws_command,
    execute_pipe_command,
    get_command_help,
    is_auth_error,
    validate_pipe_command,
)


@pytest.mark.asyncio
async def test_execute_aws_command_success():
    """Test successful command execution."""
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        # Mock a successful process
        process_mock = AsyncMock()
        process_mock.returncode = 0
        process_mock.communicate.return_value = (b"Success output", b"")
        mock_subprocess.return_value = process_mock

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "success"
        assert result["output"] == "Success output"
        mock_subprocess.assert_called_once_with("aws s3 ls", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)


@pytest.mark.asyncio
async def test_execute_aws_command_with_custom_timeout():
    """Test command execution with custom timeout."""
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        process_mock = AsyncMock()
        process_mock.returncode = 0
        process_mock.communicate.return_value = (b"Success output", b"")
        mock_subprocess.return_value = process_mock

        # Use a custom timeout
        custom_timeout = 120
        with patch("asyncio.wait_for") as mock_wait_for:
            mock_wait_for.return_value = (b"Success output", b"")
            await execute_aws_command("aws s3 ls", timeout=custom_timeout)

            # Check that wait_for was called with the custom timeout
            mock_wait_for.assert_called_once()
            args, kwargs = mock_wait_for.call_args
            assert kwargs.get("timeout") == custom_timeout or args[1] == custom_timeout


@pytest.mark.asyncio
async def test_execute_aws_command_error():
    """Test command execution error."""
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        # Mock a failed process
        process_mock = AsyncMock()
        process_mock.returncode = 1
        process_mock.communicate.return_value = (b"", b"Error message")
        mock_subprocess.return_value = process_mock

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "error"
        assert result["output"] == "Error message"


@pytest.mark.asyncio
async def test_execute_aws_command_auth_error():
    """Test command execution with authentication error."""
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        # Mock a process that returns auth error
        process_mock = AsyncMock()
        process_mock.returncode = 1
        process_mock.communicate.return_value = (b"", b"Unable to locate credentials")
        mock_subprocess.return_value = process_mock

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "error"
        assert "Authentication error" in result["output"]
        assert "Unable to locate credentials" in result["output"]
        assert "Please check your AWS credentials" in result["output"]


@pytest.mark.asyncio
async def test_execute_aws_command_timeout():
    """Test command timeout."""
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        # Mock a process that times out
        process_mock = AsyncMock()
        # Use a properly awaitable mock that raises TimeoutError
        communicate_mock = AsyncMock(side_effect=asyncio.TimeoutError())
        process_mock.communicate = communicate_mock
        mock_subprocess.return_value = process_mock

        # Mock a regular function instead of an async one for process.kill
        process_mock.kill = MagicMock()

        with pytest.raises(CommandExecutionError) as excinfo:
            await execute_aws_command("aws s3 ls", timeout=1)

        # Check error message
        assert "Command timed out after 1 seconds" in str(excinfo.value)

        # Verify process was killed
        process_mock.kill.assert_called_once()


@pytest.mark.asyncio
async def test_execute_aws_command_kill_failure():
    """Test failure to kill process after timeout."""
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        # Mock a process that times out
        process_mock = AsyncMock()
        # Use a properly awaitable mock that raises TimeoutError
        communicate_mock = AsyncMock(side_effect=asyncio.TimeoutError())
        process_mock.communicate = communicate_mock
        mock_subprocess.return_value = process_mock

        # Mock process.kill to raise an exception
        process_mock.kill = MagicMock(side_effect=Exception("Failed to kill process"))

        with pytest.raises(CommandExecutionError) as excinfo:
            await execute_aws_command("aws s3 ls", timeout=1)

        # The main exception should still be about the timeout
        assert "Command timed out after 1 seconds" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_aws_command_general_exception():
    """Test handling of general exceptions during command execution."""
    with patch("asyncio.create_subprocess_shell", side_effect=Exception("Test exception")):
        with pytest.raises(CommandExecutionError) as excinfo:
            await execute_aws_command("aws s3 ls")

        assert "Failed to execute command" in str(excinfo.value)
        assert "Test exception" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_aws_command_truncate_output():
    """Test truncation of large outputs."""
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        # Mock a successful process with large output
        process_mock = AsyncMock()
        process_mock.returncode = 0

        # Generate a large output that exceeds MAX_OUTPUT_SIZE
        from aws_mcp_server.config import MAX_OUTPUT_SIZE

        large_output = "x" * (MAX_OUTPUT_SIZE + 1000)
        process_mock.communicate.return_value = (large_output.encode("utf-8"), b"")
        mock_subprocess.return_value = process_mock

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "success"
        assert len(result["output"]) <= MAX_OUTPUT_SIZE + 100  # Allow for the truncation message
        assert "output truncated" in result["output"]


def test_is_auth_error():
    """Test the is_auth_error function."""
    # Test positive cases
    auth_error_cases = [
        "Unable to locate credentials",
        "Some text before ExpiredToken and after",
        "Error: AccessDenied when attempting to perform operation",
        "AuthFailure: credentials could not be verified",
        "The security token included in the request is invalid",
        "The config profile could not be found",
    ]

    for error_msg in auth_error_cases:
        assert is_auth_error(error_msg), f"Failed to identify auth error: {error_msg}"

    # Test negative case
    non_auth_error = "S3 bucket not found"
    assert not is_auth_error(non_auth_error), f"Incorrectly identified as auth error: {non_auth_error}"


@pytest.mark.asyncio
async def test_check_aws_cli_installed():
    """Test the check_aws_cli_installed function."""
    # Test when AWS CLI is installed
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        process_mock = AsyncMock()
        process_mock.returncode = 0
        process_mock.communicate.return_value = (b"aws-cli/2.15.0", b"")
        mock_subprocess.return_value = process_mock

        result = await check_aws_cli_installed()
        assert result is True
        mock_subprocess.assert_called_once_with("aws --version", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

    # Test when AWS CLI is not installed
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        process_mock = AsyncMock()
        process_mock.returncode = 127  # Command not found
        process_mock.communicate.return_value = (b"", b"command not found")
        mock_subprocess.return_value = process_mock

        result = await check_aws_cli_installed()
        assert result is False

    # Test when subprocess raises an exception
    with patch("asyncio.create_subprocess_shell", side_effect=Exception("Test exception")):
        result = await check_aws_cli_installed()
        assert result is False


@pytest.mark.asyncio
async def test_get_command_help():
    """Test getting command help."""
    # Test successful help retrieval
    with patch("aws_mcp_server.cli_executor.execute_aws_command", new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = {"status": "success", "output": "Help text"}

        result = await get_command_help("s3", "ls")

        assert result["help_text"] == "Help text"
        mock_execute.assert_called_once_with("aws s3 ls help")

    # Test with validation error
    with patch("aws_mcp_server.cli_executor.execute_aws_command", side_effect=CommandValidationError("Test validation error")) as mock_execute:
        result = await get_command_help("s3", "ls")

        assert "Command validation error" in result["help_text"]
        assert "Test validation error" in result["help_text"]

    # Test with execution error
    with patch("aws_mcp_server.cli_executor.execute_aws_command", side_effect=CommandExecutionError("Test execution error")) as mock_execute:
        result = await get_command_help("s3", "ls")

        assert "Error retrieving help" in result["help_text"]
        assert "Test execution error" in result["help_text"]

    # Test with generic exception
    with patch("aws_mcp_server.cli_executor.execute_aws_command", side_effect=Exception("Test exception")) as mock_execute:
        result = await get_command_help("s3", "ls")

        assert "Error retrieving help" in result["help_text"]
        assert "Test exception" in result["help_text"]

    # Test without command parameter
    with patch("aws_mcp_server.cli_executor.execute_aws_command", new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = {"status": "success", "output": "Help text for service"}

        result = await get_command_help("s3")

        assert result["help_text"] == "Help text for service"
        mock_execute.assert_called_once_with("aws s3 help")


def test_validate_pipe_command_valid():
    """Test validating valid pipe commands."""
    # These commands should pass validation
    valid_commands = [
        "aws s3 ls | grep bucket",
        "aws ec2 describe-instances | grep running | wc -l",
        "aws s3api list-buckets --query 'Buckets[*].Name' --output text | sort",
    ]

    for cmd in valid_commands:
        try:
            validate_pipe_command(cmd)
        except CommandValidationError as e:
            pytest.fail(f"Command should be valid but failed validation: {cmd}\nError: {str(e)}")


def test_validate_pipe_command_invalid():
    """Test validating invalid pipe commands."""
    # These commands should fail validation
    invalid_commands = [
        # Empty command
        "",
        # First command not AWS
        "ls | grep aws",
        # Invalid second command
        "aws s3 ls | invalid_cmd",
        # First command invalid AWS
        "aws | grep bucket",
    ]

    for cmd in invalid_commands:
        with pytest.raises(CommandValidationError):
            validate_pipe_command(cmd)


@pytest.mark.asyncio
async def test_execute_aws_command_with_pipe():
    """Test execute_aws_command with a piped command."""
    # Test that execute_aws_command calls execute_pipe_command for piped commands
    with patch("aws_mcp_server.cli_executor.is_pipe_command", return_value=True):
        with patch("aws_mcp_server.cli_executor.execute_pipe_command", new_callable=AsyncMock) as mock_pipe_exec:
            mock_pipe_exec.return_value = {"status": "success", "output": "Piped result"}

            result = await execute_aws_command("aws s3 ls | grep bucket")

            assert result["status"] == "success"
            assert result["output"] == "Piped result"
            mock_pipe_exec.assert_called_once_with("aws s3 ls | grep bucket", None)


@pytest.mark.asyncio
async def test_execute_pipe_command_success():
    """Test successful execution of a pipe command."""
    with patch("aws_mcp_server.cli_executor.validate_pipe_command") as mock_validate:
        with patch("aws_mcp_server.cli_executor.execute_piped_command", new_callable=AsyncMock) as mock_pipe_exec:
            mock_pipe_exec.return_value = {"status": "success", "output": "Filtered results"}

            result = await execute_pipe_command("aws s3 ls | grep bucket")

            assert result["status"] == "success"
            assert result["output"] == "Filtered results"
            mock_validate.assert_called_once_with("aws s3 ls | grep bucket")
            mock_pipe_exec.assert_called_once_with("aws s3 ls | grep bucket", None)


@pytest.mark.asyncio
async def test_execute_pipe_command_validation_error():
    """Test execute_pipe_command with validation error."""
    with patch("aws_mcp_server.cli_executor.validate_pipe_command", side_effect=CommandValidationError("Invalid pipe command")):
        with pytest.raises(CommandValidationError) as excinfo:
            await execute_pipe_command("invalid | pipe | command")

        assert "Invalid pipe command" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_pipe_command_execution_error():
    """Test execute_pipe_command with execution error."""
    with patch("aws_mcp_server.cli_executor.validate_pipe_command"):
        with patch("aws_mcp_server.cli_executor.execute_piped_command", side_effect=Exception("Execution error")):
            with pytest.raises(CommandExecutionError) as excinfo:
                await execute_pipe_command("aws s3 ls | grep bucket")

            assert "Failed to execute piped command" in str(excinfo.value)
            assert "Execution error" in str(excinfo.value)
