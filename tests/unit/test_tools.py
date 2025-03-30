"""Unit tests for the tools module."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from aws_mcp_server.tools import (
    ALLOWED_UNIX_COMMANDS,
    execute_piped_command,
    is_pipe_command,
    split_pipe_command,
    validate_unix_command,
)


def test_allowed_unix_commands():
    """Test that ALLOWED_UNIX_COMMANDS contains expected commands."""
    # Verify that common Unix utilities are in the allowed list
    common_commands = ["grep", "xargs", "cat", "ls", "wc", "sort", "uniq", "jq"]
    for cmd in common_commands:
        assert cmd in ALLOWED_UNIX_COMMANDS


def test_validate_unix_command():
    """Test the validate_unix_command function."""
    # Test valid commands
    for cmd in ["grep pattern", "ls -la", "wc -l", "cat file.txt"]:
        assert validate_unix_command(cmd), f"Command should be valid: {cmd}"

    # Test invalid commands
    for cmd in ["invalid_cmd", "sudo ls", ""]:
        assert not validate_unix_command(cmd), f"Command should be invalid: {cmd}"


def test_is_pipe_command():
    """Test the is_pipe_command function."""
    # Test commands with pipes
    assert is_pipe_command("aws s3 ls | grep bucket")
    assert is_pipe_command("aws s3api list-buckets | jq '.Buckets[].Name' | sort")

    # Test commands without pipes
    assert not is_pipe_command("aws s3 ls")
    assert not is_pipe_command("aws ec2 describe-instances")

    # Test commands with pipes in quotes (should not be detected as pipe commands)
    assert not is_pipe_command("aws s3 ls 's3://my-bucket/file|other'")
    assert not is_pipe_command('aws ec2 run-instances --user-data "echo hello | grep world"')


def test_split_pipe_command():
    """Test the split_pipe_command function."""
    # Test simple pipe command
    cmd = "aws s3 ls | grep bucket"
    result = split_pipe_command(cmd)
    assert result == ["aws s3 ls", "grep bucket"]

    # Test multi-pipe command
    cmd = "aws s3api list-buckets | jq '.Buckets[].Name' | sort"
    result = split_pipe_command(cmd)
    assert result == ["aws s3api list-buckets", "jq '.Buckets[].Name'", "sort"]

    # Test with quoted pipe symbols (should not split inside quotes)
    cmd = "aws s3 ls 's3://bucket/file|name' | grep 'pattern|other'"
    result = split_pipe_command(cmd)
    assert result == ["aws s3 ls 's3://bucket/file|name'", "grep 'pattern|other'"]

    # Test with double quotes
    cmd = 'aws s3 ls "s3://bucket/file|name" | grep "pattern|other"'
    result = split_pipe_command(cmd)
    assert result == ['aws s3 ls "s3://bucket/file|name"', 'grep "pattern|other"']


@pytest.mark.asyncio
async def test_execute_piped_command_success():
    """Test successful execution of a piped command."""
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        # Mock a successful process
        process_mock = AsyncMock()
        process_mock.returncode = 0
        process_mock.communicate.return_value = (b"Filtered output", b"")
        mock_subprocess.return_value = process_mock

        result = await execute_piped_command("aws s3 ls | grep bucket")

        assert result["status"] == "success"
        assert result["output"] == "Filtered output"
        mock_subprocess.assert_called_once_with("aws s3 ls | grep bucket", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)


@pytest.mark.asyncio
async def test_execute_piped_command_error():
    """Test error handling in execute_piped_command."""
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        # Mock a failed process
        process_mock = AsyncMock()
        process_mock.returncode = 1
        process_mock.communicate.return_value = (b"", b"Command not found: xyz")
        mock_subprocess.return_value = process_mock

        result = await execute_piped_command("aws s3 ls | xyz")

        assert result["status"] == "error"
        assert "Command not found: xyz" in result["output"]


@pytest.mark.asyncio
async def test_execute_piped_command_timeout():
    """Test timeout handling in execute_piped_command."""
    with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_subprocess:
        # Mock a process that times out
        process_mock = AsyncMock()
        # Use a properly awaitable mock that raises TimeoutError
        communicate_mock = AsyncMock(side_effect=asyncio.TimeoutError())
        process_mock.communicate = communicate_mock
        process_mock.kill = AsyncMock()
        mock_subprocess.return_value = process_mock

        result = await execute_piped_command("aws s3 ls | grep bucket", timeout=1)

        assert result["status"] == "error"
        assert "Command timed out after 1 seconds" in result["output"]
        process_mock.kill.assert_called_once()


@pytest.mark.asyncio
async def test_execute_piped_command_exception():
    """Test general exception handling in execute_piped_command."""
    with patch("asyncio.create_subprocess_shell", side_effect=Exception("Test exception")):
        result = await execute_piped_command("aws s3 ls | grep bucket")

        assert result["status"] == "error"
        assert "Failed to execute command" in result["output"]
        assert "Test exception" in result["output"]
