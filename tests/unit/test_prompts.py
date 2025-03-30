"""Unit tests for AWS MCP Server prompts.

Tests the prompt templates functionality in the AWS MCP Server.
"""

from unittest.mock import MagicMock

import pytest

from aws_mcp_server.prompts import register_prompts


@pytest.fixture
def prompt_functions():
    """Fixture that returns a dictionary of prompt functions.

    This fixture captures all prompt functions registered with the MCP instance.
    """
    captured_functions = {}

    # Create a special mock decorator that captures the functions
    def mock_prompt_decorator():
        def decorator(func):
            captured_functions[func.__name__] = func
            return func

        return decorator

    mock_mcp = MagicMock()
    mock_mcp.prompt = mock_prompt_decorator

    # Register prompts with our special mock
    register_prompts(mock_mcp)

    return captured_functions


def test_prompt_registration(prompt_functions):
    """Test that prompts are registered correctly."""
    # Check that we captured the expected number of functions
    expected_prompt_count = 10  # Update this if you add more prompts
    assert len(prompt_functions) == expected_prompt_count


def test_create_resource_prompt(prompt_functions):
    """Test the create_resource prompt template."""
    # Get the captured function
    create_resource = prompt_functions.get("create_resource")
    assert create_resource is not None, "create_resource prompt not found"

    # Test prompt output
    prompt_text = create_resource("s3-bucket", "my-test-bucket")
    assert "s3-bucket" in prompt_text
    assert "my-test-bucket" in prompt_text
    assert "security" in prompt_text.lower()
    assert "best practices" in prompt_text.lower()


def test_security_audit_prompt(prompt_functions):
    """Test the security_audit prompt template."""
    # Get the captured function
    security_audit = prompt_functions.get("security_audit")
    assert security_audit is not None, "security_audit prompt not found"

    # Test prompt output
    prompt_text = security_audit("s3")
    assert "s3" in prompt_text
    assert "security audit" in prompt_text.lower()
    assert "public access" in prompt_text.lower()


def test_cost_optimization_prompt(prompt_functions):
    """Test the cost_optimization prompt template."""
    # Get the captured function
    cost_optimization = prompt_functions.get("cost_optimization")
    assert cost_optimization is not None, "cost_optimization prompt not found"

    # Test prompt output
    prompt_text = cost_optimization("ec2")
    assert "ec2" in prompt_text
    assert "cost optimization" in prompt_text.lower()
    assert "unused" in prompt_text.lower()
