"""Configuration for pytest."""

import os

import pytest


def pytest_addoption(parser):
    """Add command-line options to pytest."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests that require AWS CLI and AWS account",
    )


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: mark test as requiring AWS CLI and AWS account")


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless --run-integration is specified."""
    if config.getoption("--run-integration"):
        # Run all tests
        return

    skip_integration = pytest.mark.skip(reason="Integration tests need --run-integration option")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture
def aws_s3_bucket():
    """Return the name of the S3 bucket to use for integration tests.

    This fixture requires AWS_TEST_BUCKET environment variable to be set.
    """
    bucket_name = os.environ.get("AWS_TEST_BUCKET")
    if not bucket_name:
        pytest.skip("AWS_TEST_BUCKET environment variable not set")
    return bucket_name


@pytest.fixture
def ensure_aws_credentials():
    """Ensure AWS credentials are configured."""
    if not (os.environ.get("AWS_ACCESS_KEY_ID") or os.path.exists(os.path.expanduser("~/.aws/credentials"))):
        pytest.skip("AWS credentials not configured")
