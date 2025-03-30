"""Live AWS integration tests for the AWS MCP Server.

These tests connect to real AWS resources and require:
1. AWS CLI installed locally
2. AWS credentials configured with access to test resources
3. An S3 bucket for testing (set via AWS_TEST_BUCKET environment variable)
4. The --run-integration flag when running pytest
"""

import json
import logging
import os

import pytest

from aws_mcp_server.server import describe_command, execute_command

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@pytest.mark.integration
class TestAWSLiveIntegration:
    """Integration tests that interact with real AWS services.

    These tests require AWS credentials and actual AWS resources.
    They verify the AWS MCP Server can properly interact with AWS.
    """

    @pytest.mark.asyncio
    async def test_describe_s3_command(self, ensure_aws_credentials):
        """Test getting help for AWS S3 commands."""
        result = await describe_command(service="s3", command=None, ctx=None)

        # Verify we got a valid response
        assert isinstance(result, dict)
        assert "help_text" in result
        assert "DESCRIPTION" in result["help_text"] or "description" in result["help_text"].lower()

        # Verify s3 commands are listed
        help_text = result["help_text"].lower()
        assert "ls" in help_text
        assert "cp" in help_text
        assert "mv" in help_text

    @pytest.mark.asyncio
    async def test_list_s3_buckets(self, ensure_aws_credentials):
        """Test listing S3 buckets."""
        result = await execute_command(command="aws s3 ls", timeout=None, ctx=None)

        # Verify the result format
        assert isinstance(result, dict)
        assert "status" in result
        assert "output" in result
        assert result["status"] == "success"

        # Output should be a string containing the bucket listing (or empty if no buckets)
        assert isinstance(result["output"], str)

        logger.info(f"S3 bucket list result: {result['output']}")

    @pytest.mark.asyncio
    async def test_s3_operations_with_test_bucket(self, ensure_aws_credentials, aws_s3_bucket):
        """Test S3 operations using a test bucket.

        This test:
        1. Creates a test file
        2. Uploads it to S3
        3. Lists the bucket contents
        4. Downloads the file with a different name
        5. Verifies the downloaded content
        6. Cleans up all test files
        """
        test_file_name = "test_file.txt"
        test_file_content = "This is a test file for AWS MCP Server integration tests"
        downloaded_file_name = "test_file_downloaded.txt"

        try:
            # Create a local test file
            with open(test_file_name, "w") as f:
                f.write(test_file_content)

            # Upload the file to S3
            upload_result = await execute_command(command=f"aws s3 cp {test_file_name} s3://{aws_s3_bucket}/{test_file_name}", timeout=None, ctx=None)
            assert upload_result["status"] == "success"

            # List the bucket contents
            list_result = await execute_command(command=f"aws s3 ls s3://{aws_s3_bucket}/", timeout=None, ctx=None)
            assert list_result["status"] == "success"
            assert test_file_name in list_result["output"]

            # Download the file with a different name
            download_result = await execute_command(command=f"aws s3 cp s3://{aws_s3_bucket}/{test_file_name} {downloaded_file_name}", timeout=None, ctx=None)
            assert download_result["status"] == "success"

            # Verify the downloaded file content
            with open(downloaded_file_name, "r") as f:
                downloaded_content = f.read()
            assert downloaded_content == test_file_content

        finally:
            # Clean up: Remove files from S3 and local
            await execute_command(command=f"aws s3 rm s3://{aws_s3_bucket}/{test_file_name}", timeout=None, ctx=None)

            # Clean up local files
            for file_name in [test_file_name, downloaded_file_name]:
                if os.path.exists(file_name):
                    os.remove(file_name)

    @pytest.mark.asyncio
    async def test_aws_json_output_formatting(self, ensure_aws_credentials):
        """Test JSON output formatting from AWS commands."""
        # Use EC2 describe-regions as it's available in all accounts
        result = await execute_command(command="aws ec2 describe-regions --output json", timeout=None, ctx=None)

        assert result["status"] == "success"

        # The output should be valid JSON
        try:
            json_data = json.loads(result["output"])
            assert "Regions" in json_data
            assert isinstance(json_data["Regions"], list)
        except json.JSONDecodeError:
            pytest.fail("Output is not valid JSON")

    @pytest.mark.asyncio
    async def test_piped_command_execution(self, ensure_aws_credentials):
        """Test execution of a piped command with AWS CLI and Unix utilities."""
        # Use EC2 describe-regions with pipes to count regions
        result = await execute_command(command="aws ec2 describe-regions --query 'Regions[*].RegionName' --output text | wc -l", timeout=None, ctx=None)

        assert result["status"] == "success"

        # The output should be a number (count of AWS regions)
        region_count = int(result["output"].strip())

        # AWS has multiple regions, so the count should be > 0
        assert region_count > 0, "Expected at least one AWS region"

        logger.info(f"Found {region_count} AWS regions")

    @pytest.mark.asyncio
    async def test_multiple_pipes_execution(self, ensure_aws_credentials):
        """Test execution of a command with multiple pipes."""
        # Get all EC2 regions that contain 'east' and sort them
        result = await execute_command(
            command="aws ec2 describe-regions --query 'Regions[*].RegionName' --output text | grep east | sort", timeout=None, ctx=None
        )

        assert result["status"] == "success"

        # Output should contain 'east' regions only, one per line
        regions = result["output"].strip().split("\n")

        # Verify all regions contain 'east'
        for region in regions:
            assert "east" in region.lower(), f"Expected 'east' in region name: {region}"

        # Verify regions are sorted
        sorted_regions = sorted(regions)
        assert regions == sorted_regions, "Regions should be sorted"

        logger.info(f"Found and sorted {len(regions)} 'east' regions")
