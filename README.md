# AWS MCP Server

## What is this?

AWS MCP Server is a tool that lets you control and manage your AWS infrastructure through simple commands. It connects to the Model Context Protocol (MCP), which means AI assistants like Claude can directly manage your AWS resources for you.

Think of it as a **smart AWS assistant** that can:
- 🔍 Find security problems in your AWS account
- 💰 Analyze and reduce your AWS costs
- 🚀 Automate repetitive AWS tasks
- 📊 Monitor your infrastructure health
- 🛡️ Ensure compliance with security standards

## What can I actually do with it?

### 1. **Talk to AWS through AI**
Instead of writing complex AWS CLI commands, just ask:
```
"Show me all my EC2 instances in us-east-1"
"Find security issues in my AWS account"
"Analyze my AWS costs and suggest savings"
```

### 2. **Automated Security Scanning**
```python
# Automatically scan for security issues
await compliance_scan(framework="PCI_DSS", auto_remediate=True)

# Find exposed S3 buckets
await security_hub_get_findings(severity_threshold="HIGH")

# Detect suspicious activity
await guardduty_get_threats(severity_threshold="MEDIUM")
```

### 3. **Cost Optimization**
```python
# Get AI-powered cost recommendations
await optimize_costs(optimization_goal="reduce by 30%")

# Detect unusual spending
await detect_cost_anomalies(services=["EC2", "RDS"])
```

### 4. **Smart Automation**
```python
# Auto-scale when CPU is high
await create_automation_rule(
    rule_name="AutoScaleOnHighCPU",
    trigger_type="threshold",
    conditions={"metric": "CPUUtilization", "threshold": 80},
    actions=["scale_out"]
)
```

### 5. **Fast Performance Features**
- **Cache AWS API responses** - Don't repeat expensive API calls
- **Connection pooling** - Reuse AWS connections for speed
- **Background jobs** - Run long tasks without waiting

## Real-World Examples

### Example 1: Security Audit
```bash
# Ask the AI: "Run a security audit on my AWS account"
# It will:
# 1. Scan all your resources
# 2. Check against security frameworks (PCI, HIPAA, etc.)
# 3. Find vulnerabilities
# 4. Suggest fixes
# 5. Optionally fix them automatically
```

### Example 2: Cost Reduction
```bash
# Ask the AI: "Help me reduce my AWS bill"
# It will:
# 1. Analyze your spending patterns
# 2. Find unused resources
# 3. Suggest right-sizing for overprovisioned instances
# 4. Recommend reserved instances
# 5. Identify cost anomalies
```

### Example 3: Infrastructure Discovery
```bash
# Ask the AI: "What resources do I have in all regions?"
# It will:
# 1. Scan all AWS regions
# 2. List EC2, RDS, S3, Lambda, etc.
# 3. Show resource relationships
# 4. Cache results for fast access
```

## Quick Start

### 1. Install
```bash
git clone https://github.com/yourusername/aws-mcp-server.git
cd aws-mcp-server
pip install -e .
```

### 2. Configure AWS
```bash
# Make sure AWS CLI is configured
aws configure
```

### 3. Start the Server
```bash
# Basic start
python -m aws_mcp_server

# With Redis for caching (recommended)
docker run -d -p 6379:6379 redis:alpine
python -m aws_mcp_server
```

### 4. Use with Claude Desktop
Add to your Claude Desktop config:
```json
{
  "mcpServers": {
    "aws": {
      "command": "python",
      "args": ["-m", "aws_mcp_server"],
      "cwd": "/path/to/aws-mcp-server"
    }
  }
}
```

Now you can ask Claude to manage your AWS resources!

## Key Features Explained

### 🛡️ **Security Features**
- **Security Hub**: Aggregates security findings from all AWS security services
- **GuardDuty**: Detects malicious activity and unauthorized behavior
- **IAM Analyzer**: Finds overly permissive policies and suggests improvements
- **Compliance Scanner**: Checks if you meet PCI, HIPAA, SOC2 requirements
- **Secrets Manager**: Securely stores and rotates credentials

### ⚡ **Performance Features**
- **Redis Caching**: Stores API responses to avoid repeated calls
- **Connection Pooling**: Reuses AWS connections instead of creating new ones
- **Async Jobs**: Runs long operations in the background
- **Progress Tracking**: Shows real-time progress for long operations

### 🤖 **AI Features**
- **Error Analysis**: AI explains AWS errors and how to fix them
- **Architecture Recommendations**: Suggests best AWS services for your needs
- **Cost Optimization**: AI analyzes spending and suggests savings
- **Anomaly Detection**: Finds unusual patterns in costs or usage

### 🔌 **Integration Features**
- **MCP Protocol**: Works with AI assistants like Claude
- **REST API**: Integrate with your existing tools
- **Webhooks**: Send alerts to Slack, Teams, etc.
- **Event-Driven**: React to AWS events automatically

## Common Use Cases

### For DevOps Engineers
- Automate security scans before deployments
- Monitor infrastructure health across multiple accounts
- Set up auto-scaling rules based on custom metrics
- Track and optimize AWS costs

### For Security Teams
- Continuous compliance monitoring
- Automated vulnerability scanning
- Real-time threat detection
- Policy violation alerts

### For Finance Teams
- Cost anomaly detection
- Budget alerts and forecasting
- Resource utilization reports
- Reserved instance recommendations

### For Developers
- Quick infrastructure discovery
- Error troubleshooting with AI
- Automated resource provisioning
- Performance optimization

## Architecture Overview

```
Your Request → MCP Protocol → AWS MCP Server → AWS APIs
                                   ↓
                            Cache & Job Queue
                                   ↓
                         Security & Performance
                              Features
```

## What Makes This Special?

1. **AI-Native**: Built specifically for AI assistants to manage AWS
2. **Comprehensive**: Covers security, cost, performance, and automation
3. **Fast**: Caching and connection pooling for quick responses
4. **Secure**: Built-in security scanning and compliance
5. **Extensible**: Easy to add new features and integrations

## Requirements

- Python 3.13+
- AWS CLI configured with credentials
- Redis (optional but recommended for caching)
- AWS account with appropriate permissions

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/aws-mcp-server/issues)
- Documentation: See `/docs` folder
- Examples: See `/examples` folder

## License

MIT License - see LICENSE file for details.