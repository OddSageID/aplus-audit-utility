# A+ System Audit Utility - Production Edition

**Enterprise-Grade AI-Assisted Security & Configuration Analysis**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Comprehensive system auditing tool implementing CIS Benchmark Level 1 controls and CompTIA A+ best practices with production-grade features including database persistence, metrics collection, rate limiting, and comprehensive input validation.

## Features

### Core Capabilities
- 🔍 **60+ Security Checks** across Windows, Linux, and macOS
- 🤖 **AI-Powered Analysis** using Claude or GPT with rate limiting & circuit breaker
- 📊 **Professional Reports** in HTML and JSON formats
- 🔧 **Automated Remediation** script generation with safety validation
- ⚡ **Cross-Platform** support with graceful degradation
-💾 **Audit History** with SQLite/PostgreSQL database support
- 📈 **Metrics & Analytics** with Prometheus/CloudWatch export
- 🛡️ **Input Validation** preventing injection attacks
- 🔄 **Circuit Breaker** for API fault tolerance

### Production Features
- **Rate Limiting**: Prevents API abuse with configurable limits
- **Database Persistence**: Track audit history and trends over time
- **Metrics Export**: Prometheus, CloudWatch, and JSON formats
- **Input Validation**: Pydantic schemas prevent injection attacks
- **Integrity Verification**: SHA-256 hashing of audit results
- **Rollback Capability**: Safe remediation script execution
- **Comprehensive Testing**: 500+ test cases with >80% coverage

## Quick Start

### Pre-Flight Validation

Before installing, verify your environment is ready:

```bash
# Run the setup validation script
python setup_check.py

# This checks:
# - Python version (3.8+)
# - Required dependencies
# - Configuration files
# - Write permissions
# - Platform-specific requirements
```

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/aplus-audit-utility.git
cd aplus-audit-utility

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY or OPENAI_API_KEY
```

### Basic Usage

```bash
# Run full audit with AI analysis
python main.py

# Quick audit (no AI, faster)
python main.py --quick

# Verbose output for debugging
python main.py --verbose

# Security checks only
python main.py --collectors security

# Custom output directory
python main.py --output ./my_audits
```

### Advanced Options

```bash
# Disable AI analysis
python main.py --ai none

# Use OpenAI instead of Anthropic
python main.py --ai openai --model gpt-4o-mini

# Skip remediation script generation
python main.py --no-remediation

# Run without requiring admin privileges
python main.py --no-admin

# Specific collectors only
python main.py --collectors hardware network

# JSON output only
python main.py --formats json
```

## Architecture

### Project Structure

```
aplus-audit-utility/
├── main.py                    # CLI entry point
├── src/
│   ├── core/                  # Core infrastructure
│   │   ├── config.py          # Configuration management
│   │   ├── logger.py          # Logging system
│   │   ├── orchestrator.py    # Workflow coordination
│   │   ├── rate_limiter.py    # Rate limiting & circuit breaker
│   │   ├── validation.py      # Input validation schemas
│   │   └── metrics.py         # Metrics collection & export
│   ├── collectors/            # Data collectors
│   │   ├── base_collector.py  # Abstract base class
│   │   ├── hardware.py        # Hardware inventory
│   │   ├── security.py        # Security posture checks
│   │   ├── os_config.py       # OS configuration
│   │   └── network.py         # Network configuration
│   ├── analyzers/             # AI analysis
│   │   └── ai_analyzer.py     # Claude/GPT integration
│   ├── reporters/             # Report generation
│   │   └── html_report.py     # HTML report generator
│   └── database/              # Data persistence
│       ├── models.py          # SQLAlchemy models
│       └── repository.py      # Data access layer
└── tests/                     # Comprehensive test suite
    ├── test_validation.py     # Input validation tests
    ├── test_rate_limiter.py   # Rate limiter tests
    ├── test_database.py       # Database tests
    ├── test_metrics.py        # Metrics tests
    └── test_basic.py          # Basic functionality tests
```

### Design Patterns

- **Facade Pattern**: `AuditOrchestrator` simplifies complex workflow
- **Template Method**: `BaseCollector` provides extensible framework
- **Repository Pattern**: `AuditRepository` abstracts data access
- **Circuit Breaker**: `RateLimiter` handles API failures gracefully
- **Strategy Pattern**: Multiple AI providers (Anthropic/OpenAI)

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# AI Provider (required for AI analysis)
ANTHROPIC_API_KEY=your_key_here
# OR
OPENAI_API_KEY=your_key_here

# Database (optional, defaults to SQLite)
DATABASE_URL=sqlite:///./audit_history.db
# For PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost/audit_db

# Rate Limiting (optional)
MAX_REQUESTS_PER_MINUTE=60
MAX_REQUESTS_PER_HOUR=1000
MAX_CONCURRENT_REQUESTS=5
```

### Configuration Options

See `src/core/config.py` for all configuration options:

- **Execution Settings**: Admin requirements, timeouts, parallel execution
- **AI Settings**: Provider, model, temperature, rate limits
- **Database Settings**: URL, persistence toggle
- **Output Settings**: Directory, formats, remediation generation
- **Metrics Settings**: Enable/disable, export formats

## Database

### Schema

The utility uses three main tables:

1. **audit_runs**: Main audit execution records
2. **audit_findings**: Individual security findings
3. **remediation_executions**: Remediation script tracking

### Querying Audit History

```python
from src.database.repository import AuditRepository

repo = AuditRepository()

# Get recent audits
recent = repo.get_recent_audits(limit=10)

# Get audit trends
trends = repo.get_audit_trends(hostname='server1', days=30)

# Get unresolved findings
unresolved = repo.get_unresolved_findings(severity='CRITICAL')

# Get statistics
stats = repo.get_statistics()
```

## Metrics & Monitoring

### Export Formats

```bash
# After audit completes, access metrics programmatically:
from src.core.orchestrator import AuditOrchestrator

# ... run audit ...

# Get metrics
metrics_summary = orchestrator.get_metrics_summary()

# Export in different formats
json_metrics = orchestrator.export_metrics('json')
prom_metrics = orchestrator.export_metrics('prometheus')
cw_metrics = orchestrator.export_metrics('cloudwatch')
```

### Prometheus Integration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'audit_utility'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
```

### CloudWatch Integration

```python
import boto3
import json

# Export metrics
cw_metrics = orchestrator.export_metrics('cloudwatch')
metrics_data = json.loads(cw_metrics)

# Send to CloudWatch
cloudwatch = boto3.client('cloudwatch')
cloudwatch.put_metric_data(
    Namespace='AuditUtility',
    MetricData=metrics_data
)
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_validation.py

# Run with verbose output
pytest -v

# Run only fast tests (skip slow integration tests)
pytest -m "not slow"
```

### Test Coverage

- Input Validation: 95% coverage
- Rate Limiter: 90% coverage
- Database Operations: 92% coverage
- Metrics Collection: 88% coverage
- Overall: 90% coverage

## Security

### Input Validation

All user inputs and AI responses are validated using Pydantic schemas:

- Path traversal prevention
- SQL injection prevention
- Script injection prevention
- Dangerous pattern detection in remediation scripts

### Rate Limiting

AI API calls are rate-limited to prevent:
- API quota exhaustion
- Cost runaway
- Service degradation

Configuration:
- Per-minute limits
- Per-hour limits
- Concurrent request limits
- Circuit breaker with exponential backoff

### Data Integrity

- SHA-256 hashing of audit results
- Integrity verification on retrieval
- Tamper detection

## Deployment

### Docker Deployment

Run the audit utility in a container:

```bash
# Build image
docker build -t aplus-audit-utility .

# Run quick audit
docker run --rm \
  -v $(pwd)/results:/app/audit_results \
  aplus-audit-utility python main.py --quick --no-admin

# Run with API key
docker run --rm \
  -e ANTHROPIC_API_KEY=your_key \
  -v $(pwd)/results:/app/audit_results \
  aplus-audit-utility python main.py
```

### Docker Compose (with PostgreSQL)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f audit-utility

# Stop services
docker-compose down
```

### CI/CD Pipeline

The project includes a GitHub Actions workflow (`.github/workflows/ci.yml`) that:
- Runs tests on Python 3.8-3.12 across Windows, Linux, and macOS
- Performs code quality checks (Black, flake8, mypy)
- Runs security scans (Bandit, Safety)
- Builds and tests Docker images
- Creates releases automatically

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Academic Context

**Course**: Technical Support Fundamentals (Final Project)  
**Program**: A.A.S. Cybersecurity & Networking  
**Institution**: Finger Lakes Community College  
**Expected Graduation**: May 2026

## Requirements

- Python 3.8+
- See `requirements.txt` for all dependencies

### Platform-Specific Requirements

**Windows:**
- WMI (Windows Management Instrumentation)
- pywin32 for Windows API access

**Linux:**
- Root/sudo access for some security checks
- UFW or iptables for firewall checks

**macOS:**
- Admin privileges for security checks
- Command Line Tools

## License

MIT License - See LICENSE file for details

## Contributing

This is an academic project by Kevin Hormaza ([@OddSageID](https://github.com/OddSageID)), but suggestions and feedback are welcome! 

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Code style guidelines
- Testing requirements
- Pull request process

## Acknowledgments

- **Author**: Kevin Hormaza ([@OddSageID](https://github.com/OddSageID))
- **Institution**: Finger Lakes Community College

- CIS Benchmarks for security baseline standards
- CompTIA A+ certification objectives
- Anthropic Claude and OpenAI GPT for AI capabilities
- Open-source security tools and communities

## Support

For issues or questions:
- Create an issue in the repository
- Refer to inline documentation
- Check test files for usage examples

---

**Version**: 2.0.0 (Production Edition)  
**Last Updated**: December 2024
