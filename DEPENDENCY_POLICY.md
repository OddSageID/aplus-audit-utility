# 📦 Dependency Management Policy

**A+ System Audit Utility**  
**Author**: Kevin Hormaza (@OddSageID)  
**Last Updated**: December 14, 2024

---

## Table of Contents

1. [Overview](#overview)
2. [Update Strategy](#update-strategy)
3. [Security Vulnerability Management](#security-vulnerability-management)
4. [Testing Requirements](#testing-requirements)
5. [Approval Process](#approval-process)
6. [Monitoring & Reporting](#monitoring--reporting)

---

## Overview

This document defines policies and procedures for managing third-party dependencies in the A+ System Audit Utility. Proper dependency management ensures security, stability, and maintainability.

### Goals

- **Security**: Rapidly patch known vulnerabilities
- **Stability**: Minimize breaking changes in production
- **Currency**: Stay reasonably up-to-date with ecosystem
- **Auditability**: Track all dependency changes

### Scope

This policy applies to all dependencies across:
- Python packages (requirements.txt)
- GitHub Actions workflows
- Docker base images
- Development tools

---

## Update Strategy

### Semantic Versioning Approach

We follow semantic versioning (SemVer) principles:

| Update Type | Version Change | Strategy | Approval |
|-------------|---------------|----------|----------|
| **Patch** | `1.2.3` → `1.2.4` | Auto-merge after CI | Automated |
| **Minor** | `1.2.3` → `1.3.0` | Review + test | Maintainer |
| **Major** | `1.2.3` → `2.0.0` | Full review + integration test | Team lead |

### Update Cadence

#### Production Dependencies

```python
# Core dependencies - Update conservatively
anthropic>=0.21.0      # Monthly review, security patches only
openai>=1.12.0         # Monthly review, security patches only
pydantic>=2.0.0        # Quarterly major version review
sqlalchemy>=2.0.0      # Quarterly major version review
```

**Schedule**:
- Security patches: Immediately (within 24 hours)
- Minor updates: Weekly (automated via Dependabot)
- Major updates: Quarterly (manual review required)

#### Development Dependencies

```python
# Testing & QA tools - Update more aggressively
pytest>=7.4.0          # Monthly minor updates
black>=23.0.0          # Monthly minor updates
flake8>=6.0.0          # Monthly minor updates
```

**Schedule**:
- All updates: Weekly (automated via Dependabot)
- Breaking changes: Review before merge

#### Platform-Specific Dependencies

```python
# Windows-only
wmi>=1.5.1; platform_system=="Windows"
pywin32>=306; platform_system=="Windows"
```

**Schedule**:
- Security patches: Within 48 hours
- Minor updates: Bi-weekly
- Tested on Windows CI runners before merge

---

## Security Vulnerability Management

### Vulnerability Scanning

**Tools**:
1. **GitHub Dependabot**: Automatic security advisories
2. **Safety**: Python package vulnerability scanner
3. **Bandit**: Python code security scanner

**Frequency**:
- Dependabot: Continuous monitoring
- Safety check: Every CI run
- Bandit scan: Every CI run

### Response Procedures

#### Critical Vulnerabilities (CVSS >= 9.0)

```
Timeline: Immediate response (< 4 hours)
```

**Response Steps**:

1. **Triage** (< 1 hour)
   ```bash
   # Verify vulnerability applies to our usage
   safety check --json | jq '.vulnerabilities'
   
   # Check CVE details
   curl https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX
   ```

2. **Patch** (< 2 hours)
   ```bash
   # Update vulnerable package
   pip install --upgrade vulnerable-package
   
   # Run full test suite
   pytest tests/ --cov=src
   
   # Deploy to production immediately
   ```

3. **Notification** (< 4 hours)
   - Security team notification
   - Post-mortem within 24 hours
   - Update CHANGELOG.md

#### High Vulnerabilities (CVSS 7.0-8.9)

```
Timeline: 24 hours
```

**Response Steps**:

1. **Assessment** (< 4 hours)
   - Determine if vulnerability affects our code paths
   - Identify workarounds if patch not available

2. **Testing** (< 12 hours)
   - Update dependency
   - Run integration tests
   - Test on all supported platforms

3. **Deployment** (< 24 hours)
   - Merge patch
   - Deploy to staging
   - Monitor for 2 hours
   - Deploy to production

#### Medium/Low Vulnerabilities (CVSS < 7.0)

```
Timeline: 1 week
```

**Response Steps**:
- Include in next scheduled dependency update
- Group with other minor updates
- Standard testing and approval process

### Exemptions

If a vulnerability cannot be patched immediately:

1. **Document** in `SECURITY.md`
2. **Implement** compensating controls
3. **Track** in GitHub Issues
4. **Review** weekly until resolved

Example exemption:
```markdown
## Known Vulnerabilities

### CVE-2024-XXXX (psutil v5.9.5)
- **Severity**: Medium (CVSS 5.5)
- **Status**: No patch available
- **Workaround**: Disabled affected feature (network monitoring)
- **Tracking**: Issue #42
- **Target Resolution**: Q1 2025
```

---

## Testing Requirements

### Automated Testing

All dependency updates must pass:

```yaml
# .github/workflows/ci.yml excerpt
- name: Run tests with new dependencies
  run: |
    pytest tests/ -v --cov=src --cov-report=xml
    
- name: Security scan
  run: |
    bandit -r src/ -f json
    safety check --json
    
- name: Type checking
  run: |
    mypy src/ --ignore-missing-imports
    
- name: Code quality
  run: |
    black --check src/ tests/
    flake8 src/ tests/ --max-line-length=100
```

**Pass Criteria**:
- ✅ All unit tests pass
- ✅ Code coverage >= 90%
- ✅ No new security vulnerabilities
- ✅ Type checking passes
- ✅ Code formatting maintained

### Platform Testing Matrix

Updates must pass on:

```yaml
matrix:
  os: [ubuntu-latest, windows-latest, macos-latest]
  python-version: ['3.8', '3.9', '3.10', '3.11', '3.12']
```

**15 total combinations** must pass before merge.

### Integration Testing

For major version updates:

```bash
# Run full integration test suite
python main.py --quick --no-admin --verbose

# Verify database migrations
alembic upgrade head
alembic downgrade -1
alembic upgrade head

# Test AI providers
export ANTHROPIC_API_KEY=test_key
python -c "from src.analyzers.ai_analyzer import AIAnalyzer; AIAnalyzer().test()"

# Test Docker build
docker build -t test-update .
docker run --rm test-update python -c "import sys; sys.exit(0)"
```

---

## Approval Process

### Automated Approval (Patch Updates)

**Criteria**:
- Version change: Patch only (x.y.Z)
- All CI tests pass
- No security vulnerabilities introduced
- Dependabot confidence: High

**Process**:
```yaml
# .github/workflows/auto-merge-dependabot.yml
name: Auto-merge Dependabot PRs

on:
  pull_request:
    branches: [main]

jobs:
  auto-merge:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Check if patch update
        id: check
        run: |
          # Extract version change from PR title
          # Auto-approve if patch only
          
      - name: Enable auto-merge
        run: gh pr merge --auto --squash "$PR_URL"
```

### Manual Approval (Minor/Major Updates)

**Reviewers**:
- Minor updates: Any maintainer
- Major updates: Team lead + security review

**Checklist**:
- [ ] CHANGELOG.md reviewed
- [ ] Breaking changes documented
- [ ] Migration guide provided (if applicable)
- [ ] All tests pass on all platforms
- [ ] Security scan clean
- [ ] Performance impact assessed
- [ ] Documentation updated

**Approval SLA**:
- Minor updates: 48 hours
- Major updates: 1 week

---

## Monitoring & Reporting

### Weekly Dependency Health Report

**Generated**: Every Monday 9:00 AM EST  
**Distributed**: ops-team@example.com

```bash
#!/bin/bash
# scripts/dependency-report.sh

echo "=== Weekly Dependency Health Report ==="
echo "Date: $(date)"
echo ""

# Check for outdated packages
echo "## Outdated Packages"
pip list --outdated --format=columns

# Check for vulnerabilities
echo -e "\n## Security Vulnerabilities"
safety check --json | jq -r '.vulnerabilities[] | "\(.package): \(.vulnerability)"'

# Dependency graph
echo -e "\n## Dependency Tree"
pipdeptree --warn silence | head -50

# Update statistics
echo -e "\n## Update Statistics"
echo "Dependabot PRs this week: $(gh pr list --label dependencies --state all | wc -l)"
echo "Auto-merged: $(gh pr list --label dependencies --search 'is:merged' | wc -l)"
echo "Pending review: $(gh pr list --label dependencies --state open | wc -l)"
```

### Metrics Tracked

```python
# Key Performance Indicators
metrics = {
    "mean_time_to_patch": "24 hours",  # From vulnerability disclosure
    "update_success_rate": "98%",      # Updates merged without issues
    "test_pass_rate": "100%",          # CI tests for dep updates
    "security_scan_failures": 0,       # Vulnerabilities introduced
}
```

### Quarterly Dependency Audit

**Schedule**: First Monday of Q1, Q2, Q3, Q4  
**Owner**: Platform owner (Kevin Hormaza)

**Audit Tasks**:

1. **Review all dependencies**
   ```bash
   pip list --format=freeze > dependencies-$(date +%Y-Q1).txt
   ```

2. **Identify unused dependencies**
   ```bash
   pip-autoremove --list
   ```

3. **Check for abandoned packages**
   - Last release > 2 years ago
   - No active maintainers
   - Known security issues

4. **License compliance**
   ```bash
   pip-licenses --format=markdown > LICENSE-REPORT.md
   ```

5. **Update policy if needed**
   - Review and update this document
   - Adjust Dependabot configuration
   - Update CI/CD pipelines

---

## Exception Handling

### Pinned Dependencies

Some dependencies may be pinned to specific versions:

```python
# Example: Known breaking changes in newer version
pydantic==2.5.0  # Pinned until migration to 2.6.x complete
```

**Requirements**:
- Document reason in inline comment
- Create tracking issue
- Set review date (max 90 days)
- Security patches still required

### Private/Internal Dependencies

Not applicable to this open-source project, but if used:

```python
# Private packages from internal PyPI server
my-company-auth @ git+ssh://git@github.com/company/auth.git@v1.2.3
```

**Additional Requirements**:
- Maintain separate requirements-internal.txt
- Document internal update process
- Ensure CI has access to private repos

---

## Continuous Improvement

### Policy Review

This policy is reviewed:
- **Monthly**: Security procedures
- **Quarterly**: Update strategies
- **Annually**: Complete policy revision

### Feedback Loop

Track and analyze:
- Failed dependency updates
- Time to patch vulnerabilities
- Update-related production incidents
- Developer friction points

### Updates to This Policy

Changes to this policy require:
1. Pull request with rationale
2. Team discussion
3. Approval from platform owner
4. Communication to all contributors

---

## Appendix

### A. Useful Commands

```bash
# Check for outdated packages
pip list --outdated

# Check for security vulnerabilities
safety check

# Update specific package
pip install --upgrade package-name

# Update all packages (USE WITH CAUTION)
pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 pip install -U

# Generate requirements file
pip freeze > requirements.txt

# Check dependency tree
pipdeptree

# Verify package integrity
pip hash package-name
```

### B. Security Resources

- **NVD**: https://nvd.nist.gov/
- **PyPI Advisory Database**: https://github.com/pypa/advisory-database
- **Safety DB**: https://github.com/pyupio/safety-db
- **Dependabot Docs**: https://docs.github.com/en/code-security/dependabot

### C. Related Documentation

- [SECURITY.md](SECURITY.md) - Security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [CHANGELOG.md](CHANGELOG.md) - Version history

---

**Policy Version**: 1.0  
**Effective Date**: December 14, 2024  
**Next Review**: March 14, 2025  
**Owner**: Kevin Hormaza (@OddSageID)
