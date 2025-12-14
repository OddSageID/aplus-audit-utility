# Contributing to A+ System Audit Utility

Thank you for your interest in contributing! While this is an academic project for FLCC's Cybersecurity & Networking program, suggestions and feedback are welcome.

## Author

**Kevin Hormaza**  
GitHub: [@OddSageID](https://github.com/OddSageID)  
Program: A.A.S. Cybersecurity & Networking  
Institution: Finger Lakes Community College

## Academic Context

This project serves as the final project for the Technical Support Fundamentals course. The codebase demonstrates:
- Production-ready software engineering practices
- Security best practices and compliance standards
- AI integration capabilities
- Enterprise-grade features (database, metrics, monitoring)

## Ways to Contribute

### 🐛 Bug Reports

If you find a bug, please create an issue with:
- **Description**: Clear description of the issue
- **Steps to Reproduce**: Minimal steps to reproduce the behavior
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Environment**: OS, Python version, relevant dependencies
- **Logs**: Any error messages or relevant log output

### 💡 Feature Suggestions

Feature requests are welcome! Please include:
- **Use Case**: Why this feature would be valuable
- **Proposed Solution**: How you envision it working
- **Alternatives**: Any alternative solutions you've considered
- **Additional Context**: Screenshots, mockups, or examples

### 📝 Documentation Improvements

Documentation contributions are valuable:
- Clarifying confusing sections
- Adding examples
- Fixing typos
- Improving code comments

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Git for version control
- (Optional) Docker for containerized development

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/OddSageID/aplus-audit-utility.git
cd aplus-audit-utility

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-asyncio pytest-cov black flake8 mypy

# Verify setup
python setup_check.py

# Run tests
pytest
```

### Project Structure

```
aplus-audit-utility/
├── src/
│   ├── core/           # Core infrastructure (config, logging, orchestration)
│   ├── collectors/     # Data collection modules
│   ├── analyzers/      # AI analysis integration
│   ├── reporters/      # Report generation
│   └── database/       # Data persistence layer
├── tests/              # Comprehensive test suite
├── main.py            # CLI entry point
└── setup_check.py     # Environment validation
```

## Development Guidelines

### Code Style

This project follows PEP 8 with some modifications:

```bash
# Format code with Black
black src/ tests/ main.py

# Check style with flake8
flake8 src/ tests/ --max-line-length=100

# Type checking with mypy
mypy src/ --ignore-missing-imports
```

**Key Conventions:**
- Line length: 100 characters (not 80)
- Use type hints for function signatures
- Docstrings for all public functions/classes
- Follow existing patterns in the codebase

### Writing Tests

All new features should include tests:

```python
# tests/test_new_feature.py
import pytest
from src.module import new_function

def test_new_function_success():
    """Test successful operation"""
    result = new_function("input")
    assert result == "expected"

def test_new_function_error():
    """Test error handling"""
    with pytest.raises(ValueError):
        new_function("invalid")
```

**Test Guidelines:**
- Aim for 80%+ coverage
- Test both success and failure cases
- Use descriptive test names
- Mock external dependencies (APIs, file system)

### Commit Messages

Follow conventional commit format:

```
type(scope): brief description

Longer explanation if needed.

Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

**Examples:**
```
feat(collectors): add macOS FileVault status check

Implements CIS Benchmark 2.5.3 check for FileVault encryption
status on macOS systems.

Closes #45
```

## Pull Request Process

### Before Submitting

1. **Run Tests**: Ensure all tests pass
   ```bash
   pytest -v
   ```

2. **Check Coverage**: Maintain or improve coverage
   ```bash
   pytest --cov=src --cov-report=html
   ```

3. **Format Code**: Apply consistent formatting
   ```bash
   black src/ tests/
   flake8 src/ tests/ --max-line-length=100
   ```

4. **Update Documentation**: Update relevant docs
   - README.md for user-facing changes
   - CHANGELOG.md for version history
   - Docstrings for code changes

### Submitting

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/amazing-feature`
3. Make your changes
4. Commit with descriptive messages
5. Push to your fork: `git push origin feat/amazing-feature`
6. Open a Pull Request

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All existing tests pass
- [ ] New tests added for changes
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
```

## Architecture Principles

### Design Patterns

The codebase implements several patterns:

1. **Facade Pattern** (`AuditOrchestrator`)
   - Simplifies complex audit workflow
   - Coordinates multiple subsystems

2. **Template Method** (`BaseCollector`)
   - Defines algorithm skeleton
   - Allows subclass customization

3. **Repository Pattern** (`AuditRepository`)
   - Abstracts data access
   - Provides clean CRUD interface

4. **Circuit Breaker** (`RateLimiter`)
   - Handles API failures gracefully
   - Implements exponential backoff

5. **Strategy Pattern** (AI Providers)
   - Supports multiple implementations
   - Runtime provider selection

### Best Practices

- **Type Hints**: Use throughout for clarity
- **Error Handling**: Graceful degradation over crashes
- **Async/Await**: For concurrent operations
- **Validation**: Input validation using Pydantic
- **Logging**: Comprehensive logging for debugging
- **Testing**: High coverage with meaningful tests

## Security Considerations

When contributing security-related code:

- Follow principle of least privilege
- Validate all inputs (use Pydantic schemas)
- Never store credentials in code
- Use parameterized queries (SQLAlchemy)
- Implement rate limiting for external APIs
- Document security assumptions
- Test for common vulnerabilities

## Questions?

- **GitHub Issues**: For bug reports and features
- **GitHub Discussions**: For questions and ideas
- **Email**: Available via GitHub profile

## Academic Integrity Note

This is a student project. While contributions are welcome, the original work for academic credit is solely by Kevin Hormaza. Any significant external contributions will be clearly attributed.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

---

Thank you for helping improve this project! 🚀
