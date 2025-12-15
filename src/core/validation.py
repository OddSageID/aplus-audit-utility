"""
Input validation schemas for all user inputs and API responses.
Prevents injection attacks and ensures data integrity.

UPDATED FOR PYDANTIC V2 COMPATIBILITY
"""
from pydantic import (
    BaseModel, Field, field_validator, model_validator, ConfigDict
)
from typing import Optional, List, Dict, Any
from typing_extensions import Annotated
from pydantic.types import StringConstraints
from pathlib import Path
from enum import Enum
import re


class SeverityEnum(str, Enum):
    """Valid severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CollectorEnum(str, Enum):
    """Valid collector names"""
    HARDWARE = "hardware"
    SECURITY = "security"
    OS = "os"
    NETWORK = "network"
    ALL = "all"


class ReportFormatEnum(str, Enum):
    """Valid report formats"""
    HTML = "html"
    JSON = "json"
    ALL = "all"


class AIProviderEnum(str, Enum):
    """Valid AI providers"""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    NONE = "none"


class CLIArgumentsSchema(BaseModel):
    """Validation schema for CLI arguments"""
    
    model_config = ConfigDict(use_enum_values=True)
    
    # Boolean flags
    quick: bool = False
    no_admin: bool = False
    no_remediation: bool = False
    verbose: bool = False
    
    # Enums
    ai: AIProviderEnum = AIProviderEnum.ANTHROPIC
    collectors: List[CollectorEnum] = [CollectorEnum.ALL]
    formats: List[ReportFormatEnum] = [ReportFormatEnum.ALL]
    
    # Strings with constraints
    model: Optional[Annotated[str, StringConstraints(min_length=1, max_length=100)]] = None
    output: Annotated[str, StringConstraints(min_length=1, max_length=500)] = "./audit_results"
    
    @field_validator('output')
    @classmethod
    def validate_output_path(cls, v):
        """Validate output directory path"""
        # Prevent path traversal
        if ".." in v:
            raise ValueError("Path traversal detected in output path")
        
        # Prevent absolute paths to system directories
        dangerous_paths = ['/etc', '/sys', '/proc', '/dev', 'C:\\Windows', 'C:\\System32']
        for dangerous in dangerous_paths:
            if v.startswith(dangerous):
                raise ValueError(f"Cannot write to system directory: {dangerous}")
        
        # Ensure reasonable length
        if len(v) > 500:
            raise ValueError("Output path too long (max 500 characters)")
        
        return v
    
    @field_validator('collectors')
    @classmethod
    def validate_collectors(cls, v):
        """Validate collector selection"""
        if not v:
            raise ValueError("At least one collector must be specified")
        return v
    
    @field_validator('formats')
    @classmethod
    def validate_formats(cls, v):
        """Validate report formats"""
        if not v:
            raise ValueError("At least one report format must be specified")
        return v


class AIAnalysisResponseSchema(BaseModel):
    """
    Validation schema for AI analysis responses.
    Prevents injection from malformed AI outputs.
    """
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "risk_score": 65,
                "executive_summary": "System has 12 security findings requiring attention.",
                "critical_issues": [
                    "Windows Defender disabled",
                    "Firewall not active"
                ],
                "recommendations": [
                    "Enable Windows Defender Real-time Protection",
                    "Activate Windows Firewall on all profiles"
                ]
            }
        }
    )
    
    risk_score: Annotated[int, Field(ge=0, le=100, description="Risk score from 0-100")]
    
    executive_summary: Annotated[
        str,
        StringConstraints(min_length=10, max_length=2000),
        Field(description="Executive summary of findings")
    ]
    
    critical_issues: List[str] = Field(
        default_factory=list,
        max_length=50,
        description="List of critical issues"
    )
    
    recommendations: List[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="List of recommendations"
    )
    
    @field_validator('executive_summary')
    @classmethod
    def validate_summary(cls, v):
        """Ensure executive summary is clean"""
        # Remove potential script tags
        if '<script' in v.lower() or '</script' in v.lower():
            raise ValueError("Script tags not allowed in summary")
        return v.strip()
    
    @field_validator('critical_issues', 'recommendations')
    @classmethod
    def validate_list_items(cls, v):
        """Validate individual list items"""
        for item in v:
            if len(item) > 500:
                raise ValueError("List item too long (max 500 characters)")
            
            # Remove potential injection attempts
            if '<script' in item.lower() or 'javascript:' in item.lower():
                raise ValueError("Script content not allowed")
        
        return [item.strip() for item in v]


class FindingSchema(BaseModel):
    """Validation schema for security findings"""
    
    model_config = ConfigDict(use_enum_values=True)
    
    check_id: Annotated[
        str,
        StringConstraints(pattern=r'^[A-Z0-9\-\.]+$', min_length=3, max_length=50),
        Field(description="Check identifier (e.g., CIS-10.1-001)")
    ]
    
    severity: SeverityEnum = Field(
        ...,
        description="Finding severity level"
    )
    
    description: Annotated[
        str,
        StringConstraints(min_length=10, max_length=1000),
        Field(description="Finding description")
    ]
    
    current_value: Annotated[
        str,
        StringConstraints(max_length=500),
        Field(description="Current configuration value")
    ]
    
    expected_value: Annotated[
        str,
        StringConstraints(max_length=500),
        Field(description="Expected configuration value")
    ]
    
    remediation_hint: Optional[Annotated[
        str,
        StringConstraints(max_length=1000),
        Field(description="Remediation guidance")
    ]] = None
    
    collector_name: Optional[Annotated[str, StringConstraints(max_length=100)]] = None
    
    @field_validator('check_id')
    @classmethod
    def validate_check_id_format(cls, v):
        """Ensure check ID follows standard format"""
        if not re.match(r'^[A-Z0-9\-\.]+$', v):
            raise ValueError("Check ID must contain only uppercase letters, numbers, hyphens, and dots")
        return v


class RemediationScriptSchema(BaseModel):
    """Validation schema for remediation scripts"""
    
    filename: Annotated[
        str,
        StringConstraints(pattern=r'^[a-zA-Z0-9_\-\.]+\.(ps1|sh|bat)$', max_length=255),
        Field(description="Script filename")
    ]
    
    content: Annotated[
        str,
        StringConstraints(min_length=10, max_length=50000),
        Field(description="Script content")
    ]
    
    check_id: Annotated[
        str,
        StringConstraints(min_length=3, max_length=50),
        Field(description="Associated finding check ID")
    ]
    
    @field_validator('filename')
    @classmethod
    def validate_filename(cls, v):
        """Ensure filename is safe"""
        # Prevent path traversal
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError("Filename cannot contain path separators")
        
        # Ensure proper extension
        valid_extensions = ['.ps1', '.sh', '.bat']
        if not any(v.endswith(ext) for ext in valid_extensions):
            raise ValueError(f"Filename must end with one of: {valid_extensions}")
        
        return v
    
    @field_validator('content')
    @classmethod
    def validate_script_content(cls, v):
        """Basic validation of script content"""
        # Prevent obviously malicious patterns
        dangerous_patterns = [
            r'rm\s+-rf\s+/',  # Dangerous delete on Linux
            r'del\s+/f\s+/q\s+C:\\',  # Dangerous delete on Windows
            r'format\s+C:',  # Format drive
            r':\(\)\{.*\|.*&.*\};:',  # Fork bomb
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError(f"Script contains potentially dangerous pattern: {pattern}")
        
        return v


class AuditConfigSchema(BaseModel):
    """Validation schema for audit configuration"""
    
    require_admin: bool = False
    timeout_seconds: Annotated[int, Field(ge=10, le=3600)] = 300
    parallel_execution: bool = True
    
    cis_level: Annotated[int, Field(ge=1, le=2)] = 1
    enable_custom_checks: bool = True
    
    generate_remediation: bool = True
    log_level: Annotated[
        str,
        StringConstraints(pattern=r'^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$')
    ] = "INFO"
    
    @field_validator('log_level')
    @classmethod
    def validate_log_level(cls, v):
        """Ensure valid log level"""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()


class DatabaseConfigSchema(BaseModel):
    """Validation schema for database configuration"""
    
    database_url: Annotated[
        str,
        StringConstraints(min_length=10, max_length=500),
        Field(default="sqlite:///./audit_history.db", description="Database connection string")
    ]
    
    @field_validator('database_url')
    @classmethod
    def validate_database_url(cls, v):
        """Validate database URL format"""
        valid_prefixes = ['sqlite:///', 'postgresql://', 'mysql://']
        
        if not any(v.startswith(prefix) for prefix in valid_prefixes):
            raise ValueError(
                f"Database URL must start with one of: {valid_prefixes}"
            )
        
        # Prevent SQL injection in connection string
        dangerous_chars = [';', '--', '/*', '*/']
        for char in dangerous_chars:
            if char in v and not v.startswith('sqlite'):
                raise ValueError(f"Potentially dangerous character in database URL: {char}")
        
        return v


class RateLimitConfigSchema(BaseModel):
    """Validation schema for rate limit configuration"""
    
    max_requests_per_minute: Annotated[int, Field(ge=1, le=1000)] = 60
    max_requests_per_hour: Annotated[int, Field(ge=1, le=10000)] = 1000
    max_concurrent_requests: Annotated[int, Field(ge=1, le=50)] = 5
    
    failure_threshold: Annotated[int, Field(ge=1, le=100)] = 5
    success_threshold: Annotated[int, Field(ge=1, le=10)] = 2
    timeout_seconds: Annotated[int, Field(ge=10, le=600)] = 60
    
    request_timeout_seconds: Annotated[int, Field(ge=5, le=300)] = 30
    
    @model_validator(mode='before')
    @classmethod
    def validate_thresholds(cls, values):
        """Ensure rate limits are consistent"""
        per_minute = values.get('max_requests_per_minute')
        per_hour = values.get('max_requests_per_hour')
        
        if per_minute and per_hour:
            if per_minute * 60 < per_hour:
                raise ValueError(
                    "Hourly limit should be at least 60x the per-minute limit"
                )
        
        return values


def validate_cli_args(args: dict) -> CLIArgumentsSchema:
    """
    Validate CLI arguments.
    
    Args:
        args: Dictionary of CLI arguments
        
    Returns:
        Validated CLIArgumentsSchema
        
    Raises:
        ValidationError: If validation fails
    """
    return CLIArgumentsSchema(**args)


def validate_ai_response(response: dict) -> AIAnalysisResponseSchema:
    """
    Validate AI analysis response.
    
    Args:
        response: AI response dictionary
        
    Returns:
        Validated AIAnalysisResponseSchema
        
    Raises:
        ValidationError: If validation fails
    """
    return AIAnalysisResponseSchema(**response)


def validate_finding(finding: dict) -> FindingSchema:
    """
    Validate security finding.
    
    Args:
        finding: Finding dictionary
        
    Returns:
        Validated FindingSchema
        
    Raises:
        ValidationError: If validation fails
    """
    return FindingSchema(**finding)
