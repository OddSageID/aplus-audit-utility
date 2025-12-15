from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

@dataclass
class AIConfig:
    """AI provider configuration with rate limiting"""
    provider: str = "anthropic"  # or "openai"
    model: str = "claude-3-5-haiku-20241022"  # or "gpt-4o-mini"
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY"))
    max_tokens: int = 4096
    temperature: float = 0.3  # Lower for more deterministic analysis
    
    # Rate limiting configuration
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    max_concurrent_requests: int = 5
    
    def __post_init__(self):
        if not self.api_key:
            alt_key = "OPENAI_API_KEY" if self.provider == "openai" else "ANTHROPIC_API_KEY"
            self.api_key = os.getenv(alt_key)
            if not self.api_key:
                raise ValueError(f"No API key found for {self.provider}")

@dataclass
class AuditConfig:
    """Main audit configuration"""
    # Execution settings
    require_admin: bool = False  # Graceful degradation enabled
    timeout_seconds: int = 300
    parallel_execution: bool = True
    
    # AI settings
    ai: AIConfig = field(default_factory=AIConfig)
    
    # Database settings
    database_enabled: bool = True
    database_url: str = "sqlite:///./audit_history.db"
    
    # Baseline settings
    cis_level: int = 1  # CIS Benchmark Level 1
    enable_custom_checks: bool = True
    
    # Output settings
    output_dir: Path = field(default_factory=lambda: Path("./audit_results"))
    generate_remediation: bool = True
    report_formats: List[str] = field(default_factory=lambda: ["html", "json"])
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[Path] = None
    
    # Metrics
    metrics_enabled: bool = True
    
    def __post_init__(self):
        """Initialize configuration with proper error handling for directory creation"""
        # Create output directory with comprehensive error handling
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            raise PermissionError(
                f"Permission denied creating output directory: {self.output_dir}. "
                "Please check directory permissions or choose a different location."
            )
        except OSError as e:
            if e.errno == 28:  # ENOSPC - No space left on device
                raise OSError(
                    f"Disk full - cannot create output directory: {self.output_dir}"
                )
            raise OSError(
                f"Failed to create output directory {self.output_dir}: {str(e)}"
            )
        except Exception as e:
            raise RuntimeError(
                f"Unexpected error creating output directory {self.output_dir}: {str(e)}"
            )

        # Create log file directory if specified
        if self.log_file:
            try:
                self.log_file.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                raise PermissionError(
                    f"Permission denied creating log directory: {self.log_file.parent}. "
                    "Please check directory permissions or choose a different location."
                )
            except OSError as e:
                if e.errno == 28:  # ENOSPC
                    raise OSError(
                        f"Disk full - cannot create log directory: {self.log_file.parent}"
                    )
                raise OSError(
                    f"Failed to create log directory {self.log_file.parent}: {str(e)}"
                )
            except Exception as e:
                raise RuntimeError(
                    f"Unexpected error creating log directory {self.log_file.parent}: {str(e)}"
                )
