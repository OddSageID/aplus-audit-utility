from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import logging
import os

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


@dataclass
class AIConfig:
    """AI provider configuration with rate limiting"""

    # Default to "none" so tests/environments without keys can still instantiate configs.
    provider: str = "none"  # anthropic | openai | none
    model: str = "claude-3-5-haiku-20241022"  # or "gpt-4o-mini"
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY"))
    max_tokens: int = 4096
    temperature: float = 0.3  # Lower for more deterministic analysis

    # Rate limiting configuration
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    max_concurrent_requests: int = 5

    def __post_init__(self):
        """Load API key only when an AI provider is enabled."""
        self.provider = (self.provider or "none").lower()

        if self.provider in {"anthropic", "openai"}:
            if not self.api_key:
                alt_key = "OPENAI_API_KEY" if self.provider == "openai" else "ANTHROPIC_API_KEY"
                self.api_key = os.getenv(alt_key)
            if not self.api_key:
                logger.warning(f"No API key found for {self.provider}; disabling AI features")
                self.provider = "none"


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
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
