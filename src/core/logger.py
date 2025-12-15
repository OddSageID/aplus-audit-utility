import logging
import sys
from pathlib import Path
from typing import Optional


def _ensure_path(log_file: Optional[Path]) -> Optional[str]:
    if log_file:
        path_obj = Path(log_file)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        return str(path_obj)
    return None


def setup_logger(
    name: str = "a_plus_audit", level: str = "INFO", log_file: Optional[Path] = None
) -> logging.Logger:
    """Create a configured logger (idempotent)."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)

    path_str = _ensure_path(log_file)
    if path_str and not any(
        isinstance(h, logging.FileHandler) and h.baseFilename == path_str for h in logger.handlers
    ):
        file_handler = logging.FileHandler(path_str)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

    return logger


def get_logger(
    name: str = "a_plus_audit", level: str = "INFO", log_file: Optional[Path] = None
) -> logging.Logger:
    """Compatibility function expected by tests."""
    return setup_logger(name=name, level=level, log_file=log_file)


class AuditLogger:
    """
    Backwards-compatible logger accessor.
    Orchestrator and legacy callers import this symbol directly.
    """

    @classmethod
    def get_logger(
        cls,
        name: str = "a_plus_audit",
        level: str = "INFO",
        log_file: Optional[Path] = None,
    ) -> logging.Logger:
        return setup_logger(name=name, level=level, log_file=log_file)
