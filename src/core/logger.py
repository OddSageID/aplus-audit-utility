import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

class AuditLogger:
    """Centralized logging for the audit system"""
    
    _instance: Optional[logging.Logger] = None
    
    @classmethod
    def get_logger(cls, 
                   name: str = "a_plus_audit",
                   level: str = "INFO",
                   log_file: Optional[Path] = None) -> logging.Logger:
        """
        Get or create singleton logger instance.
        
        Args:
            name: Logger name
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional file path for log output
            
        Returns:
            Configured logger instance
        """
        if cls._instance is None:
            cls._instance = logging.getLogger(name)
            cls._instance.setLevel(getattr(logging, level.upper()))
            
            # Console handler with formatting
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_format = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(console_format)
            cls._instance.addHandler(console_handler)
            
            # File handler if specified
            if log_file:
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(logging.DEBUG)
                file_format = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
                )
                file_handler.setFormatter(file_format)
                cls._instance.addHandler(file_handler)
        
        return cls._instance

def setup_logger(
    name: str = "a_plus_audit",
    level: str = "INFO",
    log_file: Optional[Path] = None
) -> logging.Logger:
    """Compatibility function expected by tests."""
    return AuditLogger.get_logger(name=name, level=level, log_file=log_file)

def get_logger(
    name: str = "a_plus_audit",
    level: str = "INFO",
    log_file: Optional[Path] = None
) -> logging.Logger:
    """Compatibility function expected by tests."""
    return AuditLogger.get_logger(name=name, level=level, log_file=log_file)
