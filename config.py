"""
Configuration management for prompt-defender service.

Handles feature flags and scanning tiers.
"""

from typing import List, Dict, Optional
from pydantic import BaseModel


class PromptGuardConfig(BaseModel):
    """Configuration for prompt-guard feature."""
    scan_tier: int = 1  # 0=critical, 1=+high, 2=+medium
    hash_cache: bool = True
    decode_base64: bool = True
    multilang: List[str] = ["en"]


class Features(BaseModel):
    """Feature flags for independent scanner toggling."""
    prompt_guard: bool = True
    ml_detection: bool = False
    secret_scanner: bool = False
    content_moderation: bool = False


class ServiceConfig(BaseModel):
    """Main service configuration."""
    features: Features = Features()
    prompt_guard: PromptGuardConfig = PromptGuardConfig()
    fail_open: bool = True


def load_config(config_dict: Optional[Dict] = None) -> ServiceConfig:
    """
    Load configuration from dictionary.
    
    Args:
        config_dict: Configuration dictionary (from request body)
    
    Returns:
        ServiceConfig instance
    """
    if config_dict is None:
        return ServiceConfig()
    
    return ServiceConfig(**config_dict)
