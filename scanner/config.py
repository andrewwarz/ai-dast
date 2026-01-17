"""Configuration management for the AI-powered DAST scanner.

This module provides centralized configuration using environment variables
and sensible defaults. Configuration can be customized via a `.env` file.

Supported LLM Providers:
    - ollama: Local Ollama instance (default)
    - openrouter: OpenRouter API (access to multiple models)
    - openai: OpenAI API (GPT models)

Environment Variables:
    LLM_PROVIDER: LLM provider to use (ollama, openrouter, openai). Default: ollama

    Ollama-specific:
        OLLAMA_MODEL: Preferred Ollama model to use (optional, auto-detected if not set)
        OLLAMA_HOST: Ollama server host URL (default: http://localhost:11434)
        OLLAMA_TIMEOUT: Request timeout in seconds (default: 500 for complex AI reasoning)
        OLLAMA_MAX_RETRIES: Maximum retry attempts for failed requests (default: 3)

    OpenRouter-specific:
        OPENROUTER_API_KEY: OpenRouter API key (required if using openrouter)
        OPENROUTER_MODEL: Model to use (e.g., anthropic/claude-3.5-sonnet)

    OpenAI-specific:
        OPENAI_API_KEY: OpenAI API key (required if using openai)
        OPENAI_MODEL: Model to use (e.g., gpt-4o, gpt-4-turbo). Default: gpt-4o

    General:
        LOG_LEVEL: Logging level (default: INFO)

Model Naming with Provider Prefixes:
    Models can be specified with provider prefixes for explicit provider selection:
    - ollama/llama3 - Use llama3 via Ollama
    - openrouter/anthropic/claude-3.5-sonnet - Use Claude via OpenRouter
    - openai/gpt-4o - Use GPT-4o via OpenAI

    When a prefix is provided, it overrides the LLM_PROVIDER setting.

Example .env file:
    LLM_PROVIDER=ollama
    OLLAMA_MODEL=llama3
    OLLAMA_TIMEOUT=600
    LOG_LEVEL=DEBUG

    # Or for OpenRouter:
    # LLM_PROVIDER=openrouter
    # OPENROUTER_API_KEY=sk-or-...
    # OPENROUTER_MODEL=anthropic/claude-3.5-sonnet

    # Or for OpenAI:
    # LLM_PROVIDER=openai
    # OPENAI_API_KEY=sk-...
    # OPENAI_MODEL=gpt-4o
"""

import os
import logging
from typing import List, Optional, Tuple
from enum import Enum

from dotenv import load_dotenv


# Load environment variables from .env file if present
load_dotenv()


# =============================================================================
# LLM PROVIDER CONFIGURATION
# =============================================================================

class LLMProvider(Enum):
    """Supported LLM providers."""
    OLLAMA = "ollama"
    OPENROUTER = "openrouter"
    OPENAI = "openai"


# Valid provider names for validation
VALID_PROVIDERS = {provider.value for provider in LLMProvider}

# Current LLM provider (default: ollama for backward compatibility)
_provider_env = os.getenv("LLM_PROVIDER", "ollama").lower()
if _provider_env not in VALID_PROVIDERS:
    logging.warning(
        f"Invalid LLM_PROVIDER '{_provider_env}', defaulting to 'ollama'. "
        f"Valid options: {', '.join(VALID_PROVIDERS)}"
    )
    _provider_env = "ollama"
LLM_PROVIDER: str = _provider_env


def parse_model_with_provider(model_string: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Parse a model string that may contain a provider prefix.

    Model strings can be in the format:
    - "model_name" - Just the model name
    - "provider/model_name" - Provider prefix with model name
    - "openrouter/org/model_name" - OpenRouter with org/model format

    Args:
        model_string: The model string to parse

    Returns:
        Tuple of (provider, model_name). Provider is None if no prefix.

    Examples:
        >>> parse_model_with_provider("llama3")
        (None, "llama3")
        >>> parse_model_with_provider("ollama/llama3")
        ("ollama", "llama3")
        >>> parse_model_with_provider("openrouter/anthropic/claude-3.5-sonnet")
        ("openrouter", "anthropic/claude-3.5-sonnet")
        >>> parse_model_with_provider("openai/gpt-4o")
        ("openai", "gpt-4o")
    """
    if not model_string:
        return None, None

    # Check if the model string starts with a known provider prefix
    for provider in VALID_PROVIDERS:
        prefix = f"{provider}/"
        if model_string.lower().startswith(prefix):
            # Extract the model name (everything after the provider prefix)
            model_name = model_string[len(prefix):]
            return provider, model_name

    # No provider prefix found
    return None, model_string


def get_effective_provider_and_model(
    model_override: Optional[str] = None
) -> Tuple[str, Optional[str]]:
    """Get the effective LLM provider and model based on configuration.

    This function resolves the provider and model by checking:
    1. Model override parameter (if provided and has provider prefix)
    2. Environment variable model settings (if has provider prefix)
    3. LLM_PROVIDER environment variable

    Args:
        model_override: Optional model string that may contain provider prefix

    Returns:
        Tuple of (provider, model_name)
    """
    # Check model override first
    if model_override:
        provider, model = parse_model_with_provider(model_override)
        if provider:
            return provider, model
        # No prefix, use current provider with override model
        return LLM_PROVIDER, model

    # Check provider-specific model settings
    if LLM_PROVIDER == LLMProvider.OPENROUTER.value:
        model = os.getenv("OPENROUTER_MODEL")
        provider, parsed_model = parse_model_with_provider(model)
        return provider or LLM_PROVIDER, parsed_model or model

    if LLM_PROVIDER == LLMProvider.OPENAI.value:
        model = os.getenv("OPENAI_MODEL", "gpt-4o")
        provider, parsed_model = parse_model_with_provider(model)
        return provider or LLM_PROVIDER, parsed_model or model

    # Default: Ollama
    model = os.getenv("OLLAMA_MODEL")
    if model:
        provider, parsed_model = parse_model_with_provider(model)
        if provider:
            return provider, parsed_model
    return LLM_PROVIDER, model


# =============================================================================
# OLLAMA CONFIGURATION
# =============================================================================

# Preferred models for security testing, in order of preference
# These are known to work well for security analysis tasks
PREFERRED_MODELS: List[str] = [
    "qwen3",             # Strong reasoning for security analysis (recommended)
    "unisast",           # Security-focused model
    "dolphin-mixtral",   # Uncensored model for security testing
    "ctf-player_elona",  # CTF-focused security model
    "qwen2.5-coder",     # Strong coding/analysis model
    "llama3.2",          # Latest Llama model
    "llama3.1",          # Llama 3.1
    "llama3",            # General purpose Llama
    "mistral",           # Mistral base model
    "gemma3",            # Google's Gemma 3 model
    "codellama",         # Code-focused Llama
]

# User-specified model (overrides auto-detection if set)
# Backward compatible: still reads OLLAMA_MODEL
DEFAULT_MODEL: Optional[str] = os.getenv("OLLAMA_MODEL")

# Ollama server configuration
def _normalize_ollama_host(host: Optional[str]) -> str:
    """Normalize Ollama host to a full URL with protocol and port.

    Handles cases where OLLAMA_HOST might be set to just an IP address
    (e.g., '0.0.0.0' or 'localhost') without the protocol or port.
    """
    if not host:
        return "http://localhost:11434"

    host = host.strip()

    # If it already has a protocol, return as-is (but ensure port if missing)
    if host.startswith("http://") or host.startswith("https://"):
        # Check if port is missing
        if host.count(":") == 1:  # Only protocol colon, no port
            return f"{host}:11434"
        return host

    # Add http:// protocol and default port
    # Handle cases like "0.0.0.0", "localhost", "127.0.0.1"
    if ":" in host:
        # Has a port already
        return f"http://{host}"
    else:
        # No port, add default
        return f"http://{host}:11434"

OLLAMA_HOST: str = _normalize_ollama_host(os.getenv("OLLAMA_HOST"))

# Request timeout in seconds (default 500s for complex AI reasoning)
OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "500"))

# Maximum retry attempts for transient failures
MAX_RETRIES: int = int(os.getenv("OLLAMA_MAX_RETRIES", "3"))

# Base delay for exponential backoff (seconds)
RETRY_BASE_DELAY: float = 1.0

# Maximum delay between retries (seconds)
RETRY_MAX_DELAY: float = 16.0


# =============================================================================
# OPENROUTER CONFIGURATION
# =============================================================================

# OpenRouter API key (required if using openrouter provider)
OPENROUTER_API_KEY: Optional[str] = os.getenv("OPENROUTER_API_KEY")

# OpenRouter model to use (e.g., "anthropic/claude-3.5-sonnet", "openai/gpt-4o")
OPENROUTER_MODEL: Optional[str] = os.getenv("OPENROUTER_MODEL")

# OpenRouter API base URL
OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"


# =============================================================================
# OPENAI CONFIGURATION
# =============================================================================

# OpenAI API key (required if using openai provider)
OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")

# OpenAI model to use (default: gpt-4o)
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")

# OpenAI API base URL (can be overridden for Azure OpenAI or compatible APIs)
OPENAI_BASE_URL: Optional[str] = os.getenv("OPENAI_BASE_URL")


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Logging level from environment or default to INFO
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

# Validate log level
_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
if LOG_LEVEL not in _VALID_LOG_LEVELS:
    LOG_LEVEL = "INFO"


def configure_logging(
    level: Optional[str] = None,
    format_string: Optional[str] = None
) -> None:
    """Configure logging for the scanner package.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
               Defaults to LOG_LEVEL from environment.
        format_string: Custom format string for log messages.
                      Defaults to a standard format with timestamp.
    
    Example:
        >>> from scanner.config import configure_logging
        >>> configure_logging(level="DEBUG")
    """
    if level is None:
        level = LOG_LEVEL
    
    if format_string is None:
        format_string = (
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
    
    logging.basicConfig(
        level=getattr(logging, level),
        format=format_string,
        datefmt="%Y-%m-%d %H:%M:%S"
    )


# =============================================================================
# SCANNER CONFIGURATION
# =============================================================================

# Maximum response body size to include in prompts (characters)
MAX_RESPONSE_BODY_SIZE: int = int(os.getenv("MAX_RESPONSE_BODY_SIZE", "4000"))

# Window size for self-termination evaluation (recent requests to consider)
SELF_TERMINATION_WINDOW: int = int(os.getenv("SELF_TERMINATION_WINDOW", "10"))

# Maximum tokens in AI response (if supported by model)
MAX_RESPONSE_TOKENS: int = int(os.getenv("MAX_RESPONSE_TOKENS", "2048"))


# =============================================================================
# KATANA CONFIGURATION
# =============================================================================

# Katana executable path (auto-detected or from environment)
KATANA_PATH: Optional[str] = os.getenv("KATANA_PATH", "katana")

# Katana crawl depth (default: 4)
KATANA_DEPTH: int = int(os.getenv("KATANA_DEPTH", "4"))

# Katana concurrency (default: 5)
KATANA_CONCURRENCY: int = int(os.getenv("KATANA_CONCURRENCY", "5"))

# Katana crawl timeout (default: 3m)
KATANA_TIMEOUT: str = os.getenv("KATANA_TIMEOUT", "3m")

# File extensions to exclude from crawling
KATANA_EXCLUDE_EXTENSIONS: List[str] = [
    "png", "jpg", "gif", "svg", "ico", "css",
    "woff", "woff2", "ttf", "eot", "map", "js"
]

# Regex patterns to filter out from results
KATANA_FILTER_REGEX: str = r'node_modules|%5C|%7B|%7D|application/|socket\.io|Edge/|Trident/'


# =============================================================================
# CONFIGURATION SUMMARY
# =============================================================================

def get_config_summary() -> dict:
    """Return a dictionary summarizing current configuration.

    Returns:
        Dictionary containing all configuration values.

    Example:
        >>> from scanner.config import get_config_summary
        >>> config = get_config_summary()
        >>> print(config["llm_provider"])
        ollama
        >>> print(config["ollama_host"])
        http://localhost:11434
    """
    effective_provider, effective_model = get_effective_provider_and_model()

    return {
        # LLM Provider settings
        "llm_provider": LLM_PROVIDER,
        "effective_provider": effective_provider,
        "effective_model": effective_model,

        # Ollama settings (backward compatible)
        "ollama_host": OLLAMA_HOST,
        "ollama_timeout": OLLAMA_TIMEOUT,
        "max_retries": MAX_RETRIES,
        "default_model": DEFAULT_MODEL,
        "preferred_models": PREFERRED_MODELS,

        # OpenRouter settings
        "openrouter_api_key": "***" if OPENROUTER_API_KEY else None,
        "openrouter_model": OPENROUTER_MODEL,
        "openrouter_base_url": OPENROUTER_BASE_URL,

        # OpenAI settings
        "openai_api_key": "***" if OPENAI_API_KEY else None,
        "openai_model": OPENAI_MODEL,
        "openai_base_url": OPENAI_BASE_URL,

        # General settings
        "log_level": LOG_LEVEL,
        "max_response_body_size": MAX_RESPONSE_BODY_SIZE,
        "self_termination_window": SELF_TERMINATION_WINDOW,
        "max_response_tokens": MAX_RESPONSE_TOKENS,

        # Katana settings
        "katana_path": KATANA_PATH,
        "katana_depth": KATANA_DEPTH,
        "katana_concurrency": KATANA_CONCURRENCY,
        "katana_timeout": KATANA_TIMEOUT,
    }

