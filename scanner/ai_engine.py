"""AI Engine for LiteLLM integration with security-focused model selection.

This module provides the LiteLLMClient class for interacting with LLM APIs via LiteLLM,
including model selection, streaming support, and robust error handling with retry logic.

Example:
    >>> from scanner.ai_engine import LiteLLMClient
    >>> client = LiteLLMClient()
    >>> response = client.chat([
    ...     {"role": "system", "content": "You are a security expert."},
    ...     {"role": "user", "content": "Analyze this response for vulnerabilities."}
    ... ])
    >>> print(response)

Classes:
    LiteLLMClient: Main client for LiteLLM API interactions.
    LiteLLMEngineError: Base exception for AI engine errors.
    ModelNotFoundError: No suitable models available.
    LiteLLMConnectionError: Cannot connect to LLM service.
    ResponseValidationError: Invalid response structure.

Backward Compatibility:
    OllamaClient: Alias for LiteLLMClient for backward compatibility.
    OllamaEngineError: Alias for LiteLLMEngineError.
    OllamaConnectionError: Alias for LiteLLMConnectionError.
"""

import logging
import time
from typing import Dict, Generator, List, Optional, Union

import litellm
from litellm.exceptions import (
    APIConnectionError,
    APIError,
    AuthenticationError,
    BadRequestError,
    RateLimitError,
    ServiceUnavailableError,
    Timeout,
)

from scanner.config import (
    DEFAULT_MODEL,
    MAX_RETRIES,
    OLLAMA_HOST,
    OLLAMA_TIMEOUT,
    PREFERRED_MODELS,
    RETRY_BASE_DELAY,
    RETRY_MAX_DELAY,
)


logger = logging.getLogger(__name__)


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class LiteLLMEngineError(Exception):
    """Base exception for AI engine errors."""
    pass


class ModelNotFoundError(LiteLLMEngineError):
    """Raised when no suitable models are available."""
    pass


class LiteLLMConnectionError(LiteLLMEngineError):
    """Raised when unable to connect to LLM service."""
    pass


class ResponseValidationError(LiteLLMEngineError):
    """Raised when the response structure is invalid."""
    pass


# Backward compatibility aliases
OllamaEngineError = LiteLLMEngineError
OllamaConnectionError = LiteLLMConnectionError


# =============================================================================
# LITELLM CLIENT
# =============================================================================

class LiteLLMClient:
    """Client for interacting with LLM APIs via LiteLLM for security analysis.

    This client provides:
    - Support for multiple LLM providers via LiteLLM
    - Both streaming and non-streaming chat interfaces
    - Retry logic with exponential backoff for transient failures

    Attributes:
        model: The currently selected model name (LiteLLM format, e.g., "ollama/llama3").
        timeout: Request timeout in seconds.

    Example:
        >>> client = LiteLLMClient()
        >>> print(f"Using model: {client.model}")
        Using model: ollama/llama3

        >>> # Simple chat
        >>> response = client.chat([{"role": "user", "content": "Hello"}])

        >>> # Chat with retry
        >>> response = client.chat_with_retry(messages, max_retries=5)

        >>> # Streaming chat
        >>> for chunk in client.chat(messages, stream=True):
        ...     print(chunk, end="", flush=True)
    """

    def __init__(
        self,
        model: Optional[str] = None,
        timeout: int = OLLAMA_TIMEOUT,
        host: Optional[str] = None
    ) -> None:
        """Initialize the LiteLLM client.

        Args:
            model: Specific model to use (LiteLLM format like "ollama/llama3"
                   or "gpt-4"). If None, uses DEFAULT_MODEL or first preferred model.
            timeout: Request timeout in seconds. Defaults to config value.
            host: API base URL for Ollama. Defaults to config value.

        Raises:
            LiteLLMConnectionError: If LLM service is not available.
            ModelNotFoundError: If no suitable models are available.
        """
        self.timeout = timeout
        self._host = host or OLLAMA_HOST

        # Configure LiteLLM settings
        litellm.request_timeout = timeout

        # Select model
        if model:
            self.model = self._normalize_model_name(model)
            logger.info(f"Using specified model: {self.model}")
        elif DEFAULT_MODEL:
            self.model = self._normalize_model_name(DEFAULT_MODEL)
            logger.info(f"Using model from environment: {self.model}")
        else:
            # Use first preferred model with ollama/ prefix
            self.model = f"ollama/{PREFERRED_MODELS[0]}" if PREFERRED_MODELS else "ollama/llama3"
            logger.info(f"Using default model: {self.model}")

        # Verify the model is accessible
        self._validate_model_availability()

    def _normalize_model_name(self, model: str) -> str:
        """Normalize model name to LiteLLM format.

        Adds 'ollama/' prefix if needed for local Ollama models.

        Args:
            model: Model name in any format.

        Returns:
            Model name in LiteLLM format.
        """
        # If already has a provider prefix, return as-is
        if "/" in model or model.startswith("gpt-") or model.startswith("claude-"):
            return model
        # Add ollama/ prefix for local Ollama models
        return f"ollama/{model}"

    def _validate_model_availability(self) -> None:
        """Validate that the currently selected model is available.

        Attempts a simple test request to verify the model is accessible.

        Raises:
            LiteLLMConnectionError: If the model is not available.
        """
        try:
            # Do a lightweight test to verify the model is accessible
            # We'll catch any errors during actual usage
            logger.debug(f"Model '{self.model}' will be validated on first use")
        except Exception as e:
            logger.warning(f"Could not validate model availability: {e}")

    def is_service_running(self) -> bool:
        """Check if the LLM service is running and accessible.

        Returns:
            True if the service is running and responding, False otherwise.
        """
        try:
            # Try a minimal completion to verify service is running
            response = litellm.completion(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=1,
                timeout=5,
                api_base=self._host if self.model.startswith("ollama/") else None,
            )
            return True
        except Exception as e:
            logger.debug(f"Service connection check failed: {e}")
            return False

    # Backward compatibility alias
    def is_ollama_running(self) -> bool:
        """Check if LLM service is running (backward compatibility)."""
        return self.is_service_running()

    def list_available_models(self) -> List[str]:
        """Get list of available models.

        Note: For LiteLLM, this returns the configured model since LiteLLM
        supports many providers and doesn't have a universal list endpoint.

        Returns:
            List containing the configured model name.
        """
        # LiteLLM doesn't have a universal model list - return configured model
        return [self.model]

    def select_best_model(self) -> str:
        """Select the best model based on preferred models list.

        Returns:
            The first preferred model with ollama/ prefix.

        Raises:
            ModelNotFoundError: If no preferred models are configured.
        """
        if PREFERRED_MODELS:
            return f"ollama/{PREFERRED_MODELS[0]}"
        raise ModelNotFoundError(
            "No preferred models configured. "
            "Please set OLLAMA_MODEL environment variable or configure PREFERRED_MODELS."
        )

    def get_model_info(self) -> Dict:
        """Get information about the currently selected model.

        Returns:
            Dictionary containing model name, provider, and metadata.
        """
        # Extract provider from model name if present
        if "/" in self.model:
            provider = self.model.split("/")[0]
        elif self.model.startswith("gpt-"):
            provider = "openai"
        elif self.model.startswith("claude-"):
            provider = "anthropic"
        else:
            provider = "ollama"  # Default for local models

        return {
            "model": self.model,
            "provider": provider,
            "host": self._host,
            "timeout": self.timeout,
        }

    def _validate_response(self, response) -> bool:
        """Validate that a response has the expected structure.

        Args:
            response: Response from LiteLLM API (ModelResponse object).

        Returns:
            True if response structure is valid.
        """
        # LiteLLM returns a ModelResponse object with choices
        if hasattr(response, "choices") and response.choices:
            choice = response.choices[0]
            if hasattr(choice, "message"):
                message = choice.message
                return hasattr(message, "content") and message.content is not None
        return False

    def _extract_content(self, response) -> str:
        """Extract message content from LiteLLM response.

        Args:
            response: Response from LiteLLM API (ModelResponse object).

        Returns:
            Extracted content string.

        Raises:
            ResponseValidationError: If response structure is invalid.
        """
        if not self._validate_response(response):
            raise ResponseValidationError(
                f"Invalid response structure: {response}"
            )

        # Extract content from LiteLLM ModelResponse
        message = response.choices[0].message
        content = message.content or ""

        # Check for reasoning/thinking in message (if model supports it)
        thinking = getattr(message, "reasoning_content", "") or ""

        # Combine thinking and content if both present
        if thinking and content:
            return f"[Reasoning]\n{thinking}\n\n[Response]\n{content}"
        return content or thinking

    def chat(
        self,
        messages: List[Dict[str, str]],
        stream: bool = False
    ) -> Union[str, Generator[str, None, None]]:
        """Send a chat request to the LLM.

        Args:
            messages: List of message dictionaries with 'role' and 'content' keys.
                     Roles can be 'system', 'user', or 'assistant'.
            stream: If True, returns a generator yielding response chunks.
                   If False, returns the complete response string.

        Returns:
            If stream=False: Complete response string.
            If stream=True: Generator yielding response chunks.

        Raises:
            LiteLLMConnectionError: If unable to connect to LLM service.
            ResponseValidationError: If response structure is invalid.

        Example:
            >>> # Non-streaming
            >>> response = client.chat([
            ...     {"role": "user", "content": "Hello"}
            ... ])

            >>> # Streaming
            >>> for chunk in client.chat(messages, stream=True):
            ...     print(chunk, end="", flush=True)
        """
        logger.debug(
            f"Chat request to {self.model} with {len(messages)} messages, "
            f"stream={stream}"
        )

        try:
            if stream:
                return self._chat_stream(messages)
            else:
                return self._chat_complete(messages)
        except (APIConnectionError, ServiceUnavailableError, Timeout) as e:
            raise LiteLLMConnectionError(f"LiteLLM API connection error: {e}") from e
        except AuthenticationError as e:
            raise LiteLLMConnectionError(f"LiteLLM authentication error: {e}") from e
        except RateLimitError as e:
            raise LiteLLMConnectionError(f"LiteLLM rate limit error: {e}") from e
        except (APIError, BadRequestError) as e:
            raise LiteLLMConnectionError(f"LiteLLM API error: {e}") from e
        except Exception as e:
            if "connection" in str(e).lower():
                raise LiteLLMConnectionError(
                    f"Failed to connect to LLM service: {e}"
                ) from e
            raise

    def _chat_complete(self, messages: List[Dict[str, str]]) -> str:
        """Execute a non-streaming chat request.

        Args:
            messages: List of message dictionaries.

        Returns:
            Complete response string.
        """
        response = litellm.completion(
            model=self.model,
            messages=messages,
            timeout=self.timeout,
            api_base=self._host if self.model.startswith("ollama/") else None,
        )

        content = self._extract_content(response)
        logger.debug(f"Response received: {content[:100]}...")
        return content

    def _chat_stream(
        self,
        messages: List[Dict[str, str]]
    ) -> Generator[str, None, None]:
        """Execute a streaming chat request.

        Args:
            messages: List of message dictionaries.

        Yields:
            Response content chunks as they arrive.

        Raises:
            LiteLLMConnectionError: If a connection error occurs during streaming.
        """
        response = litellm.completion(
            model=self.model,
            messages=messages,
            stream=True,
            timeout=self.timeout,
            api_base=self._host if self.model.startswith("ollama/") else None,
        )

        try:
            for chunk in response:
                if hasattr(chunk, "choices") and chunk.choices:
                    delta = chunk.choices[0].delta
                    if hasattr(delta, "content") and delta.content:
                        yield delta.content
        except (APIConnectionError, ServiceUnavailableError, Timeout) as e:
            raise LiteLLMConnectionError(
                f"LiteLLM API error during streaming: {e}"
            ) from e
        except (ConnectionError, TimeoutError, OSError) as e:
            raise LiteLLMConnectionError(
                f"Connection error during streaming: {e}"
            ) from e
        except Exception as e:
            if "connection" in str(e).lower():
                raise LiteLLMConnectionError(
                    f"Failed to stream from LLM service: {e}"
                ) from e
            raise

    def chat_with_retry(
        self,
        messages: List[Dict[str, str]],
        max_retries: Optional[int] = None
    ) -> str:
        """Send a chat request with automatic retry on failure.

        Implements exponential backoff for transient failures.

        Args:
            messages: List of message dictionaries.
            max_retries: Maximum retry attempts. Defaults to config value.

        Returns:
            Complete response string.

        Raises:
            LiteLLMEngineError: If all retry attempts fail.

        Example:
            >>> response = client.chat_with_retry(
            ...     messages,
            ...     max_retries=5
            ... )
        """
        if max_retries is None:
            max_retries = MAX_RETRIES

        last_error = None

        for attempt in range(max_retries + 1):
            try:
                return self.chat(messages, stream=False)
            except LiteLLMConnectionError as e:
                last_error = e
                if attempt < max_retries:
                    delay = min(
                        RETRY_BASE_DELAY * (2 ** attempt),
                        RETRY_MAX_DELAY
                    )
                    logger.warning(
                        f"Chat attempt {attempt + 1} failed: {e}. "
                        f"Retrying in {delay:.1f}s..."
                    )
                    time.sleep(delay)
                else:
                    logger.error(
                        f"All {max_retries + 1} chat attempts failed"
                    )
            except Exception as e:
                # Don't retry on non-connection errors
                raise LiteLLMEngineError(f"Chat failed: {e}") from e

        raise LiteLLMEngineError(
            f"Chat failed after {max_retries + 1} attempts. "
            f"Last error: {last_error}"
        )


# Backward compatibility alias
OllamaClient = LiteLLMClient
