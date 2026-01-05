"""Unit tests for the AI Engine module (LiteLLMClient).

This module tests:
- Model selection and initialization
- Chat functionality (streaming and non-streaming)
- Retry logic with exponential backoff
- Error handling and custom exceptions
- Response validation and content extraction
"""

import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from scanner.ai_engine import (
    LiteLLMClient,
    OllamaClient,  # Backward compatibility alias
    LiteLLMEngineError,
    OllamaEngineError,  # Backward compatibility alias
    ModelNotFoundError,
    LiteLLMConnectionError,
    OllamaConnectionError,  # Backward compatibility alias
    ResponseValidationError,
)


# =============================================================================
# MODEL SELECTION AND INITIALIZATION TESTS
# =============================================================================

class TestLiteLLMClientInitialization:
    """Tests for LiteLLMClient initialization and model selection."""

    def test_client_initialization_with_model(self):
        """Test explicit model specification during initialization."""
        client = LiteLLMClient(model="custom-model")
        # Model should be normalized with ollama/ prefix
        assert client.model == "ollama/custom-model"

    def test_client_initialization_with_provider_prefix(self):
        """Test model with provider prefix is preserved."""
        client = LiteLLMClient(model="gpt-4")
        assert client.model == "gpt-4"

    def test_client_initialization_with_ollama_prefix(self):
        """Test model already with ollama/ prefix is preserved."""
        client = LiteLLMClient(model="ollama/llama3")
        assert client.model == "ollama/llama3"

    def test_client_auto_select_model(self):
        """Test automatic model selection from preferred models."""
        with patch("scanner.ai_engine.DEFAULT_MODEL", None):
            client = LiteLLMClient()
        # Should use first preferred model with ollama/ prefix
        assert client.model.startswith("ollama/")

    def test_client_uses_environment_model(self):
        """Test model from environment variable is used."""
        with patch("scanner.ai_engine.DEFAULT_MODEL", "my-custom-model"):
            client = LiteLLMClient()
        assert client.model == "ollama/my-custom-model"

    def test_backward_compatibility_alias(self):
        """Test OllamaClient is an alias for LiteLLMClient."""
        assert OllamaClient is LiteLLMClient


# =============================================================================
# PROVIDER SWITCHING AND MODEL FORMAT TESTS
# =============================================================================

class TestProviderSwitching:
    """Tests for switching between different LLM providers."""

    def test_switch_to_openai_provider(self):
        """Test using OpenAI models (gpt-* prefix preserved)."""
        client = LiteLLMClient(model="gpt-4")
        assert client.model == "gpt-4"
        info = client.get_model_info()
        assert info["provider"] == "openai"

    def test_switch_to_openai_with_prefix(self):
        """Test using OpenAI models with explicit prefix."""
        client = LiteLLMClient(model="openai/gpt-4")
        assert client.model == "openai/gpt-4"
        info = client.get_model_info()
        assert info["provider"] == "openai"

    def test_switch_to_anthropic_provider(self):
        """Test using Anthropic models (claude-* prefix preserved)."""
        client = LiteLLMClient(model="claude-3-sonnet")
        assert client.model == "claude-3-sonnet"
        info = client.get_model_info()
        assert info["provider"] == "anthropic"

    def test_switch_to_anthropic_with_prefix(self):
        """Test using Anthropic models with explicit prefix."""
        client = LiteLLMClient(model="anthropic/claude-3-sonnet")
        assert client.model == "anthropic/claude-3-sonnet"
        info = client.get_model_info()
        assert info["provider"] == "anthropic"

    def test_switch_to_openrouter_provider(self):
        """Test using OpenRouter models."""
        client = LiteLLMClient(model="openrouter/anthropic/claude-3")
        assert client.model == "openrouter/anthropic/claude-3"
        info = client.get_model_info()
        assert info["provider"] == "openrouter"

    def test_switch_to_ollama_provider(self):
        """Test using Ollama models with explicit prefix."""
        client = LiteLLMClient(model="ollama/llama3")
        assert client.model == "ollama/llama3"
        info = client.get_model_info()
        assert info["provider"] == "ollama"

    def test_local_model_gets_ollama_prefix(self):
        """Test that local models without prefix get ollama/ added."""
        client = LiteLLMClient(model="mistral")
        assert client.model == "ollama/mistral"
        info = client.get_model_info()
        assert info["provider"] == "ollama"


class TestModelFormats:
    """Tests for different model name formats."""

    def test_model_format_ollama_llama3(self):
        """Test ollama/llama3 format."""
        client = LiteLLMClient(model="ollama/llama3")
        assert client.model == "ollama/llama3"

    def test_model_format_ollama_with_tag(self):
        """Test ollama model with tag (e.g., llama3:8b)."""
        client = LiteLLMClient(model="ollama/llama3:8b")
        assert client.model == "ollama/llama3:8b"

    def test_model_format_openrouter_model(self):
        """Test openrouter/model format."""
        client = LiteLLMClient(model="openrouter/meta-llama/llama-3-70b")
        assert client.model == "openrouter/meta-llama/llama-3-70b"
        info = client.get_model_info()
        assert info["provider"] == "openrouter"

    def test_model_format_openai_gpt4(self):
        """Test openai/gpt-4 format."""
        client = LiteLLMClient(model="openai/gpt-4")
        assert client.model == "openai/gpt-4"
        info = client.get_model_info()
        assert info["provider"] == "openai"

    def test_model_format_gpt4_without_prefix(self):
        """Test gpt-4 format (recognized as OpenAI model)."""
        client = LiteLLMClient(model="gpt-4")
        # gpt-* models are recognized and kept as-is
        assert client.model == "gpt-4"

    def test_model_format_gpt4_turbo(self):
        """Test gpt-4-turbo format."""
        client = LiteLLMClient(model="gpt-4-turbo")
        assert client.model == "gpt-4-turbo"

    def test_model_format_claude_without_prefix(self):
        """Test claude-* format (recognized as Anthropic model)."""
        client = LiteLLMClient(model="claude-3-opus")
        assert client.model == "claude-3-opus"

    def test_model_format_together_ai(self):
        """Test together_ai provider format."""
        client = LiteLLMClient(model="together_ai/meta-llama/Llama-3-70b")
        assert client.model == "together_ai/meta-llama/Llama-3-70b"
        info = client.get_model_info()
        assert info["provider"] == "together_ai"

    def test_model_format_groq(self):
        """Test groq provider format."""
        client = LiteLLMClient(model="groq/llama3-70b-8192")
        assert client.model == "groq/llama3-70b-8192"
        info = client.get_model_info()
        assert info["provider"] == "groq"

    def test_model_with_api_base_for_ollama(self):
        """Test that Ollama models use custom host."""
        custom_host = "http://custom-ollama:11434"
        client = LiteLLMClient(model="ollama/llama3", host=custom_host)
        assert client._host == custom_host


# =============================================================================
# API KEY HANDLING TESTS
# =============================================================================

class TestAPIKeyHandling:
    """Tests for API key handling across different providers."""

    def test_openai_api_key_via_environment(self):
        """Test OpenAI API key is read from environment."""
        import os
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key-123"}):
            with patch("scanner.ai_engine.litellm.completion") as mock_completion:
                mock_response = _create_mock_litellm_response("Test response")
                mock_completion.return_value = mock_response

                client = LiteLLMClient(model="openai/gpt-4")
                response = client.chat([{"role": "user", "content": "Hello"}])

                assert response == "Test response"
                mock_completion.assert_called_once()

    def test_anthropic_api_key_via_environment(self):
        """Test Anthropic API key is read from environment."""
        import os
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-anthropic-key"}):
            with patch("scanner.ai_engine.litellm.completion") as mock_completion:
                mock_response = _create_mock_litellm_response("Test response")
                mock_completion.return_value = mock_response

                client = LiteLLMClient(model="anthropic/claude-3-sonnet")
                response = client.chat([{"role": "user", "content": "Hello"}])

                assert response == "Test response"

    def test_openrouter_api_key_via_environment(self):
        """Test OpenRouter API key is read from environment."""
        import os
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-openrouter-key"}):
            with patch("scanner.ai_engine.litellm.completion") as mock_completion:
                mock_response = _create_mock_litellm_response("Test response")
                mock_completion.return_value = mock_response

                client = LiteLLMClient(model="openrouter/anthropic/claude-3")
                response = client.chat([{"role": "user", "content": "Hello"}])

                assert response == "Test response"

    def test_authentication_error_handling(self):
        """Test authentication error is raised for invalid API key."""
        from litellm.exceptions import AuthenticationError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_completion.side_effect = AuthenticationError(
                message="Invalid API Key",
                llm_provider="openai",
                model="gpt-4"
            )

            client = LiteLLMClient(model="openai/gpt-4")

            with pytest.raises(LiteLLMConnectionError) as exc_info:
                client.chat([{"role": "user", "content": "Hello"}])

            assert "authentication" in str(exc_info.value).lower()

    def test_missing_api_key_error(self):
        """Test proper error when API key is missing."""
        from litellm.exceptions import AuthenticationError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_completion.side_effect = AuthenticationError(
                message="No API key provided",
                llm_provider="openai",
                model="gpt-4"
            )

            client = LiteLLMClient(model="openai/gpt-4")

            with pytest.raises(LiteLLMConnectionError):
                client.chat([{"role": "user", "content": "Hello"}])


# =============================================================================
# PROVIDER-SPECIFIC ERROR TESTS
# =============================================================================

class TestProviderSpecificErrors:
    """Tests for provider-specific error scenarios."""

    def test_openai_rate_limit_error(self):
        """Test OpenAI rate limit error handling."""
        from litellm.exceptions import RateLimitError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_completion.side_effect = RateLimitError(
                message="Rate limit exceeded",
                llm_provider="openai",
                model="gpt-4"
            )

            client = LiteLLMClient(model="openai/gpt-4")

            with pytest.raises(LiteLLMConnectionError) as exc_info:
                client.chat([{"role": "user", "content": "Hello"}])

            assert "rate limit" in str(exc_info.value).lower()

    def test_anthropic_rate_limit_error(self):
        """Test Anthropic rate limit error handling."""
        from litellm.exceptions import RateLimitError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_completion.side_effect = RateLimitError(
                message="Rate limit exceeded for Anthropic",
                llm_provider="anthropic",
                model="claude-3-sonnet"
            )

            client = LiteLLMClient(model="anthropic/claude-3-sonnet")

            with pytest.raises(LiteLLMConnectionError) as exc_info:
                client.chat([{"role": "user", "content": "Hello"}])

            assert "rate limit" in str(exc_info.value).lower()

    def test_service_unavailable_error(self):
        """Test service unavailable error handling."""
        from litellm.exceptions import ServiceUnavailableError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_completion.side_effect = ServiceUnavailableError(
                message="Service temporarily unavailable",
                llm_provider="openai",
                model="gpt-4"
            )

            client = LiteLLMClient(model="openai/gpt-4")

            with pytest.raises(LiteLLMConnectionError):
                client.chat([{"role": "user", "content": "Hello"}])

    def test_timeout_error(self):
        """Test timeout error handling."""
        from litellm.exceptions import Timeout

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_completion.side_effect = Timeout(
                message="Request timed out",
                llm_provider="ollama",
                model="llama3"
            )

            client = LiteLLMClient(model="ollama/llama3")

            with pytest.raises(LiteLLMConnectionError):
                client.chat([{"role": "user", "content": "Hello"}])

    def test_bad_request_error(self):
        """Test bad request error handling."""
        from litellm.exceptions import BadRequestError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_completion.side_effect = BadRequestError(
                message="Invalid request format",
                llm_provider="openai",
                model="gpt-4"
            )

            client = LiteLLMClient(model="openai/gpt-4")

            with pytest.raises(LiteLLMConnectionError):
                client.chat([{"role": "user", "content": "Hello"}])

    def test_api_error(self):
        """Test general API error handling."""
        from litellm.exceptions import APIError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_completion.side_effect = APIError(
                message="Internal server error",
                llm_provider="openai",
                model="gpt-4",
                status_code=500
            )

            client = LiteLLMClient(model="openai/gpt-4")

            with pytest.raises(LiteLLMConnectionError):
                client.chat([{"role": "user", "content": "Hello"}])

    def test_ollama_connection_error(self):
        """Test Ollama-specific connection error."""
        from litellm.exceptions import APIConnectionError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_completion.side_effect = APIConnectionError(
                message="Could not connect to Ollama at localhost:11434",
                llm_provider="ollama",
                model="llama3"
            )

            client = LiteLLMClient(model="ollama/llama3")

            with pytest.raises(LiteLLMConnectionError) as exc_info:
                client.chat([{"role": "user", "content": "Hello"}])

            assert "connection" in str(exc_info.value).lower()

    def test_retry_with_rate_limit(self):
        """Test retry logic handles rate limit errors correctly."""
        from litellm.exceptions import RateLimitError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_response = _create_mock_litellm_response("Success after retry")
            # First call fails with rate limit, second succeeds
            mock_completion.side_effect = [
                RateLimitError(message="Rate limit", llm_provider="openai", model="gpt-4"),
                mock_response,
            ]

            client = LiteLLMClient(model="openai/gpt-4")

            # RateLimitError is caught and converted to LiteLLMConnectionError
            # which triggers retry in chat_with_retry
            with patch("scanner.ai_engine.time.sleep"):
                response = client.chat_with_retry(
                    [{"role": "user", "content": "Hello"}],
                    max_retries=2
                )

            assert response == "Success after retry"
            assert mock_completion.call_count == 2

    def test_retry_with_service_unavailable(self):
        """Test retry logic handles service unavailable errors."""
        from litellm.exceptions import ServiceUnavailableError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_response = _create_mock_litellm_response("Service recovered")
            mock_completion.side_effect = [
                ServiceUnavailableError(message="Unavailable", llm_provider="openai", model="gpt-4"),
                ServiceUnavailableError(message="Still unavailable", llm_provider="openai", model="gpt-4"),
                mock_response,
            ]

            client = LiteLLMClient(model="openai/gpt-4")

            with patch("scanner.ai_engine.time.sleep"):
                response = client.chat_with_retry(
                    [{"role": "user", "content": "Hello"}],
                    max_retries=3
                )

            assert response == "Service recovered"
            assert mock_completion.call_count == 3

    def test_streaming_with_provider_error(self):
        """Test streaming handles provider errors correctly."""
        from litellm.exceptions import APIConnectionError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            # Create an iterator that raises an error mid-stream
            def failing_stream():
                yield _create_mock_stream_chunk("Hello ")
                raise APIConnectionError(
                    message="Connection lost during streaming",
                    llm_provider="openai",
                    model="gpt-4"
                )

            mock_completion.return_value = failing_stream()

            client = LiteLLMClient(model="openai/gpt-4")
            response_gen = client.chat([{"role": "user", "content": "Hello"}], stream=True)

            # First chunk should work
            first_chunk = next(response_gen)
            assert first_chunk == "Hello "

            # Second chunk should raise connection error
            with pytest.raises(LiteLLMConnectionError):
                next(response_gen)


# =============================================================================
# CHAT FUNCTIONALITY TESTS
# =============================================================================

def _create_mock_litellm_response(content: str, reasoning_content: str = None):
    """Helper to create a mock LiteLLM ModelResponse."""
    mock_message = MagicMock()
    mock_message.content = content
    mock_message.reasoning_content = reasoning_content

    mock_choice = MagicMock()
    mock_choice.message = mock_message

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    return mock_response


def _create_mock_stream_chunk(content: str):
    """Helper to create a mock LiteLLM streaming chunk."""
    mock_delta = MagicMock()
    mock_delta.content = content

    mock_choice = MagicMock()
    mock_choice.delta = mock_delta

    mock_chunk = MagicMock()
    mock_chunk.choices = [mock_choice]
    return mock_chunk


class TestLiteLLMClientChat:
    """Tests for LiteLLMClient chat functionality."""

    def test_chat_non_streaming(self):
        """Test basic non-streaming chat with mocked response."""
        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_response = _create_mock_litellm_response(
                "This is a test response from the AI model."
            )
            mock_completion.return_value = mock_response

            client = LiteLLMClient(model="llama3")
            messages = [{"role": "user", "content": "Hello"}]
            response = client.chat(messages)

            assert response == "This is a test response from the AI model."
            mock_completion.assert_called_once()

    def test_chat_streaming(self):
        """Test streaming chat with generator response."""
        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            # Setup streaming response
            stream_chunks = [
                _create_mock_stream_chunk("Hello "),
                _create_mock_stream_chunk("World"),
                _create_mock_stream_chunk("!"),
            ]
            mock_completion.return_value = iter(stream_chunks)

            client = LiteLLMClient(model="llama3")
            messages = [{"role": "user", "content": "Hello"}]
            response_gen = client.chat(messages, stream=True)

            # Collect streamed chunks
            chunks = list(response_gen)
            assert chunks == ["Hello ", "World", "!"]

    def test_chat_handles_reasoning_field(self):
        """Test extraction of reasoning fields from response."""
        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_response = _create_mock_litellm_response(
                content="42",
                reasoning_content="Let me think... 6 * 7 = 42"
            )
            mock_completion.return_value = mock_response

            client = LiteLLMClient(model="llama3")
            messages = [{"role": "user", "content": "What is 6 * 7?"}]
            response = client.chat(messages)

            # Response should contain both reasoning and content
            assert "Reasoning" in response
            assert "42" in response


# =============================================================================
# RETRY LOGIC TESTS
# =============================================================================

class TestLiteLLMClientRetry:
    """Tests for LiteLLMClient retry logic."""

    def test_chat_with_retry_success(self):
        """Test retry logic succeeds after transient failure."""
        from litellm.exceptions import APIConnectionError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            mock_response = _create_mock_litellm_response(
                "This is a test response from the AI model."
            )
            # First call fails, second succeeds
            mock_completion.side_effect = [
                APIConnectionError(message="Temporary error", llm_provider="ollama", model="llama3"),
                mock_response,
            ]

            client = LiteLLMClient(model="llama3")

            with patch("scanner.ai_engine.time.sleep"):  # Skip actual delays
                response = client.chat_with_retry(
                    [{"role": "user", "content": "Hello"}],
                    max_retries=3
                )

            assert response == "This is a test response from the AI model."
            assert mock_completion.call_count == 2

    def test_chat_with_retry_exhausted(self):
        """Test all retries fail and raises LiteLLMEngineError."""
        from litellm.exceptions import APIConnectionError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            # All calls fail with connection error
            mock_completion.side_effect = APIConnectionError(
                message="Persistent error", llm_provider="ollama", model="llama3"
            )

            client = LiteLLMClient(model="llama3")

            with patch("scanner.ai_engine.time.sleep"):  # Skip actual delays
                with pytest.raises(LiteLLMEngineError) as exc_info:
                    client.chat_with_retry(
                        [{"role": "user", "content": "Hello"}],
                        max_retries=2
                    )

            assert "failed after" in str(exc_info.value).lower()
            # Initial attempt + 2 retries = 3 total calls
            assert mock_completion.call_count == 3

    def test_chat_exponential_backoff(self):
        """Verify exponential backoff timing between retries."""
        from litellm.exceptions import APIConnectionError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            # All calls fail
            mock_completion.side_effect = APIConnectionError(
                message="Error", llm_provider="ollama", model="llama3"
            )

            client = LiteLLMClient(model="llama3")

            sleep_times = []
            with patch("scanner.ai_engine.time.sleep", side_effect=lambda x: sleep_times.append(x)):
                with pytest.raises(LiteLLMEngineError):
                    client.chat_with_retry(
                        [{"role": "user", "content": "Hello"}],
                        max_retries=3
                    )

            # Verify exponential backoff pattern (delays should increase)
            assert len(sleep_times) == 3
            for i in range(1, len(sleep_times)):
                assert sleep_times[i] >= sleep_times[i - 1]


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestLiteLLMClientErrorHandling:
    """Tests for LiteLLMClient error handling."""

    def test_invalid_response_structure(self):
        """Test ResponseValidationError for malformed responses."""
        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            # Return malformed response (no choices)
            mock_response = MagicMock()
            mock_response.choices = []
            mock_completion.return_value = mock_response

            client = LiteLLMClient(model="llama3")

            with pytest.raises(ResponseValidationError):
                client.chat([{"role": "user", "content": "Hello"}])

    def test_connection_error_during_chat(self):
        """Test LiteLLMConnectionError propagation during chat."""
        from litellm.exceptions import APIConnectionError

        with patch("scanner.ai_engine.litellm.completion") as mock_completion:
            # Chat raises connection error
            mock_completion.side_effect = APIConnectionError(
                message="Connection lost", llm_provider="ollama", model="llama3"
            )

            client = LiteLLMClient(model="llama3")

            with pytest.raises(LiteLLMConnectionError):
                client.chat([{"role": "user", "content": "Hello"}])

    def test_chat_response_validation(self):
        """Test _validate_response and _extract_content methods."""
        client = LiteLLMClient(model="llama3")

        # Test valid response
        valid_response = _create_mock_litellm_response("Test content")
        assert client._validate_response(valid_response) is True
        assert client._extract_content(valid_response) == "Test content"

        # Test response with reasoning field
        reasoning_response = _create_mock_litellm_response(
            content="Answer",
            reasoning_content="Reasoning..."
        )
        assert client._validate_response(reasoning_response) is True
        extracted = client._extract_content(reasoning_response)
        assert "Reasoning" in extracted
        assert "Answer" in extracted

        # Test invalid responses
        invalid_response = MagicMock()
        invalid_response.choices = []
        assert client._validate_response(invalid_response) is False

        invalid_response2 = MagicMock()
        invalid_response2.choices = None
        assert client._validate_response(invalid_response2) is False

    def test_get_model_info(self):
        """Test get_model_info returns correct information."""
        client = LiteLLMClient(model="llama3")
        info = client.get_model_info()

        assert "model" in info
        assert "host" in info
        assert "timeout" in info
        assert info["model"] == "ollama/llama3"

    def test_backward_compatibility_exception_aliases(self):
        """Test backward compatibility exception aliases."""
        assert OllamaEngineError is LiteLLMEngineError
        assert OllamaConnectionError is LiteLLMConnectionError
