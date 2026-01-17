# AI DAST Scanner

AI-powered Dynamic Application Security Testing (DAST) scanner that uses LLMs to intelligently discover and exploit web vulnerabilities.

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/andrewwarz/ai-dast.git
cd ai-dast
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Setup Ollama (Local LLM)

```bash
brew install ollama        # macOS
ollama serve &             # Start Ollama
ollama pull gemma3         # Download a model (recommended)
```

### 3. Setup Katana (Endpoint Discovery)

Katana is a fast crawler with headless browser support for comprehensive endpoint discovery.

```bash
# macOS
brew install katana

# Linux/macOS (via Go)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Verify installation
katana -version
```

> **Note:** Katana is optional but highly recommended for modern SPAs like Juice Shop. The scanner will fall back to manual crawling if not installed.

For more information: https://github.com/projectdiscovery/katana

### 4. Run Test Target (OWASP Juice Shop)

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```

Or use the included docker-compose:
```bash
cd docker && docker-compose up -d && cd ..
```

### 5. Scan!

```bash
python main.py --target http://localhost:3000
```

Reports are saved to `reports/`.

---

## Features

- **AI-Powered Analysis** – Uses LLMs to understand responses and craft intelligent payloads
- **Multiple Vulnerability Types** – SQLi, XSS, Command Injection, Path Traversal, SSRF, SSTI
- **Multi-Provider Support** – Ollama (local), OpenAI, or OpenRouter
- **Detailed Reports** – Markdown reports with evidence and remediation steps
- **Smart Reconnaissance** – Auto-discovers endpoints, forms, and attack surfaces

## CLI Options

```
python main.py --help

--target, -t URL       Target URL to scan (required)
--provider, -p NAME    LLM provider: ollama, openai, openrouter
--model, -m NAME       Model name (e.g., qwen3, gpt-4o)
--output, -o DIR       Output directory for reports (default: reports/)
--verbose, -v          Enable debug logging
--quiet, -q            Minimal output
--no-verify-ssl        Disable SSL verification
--timeout SEC          HTTP timeout in seconds (default: 30)
--max-requests N       Limit total requests
--proxy URL            HTTP proxy for requests
```

---

## Test Target: OWASP Juice Shop

This scanner is designed to work with [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), a modern intentionally vulnerable web application.

### Why Juice Shop?

- **Modern Architecture**: Single-page application (Angular) with REST APIs
- **Real-world Vulnerabilities**: 100+ challenges covering OWASP Top 10
- **Active Development**: Continuously updated with new vulnerabilities
- **Industry Standard**: Widely used for security training and tool testing

### Key Endpoints Discovered by Scanner

| Endpoint | Vulnerability Type | Description |
|----------|-------------------|-------------|
| `/rest/user/login` | SQL Injection, Auth Bypass | User authentication endpoint |
| `/rest/products/search` | SQL Injection | Product search with injectable query |
| `/api/Users` | Broken Access Control | User data exposure |
| `/api/Products` | Information Disclosure | Product listing with sensitive data |
| `/rest/saveLoginIp` | Security Misconfiguration | IP logging endpoint |
| `/redirect` | Open Redirect | URL redirection vulnerability |
| `/api/Feedbacks` | XSS, Injection | User feedback submission |
| `/file-upload` | Arbitrary File Upload | File upload vulnerability |

> **Note**: Juice Shop contains 100+ vulnerabilities. The scanner uses Katana to discover endpoints dynamically.

## Project Structure

```
ai-dast/
├── scanner/              # Core scanner modules
│   ├── scanner.py        # Main scanning engine
│   ├── ai_engine.py      # LLM integration (LiteLLM)
│   ├── http_client.py    # HTTP request handling
│   ├── katana_client.py  # Katana crawler integration
│   ├── report_generator.py # Markdown report generation
│   ├── prompts.py        # AI prompts for vulnerability detection
│   └── config.py         # Configuration management
├── tests/                # Test suite
├── docker/               # Docker configuration
├── main.py               # CLI entry point
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

## Configuration

### Environment Variables

Create a `.env` file in the project root (optional):

```env
LLM_PROVIDER=ollama
OLLAMA_MODEL=gemma3
TARGET_URL=http://localhost:3000
```

### LLM Provider Configuration (LiteLLM)

The scanner uses [LiteLLM](https://github.com/BerriAI/litellm) to support multiple LLM providers. Switch between providers using the `LLM_PROVIDER` environment variable.

#### Supported Providers

| Provider | `LLM_PROVIDER` | Required Environment Variables |
|----------|----------------|-------------------------------|
| Ollama (default) | `ollama` | `OLLAMA_MODEL`, `OLLAMA_HOST` |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` |
| OpenAI | `openai` | `OPENAI_API_KEY`, `OPENAI_MODEL` |

#### Ollama Setup (Default)

Ollama runs locally and is free to use. Best for privacy-conscious deployments.

1. **Install Ollama**: Download from [ollama.ai](https://ollama.ai/download)
2. **Pull a model**:
   ```bash
   ollama pull llama3
   ```
3. **Configure environment**:
   ```env
   LLM_PROVIDER=ollama
   OLLAMA_MODEL=llama3
   OLLAMA_HOST=http://localhost:11434
   ```
4. **Run the scanner**:
   ```bash
   python main.py --target http://localhost:3000
   ```

**Model name format**: `ollama/gemma3` or just `gemma3`

**Recommended models for security analysis**:
- `qwen3` - Strong reasoning capabilities (recommended)
- `llama3` - General purpose, good balance
- `mistral` - Fast and efficient
- `codellama` - Code-focused analysis

#### OpenRouter Setup

OpenRouter provides access to many models through a single API. Requires an API key.

1. **Get API Key**: Sign up at [openrouter.ai](https://openrouter.ai) and create an API key at [openrouter.ai/keys](https://openrouter.ai/keys)
2. **Configure environment**:
   ```env
   LLM_PROVIDER=openrouter
   OPENROUTER_API_KEY=sk-or-v1-your-api-key-here
   OPENROUTER_MODEL=anthropic/claude-3.5-sonnet
   ```
3. **Run the scanner**:
   ```bash
   python main.py --target http://localhost:3000
   ```

**Model name format**: `openrouter/anthropic/claude-3.5-sonnet` or `anthropic/claude-3.5-sonnet`

**Popular models for security analysis**:
- `anthropic/claude-3.5-sonnet` - Excellent reasoning and code analysis
- `openai/gpt-4o` - Strong general-purpose model
- `meta-llama/llama-3-70b-instruct` - Open-source alternative

#### OpenAI Setup

Direct OpenAI API access. Requires an OpenAI API key.

1. **Get API Key**: Create at [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
2. **Configure environment**:
   ```env
   LLM_PROVIDER=openai
   OPENAI_API_KEY=sk-your-api-key-here
   OPENAI_MODEL=gpt-4o
   ```
3. **Run the scanner**:
   ```bash
   python main.py --target http://localhost:3000
   ```

**Model name format**: `openai/gpt-4o` or just `gpt-4o`

**Optional**: For Azure OpenAI or compatible APIs, set:
```env
OPENAI_BASE_URL=https://your-resource.openai.azure.com/
```

#### Quick Provider Switching Examples

```bash
# Using Ollama (default, local)
LLM_PROVIDER=ollama OLLAMA_MODEL=gemma3 python main.py --target http://localhost:3000

# Using OpenRouter with Claude
LLM_PROVIDER=openrouter OPENROUTER_API_KEY=sk-or-v1-xxx OPENROUTER_MODEL=anthropic/claude-3.5-sonnet python main.py --target http://localhost:3000

# Using OpenAI GPT-4o
LLM_PROVIDER=openai OPENAI_API_KEY=sk-xxx OPENAI_MODEL=gpt-4o python main.py --target http://localhost:3000
```

### Target URL Specification

Specify the target application URL when running the scanner. The tool is designed to work with the custom vulnerable application but can scan other web applications.

## Docker Commands Reference

| Command | Purpose |
|---------|---------|
| `docker-compose up -d` | Start vulnerable app in background |
| `docker-compose down` | Stop and remove containers |
| `docker-compose down -v` | Stop and remove containers + volumes (full reset) |
| `docker-compose ps` | Show container status |
| `docker-compose logs -f vulnerable-app` | Follow application logs |
| `docker-compose restart vulnerable-app` | Restart application container |
| `docker-compose exec vulnerable-app sh` | Access application container shell |

## Validation Steps

After starting the vulnerable application, verify the setup:

1. **Container Health:**
   ```bash
   docker-compose ps
   # vulnerable-app should show "Up" and "healthy"
   ```

2. **HTTP Connectivity:**
   ```bash
   curl -I http://localhost:3000
   # Should return HTTP/1.1 200 OK
   ```

3. **Application Verification:**
   - Visit http://localhost:3000 in your browser
   - Verify Juice Shop loads with the product catalog
   - Test the REST API: `curl http://localhost:3000/rest/products/search?q=apple`

4. **Scanner Integration Test:**
   ```bash
   python main.py --target http://localhost:3000 --model gemma3
   ```

## Testing

### Prerequisites for Integration Tests

Integration tests require external services to be running:

| Service | Default Port | Purpose |
|---------|--------------|---------|
| Juice Shop | `localhost:3000` | OWASP Juice Shop - intentionally vulnerable web application |
| Ollama | `localhost:11434` | AI model API for vulnerability analysis |

**Starting Juice Shop:**
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
# Or: cd docker && docker-compose up -d
```

**Verifying Ollama:**
```bash
ollama list  # Ensure at least one model is available (gemma3 recommended)
```

### Test Markers

The test suite uses pytest markers to categorize tests:

| Marker | Description |
|--------|-------------|
| `integration` | Tests requiring external services (Juice Shop and/or Ollama) |
| `requires_target` | Tests specifically requiring Juice Shop on localhost:3000 |
| `requires_ollama` | Tests specifically requiring Ollama on localhost:11434 |
| `requires_katana` | Tests specifically requiring Katana to be installed |
| `slow` | Slow-running tests (full scans, performance tests) |

### Running Tests

**Run all unit tests (fast, no external services required):**
```bash
pytest tests/ -m "not integration"
```

**Run all integration tests (requires vulnerable app + Ollama):**
```bash
pytest tests/ -m "integration"
```

**Run only vulnerable app integration tests:**
```bash
pytest tests/ -m "requires_target"
```

**Run only Ollama integration tests:**
```bash
pytest tests/ -m "requires_ollama"
```

**Run Katana tests (requires Katana installed):**
```bash
pytest tests/test_katana_client.py -v
```

**Run Katana unit tests only (no Katana required):**
```bash
pytest tests/test_katana_client.py -m "not requires_katana" -v
```

**Run Katana integration tests:**
```bash
pytest tests/test_integration.py::TestKatanaIntegration -v
```

**Skip all Katana tests:**
```bash
pytest tests/ -m "not requires_katana"
```

**Exclude slow tests:**
```bash
pytest tests/ -m "not slow"
```

**Run complete test suite (all tests):**
```bash
pytest tests/
```

**Run tests with coverage:**
```bash
pytest tests/ --cov=scanner --cov-report=html
```

**Run tests with verbose output:**
```bash
pytest tests/ -v
```

### CI-Ready Commands

For CI/CD pipelines, use these commands based on the pipeline stage:

```bash
# Fast CI job (unit tests only - no external services needed)
pytest tests/ -m "not integration" --tb=short

# Full CI job (requires vulnerable app and Ollama services)
pytest tests/ -m "integration" --tb=short

# Complete test suite with coverage
pytest tests/ --cov=scanner --cov-report=xml --cov-report=html
```

**Example GitHub Actions workflow snippet:**
```yaml
# Unit tests job (runs on every push)
- name: Run unit tests
  run: pytest tests/ -m "not integration" --tb=short

# Integration tests job (requires service containers)
- name: Run integration tests
  run: pytest tests/ -m "integration" --tb=short
```

## License

© 2026 Andrew Arz. All Rights Reserved.

This code is provided for viewing and educational purposes only. No permission is granted to use, copy, modify, distribute, or sell this software without explicit written consent from the author.

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## Security Notice

This tool is designed for authorized security testing only. Always obtain proper authorization before scanning any web application.

