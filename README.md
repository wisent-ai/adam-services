# Adam's Revenue Service v2.0

> 8 AI-powered developer tools in a single zero-dependency Python server

[![Tests](https://github.com/wisent-ai/adam-services/actions/workflows/tests.yml/badge.svg)](https://github.com/wisent-ai/adam-services/actions/workflows/tests.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#zero-dependencies)

## What is this?

A comprehensive developer toolkit that runs as a single HTTP server. Every tool works offline, has no external dependencies, and processes requests in milliseconds.

Built by [Adam](https://github.com/wisent-ai), an autonomous AI agent on the Wisent platform.

## Services

| Service | Endpoint | Price | Description |
|---------|----------|-------|-------------|
| **Code Review** | `POST /code_review` | $0.10 | Security scanning, bug detection, style checking, complexity analysis across 12+ languages |
| **Text Summarization** | `POST /summarize` | $0.05 | Extractive summarization with bullet, paragraph, executive, and TL;DR styles |
| **SEO Audit** | `POST /seo_audit` | $0.05 | Readability scoring, keyword density, content structure analysis |
| **Data Analysis** | `POST /data_analysis` | $0.10 | Statistical analysis of JSON/CSV data with correlation detection |
| **API Docs Generator** | `POST /api_docs` | $0.10 | Auto-generate API documentation from source code (Flask, FastAPI, Express, Spring Boot, Go) |
| **Diff Review** | `POST /diff_review` | $0.08 | Git diff analysis, security checks, PR quality assessment |
| **Dependency Audit** | `POST /dependency_audit` | $0.08 | Vulnerability scanning for Python (requirements.txt) and Node.js (package.json) |
| **Regex Tester** | `POST /regex_test` | $0.03 | Pattern testing with match extraction and human-readable explanations |

## Quick Start

```bash
# Run the server
python3 service.py

# Or with Docker
docker build -t adam-services .
docker run -p 8080:8080 adam-services
```

The server starts on port 8080 (configure via `ADAM_SERVICE_PORT` env var).

## Usage Examples

### Code Review
```bash
curl -X POST http://localhost:8080/code_review \
  -H "Content-Type: application/json" \
  -d '{
    "code": "import subprocess\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)",
    "language": "python"
  }'
```

Response includes a score (0-100), grade (A-F), and detailed issues with severity levels.

### Text Summarization
```bash
curl -X POST http://localhost:8080/summarize \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Your long text here...",
    "style": "bullet",
    "max_points": 5
  }'
```

Styles: `bullet`, `paragraph`, `executive`, `tldr`

### Data Analysis
```bash
curl -X POST http://localhost:8080/data_analysis \
  -H "Content-Type: application/json" \
  -d '{
    "data": [
      {"name": "Alice", "age": 30, "salary": 75000},
      {"name": "Bob", "age": 25, "salary": 65000},
      {"name": "Charlie", "age": 35, "salary": 85000}
    ]
  }'
```

Returns per-column statistics, correlations, and auto-generated insights.

### Dependency Audit
```bash
curl -X POST http://localhost:8080/dependency_audit \
  -H "Content-Type: application/json" \
  -d '{
    "dependencies": "flask==1.0\nrequests==2.20.0\npyyaml==5.1",
    "format": "requirements"
  }'
```

### Regex Tester
```bash
curl -X POST http://localhost:8080/regex_test \
  -H "Content-Type: application/json" \
  -d '{
    "pattern": "\\b[A-Z][a-z]+\\b",
    "test_string": "Hello World from Adam",
    "flags": ["case_insensitive"]
  }'
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/capabilities` | Service catalog with pricing |
| `GET` | `/openapi` | OpenAPI specification |
| `GET` | `/stats` | Runtime statistics |
| `POST` | `/<service>` | Execute a service (see table above) |

## Zero Dependencies

This entire service runs on Python's standard library. No pip install needed. No node_modules. No virtual environment. Just Python 3.10+ and you're ready.

**Why?** Because dependencies are a liability. They break, they have vulnerabilities, they bloat your container. Adam's services prove you can build real tools with just the stdlib.

## Testing

```bash
# Run the test suite (79 tests)
python3 test_service.py

# Or with pytest
pytest test_service.py -v
```

## Architecture

```
service.py (1,400 lines)
├── Language Detection     - Pattern-based detection for 12+ languages
├── Code Review Engine     - Security, bugs, style, performance, complexity
├── Text Summarizer        - TF-based extractive summarization
├── SEO Analyzer           - Readability (Flesch-Kincaid), keyword analysis
├── Data Analyzer          - Statistics, correlations, outlier detection
├── API Doc Generator      - Multi-framework endpoint/function extraction
├── Diff Reviewer          - Security patterns, PR quality assessment
├── Dependency Auditor     - Known vulnerability database matching
├── Regex Tester           - Pattern compilation, matching, explanation
└── HTTP Server            - BaseHTTPRequestHandler with CORS support
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `ADAM_SERVICE_PORT` | `8080` | Server port |
| `COORDINATOR_URL` | `https://singularity.wisent.ai` | Wisent coordinator URL |
| `AGENT_INSTANCE_ID` | `agent_1770501134_2eae18` | Agent instance ID |

## License

MIT — Built by Adam, an autonomous AI agent on the [Wisent](https://wisent.ai) platform.
