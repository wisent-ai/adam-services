#!/usr/bin/env python3
"""
Adam's Revenue Service - A standalone HTTP service offering:
- Code review
- Text summarization
- SEO audit
- Data analysis
- API documentation generation

Uses the Singularity revenue_services patterns but runs as a standalone
HTTP server that can earn revenue for Adam on the Wisent platform.
"""

import json
import re
import hashlib
import os
import time
from collections import Counter
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

# Configuration
PORT = int(os.environ.get("ADAM_SERVICE_PORT", 8080))
COORDINATOR_URL = os.environ.get("COORDINATOR_URL", "https://singularity.wisent.ai")
INSTANCE_ID = os.environ.get("AGENT_INSTANCE_ID", "agent_1770501134_2eae18")

# Pricing
PRICES = {
    "code_review": 0.10,
    "summarize": 0.05,
    "seo_audit": 0.05,
    "data_analysis": 0.10,
    "api_docs": 0.10,
}

# Stats
stats = {
    "total_requests": 0,
    "total_revenue": 0.0,
    "total_cost": 0.0,
    "by_service": {},
    "started_at": datetime.now().isoformat(),
}


def detect_language(code: str) -> str:
    """Detect programming language from code patterns."""
    indicators = {
        "python": [r"\bdef \w+\(", r"\bimport \w+", r"\bclass \w+:", r"print\(", r"self\."],
        "javascript": [r"\bfunction\b", r"\bconst\b", r"\blet\b", r"=>", r"console\."],
        "typescript": [r"\binterface\b", r":\s*(string|number|boolean)", r"\btype\b\s+\w+\s*="],
        "go": [r"\bfunc\b", r"\bpackage\b", r":=", r"\bgo\b\s+\w+"],
        "rust": [r"\bfn\b", r"\blet\s+mut\b", r"\bimpl\b", r"\buse\b\s+\w+"],
        "java": [r"\bpublic\s+class\b", r"\bprivate\b", r"\bvoid\b"],
    }
    scores = {}
    for lang, patterns in indicators.items():
        scores[lang] = sum(1 for p in patterns if re.search(p, code))
    if scores:
        best = max(scores, key=scores.get)
        if scores[best] > 0:
            return best
    return "unknown"


def code_review(code: str, language: str = None, focus: str = "all") -> dict:
    """Perform code review analysis."""
    if not language:
        language = detect_language(code)

    issues = []

    # Security checks
    if focus in ("all", "security"):
        security_patterns = [
            (r"eval\s*\(", "Use of eval() - potential code injection", "critical"),
            (r"exec\s*\(", "Use of exec() - potential code injection", "critical"),
            (r"subprocess\.call\s*\(.*shell\s*=\s*True", "Shell injection risk", "critical"),
            (r"os\.system\s*\(", "Use of os.system() - prefer subprocess", "high"),
            (r"password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password", "critical"),
            (r"api_key\s*=\s*['\"][^'\"]+['\"]", "Hardcoded API key", "critical"),
            (r"SELECT\s+.*\+\s*\w+", "Potential SQL injection", "high"),
            (r"innerHTML\s*=", "innerHTML - potential XSS", "high"),
            (r"pickle\.load", "Unsafe deserialization", "high"),
            (r"verify\s*=\s*False", "SSL verification disabled", "high"),
        ]
        for pattern, msg, severity in security_patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count("\n") + 1
                issues.append({"type": "security", "severity": severity, "message": msg, "line": line_num})

    # Bug checks
    if focus in ("all", "bugs"):
        bug_patterns = [
            (r"except\s*:", "Bare except clause", "medium"),
            (r"==\s*None", "Use 'is None' instead", "low"),
            (r"!=\s*None", "Use 'is not None' instead", "low"),
            (r"global\s+\w+", "Global variable usage", "medium"),
        ]
        if language == "python":
            bug_patterns.extend([
                (r"def\s+\w+\([^)]*=\s*\[\]", "Mutable default argument (list)", "high"),
                (r"def\s+\w+\([^)]*=\s*\{\}", "Mutable default argument (dict)", "high"),
            ])
        if language in ("javascript", "typescript"):
            bug_patterns.extend([
                (r"==(?!=)", "Loose equality - prefer ===", "medium"),
                (r"var\s+", "Use 'const' or 'let' instead of 'var'", "low"),
            ])
        for pattern, msg, severity in bug_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count("\n") + 1
                issues.append({"type": "bug", "severity": severity, "message": msg, "line": line_num})

    # Style checks
    if focus in ("all", "style"):
        for i, line in enumerate(code.splitlines(), 1):
            if len(line) > 120:
                issues.append({"type": "style", "severity": "low", "message": f"Line too long ({len(line)} chars)", "line": i})

    # Performance checks
    if focus in ("all", "performance"):
        perf_patterns = [
            (r"for\s+.*\bin\s+range\s*\(\s*len\s*\(", "Use enumerate() instead of range(len())", "low"),
            (r"SELECT\s+\*", "SELECT * - specify needed columns", "medium"),
            (r"import\s+\*", "Wildcard import", "medium"),
        ]
        for pattern, msg, severity in perf_patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count("\n") + 1
                issues.append({"type": "performance", "severity": severity, "message": msg, "line": line_num})

    severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    total_weight = sum(severity_weights.get(i.get("severity", "low"), 1) for i in issues)
    score = max(0, 100 - total_weight * 3)

    suggestions = []
    if any(i["severity"] == "critical" for i in issues):
        suggestions.append("URGENT: Address critical security issues before deploying")
    lines = len(code.splitlines())
    if lines > 300:
        suggestions.append(f"Consider splitting this {lines}-line file into smaller modules")
    if language == "python" and '"""' not in code and lines > 10:
        suggestions.append("Add docstrings for better documentation")

    return {
        "score": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
        "issues": issues,
        "suggestions": suggestions,
        "metrics": {"lines": lines, "characters": len(code), "language": language},
        "summary": f"Found {len(issues)} issue(s). Code quality score: {score}/100 ({language})",
    }


def summarize_text(text: str, max_points: int = 5, style: str = "bullet") -> dict:
    """Summarize text into key points."""
    sentences = re.split(r'[.!?]+\s+', text.strip())
    sentences = [s.strip() for s in sentences if len(s.strip()) > 10]

    if not sentences:
        return {"error": "Text too short or no meaningful sentences found"}

    word_freq = Counter()
    for s in sentences:
        words = re.findall(r'\b[a-zA-Z]{3,}\b', s.lower())
        word_freq.update(words)

    stopwords = {"the", "and", "for", "are", "but", "not", "you", "all", "can",
                 "has", "her", "was", "one", "our", "out", "this", "that", "with",
                 "have", "from", "they", "been", "said", "each", "which", "their",
                 "will", "way", "about", "many", "then", "them", "would", "like"}
    for sw in stopwords:
        word_freq.pop(sw, None)

    def score_sentence(s):
        words = re.findall(r'\b[a-zA-Z]{3,}\b', s.lower())
        if not words:
            return 0
        word_score = sum(word_freq.get(w, 0) for w in words) / len(words)
        idx = sentences.index(s) if s in sentences else len(sentences)
        position_bonus = 2 if idx < 2 else (1 if idx >= len(sentences) - 2 else 0)
        length_bonus = 1 if 20 < len(s) < 200 else 0
        return word_score + position_bonus + length_bonus

    scored = sorted([(s, score_sentence(s)) for s in sentences], key=lambda x: x[1], reverse=True)
    key_points = [s for s, _ in scored[:max_points]]

    word_count = len(text.split())
    if style == "paragraph":
        summary_text = ". ".join(key_points) + "."
    elif style == "executive":
        summary_text = f"Executive Summary ({word_count} words):\n" + ". ".join(key_points[:3]) + "."
    else:
        summary_text = "\n".join(f"- {p}" for p in key_points)

    return {
        "summary": summary_text,
        "key_points": key_points,
        "metrics": {"original_words": word_count, "points_extracted": len(key_points)},
    }


def seo_audit(text: str, target_keywords: list = None) -> dict:
    """Audit content for SEO."""
    target_keywords = target_keywords or []
    words = text.lower().split()
    word_count = len(words)
    sentences = [s for s in re.split(r'[.!?]+\s+', text) if s.strip()]
    sentence_count = len(sentences)
    avg_sentence_length = word_count / sentence_count if sentence_count > 0 else 0
    long_words = [w for w in words if len(w) > 6]
    reading_ease = max(0, min(100, 206.835 - 1.015 * avg_sentence_length - 84.6 * (len(long_words) / word_count if word_count > 0 else 0)))

    keyword_results = {}
    for kw in target_keywords:
        count = text.lower().count(kw.lower())
        density = (count / word_count * 100) if word_count > 0 else 0
        keyword_results[kw] = {
            "count": count,
            "density_pct": round(density, 2),
            "status": "good" if 1 <= density <= 3 else ("low" if density < 1 else "high"),
        }

    issues = []
    if word_count < 300:
        issues.append({"severity": "high", "message": f"Content too short ({word_count} words). Aim for 1000+."})
    if avg_sentence_length > 25:
        issues.append({"severity": "medium", "message": f"Sentences too long (avg {avg_sentence_length:.0f} words)."})

    score = max(0, 100 - sum(15 if i["severity"] == "high" else 8 for i in issues))

    word_freq = Counter(w for w in words if len(w) > 4)
    return {
        "score": score,
        "grade": "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D",
        "metrics": {"word_count": word_count, "reading_ease": round(reading_ease, 1)},
        "keyword_analysis": keyword_results,
        "suggested_keywords": [w for w, _ in word_freq.most_common(10)],
        "issues": issues,
    }


def log_request(service: str, revenue: float, cost: float):
    """Log a request to stats."""
    stats["total_requests"] += 1
    stats["total_revenue"] += revenue
    stats["total_cost"] += cost
    if service not in stats["by_service"]:
        stats["by_service"][service] = {"count": 0, "revenue": 0, "cost": 0}
    stats["by_service"][service]["count"] += 1
    stats["by_service"][service]["revenue"] += revenue
    stats["by_service"][service]["cost"] += cost


class AdamServiceHandler(BaseHTTPRequestHandler):
    """HTTP handler for Adam's services."""

    def _send_json(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, default=str).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/" or path == "/health":
            self._send_json({
                "agent": "Adam",
                "ticker": "ADAM",
                "status": "running",
                "version": "1.0.0",
                "services": list(PRICES.keys()),
                "pricing": PRICES,
                "toolkit": "github.com/wisent-ai/adam-agent-toolkit",
                "description": "AI-powered code review, text summarization, SEO audit, and data analysis services",
            })

        elif path == "/capabilities":
            self._send_json({
                "services": [
                    {"name": "code_review", "price": 0.10, "description": "Analyze code for bugs, security issues, style problems, and performance"},
                    {"name": "summarize", "price": 0.05, "description": "Condense text into key points"},
                    {"name": "seo_audit", "price": 0.05, "description": "Audit content for SEO optimization"},
                    {"name": "data_analysis", "price": 0.10, "description": "Extract insights from structured data"},
                    {"name": "api_docs", "price": 0.10, "description": "Generate API documentation from code"},
                ],
            })

        elif path == "/stats":
            self._send_json({
                "stats": stats,
                "profit": round(stats["total_revenue"] - stats["total_cost"], 4),
            })

        else:
            self._send_json({"error": "Not found", "available_endpoints": ["/", "/capabilities", "/stats", "/code_review", "/summarize", "/seo_audit"]}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else "{}"

        try:
            params = json.loads(body)
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        if path == "/code_review":
            code = params.get("code", "")
            if not code:
                self._send_json({"error": "'code' parameter required"}, 400)
                return
            result = code_review(code, params.get("language"), params.get("focus", "all"))
            log_request("code_review", 0.10, 0.01)
            self._send_json({"success": True, "service": "code_review", "price": 0.10, "result": result})

        elif path == "/summarize":
            text = params.get("text", "")
            if not text:
                self._send_json({"error": "'text' parameter required"}, 400)
                return
            result = summarize_text(text, params.get("max_points", 5), params.get("style", "bullet"))
            log_request("summarize", 0.05, 0.005)
            self._send_json({"success": True, "service": "summarize", "price": 0.05, "result": result})

        elif path == "/seo_audit":
            text = params.get("text", "")
            if not text:
                self._send_json({"error": "'text' parameter required"}, 400)
                return
            result = seo_audit(text, params.get("target_keywords", []))
            log_request("seo_audit", 0.05, 0.005)
            self._send_json({"success": True, "service": "seo_audit", "price": 0.05, "result": result})

        else:
            self._send_json({"error": "Unknown service", "available": list(PRICES.keys())}, 404)

    def log_message(self, format, *args):
        # Suppress default logging
        pass


def run_server():
    """Start the HTTP service."""
    server = HTTPServer(("0.0.0.0", PORT), AdamServiceHandler)
    print(f"Adam's Revenue Service running on port {PORT}")
    print(f"Services: {list(PRICES.keys())}")
    print(f"Health: http://localhost:{PORT}/")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
