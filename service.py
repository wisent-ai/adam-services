#!/usr/bin/env python3
"""
Adam's Revenue Service v2.0 - Comprehensive AI analysis toolkit.

Endpoints:
  POST /code_review     - Code quality, security, bugs, style, performance analysis
  POST /summarize       - Text summarization with multiple styles
  POST /seo_audit       - SEO content optimization analysis
  POST /data_analysis   - CSV/JSON structured data insights
  POST /api_docs        - API documentation generation from code
  POST /diff_review     - Git diff / PR review
  POST /dependency_audit - Dependency security & freshness check
  POST /regex_test      - Regex pattern tester with explanation

Zero external dependencies. Pure Python 3.10+ stdlib.
"""

import csv
import io
import json
import math
import re
import hashlib
import os
import statistics
import time
from collections import Counter, defaultdict
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

# ─── Configuration ───────────────────────────────────────────────────────────

PORT = int(os.environ.get("ADAM_SERVICE_PORT", 8080))
COORDINATOR_URL = os.environ.get("COORDINATOR_URL", "https://singularity.wisent.ai")
INSTANCE_ID = os.environ.get("AGENT_INSTANCE_ID", "agent_1770501134_2eae18")
VERSION = "2.0.0"

# Pricing per request
PRICES = {
    "code_review": 0.10,
    "summarize": 0.05,
    "seo_audit": 0.05,
    "data_analysis": 0.10,
    "api_docs": 0.10,
    "diff_review": 0.08,
    "dependency_audit": 0.08,
    "regex_test": 0.03,
}

# Runtime stats
stats = {
    "total_requests": 0,
    "total_revenue": 0.0,
    "total_cost": 0.0,
    "errors": 0,
    "by_service": {},
    "started_at": datetime.now().isoformat(),
}


# ─── Utilities ───────────────────────────────────────────────────────────────

def detect_language(code: str) -> str:
    """Detect programming language from code patterns."""
    indicators = {
        "python": [
            r"\bdef \w+\(", r"\bimport \w+", r"\bclass \w+:", r"print\(",
            r"self\.", r"\bif __name__", r"\.append\(", r"\basync def\b",
        ],
        "javascript": [
            r"\bfunction\b", r"\bconst\b", r"\blet\b", r"=>", r"console\.",
            r"require\(", r"module\.exports", r"document\.",
        ],
        "typescript": [
            r"\binterface\b", r":\s*(string|number|boolean)", r"\btype\b\s+\w+\s*=",
            r"\benum\b", r"<\w+>", r"as\s+\w+",
        ],
        "go": [
            r"\bfunc\b", r"\bpackage\b", r":=", r"\bgo\b\s+\w+",
            r"\bdefer\b", r"\bchan\b", r"fmt\.",
        ],
        "rust": [
            r"\bfn\b", r"\blet\s+mut\b", r"\bimpl\b", r"\buse\b\s+\w+",
            r"\bmatch\b", r"\bpub\s+fn\b", r"->",
        ],
        "java": [
            r"\bpublic\s+class\b", r"\bprivate\b", r"\bvoid\b",
            r"\bstatic\b", r"System\.out", r"\@Override",
        ],
        "ruby": [
            r"\bdef\s+\w+", r"\bend\b", r"\battr_", r"\bputs\b",
            r"\bdo\s*\|", r"\brequire\b",
        ],
        "php": [
            r"<\?php", r"\$\w+", r"\bfunction\b", r"->",
            r"::", r"echo\b",
        ],
        "c": [
            r"#include", r"\bint\s+main\b", r"\bprintf\b", r"\bmalloc\b",
            r"\bstruct\b", r"\btypedef\b",
        ],
        "cpp": [
            r"#include", r"\bstd::", r"\bcout\b", r"\bclass\b",
            r"\btemplate\b", r"\bnamespace\b",
        ],
        "shell": [
            r"#!/bin/(ba)?sh", r"\becho\b", r"\bfi\b", r"\bdone\b",
            r"\$\{", r"\bif\s+\[",
        ],
    }
    scores = {}
    for lang, patterns in indicators.items():
        scores[lang] = sum(1 for p in patterns if re.search(p, code))
    if scores:
        best = max(scores, key=scores.get)
        if scores[best] > 0:
            return best
    return "unknown"


def log_request(service: str, revenue: float, cost: float):
    """Log a request to stats."""
    stats["total_requests"] += 1
    stats["total_revenue"] += revenue
    stats["total_cost"] += cost
    if service not in stats["by_service"]:
        stats["by_service"][service] = {"count": 0, "revenue": 0.0, "cost": 0.0}
    stats["by_service"][service]["count"] += 1
    stats["by_service"][service]["revenue"] += revenue
    stats["by_service"][service]["cost"] += cost


def log_error():
    stats["errors"] += 1


# ─── Service: Code Review ────────────────────────────────────────────────────

SECURITY_PATTERNS = [
    # Injection
    (r"eval\s*\(", "Use of eval() - potential code injection", "critical"),
    (r"exec\s*\(", "Use of exec() - potential code injection", "critical"),
    (r"subprocess\.call\s*\(.*shell\s*=\s*True", "Shell injection risk via subprocess", "critical"),
    (r"os\.system\s*\(", "Use of os.system() - prefer subprocess with shell=False", "high"),
    (r"os\.popen\s*\(", "Use of os.popen() - prefer subprocess", "high"),
    # Secrets
    (r"""(?:password|passwd|secret|api_key|apikey|token|auth)\s*=\s*['"][^'"]{4,}['"]""", "Hardcoded secret/credential", "critical"),
    (r"BEGIN\s+(RSA|DSA|EC)?\s*PRIVATE\s+KEY", "Private key in source code", "critical"),
    # SQL injection
    (r"""(?:execute|cursor\.)\s*\(\s*['"].*?%s""", "Potential SQL injection via string formatting", "high"),
    (r"""f['"].*?SELECT.*?\{""", "Potential SQL injection via f-string", "critical"),
    (r"SELECT\s+.*\+\s*\w+", "Potential SQL injection via concatenation", "high"),
    # XSS
    (r"innerHTML\s*=", "innerHTML assignment - potential XSS", "high"),
    (r"document\.write\s*\(", "document.write() - potential XSS", "high"),
    (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML - verify input is sanitized", "medium"),
    # Deserialization
    (r"pickle\.load", "Unsafe pickle deserialization", "high"),
    (r"yaml\.load\s*\([^)]*\)", "Unsafe YAML load - use yaml.safe_load()", "high"),
    (r"marshal\.loads", "Unsafe marshal deserialization", "high"),
    # Crypto
    (r"\bMD5\b|\bmd5\b", "MD5 is cryptographically broken - use SHA-256+", "medium"),
    (r"\bSHA1\b|\bsha1\b", "SHA-1 is deprecated - use SHA-256+", "medium"),
    (r"random\.(random|randint|choice)", "random module is not cryptographically secure - use secrets", "medium"),
    # Network
    (r"verify\s*=\s*False", "SSL verification disabled", "high"),
    (r"CORS.*\*|AllowAllOrigins|Access-Control-Allow-Origin:\s*\*", "Overly permissive CORS", "medium"),
    (r"0\.0\.0\.0", "Binding to all interfaces - restrict in production", "low"),
    # File operations
    (r"open\s*\(.*(r['\"]|w['\"])", "File operation - verify path sanitization", "low"),
    (r"\.\.\/|\.\.\\\\", "Path traversal pattern", "high"),
]

BUG_PATTERNS = {
    "_common": [
        (r"except\s*:", "Bare except clause - catches SystemExit, KeyboardInterrupt too", "medium"),
        (r"==\s*None", "Use 'is None' instead of '== None'", "low"),
        (r"!=\s*None", "Use 'is not None' instead of '!= None'", "low"),
        (r"global\s+\w+", "Global variable usage - consider dependency injection", "medium"),
        (r"TODO|FIXME|HACK|XXX|TEMP", "Unresolved TODO/FIXME/HACK marker", "low"),
        (r"print\s*\(.*\).*#.*debug", "Debug print left in code", "low"),
    ],
    "python": [
        (r"def\s+\w+\([^)]*=\s*\[\]", "Mutable default argument (list) - use None", "high"),
        (r"def\s+\w+\([^)]*=\s*\{\}", "Mutable default argument (dict) - use None", "high"),
        (r"except\s+\w+\s*,\s*\w+", "Python 2-style except clause", "medium"),
        (r"\.has_key\s*\(", "dict.has_key() removed in Python 3 - use 'in'", "high"),
        (r"raise\s+\w+,", "Python 2-style raise - use raise X(args)", "high"),
        (r"from\s+__future__", "Future import may indicate Python 2 compatibility code", "low"),
    ],
    "javascript": [
        (r"==(?!=)", "Loose equality - prefer === for type-safe comparison", "medium"),
        (r"var\s+", "Use 'const' or 'let' instead of 'var'", "low"),
        (r"new\s+Array\(", "Use array literal [] instead of new Array()", "low"),
        (r"\.then\([^)]*\)(?!.*\.catch)", "Promise without .catch() - unhandled rejection", "medium"),
        (r"async\s+function[^{]*\{(?![\s\S]*try)", "Async function without try/catch", "low"),
    ],
    "typescript": [
        (r"\bany\b", "Use of 'any' type - defeats TypeScript's purpose", "medium"),
        (r"as\s+any\b", "Type assertion to 'any' - unsafe", "high"),
        (r"@ts-ignore", "@ts-ignore suppresses type checking", "medium"),
        (r"!\.", "Non-null assertion (!) - can cause runtime errors", "low"),
    ],
    "go": [
        (r"_\s*=\s*\w+\.\w+\(", "Ignored error return - handle or explicitly document", "high"),
        (r"panic\s*\(", "Panic in production code - use error returns", "medium"),
        (r"fmt\.Print", "fmt.Print in production - use structured logging", "low"),
    ],
    "rust": [
        (r"\.unwrap\(\)", ".unwrap() can panic - use ? or match", "medium"),
        (r"\.expect\(", ".expect() can panic - consider ? operator", "low"),
        (r"unsafe\s*\{", "Unsafe block - verify memory safety", "high"),
    ],
}

PERF_PATTERNS = [
    (r"for\s+.*\bin\s+range\s*\(\s*len\s*\(", "Use enumerate() instead of range(len())", "low"),
    (r"SELECT\s+\*", "SELECT * - specify needed columns only", "medium"),
    (r"import\s+\*", "Wildcard import - import only what you need", "medium"),
    (r"\.readlines\(\)", "readlines() loads entire file into memory - iterate directly", "medium"),
    (r"\+\s*=\s*['\"]", "String concatenation in loop - use join() or list", "low"),
    (r"time\.sleep", "Blocking sleep - consider async alternatives", "low"),
    (r"\.values\(\).*\.values\(\)", "Multiple .values() calls - cache the result", "low"),
    (r"N\+1|n\+1", "Potential N+1 query pattern", "high"),
]


def code_review(code: str, language: str = None, focus: str = "all") -> dict:
    """Comprehensive code review analysis."""
    if not language:
        language = detect_language(code)

    issues = []
    lines = code.splitlines()
    line_count = len(lines)

    # Security checks
    if focus in ("all", "security"):
        for pattern, msg, severity in SECURITY_PATTERNS:
            try:
                for match in re.finditer(pattern, code, re.IGNORECASE):
                    line_num = code[:match.start()].count("\n") + 1
                    issues.append({
                        "type": "security", "severity": severity,
                        "message": msg, "line": line_num,
                        "snippet": lines[line_num - 1].strip()[:80] if line_num <= line_count else "",
                    })
            except re.error:
                pass

    # Bug checks
    if focus in ("all", "bugs"):
        patterns = list(BUG_PATTERNS.get("_common", []))
        patterns.extend(BUG_PATTERNS.get(language, []))
        for pattern, msg, severity in patterns:
            try:
                for match in re.finditer(pattern, code):
                    line_num = code[:match.start()].count("\n") + 1
                    issues.append({
                        "type": "bug", "severity": severity,
                        "message": msg, "line": line_num,
                        "snippet": lines[line_num - 1].strip()[:80] if line_num <= line_count else "",
                    })
            except re.error:
                pass

    # Style checks
    if focus in ("all", "style"):
        for i, line in enumerate(lines, 1):
            stripped = line.rstrip()
            if len(stripped) > 120:
                issues.append({
                    "type": "style", "severity": "low",
                    "message": f"Line too long ({len(stripped)} chars, max 120)", "line": i,
                })
            if line.rstrip() != line.rstrip("\n") and line.endswith(" "):
                issues.append({
                    "type": "style", "severity": "low",
                    "message": "Trailing whitespace", "line": i,
                })

        # Check for inconsistent indentation
        indent_tabs = sum(1 for l in lines if l.startswith("\t"))
        indent_spaces = sum(1 for l in lines if l.startswith("  "))
        if indent_tabs > 0 and indent_spaces > 0:
            issues.append({
                "type": "style", "severity": "medium",
                "message": f"Mixed indentation: {indent_tabs} tab-indented + {indent_spaces} space-indented lines",
                "line": 0,
            })

    # Performance checks
    if focus in ("all", "performance"):
        for pattern, msg, severity in PERF_PATTERNS:
            try:
                for match in re.finditer(pattern, code, re.IGNORECASE):
                    line_num = code[:match.start()].count("\n") + 1
                    issues.append({
                        "type": "performance", "severity": severity,
                        "message": msg, "line": line_num,
                        "snippet": lines[line_num - 1].strip()[:80] if line_num <= line_count else "",
                    })
            except re.error:
                pass

    # Compute score
    severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    total_weight = sum(severity_weights.get(i.get("severity", "low"), 1) for i in issues)
    score = max(0, 100 - total_weight * 3)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    # Suggestions
    suggestions = []
    critical_count = sum(1 for i in issues if i["severity"] == "critical")
    high_count = sum(1 for i in issues if i["severity"] == "high")
    if critical_count:
        suggestions.append(f"URGENT: Fix {critical_count} critical issue(s) before deploying")
    if high_count:
        suggestions.append(f"Address {high_count} high-severity issue(s)")
    if line_count > 300:
        suggestions.append(f"Consider splitting this {line_count}-line file into smaller modules")
    if language == "python" and '"""' not in code and "'''" not in code and line_count > 20:
        suggestions.append("Add docstrings for classes and public functions")

    # Complexity estimate (simple cyclomatic)
    branches = len(re.findall(r"\b(if|elif|else|for|while|except|case|switch|catch|&&|\|\|)\b", code))
    func_count = len(re.findall(r"\b(def|function|func|fn)\s+\w+", code))
    avg_complexity = round(branches / max(func_count, 1), 1)
    if avg_complexity > 10:
        suggestions.append(f"High average complexity ({avg_complexity}) - consider refactoring")

    # Dedup issues by (type, message, line)
    seen = set()
    unique_issues = []
    for issue in issues:
        key = (issue["type"], issue["message"], issue["line"])
        if key not in seen:
            seen.add(key)
            unique_issues.append(issue)

    return {
        "score": score,
        "grade": grade,
        "issues": unique_issues,
        "issue_summary": {
            "critical": critical_count,
            "high": high_count,
            "medium": sum(1 for i in unique_issues if i["severity"] == "medium"),
            "low": sum(1 for i in unique_issues if i["severity"] == "low"),
            "total": len(unique_issues),
        },
        "suggestions": suggestions,
        "metrics": {
            "lines": line_count,
            "characters": len(code),
            "language": language,
            "functions": func_count,
            "branches": branches,
            "avg_complexity": avg_complexity,
        },
        "summary": f"Score: {score}/100 (Grade {grade}). Found {len(unique_issues)} issue(s) in {line_count} lines of {language}.",
    }


# ─── Service: Text Summarization ─────────────────────────────────────────────

STOPWORDS = frozenset({
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "has", "her",
    "was", "one", "our", "out", "this", "that", "with", "have", "from", "they",
    "been", "said", "each", "which", "their", "will", "way", "about", "many",
    "then", "them", "would", "like", "into", "could", "than", "other", "also",
    "its", "over", "such", "some", "very", "when", "what", "your", "how", "just",
    "more", "these", "those", "only", "come", "made", "find", "where", "most",
    "may", "any", "new", "take", "get", "make", "know", "much", "being", "well",
    "back", "there", "still", "here", "should", "after", "before", "does", "did",
})


def summarize_text(text: str, max_points: int = 5, style: str = "bullet") -> dict:
    """Summarize text into key points using extractive summarization."""
    # Split into sentences
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    sentences = [s.strip() for s in sentences if len(s.strip()) > 15]

    if not sentences:
        return {"error": "Text too short or no meaningful sentences found"}

    word_count = len(text.split())

    # Build word importance (TF-based)
    word_freq = Counter()
    for s in sentences:
        words = re.findall(r'\b[a-zA-Z]{3,}\b', s.lower())
        word_freq.update(w for w in words if w not in STOPWORDS)

    # Normalize frequencies
    max_freq = max(word_freq.values()) if word_freq else 1
    norm_freq = {w: c / max_freq for w, c in word_freq.items()}

    # Score sentences
    def score_sentence(idx, sentence):
        words = re.findall(r'\b[a-zA-Z]{3,}\b', sentence.lower())
        words = [w for w in words if w not in STOPWORDS]
        if not words:
            return 0

        # Word importance score
        word_score = sum(norm_freq.get(w, 0) for w in words) / len(words)

        # Position bonus (first and last sentences more important)
        total = len(sentences)
        if idx == 0:
            position_bonus = 3.0
        elif idx < total * 0.15:
            position_bonus = 2.0
        elif idx >= total * 0.85:
            position_bonus = 1.5
        else:
            position_bonus = 0

        # Length bonus (prefer medium-length sentences)
        length = len(sentence)
        length_bonus = 1.0 if 40 < length < 250 else 0

        # Named entity bonus (capitalized words = likely important)
        caps = len(re.findall(r'\b[A-Z][a-z]+\b', sentence))
        entity_bonus = min(caps * 0.3, 1.5)

        # Numbers often indicate facts
        number_bonus = 0.5 if re.search(r'\d+', sentence) else 0

        return word_score + position_bonus + length_bonus + entity_bonus + number_bonus

    scored = [(i, s, score_sentence(i, s)) for i, s in enumerate(sentences)]
    scored.sort(key=lambda x: x[2], reverse=True)

    # Select top sentences, then reorder by original position
    selected = sorted(scored[:max_points], key=lambda x: x[0])
    key_points = [s for _, s, _ in selected]

    # Extract key topics
    top_words = [w for w, _ in word_freq.most_common(10)]

    # Format output
    if style == "paragraph":
        summary_text = " ".join(key_points)
    elif style == "executive":
        summary_text = f"Executive Summary ({word_count} words analyzed):\n\n"
        summary_text += " ".join(key_points[:3])
        if len(key_points) > 3:
            summary_text += "\n\nAdditional Points:\n" + "\n".join(f"- {p}" for p in key_points[3:])
    elif style == "tldr":
        summary_text = "TL;DR: " + key_points[0] if key_points else ""
    else:  # bullet
        summary_text = "\n".join(f"• {p}" for p in key_points)

    return {
        "summary": summary_text,
        "key_points": key_points,
        "key_topics": top_words,
        "metrics": {
            "original_words": word_count,
            "original_sentences": len(sentences),
            "points_extracted": len(key_points),
            "compression_ratio": round(len(" ".join(key_points).split()) / word_count, 2) if word_count else 0,
        },
    }


# ─── Service: SEO Audit ──────────────────────────────────────────────────────

def seo_audit(text: str, target_keywords: list = None, title: str = "", meta_description: str = "") -> dict:
    """Comprehensive SEO content audit."""
    target_keywords = target_keywords or []
    words = text.lower().split()
    word_count = len(words)
    sentences = [s for s in re.split(r'[.!?]+\s+', text) if s.strip()]
    sentence_count = len(sentences)
    avg_sentence_length = word_count / sentence_count if sentence_count > 0 else 0
    paragraphs = [p for p in text.split("\n\n") if p.strip()]

    # Readability (Flesch-Kincaid approximation)
    syllable_count = sum(max(1, len(re.findall(r'[aeiouy]+', w.lower()))) for w in words)
    avg_syllables = syllable_count / word_count if word_count else 0
    reading_ease = max(0, min(100,
        206.835 - 1.015 * avg_sentence_length - 84.6 * avg_syllables
    ))

    # Grade level
    if reading_ease >= 90:
        reading_level = "5th grade (very easy)"
    elif reading_ease >= 80:
        reading_level = "6th grade (easy)"
    elif reading_ease >= 70:
        reading_level = "7th grade (fairly easy)"
    elif reading_ease >= 60:
        reading_level = "8th-9th grade (standard)"
    elif reading_ease >= 50:
        reading_level = "10th-12th grade (fairly difficult)"
    elif reading_ease >= 30:
        reading_level = "College level (difficult)"
    else:
        reading_level = "Graduate level (very difficult)"

    # Keyword analysis
    keyword_results = {}
    for kw in target_keywords:
        kw_lower = kw.lower()
        count = text.lower().count(kw_lower)
        density = (count / word_count * 100) if word_count > 0 else 0

        # Check placement
        in_first_100 = kw_lower in " ".join(words[:100])
        in_last_100 = kw_lower in " ".join(words[-100:]) if word_count > 100 else False
        in_title = kw_lower in title.lower() if title else None

        keyword_results[kw] = {
            "count": count,
            "density_pct": round(density, 2),
            "status": "good" if 1 <= density <= 3 else ("low" if density < 1 else "overstuffed"),
            "in_first_100_words": in_first_100,
            "in_conclusion": in_last_100,
            "in_title": in_title,
        }

    # Content structure analysis
    headings = re.findall(r'^#+\s+.+$', text, re.MULTILINE)  # Markdown headings
    html_headings = re.findall(r'<h[1-6][^>]*>.*?</h[1-6]>', text, re.IGNORECASE)
    links = re.findall(r'https?://[^\s<>"\']+', text)
    images = re.findall(r'!\[.*?\]\(.*?\)|<img[^>]+>', text)

    # Issues
    issues = []
    suggestions = []

    if word_count < 300:
        issues.append({"severity": "high", "message": f"Content too short ({word_count} words). Aim for 1000+ words for ranking."})
    elif word_count < 800:
        issues.append({"severity": "medium", "message": f"Content could be longer ({word_count} words). 1500+ words rank better."})

    if avg_sentence_length > 25:
        issues.append({"severity": "medium", "message": f"Sentences too long (avg {avg_sentence_length:.0f} words). Aim for 15-20."})

    if len(paragraphs) < 3:
        issues.append({"severity": "medium", "message": "Too few paragraphs. Break content into more sections."})

    if not headings and not html_headings:
        issues.append({"severity": "high", "message": "No headings found. Add H2/H3 subheadings for structure."})

    if not links:
        suggestions.append("Add internal and external links to improve SEO")

    if not images:
        suggestions.append("Add images with alt text for better engagement")

    if reading_ease < 50:
        issues.append({"severity": "medium", "message": f"Content is hard to read (Flesch score: {reading_ease:.0f}). Simplify language."})

    if title:
        if len(title) > 60:
            issues.append({"severity": "medium", "message": f"Title too long ({len(title)} chars). Keep under 60."})
        elif len(title) < 20:
            issues.append({"severity": "low", "message": f"Title too short ({len(title)} chars). Aim for 50-60."})

    if meta_description:
        if len(meta_description) > 160:
            issues.append({"severity": "medium", "message": f"Meta description too long ({len(meta_description)} chars). Keep under 160."})
        elif len(meta_description) < 70:
            issues.append({"severity": "low", "message": f"Meta description too short ({len(meta_description)} chars). Aim for 120-160."})

    # Score calculation
    score = 100
    for issue in issues:
        if issue["severity"] == "high":
            score -= 15
        elif issue["severity"] == "medium":
            score -= 8
        else:
            score -= 3
    score = max(0, score)

    # Top keywords in content
    content_words = [w for w in words if len(w) > 4 and w not in STOPWORDS]
    top_content_keywords = [w for w, _ in Counter(content_words).most_common(15)]

    return {
        "score": score,
        "grade": "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D",
        "readability": {
            "flesch_score": round(reading_ease, 1),
            "reading_level": reading_level,
            "avg_sentence_length": round(avg_sentence_length, 1),
            "avg_syllables_per_word": round(avg_syllables, 2),
        },
        "content_metrics": {
            "word_count": word_count,
            "sentence_count": sentence_count,
            "paragraph_count": len(paragraphs),
            "heading_count": len(headings) + len(html_headings),
            "link_count": len(links),
            "image_count": len(images),
        },
        "keyword_analysis": keyword_results,
        "suggested_keywords": top_content_keywords,
        "issues": issues,
        "suggestions": suggestions,
    }


# ─── Service: Data Analysis ──────────────────────────────────────────────────

def data_analysis(data: any, format: str = "auto") -> dict:
    """Analyze structured data (JSON array or CSV string)."""
    records = []

    # Parse input
    if isinstance(data, str):
        # Try CSV
        try:
            reader = csv.DictReader(io.StringIO(data))
            records = list(reader)
            format = "csv"
        except Exception:
            pass

        # Try JSON string
        if not records:
            try:
                parsed = json.loads(data)
                if isinstance(parsed, list):
                    records = parsed
                    format = "json_array"
                elif isinstance(parsed, dict):
                    records = [parsed]
                    format = "json_object"
            except json.JSONDecodeError:
                return {"error": "Could not parse data as CSV or JSON"}

    elif isinstance(data, list):
        records = data
        format = "json_array"
    elif isinstance(data, dict):
        records = [data]
        format = "json_object"
    else:
        return {"error": "Data must be a JSON array, JSON object, or CSV string"}

    if not records:
        return {"error": "No records found in data"}

    # Analyze schema
    all_keys = set()
    for r in records:
        if isinstance(r, dict):
            all_keys.update(r.keys())

    columns = sorted(all_keys)
    row_count = len(records)

    # Per-column analysis
    column_analysis = {}
    for col in columns:
        values = [r.get(col) for r in records if isinstance(r, dict)]
        non_null = [v for v in values if v is not None and v != ""]
        null_count = len(values) - len(non_null)

        col_info = {
            "total": len(values),
            "non_null": len(non_null),
            "null_count": null_count,
            "null_pct": round(null_count / len(values) * 100, 1) if values else 0,
        }

        # Try numeric analysis
        numeric_values = []
        for v in non_null:
            try:
                numeric_values.append(float(v))
            except (ValueError, TypeError):
                pass

        if numeric_values and len(numeric_values) > len(non_null) * 0.5:
            col_info["type"] = "numeric"
            col_info["min"] = min(numeric_values)
            col_info["max"] = max(numeric_values)
            col_info["mean"] = round(statistics.mean(numeric_values), 4)
            col_info["median"] = round(statistics.median(numeric_values), 4)
            if len(numeric_values) > 1:
                col_info["stdev"] = round(statistics.stdev(numeric_values), 4)
            col_info["sum"] = round(sum(numeric_values), 4)
            # Detect outliers (>2 std devs from mean)
            if len(numeric_values) > 5:
                mean = statistics.mean(numeric_values)
                std = statistics.stdev(numeric_values)
                outliers = [v for v in numeric_values if abs(v - mean) > 2 * std]
                col_info["outlier_count"] = len(outliers)
        else:
            # Categorical analysis
            str_values = [str(v) for v in non_null]
            col_info["type"] = "categorical"
            col_info["unique_count"] = len(set(str_values))
            col_info["top_values"] = [
                {"value": v, "count": c}
                for v, c in Counter(str_values).most_common(5)
            ]

        column_analysis[col] = col_info

    # Correlations between numeric columns
    numeric_cols = [c for c, info in column_analysis.items() if info.get("type") == "numeric"]
    correlations = []
    if len(numeric_cols) >= 2:
        for i, col_a in enumerate(numeric_cols):
            for col_b in numeric_cols[i + 1:]:
                vals_a = []
                vals_b = []
                for r in records:
                    if isinstance(r, dict):
                        try:
                            a = float(r.get(col_a, ""))
                            b = float(r.get(col_b, ""))
                            vals_a.append(a)
                            vals_b.append(b)
                        except (ValueError, TypeError):
                            pass
                if len(vals_a) >= 3:
                    # Pearson correlation
                    n = len(vals_a)
                    mean_a = sum(vals_a) / n
                    mean_b = sum(vals_b) / n
                    cov = sum((a - mean_a) * (b - mean_b) for a, b in zip(vals_a, vals_b)) / n
                    std_a = math.sqrt(sum((a - mean_a) ** 2 for a in vals_a) / n)
                    std_b = math.sqrt(sum((b - mean_b) ** 2 for b in vals_b) / n)
                    if std_a > 0 and std_b > 0:
                        corr = round(cov / (std_a * std_b), 4)
                        if abs(corr) > 0.3:
                            correlations.append({
                                "columns": [col_a, col_b],
                                "correlation": corr,
                                "strength": "strong" if abs(corr) > 0.7 else "moderate",
                            })

    # Generate insights
    insights = []
    for col, info in column_analysis.items():
        if info.get("null_pct", 0) > 20:
            insights.append(f"Column '{col}' has {info['null_pct']}% missing values")
        if info.get("type") == "numeric" and info.get("outlier_count", 0) > 0:
            insights.append(f"Column '{col}' has {info['outlier_count']} outlier(s)")
        if info.get("type") == "categorical" and info.get("unique_count", 0) == row_count:
            insights.append(f"Column '{col}' appears to be a unique identifier")
        if info.get("type") == "categorical" and info.get("unique_count", 0) == 1:
            insights.append(f"Column '{col}' has only one unique value - consider removing")

    for c in correlations:
        direction = "positively" if c["correlation"] > 0 else "negatively"
        insights.append(f"'{c['columns'][0]}' and '{c['columns'][1]}' are {c['strength']}ly {direction} correlated (r={c['correlation']})")

    return {
        "overview": {
            "format": format,
            "rows": row_count,
            "columns": len(columns),
            "column_names": columns,
        },
        "column_analysis": column_analysis,
        "correlations": correlations,
        "insights": insights,
        "summary": f"Analyzed {row_count} rows × {len(columns)} columns. Found {len(insights)} insight(s).",
    }


# ─── Service: API Documentation ──────────────────────────────────────────────

def api_docs(code: str, language: str = None, format: str = "markdown") -> dict:
    """Generate API documentation from source code."""
    if not language:
        language = detect_language(code)

    endpoints = []
    functions = []
    classes = []

    # Extract REST endpoints
    route_patterns = [
        # Flask/FastAPI
        r"""@(?:app|router|bp)\.(get|post|put|delete|patch)\s*\(\s*['"](.*?)['"]\s*""",
        # Express.js
        r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"](.*?)['"]\s*""",
        # Spring Boot
        r"""@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?['"](.*?)['"]\s*""",
        # Go Gorilla/Chi
        r"""\.(?:Handle|HandleFunc)\s*\(\s*['"](.*?)['"]""",
    ]

    for pattern in route_patterns:
        for match in re.finditer(pattern, code, re.IGNORECASE):
            groups = match.groups()
            if len(groups) == 2:
                method, path = groups
                endpoints.append({"method": method.upper(), "path": path, "line": code[:match.start()].count("\n") + 1})
            elif len(groups) == 1:
                endpoints.append({"method": "GET", "path": groups[0], "line": code[:match.start()].count("\n") + 1})

    # Extract functions/methods
    func_patterns = {
        "python": r'def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?\s*:\s*(?:\n\s+(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'))?',
        "javascript": r'(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)',
        "typescript": r'(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*(?:<[^>]+>)?\s*\(([^)]*)\)\s*(?::\s*([^\{]+))?',
        "go": r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(([^)]*)\)\s*(?:([^{]+))?',
        "rust": r'(?:pub\s+)?fn\s+(\w+)\s*(?:<[^>]+>)?\s*\(([^)]*)\)\s*(?:->\s*([^\{]+))?',
        "java": r'(?:public|private|protected)\s+(?:static\s+)?(\w+)\s+(\w+)\s*\(([^)]*)\)',
    }

    pattern = func_patterns.get(language)
    if pattern:
        for match in re.finditer(pattern, code, re.DOTALL):
            groups = match.groups()
            line_num = code[:match.start()].count("\n") + 1

            if language == "python":
                name = groups[0]
                params = groups[1]
                return_type = groups[2].strip() if groups[2] else None
                docstring = (groups[3] or groups[4] or "").strip() if len(groups) > 3 else ""
                functions.append({
                    "name": name,
                    "params": [p.strip() for p in params.split(",") if p.strip()],
                    "return_type": return_type,
                    "docstring": docstring[:200] if docstring else None,
                    "line": line_num,
                    "visibility": "private" if name.startswith("_") else "public",
                })
            elif language == "java":
                return_type = groups[0]
                name = groups[1]
                params = groups[2]
                functions.append({
                    "name": name, "params": [p.strip() for p in params.split(",") if p.strip()],
                    "return_type": return_type, "line": line_num,
                })
            else:
                name = groups[0]
                params = groups[1] if len(groups) > 1 else ""
                return_type = groups[2].strip() if len(groups) > 2 and groups[2] else None
                functions.append({
                    "name": name,
                    "params": [p.strip() for p in params.split(",") if p.strip()],
                    "return_type": return_type,
                    "line": line_num,
                })

    # Extract classes
    class_patterns = {
        "python": r'class\s+(\w+)\s*(?:\(([^)]*)\))?\s*:',
        "javascript": r'class\s+(\w+)\s*(?:extends\s+(\w+))?\s*\{',
        "typescript": r'(?:export\s+)?class\s+(\w+)\s*(?:extends\s+(\w+))?\s*(?:implements\s+([^{]+))?\s*\{',
        "java": r'(?:public\s+)?class\s+(\w+)\s*(?:extends\s+(\w+))?\s*(?:implements\s+([^{]+))?\s*\{',
        "rust": r'(?:pub\s+)?struct\s+(\w+)',
    }
    cls_pattern = class_patterns.get(language)
    if cls_pattern:
        for match in re.finditer(cls_pattern, code):
            name = match.group(1)
            parent = match.group(2) if len(match.groups()) > 1 else None
            classes.append({
                "name": name,
                "parent": parent,
                "line": code[:match.start()].count("\n") + 1,
            })

    # Generate documentation
    if format == "markdown":
        doc = f"# API Documentation\n\n"
        doc += f"**Language:** {language}  \n"
        doc += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  \n\n"

        if endpoints:
            doc += "## Endpoints\n\n"
            doc += "| Method | Path | Line |\n|--------|------|------|\n"
            for ep in endpoints:
                doc += f"| `{ep['method']}` | `{ep['path']}` | {ep['line']} |\n"
            doc += "\n"

        if classes:
            doc += "## Classes\n\n"
            for cls in classes:
                doc += f"### `{cls['name']}`"
                if cls.get("parent"):
                    doc += f" (extends `{cls['parent']}`)"
                doc += f"\n- Defined at line {cls['line']}\n\n"

        if functions:
            public_funcs = [f for f in functions if f.get("visibility", "public") == "public"]
            private_funcs = [f for f in functions if f.get("visibility") == "private"]

            if public_funcs:
                doc += "## Public Functions\n\n"
                for fn in public_funcs:
                    doc += f"### `{fn['name']}({', '.join(fn['params'])})`\n"
                    if fn.get("return_type"):
                        doc += f"- **Returns:** `{fn['return_type']}`\n"
                    if fn.get("docstring"):
                        doc += f"- **Description:** {fn['docstring']}\n"
                    doc += f"- **Line:** {fn['line']}\n\n"

            if private_funcs:
                doc += "## Private/Internal Functions\n\n"
                for fn in private_funcs:
                    doc += f"- `{fn['name']}` (line {fn['line']})\n"
                doc += "\n"
    else:
        doc = None

    return {
        "documentation": doc,
        "endpoints": endpoints,
        "functions": functions,
        "classes": classes,
        "metrics": {
            "language": language,
            "endpoint_count": len(endpoints),
            "function_count": len(functions),
            "class_count": len(classes),
            "lines": len(code.splitlines()),
        },
        "summary": f"Generated docs for {len(functions)} functions, {len(classes)} classes, {len(endpoints)} endpoints ({language})",
    }


# ─── Service: Diff Review ────────────────────────────────────────────────────

def diff_review(diff: str) -> dict:
    """Review a git diff for quality, risks, and suggestions."""
    files_changed = re.findall(r'^\+\+\+ b/(.+)$', diff, re.MULTILINE)
    additions = len(re.findall(r'^\+[^+]', diff, re.MULTILINE))
    deletions = len(re.findall(r'^-[^-]', diff, re.MULTILINE))

    issues = []

    # Check for common diff problems
    added_lines = [line[1:] for line in diff.splitlines() if line.startswith('+') and not line.startswith('+++')]

    added_code = "\n".join(added_lines)

    # Run security patterns on added code
    for pattern, msg, severity in SECURITY_PATTERNS:
        try:
            if re.search(pattern, added_code, re.IGNORECASE):
                issues.append({"type": "security", "severity": severity, "message": f"New code: {msg}"})
        except re.error:
            pass

    # Check for large files
    if additions > 500:
        issues.append({"type": "review", "severity": "medium", "message": f"Large PR: {additions} lines added. Consider splitting."})

    # Check for debug code
    debug_patterns = [
        (r"console\.log", "console.log left in code"),
        (r"debugger;", "debugger statement left in code"),
        (r"print\s*\(.*debug", "Debug print statement"),
        (r"TODO|FIXME|HACK", "TODO/FIXME/HACK marker added"),
    ]
    for pattern, msg in debug_patterns:
        if re.search(pattern, added_code, re.IGNORECASE):
            issues.append({"type": "quality", "severity": "low", "message": msg})

    # Check for test coverage
    test_files = [f for f in files_changed if 'test' in f.lower() or 'spec' in f.lower()]
    source_files = [f for f in files_changed if 'test' not in f.lower() and 'spec' not in f.lower()]
    if source_files and not test_files:
        issues.append({"type": "quality", "severity": "medium", "message": "No test files modified. Consider adding tests."})

    # Suggestions
    suggestions = []
    if additions > 3 * deletions and additions > 50:
        suggestions.append("Consider if any of the new code can reuse existing utilities")
    if len(files_changed) > 10:
        suggestions.append(f"{len(files_changed)} files changed - consider splitting into smaller PRs")

    score = max(0, 100 - sum(10 if i["severity"] == "critical" else 5 if i["severity"] == "high" else 3 if i["severity"] == "medium" else 1 for i in issues))

    return {
        "score": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
        "files_changed": files_changed,
        "stats": {"additions": additions, "deletions": deletions, "files": len(files_changed)},
        "issues": issues,
        "suggestions": suggestions,
        "has_tests": bool(test_files),
        "summary": f"Reviewed diff: +{additions}/-{deletions} across {len(files_changed)} file(s). Score: {score}/100. {len(issues)} issue(s).",
    }


# ─── Service: Dependency Audit ────────────────────────────────────────────────

KNOWN_VULNERABLE_PACKAGES = {
    # Python
    "pyyaml": {"before": "5.4", "issue": "Arbitrary code execution via yaml.load()"},
    "requests": {"before": "2.20.0", "issue": "Session fixation vulnerability"},
    "django": {"before": "3.2", "issue": "Multiple security fixes"},
    "flask": {"before": "2.0", "issue": "Security improvements"},
    "urllib3": {"before": "1.26.5", "issue": "CRLF injection"},
    "pillow": {"before": "9.0", "issue": "Multiple buffer overflow fixes"},
    "cryptography": {"before": "3.3.2", "issue": "Bleichenbacher timing attack"},
    "jinja2": {"before": "3.0", "issue": "Sandbox escape vulnerability"},
    # JavaScript
    "lodash": {"before": "4.17.21", "issue": "Prototype pollution"},
    "minimist": {"before": "1.2.6", "issue": "Prototype pollution"},
    "node-fetch": {"before": "2.6.7", "issue": "Exposure of sensitive information"},
    "express": {"before": "4.17.3", "issue": "Open redirect vulnerability"},
    "axios": {"before": "0.21.2", "issue": "Server-side request forgery"},
    "moment": {"before": "999", "issue": "Deprecated - use dayjs or date-fns"},
}


def dependency_audit(dependencies: str) -> dict:
    """Audit dependencies for known vulnerabilities and issues."""
    issues = []
    packages = []

    # Parse requirements.txt format
    for line in dependencies.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Parse package==version or package>=version
        match = re.match(r'([a-zA-Z0-9_-]+)\s*(?:[=><!~]+\s*([0-9][0-9.a-zA-Z]*))?', line)
        if match:
            name = match.group(1).lower().replace("-", "").replace("_", "")
            version = match.group(2) or "unknown"
            packages.append({"name": match.group(1), "version": version})

            # Check known vulnerabilities
            normalized = name.replace("-", "").replace("_", "")
            for vuln_name, vuln_info in KNOWN_VULNERABLE_PACKAGES.items():
                if normalized == vuln_name.replace("-", "").replace("_", ""):
                    issues.append({
                        "package": match.group(1),
                        "version": version,
                        "severity": "high",
                        "message": vuln_info["issue"],
                        "fix": f"Upgrade to >= {vuln_info['before']}",
                    })

    # Parse package.json format
    try:
        parsed = json.loads(dependencies)
        all_deps = {}
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            if key in parsed:
                all_deps.update(parsed[key])

        for name, version in all_deps.items():
            clean_version = re.sub(r'[^0-9.]', '', version)
            packages.append({"name": name, "version": version})

            normalized = name.lower().replace("-", "").replace("_", "")
            for vuln_name, vuln_info in KNOWN_VULNERABLE_PACKAGES.items():
                if normalized == vuln_name.replace("-", "").replace("_", ""):
                    issues.append({
                        "package": name,
                        "version": version,
                        "severity": "high",
                        "message": vuln_info["issue"],
                        "fix": f"Upgrade to >= {vuln_info['before']}",
                    })
    except (json.JSONDecodeError, AttributeError):
        pass

    # General advice
    suggestions = []
    if len(packages) > 50:
        suggestions.append(f"Large dependency tree ({len(packages)} packages). Audit for unused dependencies.")
    if any("*" in p.get("version", "") for p in packages):
        suggestions.append("Wildcard version constraints detected - pin to specific versions")

    return {
        "packages_analyzed": len(packages),
        "packages": packages,
        "vulnerabilities": issues,
        "vulnerability_count": len(issues),
        "suggestions": suggestions,
        "summary": f"Audited {len(packages)} packages. Found {len(issues)} known vulnerability/issue(s).",
    }


# ─── Service: Regex Tester ────────────────────────────────────────────────────

def regex_test(pattern: str, test_string: str, flags: str = "") -> dict:
    """Test a regex pattern and explain it."""
    # Parse flags
    flag_map = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
    regex_flags = 0
    for f in flags:
        if f in flag_map:
            regex_flags |= flag_map[f]

    try:
        compiled = re.compile(pattern, regex_flags)
    except re.error as e:
        return {"error": f"Invalid regex: {str(e)}"}

    # Find all matches
    matches = []
    for match in compiled.finditer(test_string):
        match_info = {
            "match": match.group(),
            "start": match.start(),
            "end": match.end(),
            "groups": list(match.groups()),
        }
        if match.groupdict():
            match_info["named_groups"] = match.groupdict()
        matches.append(match_info)

    # Explain pattern
    explanations = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == '^':
            explanations.append("^ - Start of string/line")
        elif c == '$':
            explanations.append("$ - End of string/line")
        elif c == '.':
            explanations.append(". - Any character (except newline)")
        elif c == '*':
            explanations.append("* - Zero or more of previous")
        elif c == '+':
            explanations.append("+ - One or more of previous")
        elif c == '?':
            explanations.append("? - Zero or one of previous (optional)")
        elif c == '\\' and i + 1 < len(pattern):
            next_c = pattern[i + 1]
            escape_map = {
                'd': '\\d - Any digit [0-9]',
                'D': '\\D - Any non-digit',
                'w': '\\w - Any word character [a-zA-Z0-9_]',
                'W': '\\W - Any non-word character',
                's': '\\s - Any whitespace',
                'S': '\\S - Any non-whitespace',
                'b': '\\b - Word boundary',
            }
            explanations.append(escape_map.get(next_c, f"\\{next_c} - Escaped character"))
            i += 1
        elif c == '[':
            end = pattern.find(']', i)
            if end != -1:
                char_class = pattern[i:end + 1]
                explanations.append(f"{char_class} - Character class")
                i = end
        elif c == '(':
            if pattern[i:i+3] == '(?:':
                explanations.append("(?: - Non-capturing group")
                i += 2
            elif pattern[i:i+4] == '(?P<':
                end = pattern.find('>', i)
                name = pattern[i+4:end] if end != -1 else "?"
                explanations.append(f"(?P<{name}> - Named capture group '{name}'")
                i = end if end != -1 else i
            else:
                explanations.append("( - Capture group start")
        elif c == ')':
            explanations.append(") - Group end")
        elif c == '|':
            explanations.append("| - OR (alternation)")
        elif c == '{':
            end = pattern.find('}', i)
            if end != -1:
                quantifier = pattern[i:end + 1]
                explanations.append(f"{quantifier} - Quantifier (repeat count)")
                i = end
        i += 1

    return {
        "pattern": pattern,
        "flags": flags,
        "test_string": test_string[:500],
        "match_count": len(matches),
        "matches": matches[:50],  # Limit matches returned
        "explanation": explanations,
        "summary": f"Pattern matched {len(matches)} time(s) in the test string.",
    }


# ─── HTTP Server ──────────────────────────────────────────────────────────────

SERVICE_CATALOG = [
    {"name": "code_review", "price": 0.10, "method": "POST",
     "description": "Comprehensive code analysis: security, bugs, style, performance",
     "params": {"code": "string (required)", "language": "string (optional)", "focus": "all|security|bugs|style|performance"}},
    {"name": "summarize", "price": 0.05, "method": "POST",
     "description": "Extract key points from text",
     "params": {"text": "string (required)", "max_points": "int (default 5)", "style": "bullet|paragraph|executive|tldr"}},
    {"name": "seo_audit", "price": 0.05, "method": "POST",
     "description": "SEO content audit with readability and keyword analysis",
     "params": {"text": "string (required)", "target_keywords": "list (optional)", "title": "string (optional)", "meta_description": "string (optional)"}},
    {"name": "data_analysis", "price": 0.10, "method": "POST",
     "description": "Statistical analysis of structured data (CSV or JSON)",
     "params": {"data": "string|array|object (required)", "format": "auto|csv|json"}},
    {"name": "api_docs", "price": 0.10, "method": "POST",
     "description": "Generate API documentation from source code",
     "params": {"code": "string (required)", "language": "string (optional)", "format": "markdown"}},
    {"name": "diff_review", "price": 0.08, "method": "POST",
     "description": "Review git diffs for quality, security, and best practices",
     "params": {"diff": "string (required)"}},
    {"name": "dependency_audit", "price": 0.08, "method": "POST",
     "description": "Audit dependencies for known vulnerabilities",
     "params": {"dependencies": "string (required) - requirements.txt or package.json content"}},
    {"name": "regex_test", "price": 0.03, "method": "POST",
     "description": "Test and explain regex patterns",
     "params": {"pattern": "string (required)", "test_string": "string (required)", "flags": "string (optional, e.g. 'im')"}},
]


class AdamServiceHandler(BaseHTTPRequestHandler):
    """HTTP handler for Adam's services."""

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Agent", "Adam")
        self.send_header("X-Version", VERSION)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def _read_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else "{}"
        return json.loads(body)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")

        if path in ("", "/", "/health"):
            uptime_secs = (datetime.now() - datetime.fromisoformat(stats["started_at"])).total_seconds()
            self._send_json({
                "agent": "Adam",
                "instance_id": INSTANCE_ID,
                "ticker": "ADAM",
                "status": "running",
                "version": VERSION,
                "uptime_seconds": int(uptime_secs),
                "services": [s["name"] for s in SERVICE_CATALOG],
                "pricing": PRICES,
                "repo": "https://github.com/wisent-ai/adam-services",
                "toolkit": "https://github.com/wisent-ai/adam-agent-toolkit",
                "description": "Comprehensive code analysis, text processing, and developer tools. Zero external dependencies.",
            })

        elif path == "/capabilities":
            self._send_json({"services": SERVICE_CATALOG})

        elif path == "/stats":
            profit = round(stats["total_revenue"] - stats["total_cost"], 4)
            self._send_json({
                "stats": stats,
                "profit": profit,
                "avg_revenue_per_request": round(stats["total_revenue"] / max(stats["total_requests"], 1), 4),
            })

        elif path == "/openapi":
            # Minimal OpenAPI spec
            paths = {}
            for svc in SERVICE_CATALOG:
                paths[f"/{svc['name']}"] = {
                    "post": {
                        "summary": svc["description"],
                        "tags": [svc["name"]],
                        "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                        "responses": {"200": {"description": "Success"}},
                    }
                }
            self._send_json({
                "openapi": "3.0.3",
                "info": {"title": "Adam's Service API", "version": VERSION, "description": "AI-powered developer tools by Adam"},
                "paths": paths,
            })

        else:
            self._send_json({"error": "Not found", "available": ["/", "/capabilities", "/stats", "/openapi"] + [f"/{s['name']}" for s in SERVICE_CATALOG]}, 404)

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        start_time = time.time()

        try:
            params = self._read_body()
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON in request body"}, 400)
            return

        try:
            result = None
            service_name = path.lstrip("/")

            if path == "/code_review":
                code = params.get("code", "")
                if not code:
                    self._send_json({"error": "'code' parameter required"}, 400)
                    return
                result = code_review(code, params.get("language"), params.get("focus", "all"))

            elif path == "/summarize":
                text = params.get("text", "")
                if not text:
                    self._send_json({"error": "'text' parameter required"}, 400)
                    return
                result = summarize_text(text, params.get("max_points", 5), params.get("style", "bullet"))

            elif path == "/seo_audit":
                text = params.get("text", "")
                if not text:
                    self._send_json({"error": "'text' parameter required"}, 400)
                    return
                result = seo_audit(text, params.get("target_keywords", []), params.get("title", ""), params.get("meta_description", ""))

            elif path == "/data_analysis":
                data = params.get("data")
                if not data:
                    self._send_json({"error": "'data' parameter required (JSON array/object or CSV string)"}, 400)
                    return
                result = data_analysis(data, params.get("format", "auto"))

            elif path == "/api_docs":
                code = params.get("code", "")
                if not code:
                    self._send_json({"error": "'code' parameter required"}, 400)
                    return
                result = api_docs(code, params.get("language"), params.get("format", "markdown"))

            elif path == "/diff_review":
                diff = params.get("diff", "")
                if not diff:
                    self._send_json({"error": "'diff' parameter required"}, 400)
                    return
                result = diff_review(diff)

            elif path == "/dependency_audit":
                deps = params.get("dependencies", "")
                if not deps:
                    self._send_json({"error": "'dependencies' parameter required (requirements.txt or package.json content)"}, 400)
                    return
                result = dependency_audit(deps)

            elif path == "/regex_test":
                pattern = params.get("pattern", "")
                test_string = params.get("test_string", "")
                if not pattern or not test_string:
                    self._send_json({"error": "'pattern' and 'test_string' parameters required"}, 400)
                    return
                result = regex_test(pattern, test_string, params.get("flags", ""))

            else:
                self._send_json({"error": f"Unknown service '{service_name}'", "available": [s["name"] for s in SERVICE_CATALOG]}, 404)
                return

            # Log and respond
            price = PRICES.get(service_name, 0.05)
            elapsed = round(time.time() - start_time, 3)
            log_request(service_name, price, price * 0.1)

            self._send_json({
                "success": True,
                "service": service_name,
                "price": price,
                "elapsed_seconds": elapsed,
                "result": result,
            })

        except Exception as e:
            log_error()
            self._send_json({"error": str(e), "service": path.lstrip("/")}, 500)

    def log_message(self, format, *args):
        """Custom log format."""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0] if args else ''}")


def run_server():
    """Start Adam's Revenue Service."""
    server = HTTPServer(("0.0.0.0", PORT), AdamServiceHandler)
    print(f"╔══════════════════════════════════════════════╗")
    print(f"║   Adam's Revenue Service v{VERSION}            ║")
    print(f"║   Port: {PORT}                                ║")
    print(f"║   Services: {len(SERVICE_CATALOG)}                              ║")
    print(f"║   Agent: {INSTANCE_ID}     ║")
    print(f"╚══════════════════════════════════════════════╝")
    print(f"\nEndpoints:")
    for svc in SERVICE_CATALOG:
        print(f"  POST /{svc['name']:20s} ${svc['price']:.2f}  {svc['description']}")
    print(f"\n  GET  /health                         Service health check")
    print(f"  GET  /capabilities                   Service catalog")
    print(f"  GET  /stats                          Usage statistics")
    print(f"  GET  /openapi                        OpenAPI specification")
    print(f"\nReady to serve requests.")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
