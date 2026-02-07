#!/usr/bin/env python3
"""Tests for Adam's Revenue Service v2.0."""

import json
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(__file__))

from service import (
    code_review, summarize_text, seo_audit, data_analysis,
    api_docs, diff_review, dependency_audit, regex_test,
    detect_language,
)

PASS = 0
FAIL = 0


def test(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name}")


def test_detect_language():
    print("\n== detect_language ==")
    test("Python", detect_language("def hello():\n    print('hi')") == "python")
    test("JavaScript", detect_language("const x = () => { console.log('hi'); }") == "javascript")
    test("Go", detect_language("package main\nfunc main() { fmt.Println() }") == "go")
    test("Rust", detect_language("fn main() { let mut x = 5; }") == "rust")
    test("Java", detect_language("public class Main { public static void main() {} }") == "java")
    test("Unknown", detect_language("just some text") == "unknown")


def test_code_review():
    print("\n== code_review ==")

    # Test with clean code
    clean = '''def greet(name: str) -> str:
    """Greet someone."""
    return f"Hello, {name}!"
'''
    result = code_review(clean, "python")
    test("Clean code gets high score", result["score"] >= 80)
    test("Returns grade", result["grade"] in ("A", "B", "C", "D", "F"))
    test("Returns metrics", "metrics" in result)
    test("Has summary", "summary" in result)

    # Test with security issues
    insecure = '''
import os
password = "secret123"
eval(user_input)
os.system("rm -rf /")
'''
    result = code_review(insecure, "python", "security")
    test("Finds security issues", len(result["issues"]) > 0)
    test("Finds critical issues", any(i["severity"] == "critical" for i in result["issues"]))
    test("Low score for insecure code", result["score"] < 50)

    # Test with Python bugs
    buggy = '''
def bad(items=[]):
    items.append(1)
    return items

try:
    x = 1 / 0
except:
    pass

if x == None:
    global y
'''
    result = code_review(buggy, "python", "bugs")
    test("Finds bug issues", len(result["issues"]) > 0)
    test("Finds mutable default arg", any("Mutable default" in i["message"] for i in result["issues"]))

    # Test JS specific
    js_code = '''
var x = 1;
if (x == "1") {
    console.log("loose");
}
'''
    result = code_review(js_code, "javascript", "bugs")
    test("JS: finds var usage", any("var" in i["message"].lower() for i in result["issues"]))
    test("JS: finds loose equality", any("Loose equality" in i["message"] for i in result["issues"]))

    # Test complexity metrics
    complex_code = "\n".join([f"def func_{i}(x):\n    if x: return x\n    else: return None" for i in range(10)])
    result = code_review(complex_code, "python")
    test("Counts functions", result["metrics"]["functions"] >= 10)
    test("Has complexity", "avg_complexity" in result["metrics"])

    # Test focus parameter
    result = code_review("eval(x)\npassword = '123'", "python", "security")
    test("Focus security only", all(i["type"] == "security" for i in result["issues"]))


def test_summarize():
    print("\n== summarize_text ==")

    text = """Artificial intelligence has made significant strides in recent years. Machine learning models can now process natural language with remarkable accuracy. Deep learning techniques have enabled breakthroughs in computer vision and speech recognition. Companies are investing billions in AI research and development. The technology sector continues to grow rapidly. New applications of AI are being discovered in healthcare, finance, and education. However, concerns about AI safety and ethics remain important topics of discussion. Researchers are working on making AI systems more transparent and accountable. The future of AI looks promising but requires careful consideration of its societal impact."""

    result = summarize_text(text)
    test("Returns summary", "summary" in result)
    test("Returns key points", len(result["key_points"]) > 0)
    test("Returns key topics", len(result["key_topics"]) > 0)
    test("Has metrics", "metrics" in result)
    test("Compression ratio < 1", result["metrics"]["compression_ratio"] < 1)

    # Test different styles
    result_para = summarize_text(text, style="paragraph")
    test("Paragraph style works", "\n" not in result_para["summary"][:100])

    result_exec = summarize_text(text, style="executive")
    test("Executive style works", "Executive Summary" in result_exec["summary"])

    result_tldr = summarize_text(text, style="tldr")
    test("TLDR style works", result_tldr["summary"].startswith("TL;DR:"))

    # Test with too-short text
    result_short = summarize_text("Hi.")
    test("Handles short text", "error" in result_short)

    # Test max_points
    result_limited = summarize_text(text, max_points=2)
    test("Respects max_points", len(result_limited["key_points"]) <= 2)


def test_seo_audit():
    print("\n== seo_audit ==")

    short_content = "This is a very short article about AI."
    result = seo_audit(short_content)
    test("Short content gets issues", len(result["issues"]) > 0)
    test("Returns score", 0 <= result["score"] <= 100)
    test("Returns readability", "readability" in result)
    test("Returns content metrics", "content_metrics" in result)

    long_content = " ".join(["This is a comprehensive article about artificial intelligence and machine learning technology."] * 100)
    result = seo_audit(long_content, target_keywords=["artificial intelligence", "machine learning"])
    test("Keyword analysis works", "artificial intelligence" in result["keyword_analysis"])
    test("Suggested keywords returned", len(result["suggested_keywords"]) > 0)

    # Test with title and meta
    result = seo_audit("Content here " * 100, title="A" * 70, meta_description="Short")
    test("Title too long detected", any("Title too long" in i["message"] for i in result["issues"]))
    test("Meta description too short", any("Meta description too short" in i["message"] for i in result["issues"]))

    # Test readability levels
    simple = "The cat sat. The dog ran. I like food. It is hot. We go home." * 20
    result = seo_audit(simple)
    test("Simple text is easy to read", result["readability"]["flesch_score"] > 60)


def test_data_analysis():
    print("\n== data_analysis ==")

    # Test with JSON array
    data = [
        {"name": "Alice", "age": 30, "score": 85},
        {"name": "Bob", "age": 25, "score": 92},
        {"name": "Charlie", "age": 35, "score": 78},
        {"name": "Diana", "age": 28, "score": 95},
        {"name": "Eve", "age": 32, "score": 88},
    ]
    result = data_analysis(data)
    test("Overview exists", "overview" in result)
    test("Correct row count", result["overview"]["rows"] == 5)
    test("Correct column count", result["overview"]["columns"] == 3)
    test("Column analysis exists", "column_analysis" in result)
    test("Age is numeric", result["column_analysis"]["age"]["type"] == "numeric")
    test("Name is categorical", result["column_analysis"]["name"]["type"] == "categorical")
    test("Has summary", "summary" in result)

    # Test with CSV string
    csv_data = "name,value\nA,10\nB,20\nC,30"
    result = data_analysis(csv_data)
    test("CSV parsing works", result["overview"]["rows"] == 3)

    # Test with correlations
    corr_data = [{"x": i, "y": i * 2 + 1, "z": 100 - i} for i in range(20)]
    result = data_analysis(corr_data)
    test("Finds correlations", len(result["correlations"]) > 0)

    # Test numeric stats
    test("Mean calculated", "mean" in result["column_analysis"]["x"])
    test("Median calculated", "median" in result["column_analysis"]["x"])

    # Test with nulls
    null_data = [{"a": 1, "b": None}, {"a": 2, "b": None}, {"a": 3, "b": "x"}]
    result = data_analysis(null_data)
    test("Null detection", result["column_analysis"]["b"]["null_count"] == 2)

    # Test error handling
    result = data_analysis("not valid at all {{{")
    test("Invalid data returns error", "error" in result)


def test_api_docs():
    print("\n== api_docs ==")

    python_code = '''
from flask import Flask
app = Flask(__name__)

class UserService:
    """Manages users."""
    pass

@app.get("/users")
def list_users():
    """List all users."""
    return []

@app.post("/users")
def create_user(name: str) -> dict:
    """Create a new user."""
    return {"name": name}

def _internal_helper(x):
    return x
'''
    result = api_docs(python_code, "python")
    test("Generates markdown", result["documentation"] is not None)
    test("Finds endpoints", len(result["endpoints"]) >= 2)
    test("Finds functions", len(result["functions"]) >= 2)
    test("Finds classes", len(result["classes"]) >= 1)
    test("Has metrics", "metrics" in result)

    # Test JS code
    js_code = '''
class Router {
    constructor() {}
}
function handleRequest(req, res) { return res.json({}); }
async function fetchData(url) { return fetch(url); }
'''
    result = api_docs(js_code, "javascript")
    test("JS: finds functions", len(result["functions"]) >= 2)
    test("JS: finds classes", len(result["classes"]) >= 1)


def test_diff_review():
    print("\n== diff_review ==")

    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,5 +1,10 @@
 import os
+import subprocess

 def run():
-    print("hello")
+    password = "secret123"
+    eval(user_input)
+    os.system("rm -rf /")
+    console.log("debug")
+    # TODO: fix this
"""
    result = diff_review(diff)
    test("Returns score", 0 <= result["score"] <= 100)
    test("Finds files changed", len(result["files_changed"]) > 0)
    test("Counts additions", result["stats"]["additions"] > 0)
    test("Counts deletions", result["stats"]["deletions"] > 0)
    test("Finds security issues", any(i["type"] == "security" for i in result["issues"]))
    test("No tests warning", any("test" in i.get("message", "").lower() for i in result["issues"]))

    # Clean diff
    clean_diff = """diff --git a/test_app.py b/test_app.py
--- a/test_app.py
+++ b/test_app.py
@@ -1,3 +1,5 @@
 def test_hello():
-    assert True
+    result = greet("world")
+    assert result == "Hello, world!"
"""
    result = diff_review(clean_diff)
    test("Clean diff gets good score", result["score"] >= 80)
    test("Has tests", result["has_tests"] is True)


def test_dependency_audit():
    print("\n== dependency_audit ==")

    requirements = """
flask==1.0.0
requests==2.18.0
pyyaml==5.1
django==2.0
numpy==1.21.0
pandas==1.3.0
"""
    result = dependency_audit(requirements)
    test("Parses packages", result["packages_analyzed"] >= 5)
    test("Finds vulnerabilities", result["vulnerability_count"] > 0)
    test("Flask vulnerability found", any("flask" in v["package"].lower() for v in result["vulnerabilities"]))

    # Test package.json
    pkg_json = json.dumps({
        "dependencies": {
            "lodash": "^4.17.10",
            "express": "^4.16.0",
            "axios": "^0.19.0",
        }
    })
    result = dependency_audit(pkg_json)
    test("Parses package.json", result["packages_analyzed"] >= 3)
    test("Finds lodash issue", any("lodash" in v["package"] for v in result["vulnerabilities"]))


def test_regex_test():
    print("\n== regex_test ==")

    result = regex_test(r"\b\w+@\w+\.\w+\b", "Contact us at hello@example.com or support@test.org")
    test("Finds email matches", result["match_count"] == 2)
    test("Has explanation", len(result["explanation"]) > 0)

    # Test named groups
    result = regex_test(r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})", "Today is 2026-02-07")
    test("Named groups work", "named_groups" in result["matches"][0])
    test("Year captured", result["matches"][0]["named_groups"]["year"] == "2026")

    # Test flags
    result = regex_test(r"hello", "Hello World HELLO", "i")
    test("Case insensitive flag", result["match_count"] == 2)

    # Test invalid regex
    result = regex_test(r"[invalid", "test")
    test("Invalid regex returns error", "error" in result)

    # Test no matches
    result = regex_test(r"\d+", "no numbers here")
    test("No matches returns 0", result["match_count"] == 0)


if __name__ == "__main__":
    print("=" * 60)
    print("Adam's Revenue Service v2.0 - Test Suite")
    print("=" * 60)

    test_detect_language()
    test_code_review()
    test_summarize()
    test_seo_audit()
    test_data_analysis()
    test_api_docs()
    test_diff_review()
    test_dependency_audit()
    test_regex_test()

    print("\n" + "=" * 60)
    print(f"Results: {PASS} passed, {FAIL} failed, {PASS + FAIL} total")
    print("=" * 60)

    sys.exit(1 if FAIL > 0 else 0)
