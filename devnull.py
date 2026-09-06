#!/usr/bin/env python3
"""
DevNull - Authorized Web Security Enumeration Assistant (Refactored)

Unified pipeline architecture in a single file.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import re
import sys
import time
import unittest
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as exc:
    sys.stderr.write("Missing dependency. Install with: pip install requests beautifulsoup4\n")
    raise SystemExit(1) from exc

try:
    from playwright.sync_api import (
        sync_playwright,
        TimeoutError as PlaywrightTimeoutError,
        Error as PlaywrightError,
    )
except ImportError:
    sync_playwright = None
    PlaywrightTimeoutError = Exception
    PlaywrightError = Exception


# ---------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------
def eprint(message: str = "") -> None:
    sys.stderr.write(str(message) + "\n")

def out(message: str = "") -> None:
    sys.stdout.write(str(message) + "\n")


# ---------------------------------------------------------------------
# Core Models
# ---------------------------------------------------------------------
@dataclass
class Target:
    url: str
    base_domain: str
    workspace: Path

@dataclass
class InputPoint:
    url: str
    method: str          # GET, POST, etc.
    location: str        # query, form, json, path, header, cookie
    name: str
    value: str
    content_type: Optional[str] = None
    source: Optional[str] = None

@dataclass
class SecurityTest:
    name: str
    category: str
    payload: str
    input_point: InputPoint
    context: Optional[str] = None

@dataclass
class TestResult:
    test_name: str
    input_point: InputPoint
    reflected: bool
    context: Optional[str]
    evidence: dict
    confidence: float

@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    category: str
    url: str
    description: str
    evidence: Dict[str, str] = field(default_factory=dict)
    manual_validation: List[str] = field(default_factory=list)
    remediation: str = ""

    def fingerprint(self) -> str:
        # Normalize URL: scheme + netloc + path (no query/fragment), so the
        # same endpoint/parameter reached via different query strings (e.g.
        # ?q=test vs a bare form action URL) collapses to one finding.
        parsed = urlparse(self.url)
        normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        parameter = self.evidence.get('parameter', '')
        location = self.evidence.get('location', '')
        # Distinct checks that share a category and target URL (e.g. six
        # different missing-security-header findings all under "Security
        # Misconfiguration" for the same root URL) have no `parameter` to
        # key on. Fall back to whichever evidence field the checker uses to
        # identify *what* was found, so those stay separate; only fall back
        # to the title itself if none of those are present.
        discriminator = (
            parameter
            or location
            or self.evidence.get('missing_header', '')
            or self.evidence.get('reason', '')
            or self.evidence.get('field_hint', '')
            or self.evidence.get('matched_assignment_sample', '')
            or self.title
        )
        raw = f"{self.category}|{normalized_url}|{discriminator}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

@dataclass
class RequestRecord:
    method: str
    url: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    length: Optional[int] = None
    note: str = ""

@dataclass
class ScanState:
    target: Target
    urls: Set[str] = field(default_factory=set)
    js_files: Set[str] = field(default_factory=set)
    forms: List[Dict[str, str]] = field(default_factory=list)
    params: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))  # fixed
    api_endpoints: Set[str] = field(default_factory=set)
    request_log: List[RequestRecord] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    technologies: Dict[str, str] = field(default_factory=dict)
    screenshots: List[str] = field(default_factory=list)
    input_points: List[InputPoint] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        existing = {f.fingerprint() for f in self.findings}
        if finding.fingerprint() not in existing:
            self.findings.append(finding)


# ---------------------------------------------------------------------
# Scope and URL utilities
# ---------------------------------------------------------------------
def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    if not parsed.netloc:
        raise ValueError("Invalid target URL")
    normalized = urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))
    return normalized.rstrip("/")

def base_domain_from_target(target: str) -> str:
    hostname = urlparse(target).hostname
    if not hostname:
        raise ValueError("Could not extract hostname from target")
    return hostname.lower()

def same_scope_url(state: ScanState, url: str) -> bool:
    hostname = (urlparse(url).hostname or "").lower()
    return hostname == state.target.base_domain or hostname.endswith("." + state.target.base_domain)

def clean_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))

def extract_params(url: str) -> Set[str]:
    return set(parse_qs(urlparse(url).query).keys())

def looks_like_api(path: str) -> bool:
    patterns = [
        r"/api/", r"/v\d+/", r"/graphql", r"/rest/", r"/ajax/", r"/json", r"/wp-json/",
        r"/auth", r"/login", r"/user", r"/account", r"/order", r"/booking", r"/admin"
    ]
    return any(re.search(p, path, re.I) for p in patterns)

def save_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    unique_lines = sorted({str(line) for line in lines if line})
    path.write_text("\n".join(unique_lines) + ("\n" if unique_lines else ""), encoding="utf-8")

def redact_long(value: str, max_len: int = 400) -> str:
    value = str(value).replace("\n", " ").replace("\r", " ")
    return value[:max_len] + ("..." if len(value) > max_len else "")

def path_depth(url: str) -> int:
    return len([p for p in urlparse(url).path.split("/") if p])

def is_vendor_js(url: str, body: str = "") -> bool:
    path = urlparse(url).path.lower()
    filename = Path(path).name.lower()
    vendor_name_hints = [
        "jquery", "bootstrap", "popper", "lodash", "underscore", "moment", "axios",
        "react", "vue", "angular", "svelte", "alpine", "datatables", "chart", "select2",
        "swiper", "slick", "modernizr", "polyfill", "vendor", "runtime", "chunk-vendors",
    ]
    if any(hint in filename for hint in vendor_name_hints):
        return True
    header = body[:600].lower()
    vendor_banner_hints = [
        "jquery v", "jquery.org/license", "bootstrap v", "getbootstrap.com",
        "popper.js", "lodash", "moment.js", "react.production", "vue.js",
    ]
    return any(hint in header for hint in vendor_banner_hints)


# ---------------------------------------------------------------------
# HTTP Client
# ---------------------------------------------------------------------
class SafeHTTPClient:
    def __init__(self, state: ScanState, rate_limit_seconds: float = 0.8, timeout: int = 10, proxy: Optional[str] = None):
        self.state = state
        self.rate_limit_seconds = max(0.0, rate_limit_seconds)
        self.timeout = max(1, timeout)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "DevNull/2.0 Authorized-Security-Assessment",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def is_allowed_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        hostname = (parsed.hostname or "").lower()
        return hostname == self.state.target.base_domain or hostname.endswith("." + self.state.target.base_domain)

    def request(self, method: str, url: str, note: str = "", **kwargs) -> Optional[requests.Response]:
        method = method.upper()
        if not self.is_allowed_url(url):
            self.state.request_log.append(RequestRecord(method, url, note="Blocked: outside target scope"))
            return None
        time.sleep(self.rate_limit_seconds)
        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=False,
                allow_redirects=kwargs.pop("allow_redirects", True),
                **kwargs,
            )
            self.state.request_log.append(RequestRecord(
                method=method,
                url=url,
                status_code=response.status_code,
                content_type=response.headers.get("Content-Type", ""),
                length=len(response.content or b""),
                note=note,
            ))
            return response
        except requests.RequestException as exc:
            self.state.request_log.append(RequestRecord(method, url, note=f"Request failed: {exc}"))
            return None

    def get(self, url: str, note: str = "") -> Optional[requests.Response]:
        return self.request("GET", url, note=note)

    def head(self, url: str, note: str = "") -> Optional[requests.Response]:
        return self.request("HEAD", url, note=note, allow_redirects=False)


# ---------------------------------------------------------------------
# Input Mapper
# ---------------------------------------------------------------------
class InputMapper:
    def normalize(self, state: ScanState) -> List[InputPoint]:
        points = []
        # From URL parameters
        for url, params in state.params.items():
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param in params:
                value = qs.get(param, [''])[0]
                points.append(InputPoint(
                    url=url,
                    method='GET',
                    location='query',
                    name=param,
                    value=value,
                    source='url'
                ))
        # From forms
        for form in state.forms:
            action = form.get('action', '')
            method = (form.get('method') or 'GET').upper()
            inputs = [i.strip() for i in form.get('inputs', '').split(',') if i.strip()]
            for name in inputs:
                points.append(InputPoint(
                    url=action,
                    method=method,
                    location='form',
                    name=name,
                    value='',
                    content_type='application/x-www-form-urlencoded' if method == 'POST' else None,
                    source='form'
                ))
        # Additional locations (json, header, cookie, path) not yet implemented.
        state.input_points = points
        return points


# ---------------------------------------------------------------------
# Context Analysis
# ---------------------------------------------------------------------
@dataclass
class ContextResult:
    context: str      # html_body, html_attribute, javascript, json, url, script, style, unknown
    reflected: bool
    encoded: bool
    location: str     # snippet around marker

class ContextEngine:
    def detect(self, response_text: str, marker: str) -> ContextResult:
        idx = response_text.find(marker)
        if idx == -1:
            return ContextResult(context='none', reflected=False, encoded=False, location='')
        before = response_text[max(0, idx-100):idx]
        after = response_text[idx+len(marker):idx+100]
        encoded = any(enc in before+after for enc in ['&lt;', '&gt;', '&quot;', '&#39;'])
        # Heuristic context detection
        if re.search(r'<script[^>]*>', before, re.I) and '</script>' in after:
            context = 'javascript'
        elif re.search(r'<[^>]+$', before):  # inside a tag
            if re.search(r'''[\s]+[a-zA-Z-]+=['"][^'"]*$''', before):
                context = 'html_attribute'
            else:
                context = 'html_tag'
        elif re.search(r'^\s*[\]}],?\s*$', after):  # JSON-like
            context = 'json'
        else:
            if '<html' in before.lower() or '<body' in before.lower():
                context = 'html_body'
            else:
                context = 'unknown'
        return ContextResult(
            context=context,
            reflected=True,
            encoded=encoded,
            location=f"...{before[-80:]}[MARKER]{after[:80]}..."
        )


# ---------------------------------------------------------------------
# Test Engine
# ---------------------------------------------------------------------
class TestEngine:
    def __init__(self, client: SafeHTTPClient):
        self.client = client

    def baseline(self, input_point: InputPoint) -> Optional[requests.Response]:
        return self._send(input_point, input_point.value, note="baseline")

    def execute(self, test: SecurityTest) -> Optional[requests.Response]:
        return self._send(test.input_point, test.payload, note=test.name)

    def _send(self, input_point: InputPoint, value: str, note: str) -> Optional[requests.Response]:
        method = input_point.method.upper()
        url = input_point.url
        location = input_point.location
        name = input_point.name
        if location == 'query':
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[name] = [value]
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(qs, doseq=True), ''))
            return self.client.request(method, new_url, note=note)
        elif location == 'form':
            if method == 'POST':
                data = {name: value}
                return self.client.request(method, url, data=data, note=note)
            else:  # GET form
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[name] = [value]
                new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(qs, doseq=True), ''))
                return self.client.request(method, new_url, note=note)
        # Additional locations not yet supported.
        return None


# ---------------------------------------------------------------------
# Analysis Engine
# ---------------------------------------------------------------------
class AnalysisEngine:
    def analyze(self, baseline_response, test_response, marker: str, context: ContextResult) -> dict:
        analysis = {
            'marker_reflected': marker in test_response.text if test_response else False,
            'baseline_marker_present': marker in baseline_response.text if baseline_response else False,
            'context': context.context,
            'encoded': context.encoded,
            'status_code': test_response.status_code if test_response else None,
            'content_type': test_response.headers.get('Content-Type', '') if test_response else '',
            'length_diff': abs(len(test_response.content) - len(baseline_response.content)) if baseline_response and test_response else None,
        }
        return analysis


# ---------------------------------------------------------------------
# Confidence Engine
# ---------------------------------------------------------------------
class ConfidenceEngine:
    def calculate(self, analysis: dict) -> str:
        score = 0
        if analysis.get('marker_reflected'):
            score += 30
        if analysis.get('context') in ['html_body', 'html_attribute', 'javascript']:
            score += 20
        if not analysis.get('encoded'):
            score += 20
        if analysis.get('baseline_marker_present'):
            score -= 30
        if score >= 60:
            return 'High'
        elif score >= 30:
            return 'Medium'
        else:
            return 'Low'


# ---------------------------------------------------------------------
# Evidence Collector
# ---------------------------------------------------------------------
class EvidenceCollector:
    def collect(self, input_point: InputPoint, test: SecurityTest, response, analysis: dict) -> dict:
        return {
            'parameter': input_point.name,
            'payload': test.payload,
            'context': analysis.get('context', ''),
            'reflection': analysis.get('marker_reflected', False),
            'status_code': str(response.status_code) if response else '',
            'content_type': response.headers.get('Content-Type', '') if response else '',
            'request_url': response.url if response else '',
            'response_snippet': redact_long(response.text[:500]) if response and response.text else '',
        }


# ---------------------------------------------------------------------
# Pipeline Orchestrator (used by XSS first)
# ---------------------------------------------------------------------
class Pipeline:
    def __init__(self, state: ScanState, client: SafeHTTPClient):
        self.state = state
        self.client = client
        self.context_engine = ContextEngine()
        self.test_engine = TestEngine(client)
        self.analysis_engine = AnalysisEngine()
        self.confidence_engine = ConfidenceEngine()
        self.evidence_collector = EvidenceCollector()

    def run_for_input(self, input_point: InputPoint, test_selector):
        baseline = self.test_engine.baseline(input_point)
        if baseline is None:
            return
        marker = "devnull_reflection_marker_12345"
        marker_test = SecurityTest(
            name="reflection-check",
            category="xss",
            payload=marker,
            input_point=input_point
        )
        marker_response = self.test_engine.execute(marker_test)
        if marker_response is None:
            return
        context = self.context_engine.detect(marker_response.text, marker)
        if not context.reflected:
            return
        # Select context-specific validation tests
        tests = test_selector.select(input_point, context)
        for test in tests:
            test_response = self.test_engine.execute(test)
            if test_response is None:
                continue
            analysis = self.analysis_engine.analyze(baseline, test_response, test.payload, context)
            confidence = self.confidence_engine.calculate(analysis)
            if confidence != 'Low':  # Report only Medium/High
                evidence = self.evidence_collector.collect(input_point, test, test_response, analysis)
                # Severity decoupled from confidence:
                # For XSS, severity can be Medium/High based on context and payload.
                severity = 'Medium'
                if context.context in ['javascript', 'html_attribute']:
                    severity = 'High'
                elif context.context == 'html_body':
                    severity = 'Medium'
                finding = Finding(
                    title="Potential reflected XSS",
                    severity=severity,
                    confidence=confidence,
                    category="Cross-Site Scripting Candidate",
                    url=input_point.url,
                    description="A context-appropriate test payload was reflected in an interesting context. Manual validation required.",
                    evidence=evidence,
                    manual_validation=[
                        "Send the captured request to Burp Repeater.",
                        "Confirm the reflection context and whether the payload executes.",
                        "Test manually with safe payloads.",
                    ],
                    remediation="Apply context-aware output encoding and validate input server-side.",
                )
                self.state.add_finding(finding)


# ---------------------------------------------------------------------
# Discovery Layer
# ---------------------------------------------------------------------
class Enumerator:
    def __init__(self, client: SafeHTTPClient, max_pages: int = 50):
        self.client = client
        self.state = client.state
        self.max_pages = max(1, max_pages)

    def run(self) -> None:
        out("[+] Starting enumeration")
        self.crawl_seed_pages()
        self.parse_js_files()
        self.detect_interesting_candidates()
        out(f"[+] Enumeration complete: {len(self.state.urls)} URLs, {len(self.state.js_files)} JS files")

    def crawl_seed_pages(self) -> None:
        queue: List[str] = [self.state.target.url]
        visited: Set[str] = set()
        while queue and len(visited) < self.max_pages:
            url = clean_url(queue.pop(0))
            if url in visited:
                continue
            visited.add(url)
            self.state.urls.add(url)
            response = self.client.get(url, note="crawl")
            if not response:
                continue
            self._fingerprint_response(response)
            if "text/html" not in response.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            self._extract_meta_tech(soup)
            for tag in soup.find_all("a", href=True):
                href = clean_url(urljoin(url, tag.get("href", "")))
                if same_scope_url(self.state, href) and href not in visited:
                    queue.append(href)
                    self.state.urls.add(href)
                    for param in extract_params(href):
                        self.state.params[href].add(param)   # now defaultdict, safe
            for script in soup.find_all("script", src=True):
                src = clean_url(urljoin(url, script.get("src", "")))
                if same_scope_url(self.state, src):
                    self.state.js_files.add(src)
            for form in soup.find_all("form"):
                action = clean_url(urljoin(url, form.get("action") or url))
                method = (form.get("method") or "GET").upper()
                inputs = [i.get("name") for i in form.find_all(["input", "textarea", "select"]) if i.get("name")]
                input_types = [i.get("type", "text") for i in form.find_all("input")]
                self.state.forms.append({
                    "page": url,
                    "action": action,
                    "method": method,
                    "inputs": ",".join(inputs),
                    "input_types": ",".join(input_types),
                })
                for name in inputs:
                    self.state.params[action].add(name)

    def _fingerprint_response(self, response: requests.Response) -> None:
        for header, key in [("Server", "server"), ("X-Powered-By", "x_powered_by"), ("Via", "via")]:
            value = response.headers.get(header)
            if value:
                self.state.technologies[key] = value

    def _extract_meta_tech(self, soup: BeautifulSoup) -> None:
        generator = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        if generator and generator.get("content"):
            self.state.technologies["generator"] = generator.get("content")

    def parse_js_files(self) -> None:
        endpoint_regex = re.compile(r"['\"]((?:/|https?://)[A-Za-z0-9_./?=&:%#\-]+)['\"]")
        secret_assignment_regex = re.compile(
            r"(?i)(api[_-]?key|secret|token|client[_-]?secret|access[_-]?key|aws[_-]?access[_-]?key[_-]?id|authorization|bearer)"
            r"\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        )
        for js_url in sorted(self.state.js_files):
            response = self.client.get(js_url, note="js-analysis")
            if not response:
                continue
            body = response.text[:2_000_000]
            secret_match = secret_assignment_regex.search(body)
            if secret_match and not is_vendor_js(js_url, body):
                self.state.add_finding(Finding(
                    title="Potential hardcoded secret in application JavaScript",
                    severity="Medium",
                    confidence="Medium",
                    category="Sensitive Data Exposure",
                    url=js_url,
                    description="The JavaScript file appears to contain a secret-like key/value assignment.",
                    evidence={"matched_assignment_sample": redact_long(secret_match.group(0), 120)},
                    manual_validation=[
                        "Open the JavaScript file in browser DevTools or Burp.",
                        "Confirm whether the matched value is app-specific.",
                        "Validate impact safely.",
                    ],
                    remediation="Move secrets server-side, restrict API keys, rotate exposed credentials.",
                ))
            for match in endpoint_regex.findall(body):
                endpoint = clean_url(urljoin(self.state.target.url + "/", match))
                if same_scope_url(self.state, endpoint):
                    self.state.urls.add(endpoint)
                    if looks_like_api(urlparse(endpoint).path):
                        self.state.api_endpoints.add(endpoint)
                    for param in extract_params(endpoint):
                        self.state.params[endpoint].add(param)

    def detect_interesting_candidates(self) -> None:
        for url in sorted(self.state.urls):
            path = urlparse(url).path
            if looks_like_api(path):
                self.state.api_endpoints.add(url)
            for param in extract_params(url):
                self.state.params[url].add(param)


# ---------------------------------------------------------------------
# Check Modules
# ---------------------------------------------------------------------
class HeaderChecker:
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "HSTS is missing.",
        "Content-Security-Policy": "CSP is missing.",
        "X-Frame-Options": "Clickjacking protection missing.",
        "X-Content-Type-Options": "MIME sniffing protection missing.",
        "Referrer-Policy": "Referrer leakage control missing.",
        "Permissions-Policy": "Browser feature policy missing.",
    }
    def __init__(self, client: SafeHTTPClient):
        self.client = client
        self.state = client.state
    def run(self) -> None:
        out("[+] Checking security headers")
        response = self.client.get(self.state.target.url, note="security-headers")
        if not response:
            return
        for header, impact in self.SECURITY_HEADERS.items():
            if header not in response.headers:
                self.state.add_finding(Finding(
                    title=f"Missing security header: {header}",
                    severity="Low",
                    confidence="High",
                    category="Security Misconfiguration",
                    url=self.state.target.url,
                    description=impact,
                    evidence={"missing_header": header},
                    manual_validation=["Verify the header is absent in Burp or browser DevTools."],
                    remediation=f"Configure the application or reverse proxy to return a suitable {header} header.",
                ))

class CookieChecker:
    def __init__(self, client: SafeHTTPClient):
        self.client = client
        self.state = client.state
    def run(self) -> None:
        out("[+] Checking cookie attributes")
        response = self.client.get(self.state.target.url, note="cookie-check")
        if not response:
            return
        raw_cookies = response.headers.get("Set-Cookie")
        if not raw_cookies:
            return
        for attr in ["Secure", "HttpOnly", "SameSite"]:
            if attr.lower() not in raw_cookies.lower():
                self.state.add_finding(Finding(
                    title=f"Cookie missing {attr} attribute",
                    severity="Low",
                    confidence="Medium",
                    category="Security Misconfiguration",
                    url=self.state.target.url,
                    description=f"Cookie missing {attr} attribute.",
                    evidence={"set_cookie_header": redact_long(raw_cookies, 300)},
                    manual_validation=[f"Check whether sensitive cookies consistently include the {attr} attribute."],
                    remediation="Set Secure, HttpOnly, and SameSite attributes on sensitive session cookies.",
                ))

class CORSChecker:
    def __init__(self, client: SafeHTTPClient):
        self.client = client
        self.state = client.state
    def run(self) -> None:
        out("[+] Checking basic CORS policy")
        test_origin = "https://example-attacker.invalid"
        response = self.client.request("GET", self.state.target.url, note="cors-check", headers={"Origin": test_origin})
        if not response:
            return
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        if acao == test_origin or acao == "*":
            self.state.add_finding(Finding(
                title="Potentially unsafe CORS policy",
                severity="High" if acac.lower() == "true" and acao == test_origin else "Medium",
                confidence="Medium",
                category="Security Misconfiguration",
                url=self.state.target.url,
                description="The application allows a cross-origin request from an arbitrary Origin.",
                evidence={"sent_origin": test_origin, "access_control_allow_origin": acao, "access_control_allow_credentials": acac},
                manual_validation=["Repeat in Burp with a controlled Origin header.", "Check authenticated sensitive responses."],
                remediation="Restrict Access-Control-Allow-Origin to trusted origins.",
            ))

class XSSTestSelector:
    def select(self, input_point: InputPoint, context: ContextResult) -> List[SecurityTest]:
        tests = []
        if context.context == 'html_body':
            tests.append(SecurityTest(name="xss-html-body", category="xss", payload='</title><h1>XSS_TEST</h1>', input_point=input_point, context=context.context))
        elif context.context == 'html_attribute':
            tests.append(SecurityTest(name="xss-attribute", category="xss", payload='"><img src=x onerror=alert(1)>', input_point=input_point, context=context.context))
        elif context.context == 'javascript':
            tests.append(SecurityTest(name="xss-js", category="xss", payload='";alert(1)//', input_point=input_point, context=context.context))
        elif context.context in ('unknown', 'html_tag', 'json'):
            # Plain-text / unclassified reflection: still validate with a
            # generic HTML breakout attempt rather than silently dropping it.
            tests.append(SecurityTest(name="xss-generic", category="xss", payload='<devnull_xss_probe>PROBE</devnull_xss_probe>', input_point=input_point, context=context.context))
        return tests

class XSSChecker:
    def __init__(self, client: SafeHTTPClient):
        self.client = client
        self.state = client.state
        self.pipeline = Pipeline(self.state, client)
        self.selector = XSSTestSelector()
    def run(self) -> None:
        out("[+] Running context-aware XSS pipeline")
        mapper = InputMapper()
        input_points = mapper.normalize(self.state)
        for ip in input_points:
            self.pipeline.run_for_input(ip, self.selector)

class IDORCandidateFinder:
    ID_LIKE_PARAM = re.compile(r"(?i)^(id|user_id|uid|account_id|order_id|booking_id|invoice_id|file_id|doc_id|customer_id|profile_id|tenant_id|org_id|member_id|project_id)$")
    ID_IN_PATH = re.compile(r"/(\d{2,}|[0-9a-f]{8,}(?:-[0-9a-f]{4,}){1,})($|[/?#])", re.I)
    def __init__(self, state: ScanState):
        self.state = state
    def run(self) -> None:
        out("[+] Finding IDOR candidates")
        for url in sorted(self.state.urls):
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param, values in qs.items():
                if self.ID_LIKE_PARAM.search(param) or any(v.isdigit() for v in values):
                    self._add_idor_candidate(url, f"ID-like parameter: {param}")
            if self.ID_IN_PATH.search(parsed.path + "/"):
                self._add_idor_candidate(url, "ID-like value in URL path")
        for action, params in self.state.params.items():
            for param in params:
                if self.ID_LIKE_PARAM.search(param):
                    self._add_idor_candidate(action, f"ID-like form/API parameter: {param}")
    def _add_idor_candidate(self, url: str, reason: str) -> None:
        self.state.add_finding(Finding(
            title="Potential IDOR testing candidate",
            severity="Medium",
            confidence="Low",
            category="Broken Access Control Candidate",
            url=url,
            description="An object identifier was detected.",
            evidence={"reason": reason},
            manual_validation=["Use two authorized test accounts.", "Replace object identifier and observe access."],
            remediation="Enforce server-side object-level authorization checks.",
        ))

class OpenRedirectChecker:
    REDIRECT_PARAMS = re.compile(r"(?i)(next|url|redirect|redirect_uri|return|return_to|continue|callback|dest|destination)")
    SAFE_TEST_URL = "https://example.com"
    def __init__(self, client: SafeHTTPClient, max_tests: int = 60):
        self.client = client
        self.state = client.state
        self.max_tests = max_tests
    def run(self) -> None:
        out("[+] Checking open redirect candidates")
        tested = 0
        for url, params in list(self.state.params.items()):
            if tested >= self.max_tests:
                break
            parsed = urlparse(url)
            original_qs = parse_qs(parsed.query)
            for param in sorted(params):
                if tested >= self.max_tests:
                    break
                if not self.REDIRECT_PARAMS.search(param):
                    continue
                qs = {k: v[:] for k, v in original_qs.items()}
                qs[param] = [self.SAFE_TEST_URL]
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(qs, doseq=True), ""))
                response = self.client.get(test_url, note="open-redirect-check")
                tested += 1
                if response and response.url.startswith(self.SAFE_TEST_URL):
                    self.state.add_finding(Finding(
                        title="Potential open redirect",
                        severity="Medium",
                        confidence="Medium",
                        category="Unvalidated Redirect Candidate",
                        url=test_url,
                        description="The application redirected to a supplied external URL.",
                        evidence={"parameter": param, "final_url": response.url},
                        manual_validation=["Repeat in Burp Repeater."],
                        remediation="Use a strict allowlist of internal redirect destinations.",
                    ))

class SensitiveFileChecker:
    CANDIDATES = [
        "/.env", "/.env.local", "/.env.production", "/config.json", "/config.php", "/phpinfo.php",
        "/.git/config", "/.svn/entries", "/backup.zip", "/backup.tar.gz", "/db.sql",
        "/robots.txt", "/sitemap.xml", "/server-status", "/actuator", "/actuator/health",
    ]
    SENSITIVE_MARKERS = re.compile(r"(?i)(db_password|database_url|secret|api[_-]?key|aws_access|private_key|BEGIN RSA|APP_KEY|password\s*=)")
    def __init__(self, client: SafeHTTPClient, max_checks: int = 40):
        self.client = client
        self.state = client.state
        self.max_checks = max_checks
    def run(self) -> None:
        out("[+] Checking sensitive file exposure candidates")
        checked = 0
        for path in self.CANDIDATES:
            if checked >= self.max_checks:
                break
            url = self.state.target.url.rstrip("/") + path
            response = self.client.get(url, note="sensitive-file-check")
            checked += 1
            if not response:
                continue
            body = response.text[:2000]
            if response.status_code == 200 and (self.SENSITIVE_MARKERS.search(body) or path in {"/robots.txt", "/sitemap.xml", "/.git/config"}):
                severity = "High" if path not in {"/robots.txt", "/sitemap.xml"} else "Info"
                self.state.add_finding(Finding(
                    title=f"Interesting exposed path: {path}",
                    severity=severity,
                    confidence="Medium",
                    category="Sensitive File / Information Exposure Candidate",
                    url=url,
                    description="A commonly sensitive or useful discovery path returned HTTP 200.",
                    evidence={"status_code": str(response.status_code), "content_type": response.headers.get("Content-Type", ""), "body_sample": redact_long(body, 300)},
                    manual_validation=["Open the URL in Burp or browser and review."],
                    remediation="Remove sensitive files from web root and block access.",
                ))

class SQLiErrorIndicator:
    SQL_PARAMS = re.compile(r"(?i)(id|q|query|search|filter|sort|page|category|product|item|user|name|email)")
    ERROR_PATTERNS = re.compile(r"(?i)(SQL syntax|mysql_fetch|ORA-\d+|PostgreSQL|SQLite/JDBCDriver|sqlite_error|ODBC SQL|Microsoft SQL Server|MariaDB|You have an error in your SQL syntax)")
    def __init__(self, client: SafeHTTPClient, max_tests: int = 40):
        self.client = client
        self.state = client.state
        self.max_tests = max_tests
    def run(self) -> None:
        out("[+] Checking SQL error indicators")
        tested = 0
        for url, params in list(self.state.params.items()):
            if tested >= self.max_tests:
                break
            parsed = urlparse(url)
            original_qs = parse_qs(parsed.query)
            for param in sorted(params):
                if tested >= self.max_tests:
                    break
                if not self.SQL_PARAMS.search(param):
                    continue
                qs = {k: v[:] for k, v in original_qs.items()}
                qs[param] = ["devnull_test'"]
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(qs, doseq=True), ""))
                response = self.client.get(test_url, note="sqli-error-indicator")
                tested += 1
                if response and self.ERROR_PATTERNS.search(response.text[:8000]):
                    self.state.add_finding(Finding(
                        title="SQL error indicator detected",
                        severity="High",
                        confidence="Medium",
                        category="SQL Injection Candidate",
                        url=test_url,
                        description="A harmless quote-based test triggered a database error message.",
                        evidence={"parameter": param, "status_code": str(response.status_code)},
                        manual_validation=["Compare normal vs modified parameter responses in Burp."],
                        remediation="Use parameterized queries and suppress verbose database errors.",
                    ))

class SSRFCandidateFinder:
    URL_PARAMS = re.compile(r"(?i)(url|uri|link|path|dest|destination|redirect|callback|webhook|image|avatar|file|feed|next|return|continue|proxy|host|domain|endpoint)")
    def __init__(self, state: ScanState):
        self.state = state
    def run(self) -> None:
        out("[+] Finding SSRF candidates")
        for url, params in list(self.state.params.items()):
            for param in sorted(params):
                if self.URL_PARAMS.search(param):
                    self.state.add_finding(Finding(
                        title="Potential SSRF testing candidate",
                        severity="Medium",
                        confidence="Low",
                        category="Server-Side Request Forgery Candidate",
                        url=url,
                        description="A parameter name suggests the application may accept a URL, host, file path, callback, or remote resource.",
                        evidence={"parameter": param},
                        manual_validation=["Check whether backend fetches the supplied resource using only controlled benign URLs."],
                        remediation="Validate and allowlist outbound destinations and block internal ranges.",
                    ))

class UploadSurfaceMapper:
    def __init__(self, state: ScanState):
        self.state = state
    def run(self) -> None:
        out("[+] Mapping file upload surfaces")
        for form in self.state.forms:
            joined = f"{form.get('inputs', '')},{form.get('input_types', '')},{form.get('action', '')}".lower()
            if any(word in joined for word in ["file", "upload", "avatar", "media"]):
                self.state.add_finding(Finding(
                    title="Potential file upload surface",
                    severity="Medium",
                    confidence="Low",
                    category="File Upload Testing Candidate",
                    url=form.get("action", self.state.target.url),
                    description="A form or endpoint appears related to file upload handling.",
                    evidence={"page": form.get("page", ""), "method": form.get("method", ""), "inputs": form.get("inputs", "")},
                    manual_validation=["Review file type validation, storage path, content handling, and access control."],
                    remediation="Validate file type server-side, store uploads outside executable paths.",
                ))

class AuthSurfaceMapper:
    AUTH_WORDS = re.compile(r"(?i)(login|signin|sign-in|register|signup|reset|forgot|password|logout|otp|mfa|2fa|admin)")
    def __init__(self, state: ScanState):
        self.state = state
    def run(self) -> None:
        out("[+] Mapping auth/admin surfaces")
        for url in sorted(self.state.urls):
            path = urlparse(url).path
            if self.AUTH_WORDS.search(path):
                self.state.add_finding(Finding(
                    title="Authentication or admin surface discovered",
                    severity="Medium" if "admin" in path.lower() else "Info",
                    confidence="Medium",
                    category="Auth Surface / Manual Review",
                    url=url,
                    description="An authentication, password recovery, MFA, logout, or admin-looking route was discovered.",
                    evidence={"path": path},
                    manual_validation=["Review login, logout, password reset, rate limiting, session fixation, and MFA behavior."],
                    remediation="Apply strong authentication controls, generic errors, rate limits.",
                ))

class CacheAndInfoLeakChecker:
    def __init__(self, client: SafeHTTPClient):
        self.client = client
        self.state = client.state
    def run(self) -> None:
        out("[+] Checking cache and information leakage hints")
        interesting = sorted(self.state.urls, key=lambda u: (path_depth(u), len(u)))[:25]
        if self.state.target.url not in interesting:
            interesting.insert(0, self.state.target.url)
        for url in interesting:
            response = self.client.get(url, note="cache-infoleak-check")
            if not response:
                continue
            headers = response.headers
            body_sample = response.text[:5000] if "text" in headers.get("Content-Type", "") else ""
            leaked = {k: headers.get(k, "") for k in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"] if headers.get(k)}
            if leaked:
                self.state.add_finding(Finding(
                    title="Technology/version disclosure header",
                    severity="Info",
                    confidence="High",
                    category="Information Disclosure",
                    url=url,
                    description="The response exposes technology or version hints.",
                    evidence=leaked,
                    manual_validation=["Confirm whether exposed versions are accurate and outdated."],
                    remediation="Remove or reduce unnecessary version disclosure.",
                ))
            if re.search(r"(?i)(stack trace|traceback|exception|debug mode|fatal error|warning:|notice:)", body_sample):
                self.state.add_finding(Finding(
                    title="Debug/error information disclosure candidate",
                    severity="Medium",
                    confidence="Medium",
                    category="Information Disclosure",
                    url=url,
                    description="The response appears to contain debug, exception, warning, or stack-trace style information.",
                    evidence={"body_sample": redact_long(body_sample, 300)},
                    manual_validation=["Review the response in Burp."],
                    remediation="Disable debug mode in production and use generic error pages.",
                ))

class MethodChecker:
    METHODS = ["OPTIONS", "TRACE"]
    def __init__(self, client: SafeHTTPClient):
        self.client = client
        self.state = client.state
    def run(self) -> None:
        out("[+] Checking risky HTTP method exposure")
        for method in self.METHODS:
            response = self.client.request(method, self.state.target.url, note="method-check", allow_redirects=False)
            if not response:
                continue
            allow = response.headers.get("Allow", "")
            if method == "TRACE" and response.status_code < 400:
                self.state.add_finding(Finding(
                    title="TRACE method appears enabled",
                    severity="Low",
                    confidence="Medium",
                    category="Security Misconfiguration",
                    url=self.state.target.url,
                    description="HTTP TRACE appears enabled.",
                    evidence={"status_code": str(response.status_code), "allow": allow},
                    manual_validation=["Confirm TRACE behavior with Burp Repeater."],
                    remediation="Disable HTTP TRACE.",
                ))
            if method == "OPTIONS" and allow:
                risky = [m for m in ["PUT", "DELETE", "PATCH", "TRACE"] if m in allow.upper()]
                if risky:
                    self.state.add_finding(Finding(
                        title="Potentially risky HTTP methods advertised",
                        severity="Low",
                        confidence="Low",
                        category="Security Misconfiguration",
                        url=self.state.target.url,
                        description="The server advertises HTTP methods that may be risky.",
                        evidence={"allow": allow, "risky_methods": ",".join(risky)},
                        manual_validation=["Confirm whether risky methods are accepted and protected."],
                        remediation="Disable unused HTTP methods and enforce authorization.",
                    ))

# ---------------------------------------------------------------------
# Browser Recon (Full implementation from original, adapted)
# ---------------------------------------------------------------------
class BrowserRecon:
    SAFE_MARKER = "devnull_browser_marker_67890"
    DANGEROUS_WORDS = re.compile(r"(?i)(delete|remove|logout|signout|pay|payment|purchase|buy|checkout|confirm|submit|send|transfer|withdraw|disable|deactivate)")
    INTERESTING_INPUTS = re.compile(r"(?i)(search|q|query|name|email|message|comment|title|description|url|link)")

    def __init__(self, state: ScanState, headed: bool = False, max_clicks: int = 20, timeout_ms: int = 12000):
        self.state = state
        self.headed = headed
        self.max_clicks = max(0, max_clicks)
        self.timeout_ms = max(3000, timeout_ms)
        self.report_dir = state.target.workspace / "reports" / state.target.base_domain
        self.screenshot_dir = self.report_dir / "screenshots"
        self.network_events: List[Dict[str, str]] = []

    def run(self) -> None:
        out("[+] Running browser recon mode")
        if sync_playwright is None:
            self.state.add_finding(Finding(
                title="Playwright is not installed",
                severity="Info",
                confidence="High",
                category="Tool Setup",
                url=self.state.target.url,
                description="Browser recon was requested, but Playwright is not installed.",
                evidence={"install_command": "pip install playwright && playwright install chromium"},
                manual_validation=["Install Playwright and rerun with --browser."],
                remediation="Install Playwright dependencies.",
            ))
            return

        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=not self.headed)
            except PlaywrightError as exc:
                # Package is installed but the browser binary itself isn't
                # (e.g. `playwright install` was never run, or was run for a
                # different Playwright version). This must not take down the
                # rest of the scan.
                self.state.add_finding(Finding(
                    title="Playwright browser binary not installed",
                    severity="Info",
                    confidence="High",
                    category="Tool Setup",
                    url=self.state.target.url,
                    description="Browser recon was requested and the Playwright package is present, but the required browser binary is missing or mismatched.",
                    evidence={"install_command": "playwright install chromium", "error": redact_long(str(exc), 300)},
                    manual_validation=["Run `playwright install chromium` and rerun with --browser."],
                    remediation="Install the Playwright browser binaries matching the installed Playwright package version.",
                ))
                return
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.on("request", self._capture_request)
            page.on("response", self._capture_response)
            try:
                page.goto(self.state.target.url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                page.wait_for_timeout(1500)
                self._save_screenshot(page, "initial")
                self._collect_page_data(page)
                self._safe_click_visible_elements(page)
                self._map_and_test_forms(page)
                self._collect_page_data(page)
            except PlaywrightTimeoutError:
                self.state.add_finding(Finding(
                    title="Browser navigation timeout",
                    severity="Info",
                    confidence="High",
                    category="Browser Recon",
                    url=self.state.target.url,
                    description="The browser could not finish loading the page within the configured timeout.",
                    evidence={"timeout_ms": str(self.timeout_ms)},
                    manual_validation=["Open the target manually and check if it is slow, blocked, or requires auth."],
                    remediation="Increase --browser-timeout or use --headed.",
                ))
            except PlaywrightError as exc:
                # Any other browser-side failure during recon (crashed page,
                # navigation blocked, etc.) should degrade to a finding, not
                # take down the whole --all run.
                self.state.add_finding(Finding(
                    title="Browser recon encountered an error",
                    severity="Info",
                    confidence="Medium",
                    category="Browser Recon",
                    url=self.state.target.url,
                    description="An unexpected browser-side error interrupted recon before it could finish.",
                    evidence={"error": redact_long(str(exc), 300)},
                    manual_validation=["Retry with --headed to observe the browser session directly."],
                    remediation="N/A",
                ))
            finally:
                self._write_network_log()
                context.close()
                browser.close()

    def _capture_request(self, request) -> None:
        url = request.url
        if self._in_scope(url):
            cleaned = clean_url(url)
            self.state.urls.add(cleaned)
            if urlparse(url).path.endswith(".js"):
                self.state.js_files.add(cleaned)
            if looks_like_api(urlparse(url).path):
                self.state.api_endpoints.add(cleaned)
            for param in extract_params(url):
                self.state.params[cleaned].add(param)
            self.network_events.append({"type": "request", "method": request.method, "url": url, "resource_type": request.resource_type})

    def _capture_response(self, response) -> None:
        url = response.url
        if self._in_scope(url):
            headers = response.headers
            self.network_events.append({"type": "response", "status": str(response.status), "url": url, "content_type": headers.get("content-type", "")})

    def _in_scope(self, url: str) -> bool:
        hostname = (urlparse(url).hostname or "").lower()
        return hostname == self.state.target.base_domain or hostname.endswith("." + self.state.target.base_domain)

    def _collect_page_data(self, page) -> None:
        current_url = clean_url(page.url)
        if self._in_scope(current_url):
            self.state.urls.add(current_url)

        try:
            links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            for link in links:
                if self._in_scope(link):
                    cleaned = clean_url(link)
                    self.state.urls.add(cleaned)
                    for param in extract_params(cleaned):
                        self.state.params[cleaned].add(param)
        except Exception:
            pass

        try:
            scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
            for src in scripts:
                if self._in_scope(src):
                    self.state.js_files.add(clean_url(src))
        except Exception:
            pass

        try:
            forms = page.eval_on_selector_all(
                "form",
                """
                forms => forms.map(f => ({
                    page: location.href,
                    action: f.action || location.href,
                    method: (f.method || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input, textarea, select')).map(i => i.name || i.id || i.type || '').filter(Boolean).join(','),
                    input_types: Array.from(f.querySelectorAll('input')).map(i => i.type || 'text').join(',')
                }))
                """,
            )
            for form in forms:
                action = clean_url(form.get("action", current_url))
                if self._in_scope(action):
                    form["action"] = action
                    self.state.forms.append(form)
                    for name in form.get("inputs", "").split(","):
                        if name:
                            self.state.params[action].add(name)
        except Exception:
            pass

    def _safe_click_visible_elements(self, page) -> None:
        clicked = 0
        try:
            candidates = page.locator("a[href], button").all()
        except Exception:
            return
        for element in candidates:
            if clicked >= self.max_clicks:
                break
            try:
                text = (element.inner_text(timeout=1000) or "").strip()
                href = element.get_attribute("href", timeout=1000) or ""
                label = f"{text} {href}".strip()
                if not label or self.DANGEROUS_WORDS.search(label):
                    continue
                if href and not self._in_scope(urljoin(page.url, href)):
                    continue
                element.click(timeout=2000)
                page.wait_for_timeout(800)
                self._collect_page_data(page)
                clicked += 1
            except Exception:
                continue

    def _map_and_test_forms(self, page) -> None:
        try:
            inputs = page.locator("input:not([type='password']):not([type='hidden']), textarea").all()
        except Exception:
            return
        tested = 0
        for field in inputs:
            if tested >= 20:
                break
            try:
                name = field.get_attribute("name", timeout=1000) or ""
                field_id = field.get_attribute("id", timeout=1000) or ""
                placeholder = field.get_attribute("placeholder", timeout=1000) or ""
                input_type = field.get_attribute("type", timeout=1000) or "text"
                label = " ".join([name, field_id, placeholder, input_type])
                if input_type.lower() in {"submit", "button", "file", "checkbox", "radio"}:
                    continue
                if label and not self.INTERESTING_INPUTS.search(label):
                    continue
                field.fill(self.SAFE_MARKER, timeout=2000)
                page.wait_for_timeout(500)
                html = page.content()
                if self.SAFE_MARKER in html:
                    screenshot = self._save_screenshot(page, f"dom-reflection-{tested+1}")
                    self.state.add_finding(Finding(
                        title="Browser DOM reflection detected",
                        severity="Medium",
                        confidence="Low",
                        category="DOM XSS Candidate",
                        url=page.url,
                        description="A safe marker entered through the browser appeared in the DOM or rendered page.",
                        evidence={"field_hint": label or "unknown", "marker": self.SAFE_MARKER, "screenshot": screenshot},
                        manual_validation=["Identify where the marker lands in the DOM.", "Use safe manual payloads only after confirming context."],
                        remediation="Use safe DOM APIs and context-aware encoding.",
                    ))
                tested += 1
            except Exception:
                continue

    def _save_screenshot(self, page, name: str) -> str:
        safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "-", name).strip("-") or "screenshot"
        path = self.screenshot_dir / f"{safe_name}-{len(self.state.screenshots)+1}.png"
        try:
            page.screenshot(path=str(path), full_page=True)
            self.state.screenshots.append(str(path))
            return str(path)
        except Exception:
            return "screenshot_failed"

    def _write_network_log(self) -> None:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        (self.report_dir / "browser-network.json").write_text(json.dumps(self.network_events, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------
# Reporting (Full implementation adapted from original)
# ---------------------------------------------------------------------
class Reporter:
    def __init__(self, state: ScanState):
        self.state = state
        self.report_dir = state.target.workspace / "reports" / state.target.base_domain
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def write_all(self) -> None:
        out("[+] Writing reports")
        save_lines(self.report_dir / "urls.txt", self.state.urls)
        save_lines(self.report_dir / "js-files.txt", self.state.js_files)
        save_lines(self.report_dir / "api-endpoints.txt", self.state.api_endpoints)
        self.write_params()
        self.write_forms()
        self.write_technologies()
        self.write_findings_json()
        self.write_markdown_report()
        self.write_poc_text_report()
        self.write_request_log()
        self.write_burp_notes()

    def write_params(self) -> None:
        lines = []
        for url, params in sorted(self.state.params.items()):
            for param in sorted(params):
                lines.append(f"{url} -> {param}")
        save_lines(self.report_dir / "params.txt", lines)

    def write_forms(self) -> None:
        (self.report_dir / "forms.json").write_text(json.dumps(self.state.forms, indent=2), encoding="utf-8")

    def write_technologies(self) -> None:
        (self.report_dir / "technologies.json").write_text(json.dumps(self.state.technologies, indent=2), encoding="utf-8")

    def write_findings_json(self) -> None:
        data = [dataclasses.asdict(f) | {"fingerprint": f.fingerprint()} for f in self.state.findings]
        (self.report_dir / "findings.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    def sorted_findings(self) -> List[Finding]:
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        return sorted(self.state.findings, key=lambda f: severity_order.get(f.severity, 99))

    def write_markdown_report(self) -> None:
        path = self.report_dir / "report.md"
        findings = self.sorted_findings()
        counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            counts[f.severity] += 1
        lines = [
            f"# DevNull Report - {self.state.target.base_domain}",
            "",
            "## Scope",
            f"- Target: `{self.state.target.url}`",
            f"- Base domain: `{self.state.target.base_domain}`",
            "- Mode: Authorized low-risk enumeration and testing lead generation",
            "",
            "## Summary",
            f"- URLs discovered: {len(self.state.urls)}",
            f"- JavaScript files discovered: {len(self.state.js_files)}",
            f"- API-like endpoints discovered: {len(self.state.api_endpoints)}",
            f"- Forms discovered: {len(self.state.forms)}",
            f"- Findings/leads: {len(findings)}",
            f"- Severity split: High={counts['High']}, Medium={counts['Medium']}, Low={counts['Low']}, Info={counts['Info']}",
            "",
        ]
        if self.state.technologies:
            lines.extend(["## Technology Hints", ""])
            for key, value in self.state.technologies.items():
                lines.append(f"- `{key}`: `{value}`")
            lines.append("")
        lines.extend(["## Findings and Testing Leads", ""])
        if not findings:
            lines.append("No findings or testing leads were generated.")
        else:
            for idx, finding in enumerate(findings, 1):
                lines.extend([
                    f"### {idx}. {finding.title}",
                    "",
                    f"- Severity: **{finding.severity}**",
                    f"- Confidence: **{finding.confidence}**",
                    f"- Category: **{finding.category}**",
                    f"- URL: `{finding.url}`",
                    "",
                    finding.description,
                    "",
                    "**Evidence**",
                ])
                for key, value in finding.evidence.items():
                    if key.lower() != "screenshot":
                        lines.append(f"- `{key}`: `{value}`")
                lines.extend(["", "**Manual validation**"])
                for step in finding.manual_validation:
                    lines.append(f"- {step}")
                lines.extend(["", "**Remediation**", finding.remediation or "N/A", ""])
        path.write_text("\n".join(lines), encoding="utf-8")

    def write_poc_text_report(self) -> None:
        path = self.report_dir / "poc.txt"
        findings = self.sorted_findings()
        lines = [
            "DEVNULL CONSOLIDATED POC REPORT",
            "=" * 80,
            "",
            "1. SCOPE",
            "-" * 80,
            f"Target: {self.state.target.url}",
            f"Base Domain: {self.state.target.base_domain}",
            "Mode: Authorized low-risk enumeration and testing lead generation",
            "",
            "2. SUMMARY",
            "-" * 80,
            f"URLs Discovered: {len(self.state.urls)}",
            f"JavaScript Files Discovered: {len(self.state.js_files)}",
            f"API-like Endpoints Discovered: {len(self.state.api_endpoints)}",
            f"Forms Discovered: {len(self.state.forms)}",
            f"Findings / Leads: {len(findings)}",
            "",
            "3. TECHNOLOGY HINTS",
            "-" * 80,
        ]
        if self.state.technologies:
            for key, value in self.state.technologies.items():
                lines.append(f"{key}: {value}")
        else:
            lines.append("No technology hints collected.")
        lines.extend(["", "4. DISCOVERED URLS", "-" * 80])
        lines.extend(sorted(self.state.urls) or ["No URLs discovered."])
        lines.extend(["", "5. API-LIKE ENDPOINTS", "-" * 80])
        lines.extend(sorted(self.state.api_endpoints) or ["No API-like endpoints discovered."])
        lines.extend(["", "6. JAVASCRIPT FILES", "-" * 80])
        lines.extend(sorted(self.state.js_files) or ["No JavaScript files discovered."])
        lines.extend(["", "7. PARAMETERS", "-" * 80])
        param_lines = []
        for url, params in sorted(self.state.params.items()):
            for param in sorted(params):
                param_lines.append(f"{url} -> {param}")
        lines.extend(param_lines or ["No parameters discovered."])
        lines.extend(["", "8. FORMS", "-" * 80])
        if self.state.forms:
            seen_forms = set()
            for form in self.state.forms:
                form_line = (
                    f"Page: {form.get('page', '')} | "
                    f"Action: {form.get('action', '')} | "
                    f"Method: {form.get('method', '')} | "
                    f"Inputs: {form.get('inputs', '')} | "
                    f"Input Types: {form.get('input_types', '')}"
                )
                if form_line not in seen_forms:
                    seen_forms.add(form_line)
                    lines.append(form_line)
        else:
            lines.append("No forms discovered.")
        lines.extend(["", "9. FINDINGS AND POC DETAILS", "-" * 80])
        if not findings:
            lines.append("No findings or testing leads generated.")
        else:
            for index, finding in enumerate(findings, 1):
                lines.extend([
                    "",
                    f"Finding #{index}: {finding.title}",
                    "~" * 80,
                    f"Severity: {finding.severity}",
                    f"Confidence: {finding.confidence}",
                    f"Category: {finding.category}",
                    f"URL: {finding.url}",
                    "",
                    "Description:",
                    finding.description,
                    "",
                    "Evidence:",
                ])
                if finding.evidence:
                    for key, value in finding.evidence.items():
                        if key.lower() != "screenshot":
                            lines.append(f"- {key}: {value}")
                else:
                    lines.append("- No evidence fields recorded.")
                lines.extend(["", "Manual Validation Steps:"])
                if finding.manual_validation:
                    for step_number, step in enumerate(finding.manual_validation, 1):
                        lines.append(f"{step_number}. {step}")
                else:
                    lines.append("No manual validation steps recorded.")
                if finding.category.lower().startswith("cross-site scripting") or "reflection" in finding.title.lower():
                    field = finding.evidence.get("field", "title")
                    lines.extend([
                        "",
                        "Suggested Safe PoC Payloads:",
                        "- Marker test: devnull_form_marker_24680",
                        "- HTML injection test: </title><h1 style=\"color:red\">HTML_INJECTION_CONFIRMED</h1>",
                        "- URL-encoded body example:",
                        f"  {field}=%3C%2Ftitle%3E%3Ch1%20style%3D%22color%3Ared%22%3EHTML_INJECTION_CONFIRMED%3C%2Fh1%3E&content=test",
                    ])
                lines.extend(["", "Remediation:", finding.remediation or "N/A"])
        lines.extend(["", "10. REQUEST AUDIT SUMMARY", "-" * 80])
        lines.append(f"Total requests recorded by DevNull: {len(self.state.request_log)}")
        lines.append("Detailed request logs are kept separately in request-log.json for debugging.")
        lines.extend(["", "END OF REPORT", "=" * 80, ""])
        path.write_text("\n".join(lines), encoding="utf-8")

    def write_request_log(self) -> None:
        data = [dataclasses.asdict(r) for r in self.state.request_log]
        (self.report_dir / "request-log.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    def write_burp_notes(self) -> None:
        burp_dir = self.report_dir / "burp-notes"
        burp_dir.mkdir(exist_ok=True)
        for idx, finding in enumerate(self.state.findings, 1):
            suffix = ""
            if finding.evidence.get("field"):
                suffix += "-" + finding.evidence["field"]
            if finding.evidence.get("method"):
                suffix += "-" + finding.evidence["method"].lower()
            safe_title = re.sub(r"[^a-zA-Z0-9_-]+", "-", (finding.title + suffix).lower()).strip("-")
            path = burp_dir / f"{idx:02d}-{safe_title}.txt"
            lines = [
                f"Title: {finding.title}",
                f"Category: {finding.category}",
                f"Severity: {finding.severity}",
                f"Confidence: {finding.confidence}",
                f"URL: {finding.url}",
                "",
                "Evidence:",
            ]
            for key, value in finding.evidence.items():
                if key.lower() != "screenshot":
                    lines.append(f"- {key}: {value}")
            lines.extend(["", "Why this matters:", finding.description, "", "Manual Burp validation steps:"])
            for step_no, step in enumerate(finding.manual_validation, 1):
                lines.append(f"{step_no}. {step}")
            path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------
# Self-Tests
# ---------------------------------------------------------------------
class DevNullSelfTests(unittest.TestCase):
    def test_normalize_target_adds_scheme(self) -> None:
        self.assertEqual(normalize_target("example.com"), "https://example.com")

    def test_base_domain(self) -> None:
        self.assertEqual(base_domain_from_target("https://Example.com/path"), "example.com")

    def test_clean_url_preserves_query(self) -> None:
        self.assertEqual(clean_url("https://EXAMPLE.com/a?x=1#frag"), "https://example.com/a?x=1")

    def test_extract_params(self) -> None:
        self.assertEqual(extract_params("https://x.test/?a=1&b=2"), {"a", "b"})

    def test_vendor_js_detection_skips_jquery(self) -> None:
        body = "/*! jQuery v3.4.1 | jquery.org/license */ function test(){}"
        self.assertTrue(is_vendor_js("https://example.com/static/js/jquery-3.4.1.min.js", body))

    def test_vendor_js_detection_does_not_skip_app_file(self) -> None:
        body = "const apiKey = 'abcd1234abcd1234';"
        self.assertFalse(is_vendor_js("https://example.com/static/js/app.js", body))

    def test_idor_candidate_adds_finding(self) -> None:
        state = ScanState(Target("https://example.com", "example.com", Path("/tmp/devnull-test")))
        state.urls.add("https://example.com/user/123")
        IDORCandidateFinder(state).run()
        self.assertTrue(any("IDOR" in f.title for f in state.findings))

    def test_form_xss_checker_adds_reflection_finding_with_mock_response(self) -> None:
        class FakeResponse:
            def __init__(self, text: str, url: str):
                self.text = text
                self.status_code = 200
                self.headers = {"Content-Type": "text/html"}
                self.content = text.encode("utf-8")
                self.url = url

        # Simulate a genuinely vulnerable endpoint: whatever value is sent for
        # the "q" parameter (via query string or form body) gets echoed back
        # verbatim in the page body, unencoded. This must distinguish the
        # baseline call (original/empty value -> no reflection) from every
        # subsequent test payload (marker, context probes -> reflected), the
        # way a real target would. A mock that returns identical output for
        # every request would falsely trigger the "value already present in
        # baseline" false-positive filter and mask genuine reflections.
        def fake_request(method, url, note="", **kwargs):
            sent_value = ""
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            if "q" in qs:
                sent_value = qs["q"][0]
            data = kwargs.get("data")
            if isinstance(data, dict) and "q" in data:
                sent_value = data["q"]
            body = f"<html><body>You searched for: {sent_value}</body></html>"
            return FakeResponse(body, url)

        state = ScanState(Target("https://example.com", "example.com", Path("/tmp/devnull-test")))
        state.params["https://example.com/search"].add("q")
        client = SafeHTTPClient(state, rate_limit_seconds=0)
        client.request = fake_request  # type: ignore[method-assign]
        XSSChecker(client).run()
        self.assertTrue(any("Potential reflected XSS" in f.title for f in state.findings))

    def test_browser_flags_parseable(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--target", "https://example.com", "--browser", "--headed", "--browser-clicks", "5"])
        self.assertTrue(args.browser)
        self.assertTrue(args.headed)
        self.assertEqual(args.browser_clicks, 5)

    def test_form_xss_flag_parseable(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--target", "https://example.com", "--form-xss"])
        self.assertTrue(args.form_xss)


def run_self_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DevNullSelfTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devnull",
        description="Authorized web security enumeration and testing lead generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 devnull.py --target https://example.com --all
  python3 devnull.py --target example.com --enum --headers --cookies
  python3 devnull.py --target https://example.com --enum --xss --browser
  python3 devnull.py --self-test
        """.strip(),
    )
    parser.add_argument("--target", help="Authorized target URL")
    parser.add_argument("--workspace", default="devnull-workspace", help="Workspace directory")
    parser.add_argument("--rate", type=float, default=0.8, help="Delay between requests in seconds")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl")
    parser.add_argument("--self-test", action="store_true", help="Run built-in unit tests")
    parser.add_argument("--enum", action="store_true", help="Run enumeration")
    parser.add_argument("--headers", action="store_true", help="Check security headers")
    parser.add_argument("--cookies", action="store_true", help="Check cookie attributes")
    parser.add_argument("--cors", action="store_true", help="Check basic CORS policy")
    parser.add_argument("--xss", action="store_true", help="Run context-aware XSS reflection checks")
    parser.add_argument("--form-xss", action="store_true", help="Run form-based XSS reflection checks (same as --xss for backward compatibility)")
    parser.add_argument("--idor", action="store_true", help="Find IDOR candidates")
    parser.add_argument("--redirect", action="store_true", help="Run safe open redirect checks")
    parser.add_argument("--sensitive-files", action="store_true", help="Check common exposed files")
    parser.add_argument("--sqli-errors", action="store_true", help="Check SQL error indicators")
    parser.add_argument("--ssrf", action="store_true", help="Find SSRF parameter candidates")
    parser.add_argument("--uploads", action="store_true", help="Map upload surfaces")
    parser.add_argument("--auth", action="store_true", help="Map auth/admin surfaces")
    parser.add_argument("--cache", action="store_true", help="Check cache and info-leak hints")
    parser.add_argument("--methods", action="store_true", help="Check risky HTTP methods")
    parser.add_argument("--browser", action="store_true", help="Run controlled browser recon")
    parser.add_argument("--headed", action="store_true", help="Show browser window")
    parser.add_argument("--browser-clicks", type=int, default=20, help="Max safe clicks in browser mode")
    parser.add_argument("--browser-timeout", type=int, default=12000, help="Browser navigation timeout ms")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    return parser

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_tests()

    if not args.target:
        eprint("\n[!] Missing required option: --target\n")
        parser.print_help()
        return 2

    try:
        target_url = normalize_target(args.target)
        base_domain = base_domain_from_target(target_url)
    except ValueError as exc:
        eprint(f"[!] Invalid target: {exc}")
        return 2

    workspace = Path(args.workspace)
    target = Target(url=target_url, base_domain=base_domain, workspace=workspace)
    state = ScanState(target=target)
    client = SafeHTTPClient(state, rate_limit_seconds=args.rate, timeout=args.timeout, proxy=args.proxy)

    run_all = args.all
    if run_all or args.enum:
        Enumerator(client, max_pages=args.max_pages).run()

    # Run enum automatically for modules that need discovered params/forms.
    if (args.xss or args.form_xss or args.idor or args.redirect or args.ssrf or args.uploads or args.auth or args.cache or args.sqli_errors) and not state.urls:
        Enumerator(client, max_pages=args.max_pages).run()

    if run_all or args.browser:
        BrowserRecon(state, headed=args.headed, max_clicks=args.browser_clicks, timeout_ms=args.browser_timeout).run()

    if run_all or args.headers:
        HeaderChecker(client).run()
    if run_all or args.cookies:
        CookieChecker(client).run()
    if run_all or args.cors:
        CORSChecker(client).run()
    if run_all or args.xss or args.form_xss:
        XSSChecker(client).run()
    if run_all or args.idor:
        IDORCandidateFinder(state).run()
    if run_all or args.redirect:
        OpenRedirectChecker(client).run()
    if run_all or args.sensitive_files:
        SensitiveFileChecker(client).run()
    if run_all or args.sqli_errors:
        SQLiErrorIndicator(client).run()
    if run_all or args.ssrf:
        SSRFCandidateFinder(state).run()
    if run_all or args.uploads:
        UploadSurfaceMapper(state).run()
    if run_all or args.auth:
        AuthSurfaceMapper(state).run()
    if run_all or args.cache:
        CacheAndInfoLeakChecker(client).run()
    if run_all or args.methods:
        MethodChecker(client).run()

    Reporter(state).write_all()
    out(f"[+] Done. Reports saved to: {workspace / 'reports' / base_domain}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
