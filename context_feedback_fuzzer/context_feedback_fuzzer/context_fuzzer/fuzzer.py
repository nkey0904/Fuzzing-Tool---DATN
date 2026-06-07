#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import sys
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from html import escape
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, urlunparse, parse_qsl

import requests
from bs4 import BeautifulSoup

from .profiles import PROFILES

BANNER = "Context Feedback Fuzzer v1.3 - authorized testing only"

CANARY = "cff_canary_9x7"
INTERESTING_STATUS = {200, 204, 206, 301, 302, 307, 308, 401, 403, 405, 500}

SENSITIVE_NAME_PATTERNS = re.compile(
    r"(config|settings|backup|\.bak|\.old|readme|license|admin|login|api|jsonws|_api|_layouts|webservice|pluginfile)",
    re.I,
)

SQL_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql|mariadb|postgresql|sqlite|odbc|pdoexception|sqlstate|ora-[0-9]{5}|jdbc|unterminated quoted|string literal|warning:.*mysql|you have an error in your sql syntax)",
    re.I,
)

TEMPLATE_ERROR_PATTERNS = re.compile(
    r"(traceback|stack trace|exception|fatal error|warning:|notice:|debug|at line [0-9]+)",
    re.I,
)

SERVER_EXTENSION_HINTS = {
    "php": [".php", ".php.bak", ".php.old"],
    "java": [".jsp", ".do", ".action"],
    "aspnet": [".aspx", ".ashx", ".asmx"],
}


@dataclass
class Finding:
    kind: str
    platform: str
    url: str
    method: str
    status: int
    length: int
    content_type: str
    score: int
    reason: str
    vulnerability_type: str = "Informational"
    conclusion: str = ""
    parameter: str = ""
    param_type: str = ""
    payload_type: str = ""
    payload: str = ""
    evidence: str = ""
    title: str = ""
    sha1: str = ""

    @property
    def cms(self) -> str:
        return self.platform


class ScopeError(Exception):
    pass


def get_platform_type(platform: str) -> str:
    if platform == "moodle":
        return "LMS"
    if platform in {"wordpress", "joomla", "drupal"}:
        return "CMS"
    if platform == "liferay":
        return "Portal / DXP"
    if platform == "sharepoint":
        return "Collaboration Platform"
    return "Web Platform"


class ContextFeedbackFuzzer:
    def __init__(
        self,
        base_url: str,
        wordlist_dir: str,
        cms_hint: str = "auto",
        threads: int = 4,
        delay: float = 0.15,
        timeout: float = 8.0,
        max_requests: int = 400,
        user_agent: str = "ContextFeedbackFuzzer/1.3 authorized-lab",
    ) -> None:
        self.base_url = self._normalize_base(base_url)
        self.base_host = urlparse(self.base_url).netloc.lower()
        self.wordlist_dir = wordlist_dir
        self.platform_hint = cms_hint.lower()
        self.cms_hint = self.platform_hint
        self.threads = max(1, min(threads, 12))
        self.delay = max(0.0, delay)
        self.timeout = timeout
        self.max_requests = max_requests

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/json,*/*;q=0.8",
            }
        )

        self.findings: List[Finding] = []
        self.seen_urls = set()
        self.lock = threading.Lock()
        self.request_count = 0
        self.baseline: Optional[Tuple[int, int, str]] = None

        self.detected_stack = {
            "language": "unknown",
            "server": "unknown",
            "extensions": [],
        }

        self.generated_wordlist_info = {
            "path_sources": [],
            "server_extensions": [],
            "parameter_strategy": {},
            "payload_strategy": {},
        }

    @staticmethod
    def _normalize_base(url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/") + "/"

    def _in_scope(self, url: str) -> bool:
        return urlparse(url).netloc.lower() == self.base_host

    def _safe_request(self, method: str, url: str) -> Optional[requests.Response]:
        if not self._in_scope(url):
            raise ScopeError(f"Out of scope URL blocked: {url}")

        with self.lock:
            if self.request_count >= self.max_requests:
                return None
            self.request_count += 1

        time.sleep(self.delay)

        try:
            return self.session.request(
                method,
                url,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            return None

    def fetch_baseline(self) -> None:
        noise = "cff-baseline-" + hashlib.sha1(str(time.time()).encode()).hexdigest()[:10]
        url = urljoin(self.base_url, noise)
        r = self._safe_request("GET", url)

        if r is None:
            self.baseline = (0, 0, "")
        else:
            self.baseline = (
                r.status_code,
                len(r.content),
                r.headers.get("Content-Type", ""),
            )

    def fingerprint(self) -> Tuple[str, Dict[str, int]]:
        scores = {name: 0 for name in PROFILES}
        urls = [self.base_url]

        for profile in PROFILES.values():
            for p in profile["signals"].get("probe_paths", [])[:2]:
                urls.append(urljoin(self.base_url, p.lstrip("/")))

        for url in dict.fromkeys(urls):
            r = self._safe_request("GET", url)
            if not r:
                continue

            self.infer_stack_from_response(r)

            header_blob = "\n".join(
                f"{k.lower()}: {v.lower()}" for k, v in r.headers.items()
            )
            cookie_blob = ";".join(r.cookies.keys()).lower()
            body = r.text[:120000].lower()

            for platform, profile in PROFILES.items():
                sig = profile["signals"]

                for marker in sig.get("headers", []):
                    if marker.lower() in header_blob:
                        scores[platform] += 4

                for marker in sig.get("cookies", []):
                    if marker.lower() in cookie_blob:
                        scores[platform] += 3

                for marker in sig.get("body", []):
                    if marker.lower() in body:
                        scores[platform] += 4

                if r.status_code in (200, 401, 403) and any(
                    url.endswith(p) for p in sig.get("probe_paths", [])
                ):
                    scores[platform] += 1

        if self.platform_hint != "auto" and self.platform_hint in PROFILES:
            scores[self.platform_hint] += 100

        best = max(scores, key=scores.get)
        return best, scores

    def infer_stack_from_response(self, r: requests.Response) -> None:
        header_blob = "\n".join(
            f"{k.lower()}: {v.lower()}" for k, v in r.headers.items()
        )
        cookie_blob = ";".join(r.cookies.keys()).lower()
        body = r.text[:50000].lower() if r.text else ""
        blob = "\n".join([header_blob, cookie_blob, body])

        language = self.detected_stack.get("language", "unknown")
        server = self.detected_stack.get("server", "unknown")

        if (
            "php" in blob
            or "wordpress" in blob
            or "joomla" in blob
            or "drupal" in blob
            or "moodle" in blob
            or "moodlesession" in blob
        ):
            language = "php"
        elif "jsessionid" in blob or "java" in blob or "apache-coyote" in blob or "liferay" in blob:
            language = "java"
        elif "asp.net" in blob or "microsoft-iis" in blob or "sharepoint" in blob:
            language = "aspnet"

        if "nginx" in blob:
            server = "nginx"
        elif "apache" in blob:
            server = "apache"
        elif "microsoft-iis" in blob:
            server = "iis"
        elif "apache-coyote" in blob:
            server = "apache-coyote"

        self.detected_stack = {
            "language": language,
            "server": server,
            "extensions": SERVER_EXTENSION_HINTS.get(language, []),
        }

    def classify_param(self, param: str, sample_value: str = "") -> str:
        p = param.lower()
        v = str(sample_value or "").lower()

        if re.search(r"(^|_)(id|uid|userid|user|course|courseid|post|page|cat|item|itemid|node|list|view|contextid|section)(_|$)", p) or p in {
            "p",
            "id",
            "page_id",
            "cat",
            "author",
            "itemid",
            "userid",
            "courseid",
            "contextid",
        }:
            return "numeric"

        if p in {
            "q",
            "s",
            "search",
            "searchword",
            "keyword",
            "query",
            "name",
            "title",
            "comment",
            "message",
            "log",
            "username",
            "wsfunction",
            "moodlewsrestformat",
            "component",
        }:
            return "text"

        if any(x in p for x in ("file", "path", "folder", "template", "module", "view", "layout", "destination", "filepath", "filename", "filearea")):
            return "path"

        if any(x in p for x in ("url", "redirect", "redirect_to", "returnurl", "next", "return", "source")) or v.startswith(
            ("http://", "https://", "//")
        ):
            return "redirect"

        if any(x in p for x in ("cmd", "action", "task", "option", "operation")):
            return "action"

        if any(x in p for x in ("token", "sesskey", "wstoken", "__requestdigest", "__viewstate")):
            return "token"

        return "generic"

    def generate_payloads(self, param: str, sample_value: str = "") -> List[Tuple[str, str]]:
        param_type = self.classify_param(param, sample_value)
        payloads: List[Tuple[str, str]] = []

        if param_type == "numeric":
            payloads += [
                ("numeric_boundary", "1"),
                ("numeric_boundary", "0"),
                ("numeric_boundary", "-1"),
                ("numeric_boundary", "999999"),
                ("sqli_probe", "1'"),
                ("sqli_probe", '1"'),
            ]

        elif param_type == "text":
            payloads += [
                ("text_canary", CANARY),
                ("xss_reflection_probe", f"<{CANARY}>"),
                ("xss_reflection_probe", f'"{CANARY}'),
                ("xss_reflection_probe", f"'{CANARY}"),
                ("sqli_probe", "'"),
            ]

        elif param_type == "path":
            payloads += [
                ("path_canary", CANARY),
                ("path_traversal_probe", f"../{CANARY}"),
                ("path_traversal_probe", f"../../{CANARY}"),
            ]

        elif param_type == "redirect":
            payloads += [
                ("redirect_probe", f"https://example.com/{CANARY}"),
                ("redirect_probe", f"//example.com/{CANARY}"),
            ]

        elif param_type == "token":
            payloads += [
                ("token_canary", CANARY),
                ("token_empty", ""),
                ("token_invalid", "invalid_token_value"),
            ]

        elif param_type == "action":
            payloads += [
                ("action_canary", CANARY),
                ("text_canary", "invalid_action"),
                ("sqli_probe", "'"),
            ]

        else:
            payloads += [
                ("generic_canary", CANARY),
                ("generic_bool", "true"),
                ("generic_number", "12345"),
                ("sqli_probe", "'"),
            ]

        self.generated_wordlist_info["parameter_strategy"][param] = param_type
        self.generated_wordlist_info["payload_strategy"][param] = [
            ptype for ptype, _ in payloads
        ]

        return payloads

    def generate_extension_paths(self, platform: str) -> List[str]:
        extensions = self.detected_stack.get("extensions") or []

        if not extensions:
            return []

        names = [
            "index",
            "login",
            "admin",
            "search",
            "upload",
            "api",
            "config",
            "backup",
            "readme",
        ]

        if platform == "moodle":
            names.extend([
                "course",
                "user",
                "pluginfile",
                "webservice",
                "lib",
                "theme",
            ])

        generated = [f"/{name}{ext}" for name in names for ext in extensions]
        self.generated_wordlist_info["server_extensions"] = extensions

        return generated

    def analyze_payload_response(
        self,
        param: str,
        payload_type: str,
        payload: str,
        r: requests.Response,
    ) -> Tuple[int, str, str, str]:
        content_type = r.headers.get("Content-Type", "")
        readable = any(x in content_type.lower() for x in ("text", "html", "json", "xml"))
        body_text = r.text[:120000] if readable else ""
        body_lower = body_text.lower()

        score = 0
        vuln_type = ""
        evidence = []

        if payload_type == "sqli_probe":
            if r.status_code >= 500:
                score += 12
                vuln_type = "Possible SQL Injection / input handling error"
                evidence.append("server returned 5xx after SQL-shaped canary")

            if SQL_ERROR_PATTERNS.search(body_lower):
                score += 22
                vuln_type = "Possible SQL Injection"
                evidence.append("SQL-like error keyword appeared in response")

        if payload_type == "xss_reflection_probe":
            if payload.lower() in body_lower:
                score += 18
                vuln_type = "Possible Reflected XSS"
                evidence.append("canary payload was reflected in response body")
            elif CANARY.lower() in body_lower:
                score += 8
                vuln_type = "Input Reflection"
                evidence.append("canary value was reflected but appears transformed or encoded")

        if payload_type == "path_traversal_probe":
            if r.status_code >= 500:
                score += 10
                vuln_type = "Possible Path Handling Issue"
                evidence.append("server returned 5xx after path-shaped canary")
            elif self.baseline and abs(len(r.content) - self.baseline[1]) > 1800:
                score += 6
                vuln_type = "Path Input Behavior Change"
                evidence.append("path-like input changed response size compared with baseline")

        if payload_type == "redirect_probe":
            location = r.headers.get("Location", "")
            if f"example.com/{CANARY}" in location:
                score += 22
                vuln_type = "Possible Open Redirect"
                evidence.append("external canary appeared in Location header")

        if payload_type.startswith("token_"):
            if r.status_code >= 500:
                score += 8
                vuln_type = "Possible Token/Input Handling Issue"
                evidence.append("server returned 5xx after token-shaped canary")

        if TEMPLATE_ERROR_PATTERNS.search(body_lower) and payload_type != "sqli_probe":
            score += 8
            vuln_type = vuln_type or "Verbose Error Disclosure / input handling error"
            evidence.append("debug/error keyword appeared in response")

        conclusion = ""
        if vuln_type:
            conclusion = f"Có dấu hiệu/nguy cơ: {vuln_type}"

        return score, vuln_type, conclusion, "; ".join(evidence)

    def load_paths(self, platform: str, limit_wordlist: int = 250) -> List[str]:
        profile = PROFILES[platform]
        paths = list(profile["paths"])

        for name in profile.get("wordlists", []):
            path = os.path.join(self.wordlist_dir, name)

            if not os.path.exists(path):
                continue

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()

                    if not s or s.startswith("#"):
                        continue

                    if not s.startswith("/"):
                        s = "/" + s

                    paths.append(s)

                    if len(paths) >= limit_wordlist + len(profile["paths"]):
                        break

        paths.extend(self.generate_extension_paths(platform))
        self.generated_wordlist_info["path_sources"] = list(profile.get("wordlists", []))

        paths = sorted(
            dict.fromkeys(paths),
            key=lambda p: (0 if SENSITIVE_NAME_PATTERNS.search(p) else 1, len(p)),
        )

        return paths

    def score_response(self, url: str, r: requests.Response) -> Tuple[int, str]:
        status = r.status_code
        length = len(r.content)
        content_type = r.headers.get("Content-Type", "")

        score = 0
        reasons = []

        if status in INTERESTING_STATUS:
            score += 10
            reasons.append(f"status={status}")

        if status in (401, 403):
            score += 8
            reasons.append("access-controlled endpoint")

        if status >= 500:
            score += 7
            reasons.append("server error / unusual behavior")

        if self.baseline:
            b_status, b_len, _ = self.baseline

            if status != b_status:
                score += 5
                reasons.append("different from 404 baseline")

            if abs(length - b_len) > 600:
                score += 3
                reasons.append("length delta")

        if SENSITIVE_NAME_PATTERNS.search(url):
            score += 4
            reasons.append("sensitive-looking path")

        if "json" in content_type.lower() or url.endswith(
            (".asmx", "/wp-json/", "/api/jsonws", "/_api/web/", "/webservice/rest/server.php")
        ):
            score += 4
            reasons.append("API-like endpoint")

        return score, "; ".join(reasons) or "low signal"

    def extract_title(self, html: str) -> str:
        try:
            soup = BeautifulSoup(html[:80000], "html.parser")
            if soup.title and soup.title.string:
                return " ".join(soup.title.string.split())[:120]
        except Exception:
            pass

        return ""

    def add_finding(
        self,
        platform: str,
        kind: str,
        url: str,
        method: str,
        r: requests.Response,
        reason: str,
        score: int,
        vulnerability_type: str = "Informational",
        conclusion: str = "",
        parameter: str = "",
        param_type: str = "",
        payload_type: str = "",
        payload: str = "",
        evidence: str = "",
    ) -> None:
        body_hash = hashlib.sha1(r.content[:200000]).hexdigest()

        finding = Finding(
            kind=kind,
            platform=platform,
            url=url,
            method=method,
            status=r.status_code,
            length=len(r.content),
            content_type=r.headers.get("Content-Type", ""),
            score=score,
            reason=reason,
            vulnerability_type=vulnerability_type,
            conclusion=conclusion,
            parameter=parameter,
            param_type=param_type,
            payload_type=payload_type,
            payload=payload,
            evidence=evidence,
            title=self.extract_title(
                r.text
                if "text" in r.headers.get("Content-Type", "").lower()
                or "html" in r.headers.get("Content-Type", "").lower()
                else ""
            ),
            sha1=body_hash,
        )

        with self.lock:
            self.findings.append(finding)

    def fuzz_paths(self, platform: str, paths: List[str]) -> None:
        q: "queue.Queue[str]" = queue.Queue()

        for p in paths:
            url = urljoin(self.base_url, p.lstrip("/"))

            if url not in self.seen_urls:
                self.seen_urls.add(url)
                q.put(url)

        def worker() -> None:
            while True:
                try:
                    url = q.get_nowait()
                except queue.Empty:
                    return

                r = self._safe_request("GET", url)

                if r:
                    score, reason = self.score_response(url, r)

                    if score >= 14:
                        self.add_finding(
                            platform,
                            "path",
                            url,
                            "GET",
                            r,
                            reason,
                            score,
                            vulnerability_type="Interesting path / response anomaly",
                            conclusion="Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server",
                            evidence=reason,
                        )

                    if r.status_code in (200, 401, 403) and url.endswith("/"):
                        for suffix in ("index.php", "index.html", "readme.txt"):
                            child = urljoin(url, suffix)

                            if child not in self.seen_urls and self._in_scope(child):
                                with self.lock:
                                    self.seen_urls.add(child)
                                q.put(child)

                q.task_done()

        threads = [
            threading.Thread(target=worker, daemon=True)
            for _ in range(self.threads)
        ]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

    def fuzz_params(self, platform: str) -> None:
        params = PROFILES[platform]["params"]
        candidate_bases = [self.base_url] + [
            f.url for f in sorted(self.findings, key=lambda x: -x.score)[:8]
        ]

        for base in candidate_bases:
            parsed = urlparse(base)
            existing = dict(parse_qsl(parsed.query, keep_blank_values=True))

            for param in params:
                sample_value = existing.get(param, "")
                param_type = self.classify_param(param, sample_value)

                for payload_type, value in self.generate_payloads(param, sample_value):
                    merged = existing.copy()
                    merged[param] = value

                    new_query = urlencode(merged, doseq=True)
                    url = urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path or "/",
                            parsed.params,
                            new_query,
                            parsed.fragment,
                        )
                    )

                    if url in self.seen_urls:
                        continue

                    self.seen_urls.add(url)
                    r = self._safe_request("GET", url)

                    if not r:
                        continue

                    score, reason = self.score_response(url, r)
                    payload_score, vuln_type, conclusion, evidence = self.analyze_payload_response(
                        param,
                        payload_type,
                        value,
                        r,
                    )

                    score += payload_score

                    if r.status_code >= 500:
                        reason += "; parameter canary triggered server error"
                        score += 8

                    elif self.baseline and abs(len(r.content) - self.baseline[1]) > 1200:
                        reason += "; parameter changed response shape"
                        score += 4

                    if evidence:
                        reason += "; " + evidence

                    if score >= 18 or payload_score >= 12:
                        self.add_finding(
                            platform,
                            "parameter",
                            url,
                            "GET",
                            r,
                            reason,
                            score,
                            vulnerability_type=vuln_type or "Parameter behavior anomaly",
                            conclusion=conclusion
                            or "Có dấu hiệu phản hồi bất thường khi fuzz parameter",
                            parameter=param,
                            param_type=param_type,
                            payload_type=payload_type,
                            payload=value,
                            evidence=evidence or reason,
                        )

    def run(self) -> Dict:
        started = datetime.now(timezone.utc).isoformat()

        self.fetch_baseline()
        platform, scores = self.fingerprint()

        paths = self.load_paths(platform)

        self.fuzz_paths(platform, paths)
        self.fuzz_params(platform)

        self.findings.sort(key=lambda f: (-f.score, f.status, f.url))

        return {
            "tool": BANNER,
            "target": self.base_url,
            "started_utc": started,
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "detected_platform": platform,
            "detected_cms": platform,
            "platform_type": get_platform_type(platform),
            "fingerprint_scores": scores,
            "detected_stack": self.detected_stack,
            "generated_wordlist_info": self.generated_wordlist_info,
            "requests_sent": self.request_count,
            "safety": {
                "authorization_required": True,
                "methods": ["GET"],
                "max_requests": self.max_requests,
                "delay_seconds": self.delay,
                "scope_host": self.base_host,
            },
            "findings": [asdict(f) for f in self.findings],
        }


def write_reports(result: Dict, out_prefix: str) -> Tuple[str, str]:
    os.makedirs(os.path.dirname(out_prefix) or ".", exist_ok=True)

    json_path = out_prefix + ".json"
    md_path = out_prefix + ".md"

    platform = result.get("detected_platform") or result.get("detected_cms", "unknown")
    platform_type = result.get("platform_type") or get_platform_type(platform)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Context Feedback Fuzzer Report\n\n")
        f.write(f"- Target: `{escape(result['target'])}`\n")
        f.write(f"- Detected Platform: **{escape(platform)}**\n")
        f.write(f"- Platform type: `{escape(platform_type)}`\n")
        f.write(f"- Requests sent: `{result['requests_sent']}`\n")
        f.write("- Safety: GET-only, same-host scope, rate-limited, authorization flag required.\n")

        stack = result.get("detected_stack", {})
        f.write(
            f"- Server technology hint: `{escape(str(stack.get('language', 'unknown')))}` / `{escape(str(stack.get('server', 'unknown')))}`\n\n"
        )

        f.write("## Wordlist generation mechanism\n\n")
        f.write(
            "Tool tạo wordlist theo 3 lớp: platform paths từ profile/wordlist, extension paths theo server technology, và payload values theo loại parameter.\n\n"
        )

        w = result.get("generated_wordlist_info", {})

        f.write(
            f"- Path wordlist sources: `{escape(', '.join(w.get('path_sources', [])) or 'profile defaults')}`\n"
        )
        f.write(
            f"- Server extension priority: `{escape(', '.join(w.get('server_extensions', [])) or 'none')}`\n"
        )

        f.write("- Parameter strategy examples:\n")

        for k, v in list(w.get("parameter_strategy", {}).items())[:20]:
            f.write(f"  - `{escape(k)}` => `{escape(v)}`\n")

        f.write("\n- Payload strategy examples:\n")

        for k, payloads in list(w.get("payload_strategy", {}).items())[:20]:
            payload_text = ", ".join(payloads)
            f.write(f"  - `{escape(k)}` => `{escape(payload_text)}`\n")

        f.write("\n## Fingerprint scores\n\n")

        for k, v in result["fingerprint_scores"].items():
            f.write(f"- {k}: {v}\n")

        f.write("\n## Findings\n\n")
        f.write(
            "Các finding dưới đây là giả thuyết nguy cơ bug dựa trên phản hồi server, không phải xác nhận khai thác thành công hay chấm severity.\n\n"
        )

        if not result["findings"]:
            f.write("Không phát hiện dấu hiệu bất thường đáng kể.\n")

        for i, item in enumerate(result["findings"], 1):
            vuln = item.get("vulnerability_type") or item["kind"]
            conclusion = item.get("conclusion") or f"Có dấu hiệu/nguy cơ: {vuln}"

            f.write(f"### {i}. {escape(vuln)}\n")
            f.write(f"- Kind: `{escape(item['kind'])}`\n")
            f.write(f"- Kết luận nguy cơ: {escape(conclusion)}\n")
            f.write(f"- URL: `{escape(item['url'])}`\n")

            if item.get("parameter"):
                f.write(
                    f"- Parameter: `{escape(item.get('parameter', ''))}` | Param type: `{escape(item.get('param_type', ''))}`\n"
                )
                f.write(
                    f"- Payload type: `{escape(item.get('payload_type', ''))}` | Payload: `{escape(item.get('payload', ''))}`\n"
                )

            f.write(
                f"- Response: HTTP `{item['status']}` / Length `{item['length']}` / Type `{escape(item['content_type'])}`\n"
            )

            if item.get("title"):
                f.write(f"- Title: {escape(item['title'])}\n")

            if item.get("evidence"):
                f.write(f"- Evidence: {escape(item['evidence'])}\n")

            f.write("- Why detected / Feedback analysis:\n")
            f.write(f"  - Response status: `{item['status']}`\n")
            f.write(f"  - Response length: `{item['length']}`\n")
            f.write(f"  - Content-Type: `{escape(item['content_type'])}`\n")
            f.write(f"  - Reason: {escape(item['reason'])}\n\n")


    return json_path, md_path


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=BANNER)

    p.add_argument(
        "--target",
        required=True,
        help="Authorized target base URL, e.g. http://127.0.0.1:8080",
    )
    p.add_argument(
        "--cms",
        default="auto",
        choices=["auto"] + sorted(PROFILES),
        help="Platform hint or auto fingerprint",
    )
    p.add_argument(
        "--wordlist-dir",
        default=os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists"),
    )
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--delay", type=float, default=0.15)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--max-requests", type=int, default=400)
    p.add_argument("--out", default=None)
    p.add_argument("--i-have-authorization", action="store_true")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)

    if not args.i_have_authorization:
        print(
            "Refusing to run: add --i-have-authorization for systems you own or are explicitly allowed to test.",
            file=sys.stderr,
        )
        return 2

    fuzzer = ContextFeedbackFuzzer(
        base_url=args.target,
        wordlist_dir=args.wordlist_dir,
        cms_hint=args.cms,
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        max_requests=args.max_requests,
    )

    result = fuzzer.run()

    platform = result.get("detected_platform") or result["detected_cms"]
    host = urlparse(result["target"]).netloc.replace(":", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    out_prefix = args.out or f"reports/{platform}_{host}_{ts}"

    json_path, md_path = write_reports(result, out_prefix)

    print(
        json.dumps(
            {
                "detected_platform": platform,
                "platform_type": result.get("platform_type", get_platform_type(platform)),
                "requests_sent": result["requests_sent"],
                "findings": len(result["findings"]),
                "json": json_path,
                "markdown": md_path,
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())