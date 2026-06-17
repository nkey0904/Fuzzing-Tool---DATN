#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from html import escape
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, urlunparse, parse_qsl

import requests
from bs4 import BeautifulSoup

# --- THƯ VIỆN SELENIUM DÙNG ĐỂ TRIGGER XSS ---
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from .profiles import PROFILES

BANNER = "Context Feedback Fuzzer v2.1 - Hybrid Fuzzer (Static + Selenium) - authorized testing only"

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
    marker: str = ""
    marker_reflected: bool = False
    marker_hits: List[Dict] = None
    confirmation: str = "possible"
    confirmation_reason: str = ""
    verification_pages: List[Dict] = None
    confirmation_level: str = "possible"
    confidence: int = 0
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
        user_agent: str = "ContextFeedbackFuzzer/2.1 marker-verification authorized-lab",
        progress_callback: Optional[Callable[[dict], None]] = None,
        control_callback: Optional[Callable[[], dict]] = None,
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
        self.progress_callback = progress_callback
        self.control_callback = control_callback

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/json,*/*;q=0.8",
                "Cookie": "security=low; PHPSESSID=c18a1b0c2650cd1126ca085243a9424d"
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
            "marker_based_fuzzing": {
                "enabled": True,
                "description": "Each payload is tagged with a unique marker, then a verification engine re-checks collected pages for marker reflection.",
                "markers_generated": 0,
                "markers_verified": 0,
                "confirmed_markers": [],
                "verification_pages": [],
            },
        }

        self.marker_registry: Dict[str, Dict] = {}
        self.confirmed_markers: List[Dict] = []
        self.marker_verified_count = 0
        self.marker_failed_count = 0
        self.marker_verification_rate = 0.0
        self.crawled_links_count = 0
        self.confirmed_findings_count = 0
        self.possible_findings_count = 0
        self.confirmation_rate = 0.0
        self.verification_pages: List[Dict] = []

    # --- HÀM SELENIUM VERIFICATION ENGINE ---
    def verify_xss_with_selenium(self, url_with_payload: str, marker: str) -> bool:
        """Mở trình duyệt ẩn, nạp cookie và kiểm tra xem JS có thực thi không"""
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        
        try:
            driver = webdriver.Chrome(options=options)
        except Exception as e:
            print(f"[!] Không thể khởi tạo Selenium: {e}")
            return False

        try:
            # Truy cập domain trước để set Cookie
            driver.get(self.base_url)
            
            # Đồng bộ Cookie từ requests sang Selenium
            cookie_header = self.session.headers.get("Cookie", "")
            if cookie_header:
                for cookie_str in cookie_header.split(";"):
                    if "=" in cookie_str:
                        k, v = cookie_str.strip().split("=", 1)
                        driver.add_cookie({"name": k, "value": v})
            
            # Truy cập URL chứa payload
            driver.get(url_with_payload)
            
            # Đợi tối đa 3 giây xem có hộp thoại Alert xuất hiện không
            WebDriverWait(driver, 3).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            
            # Bắt Alert và đối chiếu Marker
            is_success = marker in alert.text
            alert.accept()
            return is_success
            
        except TimeoutException:
            return False
        except Exception:
            return False
        finally:
            try:
                driver.quit()
            except:
                pass

    @staticmethod
    def _normalize_base(url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/") + "/"

    def emit_progress(self, step: int, progress: int, message: str, extra: Optional[dict] = None) -> None:
        if not self.progress_callback:
            return
        self.progress_callback({
            "step": step,
            "progress": max(0, min(progress, 100)),
            "message": message,
            "extra": extra or {},
            "requests_sent": self.request_count,
            "findings_count": len(self.findings),
        })

    def check_control(self) -> bool:
        if not self.control_callback:
            return True
        while True:
            state = self.control_callback() or {}
            if state.get("stopped"):
                return False
            if state.get("paused"):
                self.emit_progress(0, state.get("progress", 0), "Scan đang tạm dừng. Bấm Resume để tiếp tục.", {"phase": "paused"})
                time.sleep(0.5)
                continue
            return True

    def _in_scope(self, url: str) -> bool:
        return urlparse(url).netloc.lower() == self.base_host

    def _safe_request(self, method: str, url: str) -> Optional[requests.Response]:
        if not self.check_control():
            return None
        if not self._in_scope(url):
            raise ScopeError(f"Out of scope URL blocked: {url}")

        with self.lock:
            if self.request_count >= self.max_requests:
                return None
            self.request_count += 1

        time.sleep(self.delay)
        try:
            return self.session.request(method, url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

    def fetch_baseline(self) -> None:
        noise = "cff-baseline-" + hashlib.sha1(str(time.time()).encode()).hexdigest()[:10]
        url = urljoin(self.base_url, noise)
        r = self._safe_request("GET", url)

        if r is None:
            self.baseline = (0, 0, "")
        else:
            self.baseline = (r.status_code, len(r.content), r.headers.get("Content-Type", ""))

        self.emit_progress(1, 10, "Baseline response đã được tạo", {"phase": "baseline"})

    def fingerprint(self) -> Tuple[str, Dict[str, int]]:
        scores = {name: 0 for name in PROFILES}
        urls = [self.base_url]

        for profile in PROFILES.values():
            for p in profile["signals"].get("probe_paths", [])[:2]:
                urls.append(urljoin(self.base_url, p.lstrip("/")))

        unique_urls = list(dict.fromkeys(urls))
        total = max(1, len(unique_urls))

        for index, url in enumerate(unique_urls, 1):
            if not self.check_control():
                break

            self.emit_progress(2, 10 + int((index / total) * 15), f"Fingerprint platform: {index}/{total}", {"phase": "fingerprint"})
            r = self._safe_request("GET", url)
            if not r:
                continue

            self.infer_stack_from_response(r)
            header_blob = "\n".join(f"{k.lower()}: {v.lower()}" for k, v in r.headers.items())
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
                if r.status_code in (200, 401, 403) and any(url.endswith(p) for p in sig.get("probe_paths", [])):
                    scores[platform] += 1

        if self.platform_hint != "auto" and self.platform_hint in PROFILES:
            scores[self.platform_hint] += 100

        best = max(scores, key=scores.get)
        self.emit_progress(2, 25, f"Fingerprint hoàn tất: {best}", {"phase": "fingerprint_done", "detected_platform": best})
        return best, scores

    def infer_stack_from_response(self, r: requests.Response) -> None:
        header_blob = "\n".join(f"{k.lower()}: {v.lower()}" for k, v in r.headers.items())
        cookie_blob = ";".join(r.cookies.keys()).lower()
        body = r.text[:50000].lower() if r.text else ""
        blob = "\n".join([header_blob, cookie_blob, body])

        language = self.detected_stack.get("language", "unknown")
        server = self.detected_stack.get("server", "unknown")

        if any(x in blob for x in ("php", "wordpress", "joomla", "drupal", "moodle", "moodlesession")):
            language = "php"
        elif any(x in blob for x in ("jsessionid", "java", "apache-coyote", "liferay")):
            language = "java"
        elif any(x in blob for x in ("asp.net", "microsoft-iis", "sharepoint")):
            language = "aspnet"

        if "nginx" in blob:
            server = "nginx"
        elif "apache" in blob:
            server = "apache"
        elif "microsoft-iis" in blob:
            server = "iis"
        elif "apache-coyote" in blob:
            server = "apache-coyote"

        self.detected_stack = {"language": language, "server": server, "extensions": SERVER_EXTENSION_HINTS.get(language, [])}

    def make_marker(self, param: str, payload_type: str) -> str:
        safe_param = re.sub(r"[^a-zA-Z0-9_]+", "_", param or "param")[:28]
        safe_type = re.sub(r"[^a-zA-Z0-9_]+", "_", payload_type or "payload")[:32]
        token = secrets.token_hex(5)
        return f"cff_marker_{safe_param}_{safe_type}_{token}"

    def apply_marker_to_payload(self, value: str, marker: str, payload_type: str) -> str:
        value = "" if value is None else str(value)
        if CANARY in value:
            return value.replace(CANARY, marker)
        if value == "":
            return marker
        if payload_type in {"numeric_boundary", "generic_number", "sqli_probe"}:
            return f"{value}_{marker}"
        return f"{value}_{marker}"

    def response_is_readable(self, r: requests.Response) -> bool:
        content_type = r.headers.get("Content-Type", "").lower()
        return any(x in content_type for x in ("text", "html", "json", "xml", "javascript"))

    # --- HÀM KIỂM TRA MARKER NGHIÊM NGẶT ---
    def check_marker_reflection(self, marker: str, r: requests.Response, payload_type: str = "") -> bool:
        if not marker or not r or not self.response_is_readable(r):
            return False

        try:
            body = r.text[:200000].lower()
            marker_lower = marker.lower()
            
            # Chỉ bắt khi payload có chứa dấu ngoặc hoặc thẻ HTML còn sống sót
            if payload_type == "xss_reflection_probe":
                if f"<{marker_lower}>" in body or f'"{marker_lower}' in body or f"'{marker_lower}" in body:
                    return True
                return False 
            
            elif payload_type == "xss_trigger_probe":
                if marker_lower in body and ("<script" in body or "<img" in body):
                    return True
                return False

            return marker_lower in body
        except Exception:
            return False

    def extract_links_from_response(self, r: requests.Response, base_url: str, limit: int = 80) -> List[str]:
        links: List[str] = []
        if not r or not self.response_is_readable(r):
            return links
        content_type = r.headers.get("Content-Type", "").lower()
        if "html" not in content_type and "text" not in content_type:
            return links
        try:
            soup = BeautifulSoup(r.text[:200000], "html.parser")
        except Exception:
            return links
        for tag in soup.find_all(["a", "link", "script", "iframe", "form"]):
            raw = tag.get("href") or tag.get("src") or tag.get("action")
            if not raw: continue
            raw = raw.strip()
            if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:")): continue
            absolute = urljoin(base_url, raw).split("#", 1)[0]
            if not self._in_scope(absolute): continue
            if absolute not in links: links.append(absolute)
            if len(links) >= limit: break
        return links

    def crawl_internal_links_for_verification(self, seed_urls: List[str], max_pages: int = 80, per_page_limit: int = 30) -> List[str]:
        collected: List[str] = []
        queued: List[str] = []

        def add(url: str) -> None:
            if not url: return
            normalized = url.split("#", 1)[0]
            if self._in_scope(normalized) and normalized not in collected and normalized not in queued:
                queued.append(normalized)

        for seed in seed_urls: add(seed)

        while queued and len(collected) < max_pages:
            if not self.check_control(): break
            url = queued.pop(0)
            if url in collected: continue
            collected.append(url)
            r = self._safe_request("GET", url)
            if not r: continue
            for link in self.extract_links_from_response(r, url, limit=per_page_limit):
                if len(collected) + len(queued) >= max_pages: break
                add(link)
        self.crawled_links_count = len(collected)
        return collected

    def verify_marker_across_known_pages(self, marker: str, source_url: str, limit: int = 20) -> List[Dict]:
        hits: List[Dict] = []
        known_urls = []
        for url in list(self.seen_urls):
            if url != source_url and self._in_scope(url):
                known_urls.append(url)
            if len(known_urls) >= limit: break

        for url in known_urls:
            if not self.check_control(): break
            r = self._safe_request("GET", url)
            if not r: continue
            if self.check_marker_reflection(marker, r):
                hits.append({"url": url, "status": r.status_code, "length": len(r.content), "source_url": source_url, "source": "known_page_recheck"})
        return hits

    def collect_marker_verification_pages(self, platform: str, limit: int = 80) -> List[str]:
        seed_candidates: List[str] = []

        def add_seed(url: str) -> None:
            if not url: return
            normalized = urljoin(self.base_url, url.lstrip("/")) if url.startswith("/") else url
            normalized = normalized.split("#", 1)[0]
            if self._in_scope(normalized) and normalized not in seed_candidates:
                seed_candidates.append(normalized)

        add_seed(self.base_url)
        for finding in sorted(self.findings, key=lambda f: -f.score):
            add_seed(finding.url)
            if len(seed_candidates) >= limit // 2: break
        for url in list(self.seen_urls):
            add_seed(url)
            if len(seed_candidates) >= limit: break
        profile = PROFILES.get(platform, {})
        for path in profile.get("paths", [])[:30]:
            add_seed(urljoin(self.base_url, path.lstrip("/")))
            if len(seed_candidates) >= limit: break

        crawled = self.crawl_internal_links_for_verification(seed_candidates[:limit], max_pages=limit, per_page_limit=25)
        candidates: List[str] = []
        for url in seed_candidates + crawled:
            if self._in_scope(url) and url not in candidates:
                candidates.append(url)
            if len(candidates) >= limit: break

        self.verification_pages = [{"url": url, "source": "marker_verification_candidate"} for url in candidates]
        self.generated_wordlist_info["marker_based_fuzzing"]["verification_pages"] = self.verification_pages
        return candidates

    def classify_confirmation(self, marker_reflected: bool, marker_hits: Optional[List[Dict]] = None, vulnerability_type: str = "", score: int = 0) -> Tuple[str, str, str, int]:
        marker_hits = marker_hits or []
        verification_hits = [h for h in marker_hits if h.get("source") in {"known_page_recheck", "verification_engine"}]
        immediate_hits = [h for h in marker_hits if h.get("source") == "immediate_response"]
        vt = (vulnerability_type or "").lower()

        if verification_hits:
            confidence = 95 if len(verification_hits) == 1 else 100
            return ("confirmed", "confirmed", f"Marker xuất hiện lại trên {len(verification_hits)} trang xác minh.", confidence)

        if marker_reflected or immediate_hits or "marker-based" in vt or "javascript executed" in vt:
            return ("confirmed", "verified_reflection", "Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.", 85)

        confidence = 45
        if score >= 35: confidence = 70
        elif score >= 25: confidence = 60
        elif score >= 18: confidence = 50

        return ("possible", "possible", "Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.", confidence)

    def verify_marker_engine(self, platform: str, max_markers: int = 100, max_pages: int = 80) -> None:
        markers = list(self.marker_registry.items())[:max_markers]
        pages = self.collect_marker_verification_pages(platform, limit=max_pages)
        total = max(1, len(markers))

        if not markers or not pages:
            self.update_confirmation_stats()
            return

        for idx, (marker, meta) in enumerate(markers, 1):
            if not self.check_control(): break

            hits: List[Dict] = []
            source_url = meta.get("source_url") or meta.get("base_url") or ""

            for url in pages:
                if not self.check_control(): break
                if url == source_url: continue
                r = self._safe_request("GET", url)
                if not r: continue
                
                # Gọi check marker nhớ truyền payload_type
                if self.check_marker_reflection(marker, r, meta.get("payload_type", "")):
                    hits.append({"url": url, "status": r.status_code, "length": len(r.content), "source_url": source_url, "source": "verification_engine"})

            if hits:
                self.marker_registry[marker]["verified"] = True
                self.marker_registry[marker]["verification_hits"] = hits
                self.marker_verified_count += 1
                confirmed = {
                    "marker": marker, "param": meta.get("param", ""), "param_type": meta.get("param_type", ""),
                    "payload_type": meta.get("payload_type", ""), "payload": meta.get("payload", ""),
                    "source_url": source_url, "hits": hits, "confirmation": "confirmed", "confirmation_level": "confirmed",
                    "confidence": 95 if len(hits) == 1 else 100, "confirmation_reason": f"Marker được xác minh trên {len(hits)} trang bởi verification engine."
                }
                if not any(x.get("marker") == marker for x in self.confirmed_markers):
                    self.confirmed_markers.append(confirmed)
                    self.generated_wordlist_info["marker_based_fuzzing"]["confirmed_markers"].append(confirmed)

                for finding in self.findings:
                    if finding.marker == marker:
                        finding.marker_hits = list(finding.marker_hits or []) + hits
                        finding.marker_reflected = True
                        finding.confirmation = "confirmed"
                        finding.confirmation_level = "confirmed"
                        finding.confidence = confirmed["confidence"]
                        finding.confirmation_reason = confirmed["confirmation_reason"]
                        finding.verification_pages = hits
                        if "Marker verification confirmed" not in finding.reason: finding.reason += f"; Marker verification confirmed on {len(hits)} page(s)"
                        if "marker verified" not in (finding.evidence or "").lower(): finding.evidence = (finding.evidence + "; " if finding.evidence else "") + f"marker verified on {len(hits)} page(s)"

            self.emit_progress(6, min(95, 88 + int((idx / total) * 7)), f"Marker verification: {idx}/{total}", {"phase": "marker_verification", "markers_generated": len(self.marker_registry), "markers_verified": self.marker_verified_count})
        self.update_confirmation_stats()

    def update_confirmation_stats(self) -> None:
        confirmed = possible = 0
        for finding in self.findings:
            if finding.confirmation != "confirmed":
                status, level, reason, confidence = self.classify_confirmation(finding.marker_reflected, finding.marker_hits, finding.vulnerability_type, finding.score)
                finding.confirmation = status
                finding.confirmation_level = level
                finding.confidence = confidence
                if not finding.confirmation_reason: finding.confirmation_reason = reason
            else:
                finding.confirmation_level = finding.confirmation_level or "confirmed"
                finding.confidence = max(finding.confidence or 0, 95)
            if finding.verification_pages is None: finding.verification_pages = finding.marker_hits or []
            if finding.confirmation == "confirmed": confirmed += 1
            else: possible += 1

        total = confirmed + possible
        self.confirmed_findings_count = confirmed
        self.possible_findings_count = possible
        self.confirmation_rate = round((confirmed / total) * 100, 2) if total else 0.0
        self.marker_failed_count = max(0, len(self.marker_registry) - self.marker_verified_count)
        self.marker_verification_rate = round((self.marker_verified_count / max(1, len(self.marker_registry))) * 100, 2)

        mb = self.generated_wordlist_info["marker_based_fuzzing"]
        mb["markers_generated"] = len(self.marker_registry)
        mb["markers_verified"] = self.marker_verified_count
        mb["markers_failed"] = self.marker_failed_count
        mb["marker_verification_rate"] = self.marker_verification_rate
        mb["crawled_links_count"] = self.crawled_links_count

    def classify_param(self, param: str, sample_value: str = "") -> str:
        p = param.lower()
        v = str(sample_value or "").lower()

        if re.search(r"(^|_)(id|uid|userid|user|course|courseid|post|page|cat|item|itemid|node|list|view|contextid|section)(_|$)", p) or p in {"p", "id", "page_id", "cat", "author", "itemid", "userid", "courseid", "contextid"}:
            return "numeric"
        if p in {"q", "s", "search", "searchword", "keyword", "query", "name", "title", "comment", "message", "log", "username", "wsfunction", "moodlewsrestformat", "component"}:
            return "text"
        if any(x in p for x in ("file", "path", "folder", "template", "module", "view", "layout", "destination", "filepath", "filename", "filearea")):
            return "path"
        if any(x in p for x in ("url", "redirect", "redirect_to", "returnurl", "next", "return", "source")) or v.startswith(("http://", "https://", "//")):
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
            payloads += [("numeric_boundary", "1"), ("numeric_boundary", "0"), ("numeric_boundary", "-1"), ("numeric_boundary", "999999"), ("sqli_probe", "1'"), ("sqli_probe", '1"')]
        elif param_type == "text":
            payloads += [
                ("text_canary", CANARY),
                ("xss_reflection_probe", f"<{CANARY}>"),
                # -- BỔ SUNG CÁC PAYLOAD TRIGGER ĐỂ SELENIUM BẮT --
                ("xss_trigger_probe", f"<script>alert('{CANARY}')</script>"),
                ("xss_trigger_probe", f"<img src=x onerror=alert('{CANARY}')>"),
                ("sqli_probe", "'"),
            ]
        elif param_type == "path":
            payloads += [("path_canary", CANARY), ("path_traversal_probe", f"../{CANARY}"), ("path_traversal_probe", f"../../{CANARY}")]
        elif param_type == "redirect":
            payloads += [("redirect_probe", f"https://example.com/{CANARY}"), ("redirect_probe", f"//example.com/{CANARY}")]
        elif param_type == "token":
            payloads += [("token_canary", CANARY), ("token_empty", ""), ("token_invalid", "invalid_token_value")]
        elif param_type == "action":
            payloads += [("action_canary", CANARY), ("text_canary", "invalid_action"), ("sqli_probe", "'")]
        else:
            payloads += [("generic_canary", CANARY), ("generic_bool", "true"), ("generic_number", "12345"), ("sqli_probe", "'")]

        self.generated_wordlist_info["parameter_strategy"][param] = param_type
        self.generated_wordlist_info["payload_strategy"][param] = [ptype for ptype, _ in payloads]
        return payloads

    def generate_extension_paths(self, platform: str) -> List[str]:
        extensions = self.detected_stack.get("extensions") or []
        if not extensions: return []
        names = ["index", "login", "admin", "search", "upload", "api", "config", "backup", "readme"]
        if platform == "moodle": names.extend(["course", "user", "pluginfile", "webservice", "lib", "theme"])
        generated = [f"/{name}{ext}" for name in names for ext in extensions]
        self.generated_wordlist_info["server_extensions"] = extensions
        return generated

    def analyze_payload_response(
        self, param: str, payload_type: str, payload: str, r: requests.Response, marker: str = "", marker_reflected: bool = False, marker_hits: Optional[List[Dict]] = None,
    ) -> Tuple[int, str, str, str]:
        content_type = r.headers.get("Content-Type", "")
        readable = any(x in content_type.lower() for x in ("text", "html", "json", "xml"))
        body_text = r.text[:120000] if readable else ""
        body_lower = body_text.lower()
        score, vuln_type, evidence = 0, "", []

        if payload_type == "sqli_probe":
            if r.status_code >= 500:
                score += 12; vuln_type = "Possible SQL Injection / input handling error"; evidence.append("server returned 5xx after SQL-shaped canary")
            if SQL_ERROR_PATTERNS.search(body_lower):
                score += 22; vuln_type = "Possible SQL Injection"; evidence.append("SQL-like error keyword appeared in response")

        # --- LOGIC MỚI CHO XSS KẾT HỢP SELENIUM ---
        if payload_type in {"xss_reflection_probe", "xss_trigger_probe"}:
            if marker_reflected:
                score += 15
                vuln_type = "Unescaped Payload Reflection"
                evidence.append("Dangerous characters (<, \") survived encoding.")
                
                # Chuyển qua Bước 2: Verification bằng Selenium
                if payload_type == "xss_trigger_probe":
                    target_url = r.url
                    is_executed = self.verify_xss_with_selenium(target_url, marker)
                    
                    if is_executed:
                        score += 35
                        vuln_type = "Confirmed XSS (JavaScript Executed)"
                        evidence.append("SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!")
                    else:
                        vuln_type = "Unescaped Reflection (Blocked by Browser/CSP)"
                        evidence.append("Selenium tried to execute JS but no alert appeared.")

        if payload_type == "path_traversal_probe":
            if r.status_code >= 500:
                score += 10; vuln_type = "Possible Path Handling Issue"; evidence.append("server returned 5xx after path-shaped canary")
            elif self.baseline and abs(len(r.content) - self.baseline[1]) > 1800:
                score += 6; vuln_type = "Path Input Behavior Change"; evidence.append("path-like input changed response size compared with baseline")

        if payload_type == "redirect_probe":
            location = r.headers.get("Location", "")
            if (marker and marker in location) or (f"example.com/{CANARY}" in location):
                score += 22; vuln_type = "Possible Open Redirect"; evidence.append("unique marker appeared in Location header")

        if payload_type.startswith("token_"):
            if r.status_code >= 500:
                score += 8; vuln_type = "Possible Token/Input Handling Issue"; evidence.append("server returned 5xx after token-shaped canary")

        if TEMPLATE_ERROR_PATTERNS.search(body_lower) and payload_type != "sqli_probe":
            score += 8; vuln_type = vuln_type or "Verbose Error Disclosure / input handling error"; evidence.append("debug/error keyword appeared in response")

        marker_hits = marker_hits or []
        if marker_reflected and payload_type not in {"xss_reflection_probe", "xss_trigger_probe"}:
            score += 25
            vuln_type = vuln_type or "Marker-based Input Reflection"
            evidence.append(f"unique marker reflected: {marker}")

        cross_page_hits = [h for h in marker_hits if h.get("source") in {"known_page_recheck", "verification_engine"}]
        if cross_page_hits:
            score += 15
            vuln_type = "Marker-based Stored Reflection"
            evidence.append(f"marker appeared on {len(cross_page_hits)} known page(s)")

        conclusion = f"Có dấu hiệu/nguy cơ: {vuln_type}" if vuln_type else ""
        return score, vuln_type, conclusion, "; ".join(evidence)

    def load_paths(self, platform: str, limit_wordlist: int = 250) -> List[str]:
        profile = PROFILES[platform]
        paths = list(profile["paths"])
        for name in profile.get("wordlists", []):
            path = os.path.join(self.wordlist_dir, name)
            if not os.path.exists(path): continue
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"): continue
                    if not s.startswith("/"): s = "/" + s
                    paths.append(s)
                    if len(paths) >= limit_wordlist + len(profile["paths"]): break
        paths.extend(self.generate_extension_paths(platform))
        self.generated_wordlist_info["path_sources"] = list(profile.get("wordlists", []))
        paths = sorted(dict.fromkeys(paths), key=lambda p: (0 if SENSITIVE_NAME_PATTERNS.search(p) else 1, len(p)))
        self.emit_progress(3, 35, f"Đã tạo {len(paths)} path theo ngữ cảnh platform", {"phase": "wordlist_generation", "paths_count": len(paths), "path_sources": self.generated_wordlist_info["path_sources"], "server_extensions": self.generated_wordlist_info["server_extensions"], "params_count": len(profile.get("params", [])), "params_preview": profile.get("params", [])[:20]})
        return paths

    def score_response(self, url: str, r: requests.Response) -> Tuple[int, str]:
        status, length, content_type = r.status_code, len(r.content), r.headers.get("Content-Type", "")
        score, reasons = 0, []
        if status in INTERESTING_STATUS: score += 10; reasons.append(f"status={status}")
        if status in (401, 403): score += 8; reasons.append("access-controlled endpoint")
        if status >= 500: score += 7; reasons.append("server error / unusual behavior")
        if self.baseline:
            b_status, b_len, _ = self.baseline
            if status != b_status: score += 5; reasons.append("different from 404 baseline")
            if abs(length - b_len) > 600: score += 3; reasons.append("length delta")
        if SENSITIVE_NAME_PATTERNS.search(url): score += 4; reasons.append("sensitive-looking path")
        if "json" in content_type.lower() or url.endswith((".asmx", "/wp-json/", "/api/jsonws", "/_api/web/", "/webservice/rest/server.php")): score += 4; reasons.append("API-like endpoint")
        return score, "; ".join(reasons) or "low signal"

    def extract_title(self, html: str) -> str:
        try:
            soup = BeautifulSoup(html[:80000], "html.parser")
            if soup.title and soup.title.string: return " ".join(soup.title.string.split())[:120]
        except Exception: pass
        return ""

    def add_finding(self, platform: str, kind: str, url: str, method: str, r: requests.Response, reason: str, score: int, vulnerability_type: str = "Informational", conclusion: str = "", parameter: str = "", param_type: str = "", payload_type: str = "", payload: str = "", evidence: str = "", marker: str = "", marker_reflected: bool = False, marker_hits: Optional[List[Dict]] = None, confirmation: str = "possible", confirmation_reason: str = "", verification_pages: Optional[List[Dict]] = None, confirmation_level: str = "possible", confidence: int = 0) -> None:
        body_hash = hashlib.sha1(r.content[:200000]).hexdigest()
        finding = Finding(kind=kind, platform=platform, url=url, method=method, status=r.status_code, length=len(r.content), content_type=r.headers.get("Content-Type", ""), score=score, reason=reason, vulnerability_type=vulnerability_type, conclusion=conclusion, parameter=parameter, param_type=param_type, payload_type=payload_type, payload=payload, evidence=evidence, marker=marker, marker_reflected=marker_reflected, marker_hits=marker_hits or [], confirmation=confirmation, confirmation_reason=confirmation_reason, verification_pages=verification_pages or marker_hits or [], confirmation_level=confirmation_level, confidence=confidence, title=self.extract_title(r.text if "text" in r.headers.get("Content-Type", "").lower() or "html" in r.headers.get("Content-Type", "").lower() else ""), sha1=body_hash)
        with self.lock: self.findings.append(finding)
        self.emit_progress(5, 85, f"Phát hiện finding mới: {vulnerability_type}", {"phase": "finding_detected", "finding": asdict(finding), "findings_count": len(self.findings)})

    def fuzz_paths(self, platform: str, paths: List[str]) -> None:
        q: "queue.Queue[str]" = queue.Queue()
        for p in paths:
            url = urljoin(self.base_url, p.lstrip("/"))
            if url not in self.seen_urls:
                self.seen_urls.add(url)
                q.put(url)
        total = q.qsize()
        done_counter = {"count": 0}
        counter_lock = threading.Lock()

        def worker() -> None:
            while True:
                if not self.check_control(): return
                try: url = q.get_nowait()
                except queue.Empty: return
                r = self._safe_request("GET", url)
                with counter_lock:
                    done_counter["count"] += 1
                    current = done_counter["count"]
                self.emit_progress(4, min(70, 40 + int((current / max(1, total)) * 30)), f"Đang fuzz path: {current}/{total}", {"phase": "path_fuzzing", "current_url": url, "current": current, "total": total, "requests_sent": self.request_count, "findings_count": len(self.findings)})
                if r:
                    score, reason = self.score_response(url, r)
                    if score >= 14: self.add_finding(platform, "path", url, "GET", r, reason, score, vulnerability_type="Interesting path / response anomaly", conclusion="Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server", evidence=reason, confirmation="possible", confirmation_reason="Finding dựa trên response anomaly, chưa có marker xác nhận.")
                    if r.status_code in (200, 401, 403) and url.endswith("/"):
                        for suffix in ("index.php", "index.html", "readme.txt"):
                            child = urljoin(url, suffix)
                            if child not in self.seen_urls and self._in_scope(child):
                                with self.lock: self.seen_urls.add(child)
                                q.put(child)
                q.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(self.threads)]
        for t in threads: t.start()
        for t in threads: t.join()

    def fuzz_params(self, platform: str) -> None:
        # BỔ SUNG: Khởi tạo base_params và lấy thêm tham số từ URL người dùng
        base_params = list(PROFILES[platform]["params"])
        candidate_bases = [self.base_url] + [f.url for f in sorted(self.findings, key=lambda x: -x.score)[:8]]

        for base in candidate_bases:
            parsed = urlparse(base)
            for k, _ in parse_qsl(parsed.query, keep_blank_values=True):
                if k not in base_params:
                    base_params.append(k)

        total = max(1, len(candidate_bases) * len(base_params))
        current = 0

        for base in candidate_bases:
            if not self.check_control(): return
            parsed = urlparse(base)
            existing = dict(parse_qsl(parsed.query, keep_blank_values=True))

            for param in base_params:
                if not self.check_control(): return
                current += 1
                sample_value = existing.get(param, "")
                param_type = self.classify_param(param, sample_value)

                for payload_type, value in self.generate_payloads(param, sample_value):
                    if not self.check_control(): return
                    marker = self.make_marker(param, payload_type)
                    value = self.apply_marker_to_payload(value, marker, payload_type)
                    self.marker_registry[marker] = {"param": param, "param_type": param_type, "payload_type": payload_type, "payload": value, "base_url": base}

                    merged = existing.copy()
                    merged[param] = value
                    new_query = urlencode(merged, doseq=True)
                    url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))
                    self.marker_registry[marker]["source_url"] = url

                    if url in self.seen_urls: continue
                    self.seen_urls.add(url)
                    r = self._safe_request("GET", url)

                    marker_reflected = False
                    marker_hits: List[Dict] = []

                    if r:
                        # Truyền payload_type để check nghiêm ngặt
                        marker_reflected = self.check_marker_reflection(marker, r, payload_type)

                        if marker_reflected:
                            marker_hits.append({"url": url, "status": r.status_code, "length": len(r.content), "source": "immediate_response"})
                            marker_hits.extend(self.verify_marker_across_known_pages(marker, url))

                            confirmed = {"marker": marker, "param": param, "param_type": param_type, "payload_type": payload_type, "payload": value, "source_url": url, "hits": marker_hits}
                            self.confirmed_markers.append(confirmed)
                            self.generated_wordlist_info["marker_based_fuzzing"]["confirmed_markers"].append(confirmed)

                    self.emit_progress(5, min(88, 70 + int((current / total) * 18)), f"Đang fuzz parameter: {param}", {"phase": "parameter_fuzzing", "current_url": url, "current_param": param, "param_type": param_type, "payload_type": payload_type, "marker": marker, "marker_reflected": marker_reflected, "marker_hits": marker_hits, "current": current, "total": total, "requests_sent": self.request_count, "findings_count": len(self.findings)})

                    if not r: continue

                    score, reason = self.score_response(url, r)
                    payload_score, vuln_type, conclusion, evidence = self.analyze_payload_response(param, payload_type, value, r, marker=marker, marker_reflected=marker_reflected, marker_hits=marker_hits)
                    score += payload_score

                    if r.status_code >= 500:
                        reason += "; parameter canary triggered server error"
                        score += 8
                    elif self.baseline and abs(len(r.content) - self.baseline[1]) > 1200:
                        reason += "; parameter changed response shape"
                        score += 4

                    if marker_reflected: reason += f"; marker reflected: {marker}"
                    if marker_hits: reason += f"; marker hits: {len(marker_hits)}"
                    if evidence: reason += "; " + evidence

                    if score >= 18 or payload_score >= 12 or marker_reflected:
                        final_vuln_type = vuln_type or "Parameter behavior anomaly"
                        confirmation, confirmation_level, confirmation_reason, confidence = self.classify_confirmation(marker_reflected, marker_hits, final_vuln_type, score)
                        self.add_finding(platform, "parameter", url, "GET", r, reason, score, vulnerability_type=final_vuln_type, conclusion=conclusion or "Có dấu hiệu phản hồi bất thường khi fuzz parameter", parameter=param, param_type=param_type, payload_type=payload_type, payload=value, evidence=evidence or reason, marker=marker, marker_reflected=marker_reflected, marker_hits=marker_hits, confirmation=confirmation, confirmation_reason=confirmation_reason, verification_pages=marker_hits, confirmation_level=confirmation_level, confidence=confidence)

    def build_result(self, started: str, scan_status: str, platform: str = "unknown", scores: Optional[Dict[str, int]] = None) -> Dict:
        self.update_confirmation_stats()
        self.findings.sort(key=lambda f: (0 if f.confirmation == "confirmed" else 1, -f.score, f.status, f.url))
        return {
            "tool": BANNER, "target": self.base_url, "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(), "scan_status": scan_status, "detected_platform": platform, "detected_cms": platform, "platform_type": get_platform_type(platform), "fingerprint_scores": scores or {}, "detected_stack": self.detected_stack, "generated_wordlist_info": self.generated_wordlist_info,
            "marker_based_fuzzing": {"enabled": True, "markers_generated": len(self.marker_registry), "marker_verified_count": self.marker_verified_count, "markers_failed": self.marker_failed_count, "marker_verification_rate": self.marker_verification_rate, "crawled_links_count": self.crawled_links_count, "confirmed_markers": self.confirmed_markers, "verification_pages": self.verification_pages},
            "confirmation_summary": {"confirmed_findings_count": self.confirmed_findings_count, "possible_findings_count": self.possible_findings_count, "confirmation_rate": self.confirmation_rate, "marker_verified_count": self.marker_verified_count, "markers_failed": self.marker_failed_count, "marker_verification_rate": self.marker_verification_rate, "crawled_links_count": self.crawled_links_count},
            "confirmed_findings_count": self.confirmed_findings_count, "possible_findings_count": self.possible_findings_count, "confirmation_rate": self.confirmation_rate, "marker_verified_count": self.marker_verified_count, "markers_failed": self.marker_failed_count, "marker_verification_rate": self.marker_verification_rate, "crawled_links_count": self.crawled_links_count, "requests_sent": self.request_count,
            "safety": {"authorization_required": True, "methods": ["GET"], "max_requests": self.max_requests, "delay_seconds": self.delay, "scope_host": self.base_host},
            "findings": [asdict(f) for f in self.findings]
        }

    def run(self) -> Dict:
        started = datetime.now(timezone.utc).isoformat()
        platform = "unknown"
        scores: Dict[str, int] = {}

        self.emit_progress(1, 5, "Bước 1/7: Tạo baseline response", {"phase": "baseline"})
        if not self.check_control(): return self.build_result(started, "stopped", platform, scores)
        self.fetch_baseline()

        self.emit_progress(2, 15, "Bước 2/7: Fingerprint platform", {"phase": "fingerprint"})
        if not self.check_control(): return self.build_result(started, "stopped", platform, scores)
        platform, scores = self.fingerprint()

        self.emit_progress(3, 30, "Bước 3/7: Tạo context-aware wordlist", {"phase": "wordlist_generation", "detected_platform": platform})
        if not self.check_control(): return self.build_result(started, "stopped", platform, scores)
        paths = self.load_paths(platform)

        self.emit_progress(4, 40, "Bước 4/7: Fuzz paths", {"phase": "path_fuzzing", "paths_count": len(paths)})
        if not self.check_control(): return self.build_result(started, "stopped", platform, scores)
        self.fuzz_paths(platform, paths)

        self.emit_progress(5, 70, "Bước 5/7: Fuzz parameters", {"phase": "parameter_fuzzing"})
        if not self.check_control(): return self.build_result(started, "stopped", platform, scores)
        self.fuzz_params(platform)

        self.emit_progress(6, 88, "Bước 6/7: Marker verification engine", {"phase": "marker_verification", "markers_generated": len(self.marker_registry), "markers_verified": self.marker_verified_count, "findings_count": len(self.findings)})
        if not self.check_control(): return self.build_result(started, "stopped", platform, scores)
        self.verify_marker_engine(platform)

        self.emit_progress(7, 96, "Bước 7/7: Confirmation analysis và tạo report", {"phase": "confirmation_analysis", "findings_count": len(self.findings), "confirmed_findings": self.confirmed_findings_count, "possible_findings": self.possible_findings_count, "confirmation_rate": self.confirmation_rate, "requests_sent": self.request_count})
        result = self.build_result(started, "done", platform, scores)
        self.emit_progress(7, 100, "Scan hoàn tất", {"phase": "done", "findings_count": len(self.findings), "confirmed_findings": self.confirmed_findings_count, "possible_findings": self.possible_findings_count, "confirmation_rate": self.confirmation_rate, "requests_sent": self.request_count})
        return result

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
        f.write(f"- Scan status: `{escape(result.get('scan_status', 'unknown'))}`\n")
        f.write(f"- Requests sent: `{result['requests_sent']}`\n")
        f.write("- Safety: GET-only, same-host scope, rate-limited, authorization flag required.\n")
        stack = result.get("detected_stack", {})
        f.write(f"- Server technology hint: `{escape(str(stack.get('language', 'unknown')))}` / `{escape(str(stack.get('server', 'unknown')))}`\n")
        summary = result.get("confirmation_summary", {})
        f.write(f"- Confirmed findings: `{summary.get('confirmed_findings_count', result.get('confirmed_findings_count', 0))}`\n")
        f.write(f"- Possible findings: `{summary.get('possible_findings_count', result.get('possible_findings_count', 0))}`\n")
        f.write(f"- Confirmation rate: `{summary.get('confirmation_rate', result.get('confirmation_rate', 0.0))}%`\n")
        f.write(f"- Marker verified count: `{summary.get('marker_verified_count', result.get('marker_verified_count', 0))}`\n")
        f.write(f"- Marker verification rate: `{summary.get('marker_verification_rate', result.get('marker_verification_rate', 0.0))}%`\n")
        f.write(f"- Crawled links for verification: `{summary.get('crawled_links_count', result.get('crawled_links_count', 0))}`\n\n")

        f.write("## Wordlist generation mechanism\n\n")
        f.write("Tool tạo wordlist theo 3 lớp: platform paths từ profile/wordlist, extension paths theo server technology, và payload values theo loại parameter.\n\n")
        w = result.get("generated_wordlist_info", {})
        f.write(f"- Path wordlist sources: `{escape(', '.join(w.get('path_sources', [])) or 'profile defaults')}`\n")
        f.write(f"- Server extension priority: `{escape(', '.join(w.get('server_extensions', [])) or 'none')}`\n")
        f.write("- Parameter strategy examples:\n")
        for k, v in list(w.get("parameter_strategy", {}).items())[:20]: f.write(f"  - `{escape(k)}` => `{escape(v)}`\n")
        f.write("\n- Payload strategy examples:\n")
        for k, payloads in list(w.get("payload_strategy", {}).items())[:20]:
            payload_text = ", ".join(payloads)
            f.write(f"  - `{escape(k)}` => `{escape(payload_text)}`\n")

        f.write("\n## Marker verification mechanism\n\n")
        mb = result.get("marker_based_fuzzing", {})
        f.write("Marker-based fuzzing gắn marker duy nhất vào từng payload. Sau fuzzing, verification engine crawl các link cùng host và kiểm tra marker có xuất hiện lại không. Nếu có bằng chứng marker, finding được phân loại là confirmed.\n\n")
        f.write(f"- Markers generated: `{mb.get('markers_generated', 0)}`\n")
        f.write(f"- Markers verified: `{mb.get('marker_verified_count', 0)}`\n")
        f.write(f"- Markers failed: `{mb.get('markers_failed', 0)}`\n")
        f.write(f"- Marker verification rate: `{mb.get('marker_verification_rate', 0.0)}%`\n")
        f.write(f"- Crawled links: `{mb.get('crawled_links_count', 0)}`\n")

        f.write("\n## Fingerprint scores\n\n")
        for k, v in result.get("fingerprint_scores", {}).items(): f.write(f"- {escape(k)}: {v}\n")

        f.write("\n## Findings\n\n")
        f.write("Các finding được chia theo trạng thái `confirmed` hoặc `possible`. Confirmed nghĩa là có bằng chứng marker-based reflection/verification; possible nghĩa là dựa trên feedback/anomaly nhưng chưa có marker xác nhận.\n\n")

        if not result["findings"]: f.write("Không phát hiện dấu hiệu bất thường đáng kể.\n")
        for i, item in enumerate(result["findings"], 1):
            vuln = item.get("vulnerability_type") or item["kind"]
            conclusion = item.get("conclusion") or f"Có dấu hiệu/nguy cơ: {vuln}"
            f.write(f"### {i}. {escape(vuln)}\n")
            f.write(f"- Kind: `{escape(item['kind'])}`\n")
            f.write(f"- Confirmation: `{escape(str(item.get('confirmation', 'possible')))}` | Level: `{escape(str(item.get('confirmation_level', 'possible')))}` | Confidence: `{item.get('confidence', 0)}`\n")
            f.write(f"- Confirmation reason: {escape(str(item.get('confirmation_reason', '')))}\n")
            f.write(f"- Kết luận nguy cơ: {escape(conclusion)}\n")
            f.write(f"- URL: `{escape(item['url'])}`\n")
            if item.get("parameter"):
                f.write(f"- Parameter: `{escape(item.get('parameter', ''))}` | Param type: `{escape(item.get('param_type', ''))}`\n")
                f.write(f"- Payload type: `{escape(item.get('payload_type', ''))}` | Payload: `{escape(item.get('payload', ''))}`\n")
            f.write(f"- Response: HTTP `{item['status']}` / Length `{item['length']}` / Type `{escape(item['content_type'])}`\n")
            if item.get("title"): f.write(f"- Title: {escape(item['title'])}\n")
            if item.get("evidence"): f.write(f"- Evidence: {escape(item['evidence'])}\n")
            if item.get("marker"):
                f.write(f"- Marker: `{escape(str(item.get('marker', '')))}` | Reflected: `{item.get('marker_reflected', False)}` | Hits: `{len(item.get('marker_hits') or [])}`\n")
                for hit in (item.get("marker_hits") or [])[:5]:
                    f.write(f"  - Hit: `{escape(str(hit.get('url', '')))}` / source `{escape(str(hit.get('source', '')))}`\n")
            f.write("- Why detected / Feedback analysis:\n")
            f.write(f"  - Response status: `{item['status']}`\n")
            f.write(f"  - Response length: `{item['length']}`\n")
            f.write(f"  - Content-Type: `{escape(item['content_type'])}`\n")
            f.write(f"  - Reason: {escape(item['reason'])}\n\n")

    return json_path, md_path

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=BANNER)
    p.add_argument("--target", required=True, help="Authorized target base URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--cms", default="auto", choices=["auto"] + sorted(PROFILES), help="Platform hint or auto fingerprint")
    p.add_argument("--wordlist-dir", default=os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists"))
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
        print("Refusing to run: add --i-have-authorization for systems you own or are explicitly allowed to test.", file=sys.stderr)
        return 2

    fuzzer = ContextFeedbackFuzzer(
        base_url=args.target, wordlist_dir=args.wordlist_dir, cms_hint=args.cms, threads=args.threads, delay=args.delay, timeout=args.timeout, max_requests=args.max_requests,
    )
    result = fuzzer.run()
    platform = result.get("detected_platform") or result["detected_cms"]
    host = urlparse(result["target"]).netloc.replace(":", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_prefix = args.out or f"reports/{platform}_{host}_{ts}"
    json_path, md_path = write_reports(result, out_prefix)
    print(json.dumps({"detected_platform": platform, "platform_type": result.get("platform_type", get_platform_type(platform)), "scan_status": result.get("scan_status", "unknown"), "requests_sent": result["requests_sent"], "findings": len(result["findings"]), "confirmed_findings": result.get("confirmed_findings_count", 0), "possible_findings": result.get("possible_findings_count", 0), "confirmation_rate": result.get("confirmation_rate", 0.0), "marker_verified_count": result.get("marker_verified_count", 0), "marker_verification_rate": result.get("marker_verification_rate", 0.0), "crawled_links_count": result.get("crawled_links_count", 0), "json": json_path, "markdown": md_path}, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())