from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, Response, flash, redirect, render_template, request, send_file, url_for

from context_fuzzer.fuzzer import ContextFeedbackFuzzer, write_reports
from context_fuzzer.profiles import PROFILES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

app = Flask(__name__)
app.secret_key = os.environ.get("CFF_SECRET_KEY", "context-feedback-fuzzer-dev-key")

SCAN_JOBS: dict[str, dict] = {}


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


def make_out_prefix(target: str, platform: str) -> str:
    parsed = urlparse(target if "://" in target else "http://" + target)
    host = parsed.netloc.replace(":", "_").replace("/", "_") or "target"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(REPORT_DIR, f"{platform}_{host}_{ts}")


def normalize_findings_for_report(result: dict) -> dict:
    platform = result.get("detected_platform") or result.get("detected_cms") or "unknown"

    result["detected_platform"] = platform
    result["detected_cms"] = platform
    result["platform_type"] = result.get("platform_type") or get_platform_type(platform)

    for item in result.get("findings", []):
        vuln = item.get("vulnerability_type") or item.get("kind") or "Response Anomaly"
        evidence = item.get("evidence") or item.get("reason") or ""

        item["bug_hypothesis"] = vuln
        item["conclusion"] = item.get("conclusion") or f"Có dấu hiệu/nguy cơ: {vuln}"
        item["evidence_summary"] = evidence
        item["research_note"] = "Finding được sinh ra từ cơ chế feedback-based fuzzing."

        if "confidence" in item:
            item.pop("confidence", None)

    return result


def list_reports() -> list[dict]:
    if not os.path.exists(REPORT_DIR):
        return []

    items = []

    for name in os.listdir(REPORT_DIR):
        if not name.endswith(".json"):
            continue

        path = os.path.join(REPORT_DIR, name)

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            data = normalize_findings_for_report(data)
            platform = data.get("detected_platform", data.get("detected_cms", ""))

            items.append({
                "name": name,
                "target": data.get("target", ""),
                "platform": platform,
                "cms": platform,
                "platform_type": data.get("platform_type", get_platform_type(platform)),
                "requests": data.get("requests_sent", 0),
                "findings": len(data.get("findings", [])),
                "json": name,
                "md": name[:-5] + ".md",
                "mtime": os.path.getmtime(path),
            })

        except Exception:
            continue

    return sorted(items, key=lambda x: x["mtime"], reverse=True)[:20]


@app.route("/", methods=["GET"])
def index():
    platform_options = ["auto"] + sorted(PROFILES)

    return render_template(
        "index.html",
        platform_options=platform_options,
        cms_options=platform_options,
        reports=list_reports(),
    )


@app.route("/scan/start", methods=["POST"])
def scan_start():
    target = request.form.get("target", "").strip()
    platform = request.form.get("platform", request.form.get("cms", "auto")).strip().lower()
    authorization = request.form.get("authorization") == "on"

    try:
        threads = int(request.form.get("threads", "4"))
        delay = float(request.form.get("delay", "0.15"))
        max_requests = int(request.form.get("max_requests", "400"))
        timeout = float(request.form.get("timeout", "8"))
    except ValueError:
        flash("Threads, delay, timeout và max_requests phải là số hợp lệ.", "error")
        return redirect(url_for("index"))

    if not target:
        flash("Bạn cần nhập target URL.", "error")
        return redirect(url_for("index"))

    if not authorization:
        flash("Bạn cần xác nhận chỉ scan target được phép hoặc môi trường lab.", "error")
        return redirect(url_for("index"))

    if platform not in (["auto"] + sorted(PROFILES)):
        flash("Platform không hợp lệ.", "error")
        return redirect(url_for("index"))

    job_id = str(uuid.uuid4())

    SCAN_JOBS[job_id] = {
        "status": "running",
        "progress": 0,
        "step": "Khởi tạo scan",
        "error": "",
        "result": None,
    }

    def worker() -> None:
        try:
            SCAN_JOBS[job_id]["progress"] = 10
            SCAN_JOBS[job_id]["step"] = "Bước 1/5: Chuẩn bị cấu hình scan"

            fuzzer = ContextFeedbackFuzzer(
                base_url=target,
                wordlist_dir=WORDLIST_DIR,
                cms_hint=platform,
                threads=threads,
                delay=delay,
                timeout=timeout,
                max_requests=max_requests,
            )

            SCAN_JOBS[job_id]["progress"] = 20
            SCAN_JOBS[job_id]["step"] = "Bước 2/5: Fingerprint platform và server technology"

            result = fuzzer.run()

            SCAN_JOBS[job_id]["progress"] = 75
            SCAN_JOBS[job_id]["step"] = "Bước 4/5: Chuẩn hóa finding và kết luận nguy cơ"

            result = normalize_findings_for_report(result)

            SCAN_JOBS[job_id]["progress"] = 90
            SCAN_JOBS[job_id]["step"] = "Bước 5/5: Tạo JSON và Markdown report"

            detected_platform = result.get("detected_platform", result.get("detected_cms", "unknown"))

            out_prefix = make_out_prefix(result["target"], detected_platform)
            json_path, md_path = write_reports(result, out_prefix)

            summary = {
                "detected_platform": detected_platform,
                "detected_cms": detected_platform,
                "platform_type": result.get("platform_type", get_platform_type(detected_platform)),
                "requests_sent": result["requests_sent"],
                "findings_count": len(result["findings"]),
                "json_file": os.path.basename(json_path),
                "md_file": os.path.basename(md_path),
                "target": result["target"],
            }

            SCAN_JOBS[job_id]["status"] = "done"
            SCAN_JOBS[job_id]["progress"] = 100
            SCAN_JOBS[job_id]["step"] = "Hoàn tất scan"
            SCAN_JOBS[job_id]["result"] = {
                "result": result,
                "summary": summary,
            }

        except Exception as e:
            SCAN_JOBS[job_id]["status"] = "error"
            SCAN_JOBS[job_id]["error"] = str(e)
            SCAN_JOBS[job_id]["step"] = "Scan bị lỗi"

    threading.Thread(target=worker, daemon=True).start()

    return render_template("progress.html", job_id=job_id)


@app.route("/scan/progress/<job_id>", methods=["GET"])
def scan_progress(job_id: str):
    job = SCAN_JOBS.get(job_id)

    if not job:
        return {
            "status": "error",
            "progress": 0,
            "step": "Không tìm thấy job",
            "error": "Job not found",
        }, 404

    return {
        "status": job.get("status", "unknown"),
        "progress": job.get("progress", 0),
        "step": job.get("step", ""),
        "error": job.get("error", ""),
    }


@app.route("/scan/result/<job_id>", methods=["GET"])
def scan_result(job_id: str):
    job = SCAN_JOBS.get(job_id)

    if not job:
        flash("Không tìm thấy job scan.", "error")
        return redirect(url_for("index"))

    if job.get("status") == "error":
        flash(f"Scan bị lỗi: {job.get('error', '')}", "error")
        return redirect(url_for("index"))

    if job.get("status") != "done" or not job.get("result"):
        return redirect(url_for("index"))

    return render_template(
        "result.html",
        result=job["result"]["result"],
        summary=job["result"]["summary"],
    )


@app.route("/scan", methods=["POST"])
def scan():
    return scan_start()


@app.route("/reports/<path:filename>")
def download_report(filename: str):
    safe_name = os.path.basename(filename)
    path = os.path.join(REPORT_DIR, safe_name)

    if not os.path.exists(path):
        return Response("Report not found", status=404)

    return send_file(path, as_attachment=True)


@app.route("/view/<path:filename>")
def view_report(filename: str):
    safe_name = os.path.basename(filename)
    path = os.path.join(REPORT_DIR, safe_name)

    if not os.path.exists(path):
        return Response("Report not found", status=404)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if safe_name.endswith(".md"):
        return render_template(
            "md_view.html",
            filename=safe_name,
            content=content,
        )

    return Response(content, mimetype="application/json")


if __name__ == "__main__":
    os.makedirs(REPORT_DIR, exist_ok=True)
    app.run(host="127.0.0.1", port=5000, debug=True)