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


def safe_percent(value: float | int | str | None) -> float:
    try:
        return round(float(value), 2)
    except (TypeError, ValueError):
        return 0.0


def get_confirmation_summary(result: dict) -> dict:
    """
    Lấy thống kê confirmation từ fuzzer v2.1.
    Nếu report cũ chưa có confirmation_summary thì tự tính từ findings.
    """
    summary = result.get("confirmation_summary") or {}
    findings = result.get("findings", [])

    confirmed = summary.get("confirmed_findings_count")
    possible = summary.get("possible_findings_count")

    if confirmed is None:
        confirmed = sum(1 for f in findings if f.get("confirmation") == "confirmed")

    if possible is None:
        possible = max(0, len(findings) - confirmed)

    total = confirmed + possible
    confirmation_rate = summary.get("confirmation_rate")
    if confirmation_rate is None:
        confirmation_rate = round((confirmed / total) * 100, 2) if total else 0.0

    marker_block = result.get("marker_based_fuzzing") or {}

    return {
        "confirmed_findings_count": int(confirmed or 0),
        "possible_findings_count": int(possible or 0),
        "confirmation_rate": safe_percent(confirmation_rate),
        "marker_verified_count": int(
            summary.get("marker_verified_count", result.get("marker_verified_count", marker_block.get("marker_verified_count", 0))) or 0
        ),
        "markers_failed": int(
            summary.get("markers_failed", result.get("markers_failed", marker_block.get("markers_failed", 0))) or 0
        ),
        "marker_verification_rate": safe_percent(
            summary.get(
                "marker_verification_rate",
                result.get("marker_verification_rate", marker_block.get("marker_verification_rate", 0.0)),
            )
        ),
        "crawled_links_count": int(
            summary.get("crawled_links_count", result.get("crawled_links_count", marker_block.get("crawled_links_count", 0))) or 0
        ),
        "markers_generated": int(marker_block.get("markers_generated", 0) or 0),
    }


def normalize_findings_for_report(result: dict) -> dict:
    """
    Chuẩn hóa dữ liệu để UI dùng được với cả report cũ và report v2.1.
    Không xóa confidence vì v2.1 dùng confidence để hiển thị độ tin cậy.
    """
    platform = result.get("detected_platform") or result.get("detected_cms") or "unknown"

    result["detected_platform"] = platform
    result["detected_cms"] = platform
    result["platform_type"] = result.get("platform_type") or get_platform_type(platform)

    confirmation_summary = get_confirmation_summary(result)
    result["confirmation_summary"] = confirmation_summary

    result["confirmed_findings_count"] = confirmation_summary["confirmed_findings_count"]
    result["possible_findings_count"] = confirmation_summary["possible_findings_count"]
    result["confirmation_rate"] = confirmation_summary["confirmation_rate"]
    result["marker_verified_count"] = confirmation_summary["marker_verified_count"]
    result["markers_failed"] = confirmation_summary["markers_failed"]
    result["marker_verification_rate"] = confirmation_summary["marker_verification_rate"]
    result["crawled_links_count"] = confirmation_summary["crawled_links_count"]

    for item in result.get("findings", []):
        vuln = item.get("vulnerability_type") or item.get("kind") or "Response Anomaly"
        evidence = item.get("evidence") or item.get("reason") or ""

        item["bug_hypothesis"] = vuln
        item["conclusion"] = item.get("conclusion") or f"Có dấu hiệu/nguy cơ: {vuln}"
        item["evidence_summary"] = evidence
        item["research_note"] = "Finding được sinh ra từ context-aware, feedback-based và marker-based verification."

        item["confirmation"] = item.get("confirmation", "possible")
        item["confirmation_level"] = item.get("confirmation_level", item.get("confirmation", "possible"))
        item["confirmation_reason"] = item.get(
            "confirmation_reason",
            "Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.",
        )
        item["confidence"] = item.get("confidence", 0)
        item["marker_reflected"] = item.get("marker_reflected", False)
        item["marker_hits"] = item.get("marker_hits") or []
        item["verification_pages"] = item.get("verification_pages") or item.get("marker_hits") or []

    return result


def build_summary(result: dict, json_path: str, md_path: str) -> dict:
    detected_platform = result.get("detected_platform", result.get("detected_cms", "unknown"))
    confirmation_summary = get_confirmation_summary(result)
    marker_block = result.get("marker_based_fuzzing") or {}

    return {
        "detected_platform": detected_platform,
        "detected_cms": detected_platform,
        "platform_type": result.get("platform_type", get_platform_type(detected_platform)),
        "requests_sent": result.get("requests_sent", 0),
        "findings_count": len(result.get("findings", [])),
        "confirmed_findings_count": confirmation_summary["confirmed_findings_count"],
        "possible_findings_count": confirmation_summary["possible_findings_count"],
        "confirmation_rate": confirmation_summary["confirmation_rate"],
        "marker_verified_count": confirmation_summary["marker_verified_count"],
        "markers_generated": marker_block.get("markers_generated", confirmation_summary["markers_generated"]),
        "markers_failed": confirmation_summary["markers_failed"],
        "marker_verification_rate": confirmation_summary["marker_verification_rate"],
        "crawled_links_count": confirmation_summary["crawled_links_count"],
        "json_file": os.path.basename(json_path),
        "md_file": os.path.basename(md_path),
        "target": result.get("target", ""),
        "scan_status": result.get("scan_status", "unknown"),
    }


def list_reports() -> list[dict]:
    """
    Chỉ lấy report mới nhất của mỗi target.
    Tránh dashboard bị lặp nhiều dòng khi scan cùng một target nhiều lần.
    """
    if not os.path.exists(REPORT_DIR):
        return []

    latest_by_target: dict[str, dict] = {}

    for name in os.listdir(REPORT_DIR):
        if not name.endswith(".json"):
            continue

        path = os.path.join(REPORT_DIR, name)

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            data = normalize_findings_for_report(data)

            target = data.get("target", "")
            platform = data.get("detected_platform", data.get("detected_cms", ""))
            confirmation_summary = get_confirmation_summary(data)
            marker_block = data.get("marker_based_fuzzing") or {}
            mtime = os.path.getmtime(path)

            item = {
                "name": name,
                "target": target,
                "platform": platform,
                "cms": platform,
                "platform_type": data.get("platform_type", get_platform_type(platform)),
                "requests": data.get("requests_sent", 0),
                "findings": len(data.get("findings", [])),
                "confirmed_findings": confirmation_summary["confirmed_findings_count"],
                "possible_findings": confirmation_summary["possible_findings_count"],
                "confirmation_rate": confirmation_summary["confirmation_rate"],
                "marker_verified_count": confirmation_summary["marker_verified_count"],
                "markers_generated": marker_block.get("markers_generated", confirmation_summary["markers_generated"]),
                "markers_failed": confirmation_summary["markers_failed"],
                "marker_verification_rate": confirmation_summary["marker_verification_rate"],
                "crawled_links_count": confirmation_summary["crawled_links_count"],
                "scan_status": data.get("scan_status", "unknown"),
                "json": name,
                "md": name[:-5] + ".md",
                "mtime": mtime,
                "time": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }

            if target not in latest_by_target:
                latest_by_target[target] = item
            elif mtime > latest_by_target[target]["mtime"]:
                latest_by_target[target] = item

        except Exception:
            continue

    return sorted(
        latest_by_target.values(),
        key=lambda x: x["mtime"],
        reverse=True,
    )


@app.route("/", methods=["GET"])
def index():
    platform_options = ["auto"] + sorted(PROFILES)

    return render_template(
        "index.html",
        platform_options=platform_options,
        cms_options=platform_options,
        reports=list_reports(),
        jobs=SCAN_JOBS,
    )


@app.route("/scan/start", methods=["POST"])
def scan_start():
    target = request.form.get("target", "").strip()
    platform = request.form.get("platform", request.form.get("cms", "auto")).strip().lower()
    authorization = request.form.get("authorization") == "on"

    try:
        threads = int(request.form.get("threads", "4"))
        delay = float(request.form.get("delay", "0.15"))
        max_requests = int(request.form.get("max_requests", "1000"))
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
        "step_number": 0,
        "error": "",
        "result": None,
        "summary": None,
        "paused": False,
        "stopped": False,
        "logs": [],
        "current": {},
        "requests_sent": 0,
        "findings_count": 0,
        "confirmed_findings_count": 0,
        "possible_findings_count": 0,
        "confirmation_rate": 0.0,
        "markers_generated": 0,
        "marker_verified_count": 0,
        "markers_failed": 0,
        "marker_verification_rate": 0.0,
        "crawled_links_count": 0,
        "target": target,
        "platform_hint": platform,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    def append_log(message: str) -> None:
        if not message:
            return
        SCAN_JOBS[job_id]["logs"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "message": message,
        })
        SCAN_JOBS[job_id]["logs"] = SCAN_JOBS[job_id]["logs"][-60:]

    def update_progress(event: dict) -> None:
        job = SCAN_JOBS[job_id]
        extra = event.get("extra", {}) or {}

        # Nếu user bấm pause thì giữ trạng thái paused, còn không thì running.
        if job.get("stopped"):
            job["status"] = "stopping"
        else:
            job["status"] = "paused" if job.get("paused") else "running"

        job["progress"] = event.get("progress", job.get("progress", 0))
        job["step"] = event.get("message", job.get("step", ""))
        job["step_number"] = event.get("step", job.get("step_number", 0))
        job["current"] = extra
        job["requests_sent"] = event.get("requests_sent", job.get("requests_sent", 0))
        job["findings_count"] = event.get("findings_count", job.get("findings_count", 0))

        # Metrics từ fuzzer v2.1
        job["confirmed_findings_count"] = extra.get("confirmed_findings", job.get("confirmed_findings_count", 0))
        job["possible_findings_count"] = extra.get("possible_findings", job.get("possible_findings_count", 0))
        job["confirmation_rate"] = extra.get("confirmation_rate", job.get("confirmation_rate", 0.0))
        job["markers_generated"] = extra.get("markers_generated", job.get("markers_generated", 0))
        job["marker_verified_count"] = extra.get("markers_verified", job.get("marker_verified_count", 0))
        job["marker_verification_rate"] = extra.get("marker_verification_rate", job.get("marker_verification_rate", 0.0))
        job["crawled_links_count"] = extra.get("crawled_links", job.get("crawled_links_count", 0))

        append_log(event.get("message", ""))

    def read_control() -> dict:
        job = SCAN_JOBS[job_id]
        return {
            "paused": job.get("paused", False),
            "stopped": job.get("stopped", False),
            "progress": job.get("progress", 0),
        }

    def worker() -> None:
        try:
            append_log("Scan job được khởi tạo")

            fuzzer = ContextFeedbackFuzzer(
                base_url=target,
                wordlist_dir=WORDLIST_DIR,
                cms_hint=platform,
                threads=threads,
                delay=delay,
                timeout=timeout,
                max_requests=max_requests,
                progress_callback=update_progress,
                control_callback=read_control,
            )

            result = fuzzer.run()
            result = normalize_findings_for_report(result)

            detected_platform = result.get("detected_platform", result.get("detected_cms", "unknown"))
            out_prefix = make_out_prefix(result["target"], detected_platform)
            json_path, md_path = write_reports(result, out_prefix)
            summary = build_summary(result, json_path, md_path)

            if result.get("scan_status") == "stopped" or SCAN_JOBS[job_id].get("stopped"):
                SCAN_JOBS[job_id]["status"] = "stopped"
                SCAN_JOBS[job_id]["step"] = "Scan đã dừng. Partial report đã được tạo."
                append_log("Scan đã dừng theo yêu cầu người dùng")
            else:
                SCAN_JOBS[job_id]["status"] = "done"
                SCAN_JOBS[job_id]["progress"] = 100
                SCAN_JOBS[job_id]["step"] = "Hoàn tất scan"
                append_log("Scan hoàn tất")

            SCAN_JOBS[job_id]["result"] = {
                "result": result,
                "summary": summary,
            }
            SCAN_JOBS[job_id]["summary"] = summary
            SCAN_JOBS[job_id]["requests_sent"] = result.get("requests_sent", 0)
            SCAN_JOBS[job_id]["findings_count"] = len(result.get("findings", []))
            SCAN_JOBS[job_id]["confirmed_findings_count"] = summary["confirmed_findings_count"]
            SCAN_JOBS[job_id]["possible_findings_count"] = summary["possible_findings_count"]
            SCAN_JOBS[job_id]["confirmation_rate"] = summary["confirmation_rate"]
            SCAN_JOBS[job_id]["markers_generated"] = summary["markers_generated"]
            SCAN_JOBS[job_id]["marker_verified_count"] = summary["marker_verified_count"]
            SCAN_JOBS[job_id]["markers_failed"] = summary["markers_failed"]
            SCAN_JOBS[job_id]["marker_verification_rate"] = summary["marker_verification_rate"]
            SCAN_JOBS[job_id]["crawled_links_count"] = summary["crawled_links_count"]

        except Exception as e:
            SCAN_JOBS[job_id]["status"] = "error"
            SCAN_JOBS[job_id]["error"] = str(e)
            SCAN_JOBS[job_id]["step"] = "Scan bị lỗi"
            append_log(f"Scan bị lỗi: {e}")

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
            "requests_sent": 0,
            "findings_count": 0,
            "confirmed_findings_count": 0,
            "possible_findings_count": 0,
            "confirmation_rate": 0.0,
            "markers_generated": 0,
            "marker_verified_count": 0,
            "markers_failed": 0,
            "marker_verification_rate": 0.0,
            "crawled_links_count": 0,
            "current": {},
            "logs": [],
        }, 404

    return {
        "status": job.get("status", "unknown"),
        "progress": job.get("progress", 0),
        "step": job.get("step", ""),
        "step_number": job.get("step_number", 0),
        "error": job.get("error", ""),
        "requests_sent": job.get("requests_sent", 0),
        "findings_count": job.get("findings_count", 0),
        "confirmed_findings_count": job.get("confirmed_findings_count", 0),
        "possible_findings_count": job.get("possible_findings_count", 0),
        "confirmation_rate": job.get("confirmation_rate", 0.0),
        "markers_generated": job.get("markers_generated", 0),
        "marker_verified_count": job.get("marker_verified_count", 0),
        "markers_failed": job.get("markers_failed", 0),
        "marker_verification_rate": job.get("marker_verification_rate", 0.0),
        "crawled_links_count": job.get("crawled_links_count", 0),
        "current": job.get("current", {}),
        "logs": job.get("logs", []),
        "target": job.get("target", ""),
        "platform_hint": job.get("platform_hint", ""),
        "created_at": job.get("created_at", ""),
        "has_result": bool(job.get("result")),
    }


@app.route("/scan/watch/<job_id>", methods=["GET"])
def scan_watch(job_id: str):
    if job_id not in SCAN_JOBS:
        flash("Không tìm thấy job scan.", "error")
        return redirect(url_for("index"))

    return render_template("progress.html", job_id=job_id)


@app.route("/scan/pause/<job_id>", methods=["POST"])
def scan_pause(job_id: str):
    if job_id in SCAN_JOBS and SCAN_JOBS[job_id].get("status") in {"running", "paused"}:
        SCAN_JOBS[job_id]["paused"] = True
        SCAN_JOBS[job_id]["status"] = "paused"
        SCAN_JOBS[job_id]["logs"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "message": "Scan đã được tạm dừng",
        })

    return {"ok": True}


@app.route("/scan/resume/<job_id>", methods=["POST"])
def scan_resume(job_id: str):
    if job_id in SCAN_JOBS and SCAN_JOBS[job_id].get("status") in {"paused", "running"}:
        SCAN_JOBS[job_id]["paused"] = False
        SCAN_JOBS[job_id]["status"] = "running"
        SCAN_JOBS[job_id]["logs"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "message": "Scan tiếp tục chạy",
        })

    return {"ok": True}


@app.route("/scan/stop/<job_id>", methods=["POST"])
def scan_stop(job_id: str):
    if job_id in SCAN_JOBS and SCAN_JOBS[job_id].get("status") not in {"done", "error", "stopped"}:
        SCAN_JOBS[job_id]["stopped"] = True
        SCAN_JOBS[job_id]["paused"] = False
        SCAN_JOBS[job_id]["status"] = "stopping"
        SCAN_JOBS[job_id]["logs"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "message": "Đang dừng scan và tạo partial report",
        })

    return {"ok": True}


@app.route("/scan/result/<job_id>", methods=["GET"])
def scan_result(job_id: str):
    job = SCAN_JOBS.get(job_id)

    if not job:
        flash("Không tìm thấy job scan.", "error")
        return redirect(url_for("index"))

    if job.get("status") == "error":
        flash(f"Scan bị lỗi: {job.get('error', '')}", "error")
        return redirect(url_for("index"))

    if not job.get("result"):
        flash("Scan chưa có kết quả. Vui lòng chờ hoặc dừng scan để tạo partial report.", "error")
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
