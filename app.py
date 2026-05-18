"""
APKManifest - Android Manifest Security Analyzer
Main Flask web server.
"""

import os
import uuid
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash

from analyzer.scanner import APKScanner
from analyzer.reporter import generate_pdf_report

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORTS_DIR = BASE_DIR / "reports"
ALLOWED_EXTENSIONS = {"apk"}
MAX_FILE_SIZE_MB = 100

UPLOAD_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE_MB * 1024 * 1024
app.secret_key = "apkmanifest-dev-key-change-in-production"

scan_results_cache = {}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/compare")
def compare():
    return render_template("compare.html")


@app.route("/scan", methods=["POST"])
def scan():
    if "apk_file" not in request.files:
        flash("No file part in request", "error")
        return redirect(url_for("index"))

    file = request.files["apk_file"]

    if file.filename == "":
        flash("No file selected", "error")
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash("Only .apk files are allowed", "error")
        return redirect(url_for("index"))

    scan_id = str(uuid.uuid4())[:8]
    safe_filename = f"{scan_id}_{file.filename}"
    apk_path = UPLOAD_DIR / safe_filename
    file.save(apk_path)

    try:
        scanner = APKScanner(str(apk_path))
        results = scanner.run_full_scan()
        results["scan_id"] = scan_id
        results["original_filename"] = file.filename
        scan_results_cache[scan_id] = results
        return render_template("results.html", data=results)

    except Exception as e:
        flash(f"Error analyzing APK: {str(e)}", "error")
        return redirect(url_for("index"))

    finally:
        if apk_path.exists():
            try:
                os.remove(apk_path)
            except OSError:
                pass


@app.route("/report/<scan_id>")
def view_report(scan_id: str):
    if scan_id not in scan_results_cache:
        flash("Report not found or expired.", "error")
        return redirect(url_for("index"))
    results = scan_results_cache[scan_id]
    return render_template("results.html", data=results)


@app.route("/download/<scan_id>")
def download_report(scan_id: str):
    if scan_id not in scan_results_cache:
        flash("Report not found or expired", "error")
        return redirect(url_for("index"))

    results = scan_results_cache[scan_id]
    pdf_path = REPORTS_DIR / f"report_{scan_id}.pdf"
    generate_pdf_report(results, str(pdf_path))

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"APKManifest_Report_{scan_id}.pdf",
        mimetype="application/pdf",
    )


@app.route("/compare/scan", methods=["POST"])
def compare_scan():
    if "apk_file_1" not in request.files or "apk_file_2" not in request.files:
        flash("Please upload two APK files", "error")
        return redirect(url_for("compare"))

    file1 = request.files["apk_file_1"]
    file2 = request.files["apk_file_2"]

    if file1.filename == "" or file2.filename == "":
        flash("Please select both files", "error")
        return redirect(url_for("compare"))

    if not allowed_file(file1.filename) or not allowed_file(file2.filename):
        flash("Only .apk files are allowed", "error")
        return redirect(url_for("compare"))

    results = []
    paths = []

    try:
        for file in [file1, file2]:
            scan_id = str(uuid.uuid4())[:8]
            apk_path = UPLOAD_DIR / f"{scan_id}_{file.filename}"
            file.save(apk_path)
            paths.append(apk_path)
            scanner = APKScanner(str(apk_path))
            result = scanner.run_full_scan()
            result["scan_id"] = scan_id
            result["original_filename"] = file.filename
            scan_results_cache[scan_id] = result
            results.append(result)

        comparison = build_comparison(results[0], results[1])
        return render_template("compare_results.html", r1=results[0], r2=results[1], comparison=comparison)

    except Exception as e:
        flash(f"Error analyzing APKs: {str(e)}", "error")
        return redirect(url_for("compare"))

    finally:
        for p in paths:
            if p.exists():
                try:
                    os.remove(p)
                except OSError:
                    pass


def build_comparison(r1: dict, r2: dict) -> dict:
    score1 = r1.get("risk_score", 0)
    score2 = r2.get("risk_score", 0)
    diff = score2 - score1
    findings1_ids = {f["id"] for f in r1.get("findings", [])}
    findings2_ids = {f["id"] for f in r2.get("findings", [])}
    fixed = findings1_ids - findings2_ids
    new_issues = findings2_ids - findings1_ids
    common = findings1_ids & findings2_ids
    return {
        "score_diff": diff,
        "improved": diff < 0,
        "worsened": diff > 0,
        "score1": score1,
        "score2": score2,
        "fixed_count": len(fixed),
        "new_count": len(new_issues),
        "common_count": len(common),
        "fixed_ids": list(fixed),
        "new_ids": list(new_issues),
    }


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if "apk_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["apk_file"]
    if not allowed_file(file.filename):
        return jsonify({"error": "Only .apk files are allowed"}), 400
    scan_id = str(uuid.uuid4())[:8]
    apk_path = UPLOAD_DIR / f"{scan_id}_{file.filename}"
    file.save(apk_path)
    try:
        scanner = APKScanner(str(apk_path))
        results = scanner.run_full_scan()
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if apk_path.exists():
            os.remove(apk_path)


@app.errorhandler(413)
def file_too_large(e):
    flash(f"File too large. Maximum size is {MAX_FILE_SIZE_MB} MB", "error")
    return redirect(url_for("index"))


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Server error"), 500


if __name__ == "__main__":
    print("=" * 60)
    print("  APKManifest - Android Manifest Security Analyzer")
    print("=" * 60)
    print("  Server running at: http://localhost:7777")
    print("  Press CTRL+C to stop")
    print("=" * 60)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 7777)), debug=False)
