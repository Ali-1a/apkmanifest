"""
APK Scanner - Main orchestrator.
Compatible with androguard 3.x and 4.x.
"""

from datetime import datetime
from pathlib import Path

try:
    from androguard.core.apk import APK
except ImportError:
    from androguard.core.bytecodes.apk import APK

from analyzer.manifest_checker import ManifestChecker
from analyzer.risk_scorer import RiskScorer


class APKScanner:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk = APK(apk_path)

    def get_basic_info(self) -> dict:
        try:
            file_size_mb = round(Path(self.apk_path).stat().st_size / (1024 * 1024), 2)
        except OSError:
            file_size_mb = 0
        return {
            "app_name": self.apk.get_app_name() or "Unknown",
            "package_name": self.apk.get_package() or "Unknown",
            "version_name": self.apk.get_androidversion_name() or "Unknown",
            "version_code": self.apk.get_androidversion_code() or "Unknown",
            "min_sdk": self.apk.get_min_sdk_version() or "Unknown",
            "target_sdk": self.apk.get_target_sdk_version() or "Unknown",
            "file_size_mb": file_size_mb,
            "main_activity": self.apk.get_main_activity() or "Unknown",
        }

    def run_full_scan(self) -> dict:
        checker = ManifestChecker(self.apk)
        findings = checker.check_all()
        dangerous_perms = checker.get_dangerous_permissions()

        scorer = RiskScorer(findings)
        score = scorer.calculate()

        return {
            "basic_info": self.get_basic_info(),
            "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "findings": findings,
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f["severity"] == "critical"),
                "medium":   sum(1 for f in findings if f["severity"] == "medium"),
                "low":      sum(1 for f in findings if f["severity"] == "low"),
            },
            "risk_score": score,
            "risk_level": scorer.get_risk_level(score),
            "permissions": {
                "total": len(list(self.apk.get_permissions())),
                "all": list(self.apk.get_permissions()),
                "dangerous": dangerous_perms,
            },
        }
