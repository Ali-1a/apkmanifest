from xml.etree import ElementTree

ANDROID_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": ("Read SMS", "Can read all your text messages."),
    "android.permission.SEND_SMS": ("Send SMS", "Can send SMS messages."),
    "android.permission.RECEIVE_SMS": ("Receive SMS", "Can intercept incoming SMS."),
    "android.permission.READ_CONTACTS": ("Read contacts", "Can access your entire contact list."),
    "android.permission.WRITE_CONTACTS": ("Modify contacts", "Can add, edit or delete contacts."),
    "android.permission.RECORD_AUDIO": ("Record audio", "Can activate microphone at any time."),
    "android.permission.CAMERA": ("Access camera", "Can take photos and record video."),
    "android.permission.ACCESS_FINE_LOCATION": ("Precise location", "Can track exact physical location."),
    "android.permission.ACCESS_COARSE_LOCATION": ("Approximate location", "Can determine location via Wi-Fi."),
    "android.permission.READ_EXTERNAL_STORAGE": ("Read storage", "Can read all files on external storage."),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("Write storage", "Can create, modify or delete files on storage."),
    "android.permission.READ_PHONE_STATE": ("Read phone state", "Can access phone number and IMEI."),
    "android.permission.CALL_PHONE": ("Make calls", "Can make calls without user confirmation."),
    "android.permission.READ_CALENDAR": ("Read calendar", "Can read all calendar events."),
    "android.permission.WRITE_CALENDAR": ("Modify calendar", "Can create, edit or delete calendar events."),
    "android.permission.BODY_SENSORS": ("Body sensors", "Can access heart rate and other sensors."),
    "android.permission.READ_MEDIA_IMAGES": ("Read images", "Can access all photos on the device."),
    "android.permission.READ_MEDIA_VIDEO": ("Read videos", "Can access all videos on the device."),
    "android.permission.READ_MEDIA_AUDIO": ("Read audio", "Can access all audio files."),
}

HIGH_RISK_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW": ("Draw over other apps", "Abused for clickjacking overlays."),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Install unknown apps", "Can silently install other APKs."),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("Start at boot", "App starts automatically on every reboot."),
}

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class ManifestChecker:
    def __init__(self, apk):
        self.apk = apk
        self.findings = []
        self._manifest_xml = self._parse_manifest()

    def check_all(self):
        self.findings = []
        self._check_dangerous_permissions()
        self._check_high_risk_permissions()
        self._check_debuggable()
        self._check_allow_backup()
        self._check_cleartext_traffic()
        self._check_exported_components()
        self._check_min_sdk()
        return self.findings

    def get_dangerous_permissions(self):
        permissions = list(self.apk.get_permissions())
        result = []
        for p in permissions:
            if p in ANDROID_DANGEROUS_PERMISSIONS:
                name, desc = ANDROID_DANGEROUS_PERMISSIONS[p]
                result.append({"permission": p, "description": name, "detail": desc, "classification": "dangerous"})
            elif p in HIGH_RISK_PERMISSIONS:
                name, desc = HIGH_RISK_PERMISSIONS[p]
                result.append({"permission": p, "description": name, "detail": desc, "classification": "high-risk"})
        return result

    def _parse_manifest(self):
        try:
            raw = self.apk.get_android_manifest_axml().get_xml()
            return ElementTree.fromstring(raw)
        except Exception:
            return None

    def _get_app_attr(self, attr):
        if self._manifest_xml is not None:
            app_el = self._manifest_xml.find("application")
            if app_el is not None:
                val = app_el.get(f"{{{ANDROID_NS}}}{attr}")
                if val is not None:
                    return val
                val = app_el.get(attr)
                if val is not None:
                    return val
        try:
            return self.apk.get_element("application", attr)
        except Exception:
            return None

    def _check_dangerous_permissions(self):
        permissions = list(self.apk.get_permissions())
        found = [p for p in permissions if p in ANDROID_DANGEROUS_PERMISSIONS]
        if not found:
            return
        details = []
        for p in found:
            name, desc = ANDROID_DANGEROUS_PERMISSIONS[p]
            details.append(f"{p.split('.')[-1]} — {desc}")
        severity = "critical" if len(found) >= 5 else "medium" if len(found) >= 3 else "low"
        self.findings.append({
            "id": "PERM-001",
            "title": f"{len(found)} Android dangerous permission(s) declared",
            "description": f"The app declares {len(found)} permission(s) that Android officially classifies as dangerous. These require explicit user approval and grant access to sensitive data.",
            "severity": severity,
            "confidence": "HIGH",
            "masvs": "MASVS-PLATFORM-2",
            "masvs_url": "https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/",
            "fix": "Request only permissions that are strictly necessary. Remove any permission the app does not actively use.",
            "category": "Permissions",
            "owasp": "M1: Improper Platform Usage",
            "details": details,
        })

    def _check_high_risk_permissions(self):
        permissions = list(self.apk.get_permissions())
        found = [p for p in permissions if p in HIGH_RISK_PERMISSIONS]
        if not found:
            return
        details = []
        for p in found:
            name, desc = HIGH_RISK_PERMISSIONS[p]
            details.append(f"{p.split('.')[-1]} — {desc}")
        self.findings.append({
            "id": "PERM-002",
            "title": f"{len(found)} high-risk permission(s) declared",
            "description": "These permissions are frequently abused by spyware and malware. Verify each one is strictly necessary.",
            "severity": "medium",
            "confidence": "HIGH",
            "masvs": "MASVS-PLATFORM-2",
            "masvs_url": "https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/",
            "fix": "Audit each permission and remove any that are not required for core functionality.",
            "category": "Permissions",
            "owasp": "M1: Improper Platform Usage",
            "details": details,
        })

    def _check_debuggable(self):
        val = self._get_app_attr("debuggable")
        if val is not None and str(val).lower() == "true":
            self.findings.append({
                "id": "MAN-001",
                "title": "Application is debuggable",
                "description": "android:debuggable='true' allows any attacker with ADB access to attach a debugger, read memory, and extract secrets. Must be false in all production builds.",
                "severity": "critical",
                "confidence": "HIGH",
                "masvs": "MASVS-RESILIENCE-2",
                "masvs_url": "https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/",
                "fix": "Set android:debuggable=\"false\" in AndroidManifest.xml. Ensure release builds use a release signing config.",
                "category": "Manifest",
                "owasp": "M10: Extraneous Functionality",
                "details": ["android:debuggable is explicitly set to true in AndroidManifest.xml"],
            })

    def _check_allow_backup(self):
        val = self._get_app_attr("allowBackup")
        try:
            target_sdk_int = int(self.apk.get_target_sdk_version() or 0)
        except (ValueError, TypeError):
            target_sdk_int = 0
        if val is not None and str(val).lower() == "true":
            self.findings.append({
                "id": "MAN-002",
                "title": "Application backup is explicitly enabled",
                "description": "android:allowBackup='true' allows anyone with ADB access to extract the app private data using adb backup.",
                "severity": "medium",
                "confidence": "HIGH",
                "masvs": "MASVS-STORAGE-1",
                "masvs_url": "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/",
                "fix": "Set android:allowBackup=\"false\" in AndroidManifest.xml unless backup is a required feature.",
                "category": "Manifest",
                "owasp": "M2: Insecure Data Storage",
                "details": ["android:allowBackup is explicitly set to true in AndroidManifest.xml"],
            })
        elif val is None and target_sdk_int > 0 and target_sdk_int < 31:
            self.findings.append({
                "id": "MAN-002",
                "title": "Backup may be enabled (attribute absent, targetSdk < 31)",
                "description": "android:allowBackup is not set. For apps targeting API < 31 the default is true.",
                "severity": "low",
                "confidence": "MEDIUM",
                "masvs": "MASVS-STORAGE-1",
                "masvs_url": "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/",
                "fix": "Explicitly set android:allowBackup=\"false\" in AndroidManifest.xml.",
                "category": "Manifest",
                "owasp": "M2: Insecure Data Storage",
                "details": [f"targetSdkVersion={target_sdk_int}"],
            })

    def _check_cleartext_traffic(self):
        val = self._get_app_attr("usesCleartextTraffic")
        if val is not None and str(val).lower() == "true":
            self.findings.append({
                "id": "NET-001",
                "title": "Cleartext HTTP traffic explicitly permitted",
                "description": "android:usesCleartextTraffic='true' allows unencrypted HTTP connections. An attacker on the same network can read or modify all traffic.",
                "severity": "critical",
                "confidence": "HIGH",
                "masvs": "MASVS-NETWORK-1",
                "masvs_url": "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/",
                "fix": "Remove android:usesCleartextTraffic and use HTTPS for all network connections.",
                "category": "Network",
                "owasp": "M3: Insecure Communication",
                "details": ["android:usesCleartextTraffic is explicitly set to true in AndroidManifest.xml"],
            })

    def _check_exported_components(self):
        if self._manifest_xml is None:
            return
        exported_names = []
        for tag in ("activity", "service", "receiver"):
            for el in self._manifest_xml.iter(tag):
                exp = el.get(f"{{{ANDROID_NS}}}exported") or el.get("exported")
                perm = el.get(f"{{{ANDROID_NS}}}permission") or el.get("permission")
                name = el.get(f"{{{ANDROID_NS}}}name") or el.get("name", "unknown")
                if exp and exp.lower() == "true" and not perm:
                    exported_names.append(f"{tag}: ...{name.split('.')[-1]}")
        if len(exported_names) > 2:
            self.findings.append({
                "id": "EXP-001",
                "title": f"{len(exported_names)} components exported without permission",
                "description": "These components are accessible by any other app on the device with no permission requirement.",
                "severity": "medium",
                "confidence": "HIGH",
                "masvs": "MASVS-PLATFORM-1",
                "masvs_url": "https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/",
                "fix": "Set android:exported=\"false\" on components that do not need to be accessed by other apps.",
                "category": "Components",
                "owasp": "M1: Improper Platform Usage",
                "details": exported_names[:10],
            })

    def _check_min_sdk(self):
        try:
            min_sdk = self.apk.get_min_sdk_version()
            if min_sdk and int(min_sdk) < 21:
                self.findings.append({
                    "id": "SDK-001",
                    "title": f"Supports Android < 5.0 (minSdkVersion={min_sdk})",
                    "description": "Supporting API < 21 means the app may run on devices lacking runtime permissions, full-disk encryption, and Network Security Config.",
                    "severity": "low",
                    "confidence": "HIGH",
                    "masvs": "MASVS-RESILIENCE-1",
                    "masvs_url": "https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/",
                    "fix": "Raise minSdkVersion to at least 21 (Android 5.0) to ensure modern security features are available.",
                    "category": "Configuration",
                    "owasp": "M9: Reverse Engineering",
                    "details": [f"minSdkVersion={min_sdk} (recommended >= 21)"],
                })
        except Exception:
            pass
