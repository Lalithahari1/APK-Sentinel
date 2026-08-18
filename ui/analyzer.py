import os
import re
import subprocess
import json
import math
import zipfile
from collections import Counter

# ============================================================
# APK SENTINEL - ROBUST STATIC ANALYZER
# ============================================================

SDK_PATH = os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk")


def find_tool(filename, subfolder):
    base = os.path.join(SDK_PATH, subfolder)
    if not os.path.isdir(base):
        return None

    versions = []
    try:
        versions = sorted(
            os.listdir(base),
            key=lambda x: [int(p) if p.isdigit() else p.lower()
                           for p in re.split(r"(\d+)", x)],
            reverse=True,
        )
    except Exception:
        return None

    for version in versions:
        candidate = os.path.join(base, version, filename)
        if os.path.exists(candidate):
            return candidate
    return None


APK_ANALYZER = os.path.join(
    SDK_PATH, "cmdline-tools", "latest", "bin", "apkanalyzer.bat"
)
if not os.path.exists(APK_ANALYZER):
    APK_ANALYZER = None

AAPT = find_tool("aapt.exe", "build-tools")


# ============================================================
# PERMISSION CLASSIFICATION
# ============================================================

COMMON_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.POST_NOTIFICATIONS",
}

SECURITY_RELEVANT_PERMISSIONS = {
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.NFC",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
}

HIGH_CONCERN_PERMISSIONS = {
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION",
    "android.permission.WRITE_SETTINGS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
}

PERMISSION_REASONS = {
    "CAMERA": "Allows access to the device camera; review whether camera use is expected.",
    "RECORD_AUDIO": "Allows microphone/audio capture; review whether recording is necessary.",
    "ACCESS_FINE_LOCATION": "Provides precise device location access; review the application's location purpose.",
    "ACCESS_COARSE_LOCATION": "Provides approximate device location access; review the application's location purpose.",
    "READ_CONTACTS": "Allows reading contacts; sensitive personal-data access should match the app's purpose.",
    "WRITE_CONTACTS": "Allows modifying contacts; review whether contact modification is expected.",
    "READ_SMS": "Allows reading SMS messages, which can expose sensitive communications or verification codes.",
    "SEND_SMS": "Allows sending SMS messages and may incur charges or perform actions on the user's behalf.",
    "READ_CALL_LOG": "Allows reading call history, which is sensitive personal information.",
    "WRITE_CALL_LOG": "Allows modifying call history and deserves additional review.",
    "CALL_PHONE": "Allows initiating calls without the normal dialer flow; review intended use.",
    "READ_PHONE_STATE": "Provides access to phone/device state and identifiers depending on Android version.",
    "QUERY_ALL_PACKAGES": "Allows broad package discovery; review whether visibility of installed apps is necessary.",
    "MANAGE_EXTERNAL_STORAGE": "Provides broad external-storage management access and deserves careful review.",
    "READ_EXTERNAL_STORAGE": "Allows reading shared external storage on supported Android versions.",
    "WRITE_EXTERNAL_STORAGE": "Allows writing shared external storage on supported Android versions.",
    "BLUETOOTH": "Legacy Bluetooth access; review whether Bluetooth functionality is required.",
    "BLUETOOTH_ADMIN": "Legacy Bluetooth administration capability; review whether it is required.",
    "BLUETOOTH_SCAN": "Allows Bluetooth device discovery; review whether scanning is expected.",
    "BLUETOOTH_CONNECT": "Allows communication with paired Bluetooth devices; review intended use.",
    "BLUETOOTH_ADVERTISE": "Allows the device to advertise over Bluetooth; review intended use.",
    "NFC": "Allows NFC communication; review whether NFC functionality is expected.",
    "FOREGROUND_SERVICE": "Allows long-running foreground work; review the declared service purpose.",
    "RECEIVE_BOOT_COMPLETED": "Allows startup after device boot; review whether automatic startup is necessary.",
    "REQUEST_INSTALL_PACKAGES": "Can enable installation of packages outside the normal app-store flow; high-concern capability.",
    "REQUEST_DELETE_PACKAGES": "Can request package deletion and deserves careful review.",
    "UPDATE_PACKAGES_WITHOUT_USER_ACTION": "Can support package updates without normal user interaction; high-concern capability.",
    "WRITE_SETTINGS": "Can modify system settings and should be carefully reviewed.",
    "SYSTEM_ALERT_WINDOW": "Can draw over other applications; this can enable deceptive or intrusive UI.",
    "PACKAGE_USAGE_STATS": "Provides access to app-usage information and can expose sensitive behavioral data.",
    "BIND_ACCESSIBILITY_SERVICE": "Accessibility services can observe/interact with other apps and require especially careful review.",
}


def classify_permission(permission):
    if permission in HIGH_CONCERN_PERMISSIONS:
        return "HIGH_CONCERN", 3
    if permission in SECURITY_RELEVANT_PERMISSIONS:
        return "SECURITY_RELEVANT", 1
    if permission in COMMON_PERMISSIONS:
        return "COMMON", 0
    return "OTHER", 0


def classify_permissions(permissions):
    categories = {
        "common": [],
        "security_relevant": [],
        "high_concern": [],
        "other": [],
    }
    details = []

    for permission in permissions:
        category, score = classify_permission(permission)
        key = {
            "COMMON": "common",
            "SECURITY_RELEVANT": "security_relevant",
            "HIGH_CONCERN": "high_concern",
            "OTHER": "other",
        }[category]
        categories[key].append(permission)

        if category != "COMMON" and category != "OTHER":
            short = permission.replace("android.permission.", "")
            details.append({
                "permission": permission,
                "name": short,
                "category": category,
                "score": score,
                "reason": PERMISSION_REASONS.get(
                    short,
                    "This permission provides a security-sensitive capability and should be reviewed in application context.",
                ),
            })

    return categories, details


# ============================================================
# COMMAND HELPERS
# ============================================================

def run_command(command):
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            shell=isinstance(command, str),
            timeout=45,
        )
        return completed.stdout.strip(), completed.stderr.strip(), completed.returncode
    except Exception as exc:
        return "", str(exc), -1


def run_apkanalyzer(*args):
    if not APK_ANALYZER or not os.path.exists(APK_ANALYZER):
        return ""

    # .bat files are executed through cmd.exe on Windows.
    command = ["cmd", "/c", APK_ANALYZER, *map(str, args)]
    out, _, code = run_command(command)
    return out if code == 0 else out


def run_aapt(*args):
    if not AAPT or not os.path.exists(AAPT):
        return ""
    command = [AAPT, *map(str, args)]
    out, _, code = run_command(command)
    return out if code == 0 else out


# ============================================================
# BASIC APK METADATA
# ============================================================

def parse_aapt_badging(apk_path):
    output = run_aapt("dump", "badging", apk_path)
    meta = {
        "package": "Unknown",
        "version_name": "Unknown",
        "version_code": "Unknown",
        "min_sdk": "Unknown",
        "target_sdk": "Unknown",
    }

    match = re.search(
        r"package:\s+name='([^']+)'\s+versionCode='([^']+)'\s+versionName='([^']*)'",
        output,
        re.I,
    )
    if match:
        meta["package"] = match.group(1)
        meta["version_code"] = match.group(2)
        meta["version_name"] = match.group(3) or "Unknown"

    min_match = re.search(r"sdkVersion:'([^']+)'", output)
    target_match = re.search(r"targetSdkVersion:'([^']+)'", output)
    if min_match:
        meta["min_sdk"] = min_match.group(1)
    if target_match:
        meta["target_sdk"] = target_match.group(1)

    return meta


# ============================================================
# PERMISSIONS
# ============================================================

def clean_permissions(text):
    found = re.findall(r"android\.permission\.[A-Z0-9_]+", text or "")
    return list(dict.fromkeys(found))


def get_permissions(apk_path):
    output = run_apkanalyzer("manifest", "permissions", apk_path)
    permissions = clean_permissions(output)
    if permissions:
        return permissions

    output = run_aapt("dump", "permissions", apk_path)
    permissions = clean_permissions(output)
    if permissions:
        return permissions

    # Last fallback: inspect manifest text.
    output = run_apkanalyzer("manifest", "print", apk_path)
    return clean_permissions(output)


# ============================================================
# MANIFEST / COMPONENTS
# ============================================================

def get_manifest(apk_path):
    """Return as much decoded manifest information as possible.

    apkanalyzer and aapt expose slightly different representations.  The
    previous implementation stopped after the first non-empty output, which
    could leave the component parser with a representation it did not match.
    We now combine both outputs and let extract_components parse them.
    """
    outputs = []

    output = run_apkanalyzer("manifest", "print", apk_path)
    if output:
        outputs.append(output)

    output = run_aapt(
        "dump", "xmltree", apk_path,
        "--file", "AndroidManifest.xml"
    )
    if output and output not in outputs:
        outputs.append(output)

    return "\n\n".join(outputs)


def extract_components(manifest_text):
    """Extract Android components from apkanalyzer/aapt manifest output.

    Supports: activity, activity-alias, service, receiver and provider.
    Handles both apkanalyzer ``E:/A:`` output and XML-like output.
    """
    components = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }

    if not manifest_text:
        return components

    def add(kind, name):
        name = str(name or "").strip().strip("'\"")
        if not name:
            return
        # aapt can print a resource/reference wrapper around values.
        name = re.sub(r"^.*?\b(?:string|raw):", "", name, flags=re.I)
        if name and name not in components[kind]:
            components[kind].append(name)

    lines = manifest_text.splitlines()
    current_type = None

    for line in lines:
        stripped = line.strip()

        # apkanalyzer / aapt xmltree element marker.
        m_type = re.match(
            r"E:\s*(activity-alias|activity|service|receiver|provider)\b",
            stripped,
            re.I,
        )
        if m_type:
            raw_type = m_type.group(1).lower()
            current_type = "activities" if raw_type in {"activity", "activity-alias"} else raw_type + "s"
            continue

        if current_type:
            # Quoted value: android:name(...)="com.example.Main"
            m_name = re.search(
                r"android:name(?:\([^)]*\))?\s*=\s*\"([^\"]+)\"",
                stripped,
                re.I,
            )
            if not m_name:
                # Single quotes are used by some XML renderers.
                m_name = re.search(
                    r"android:name(?:\([^)]*\))?\s*=\s*'([^']+)'",
                    stripped,
                    re.I,
                )
            if not m_name:
                # aapt can emit: A: android:name(...)=(type 0x10)0x...
                # In that case there may still be a quoted resolved value
                # later in the line.
                m_name = re.search(
                    r"android:name[^=]*=.*?\"([^\"]+)\"",
                    stripped,
                    re.I,
                )

            if m_name:
                add(current_type, m_name.group(1))
                current_type = None

    # XML-like fallback, including attributes that span additional spaces.
    xml_patterns = {
        "activities": r"<(?:activity|activity-alias)\b[^>]*?android:name\s*=\s*['\"]([^'\"]+)['\"]",
        "services": r"<service\b[^>]*?android:name\s*=\s*['\"]([^'\"]+)['\"]",
        "receivers": r"<receiver\b[^>]*?android:name\s*=\s*['\"]([^'\"]+)['\"]",
        "providers": r"<provider\b[^>]*?android:name\s*=\s*['\"]([^'\"]+)['\"]",
    }

    for kind, pattern in xml_patterns.items():
        for name in re.findall(pattern, manifest_text, re.I | re.S):
            add(kind, name)

    return components


def detect_boot_receiver(manifest_text, receivers):
    if not manifest_text:
        return False

    boot_action = re.search(
        r"android\.intent\.action\.BOOT_COMPLETED",
        manifest_text,
        re.I,
    )
    return bool(boot_action and receivers)


# ============================================================
# APK CONTENT / STATIC METRICS
# ============================================================

TEXT_EXTENSIONS = {
    ".xml", ".json", ".txt", ".properties", ".html", ".htm", ".js",
    ".css", ".smali", ".java", ".kt", ".gradle", ".pro", ".cfg", ".ini",
    ".csv", ".md", ".mf", ".sf", ".rsa",
}

IGNORED_PREFIXES = (
    "META-INF/com/android/",
)


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(
        -sum((c / n) * math.log2(c / n) for c in counts.values()),
        3,
    )


def valid_domain(host):
    host = host.lower().strip(".")
    if not host or len(host) > 253:
        return False
    if host in {
        "schemas.android.com",
        "www.w3.org",
        "xmlpull.org",
        "apache.org",
        "android.googlesource.com",
    }:
        return False

    if "." not in host:
        return False

    # Avoid Java/Kotlin class names such as:
    # org.foo.Bar.SomeClass because they do not end in a normal TLD.
    labels = host.split(".")
    if any(not re.fullmatch(r"[a-z0-9-]{1,63}", x) for x in labels):
        return False
    if labels[-1] not in {
        "com", "org", "net", "io", "dev", "app", "ai", "co", "in", "uk",
        "de", "fr", "jp", "cn", "xyz", "me", "info", "biz", "edu", "gov",
        "tv", "ly", "be", "ch", "ca", "au", "us",
    }:
        return False
    return True


def extract_network_indicators(apk_path):
    urls = set()
    domains = set()

    try:
        with zipfile.ZipFile(apk_path, "r") as apk:
            for info in apk.infolist():
                name = info.filename
                suffix = os.path.splitext(name.lower())[1]

                # Do not scan arbitrary binary/Dex blobs for domains.
                # They create large numbers of false positives from class names.
                if suffix not in TEXT_EXTENSIONS:
                    continue
                if name.startswith(IGNORED_PREFIXES):
                    continue
                if info.file_size > 2_000_000:
                    continue

                try:
                    data = apk.read(info)
                    text = data.decode("utf-8", errors="ignore")
                except Exception:
                    continue

                for url in re.findall(
                    r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
                    text,
                    re.I,
                ):
                    url = url.rstrip(").,;>'\"")
                    host_match = re.match(r"https?://([^/:?#]+)", url, re.I)
                    if host_match and valid_domain(host_match.group(1)):
                        urls.add(url)
                        domains.add(host_match.group(1).lower())

                for host in re.findall(
                    r"\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b",
                    text,
                    re.I,
                ):
                    if valid_domain(host):
                        domains.add(host.lower())

    except (zipfile.BadZipFile, OSError):
        pass

    return sorted(urls)[:100], sorted(domains)[:100]


def inspect_apk_contents(apk_path):
    result = {
        "apk_files": 0,
        "assets": 0,
        "native_libraries": 0,
        "signature_files": 0,
        "dex_files": [],
        "dex_entropy": [],
    }

    try:
        with zipfile.ZipFile(apk_path, "r") as apk:
            names = apk.namelist()
            result["apk_files"] = len(names)
            result["assets"] = sum(
                1 for n in names if n.startswith("assets/")
            )
            result["native_libraries"] = sum(
                1 for n in names if n.startswith("lib/") and n.endswith(".so")
            )
            result["signature_files"] = sum(
                1 for n in names
                if n.startswith("META-INF/")
                and n.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))
            )

            for info in apk.infolist():
                if info.filename.lower().endswith(".dex"):
                    result["dex_files"].append(info.filename)
                    try:
                        data = apk.read(info.filename)
                        result["dex_entropy"].append({
                            "file": info.filename,
                            "size": info.file_size,
                            "entropy": shannon_entropy(data),
                        })
                    except Exception:
                        pass

    except (zipfile.BadZipFile, OSError):
        pass

    return result


# ============================================================
# STATIC INDICATORS
# ============================================================

def static_code_indicators(apk_path):
    # These are intentionally conservative and only scan text resources.
    indicators = []
    try:
        with zipfile.ZipFile(apk_path, "r") as apk:
            for info in apk.infolist():
                suffix = os.path.splitext(info.filename.lower())[1]
                if suffix not in TEXT_EXTENSIONS or info.file_size > 2_000_000:
                    continue
                try:
                    text = apk.read(info.filename).decode("utf-8", errors="ignore")
                except Exception:
                    continue

                rules = {
                    "Runtime command execution": r"\b(Runtime\.getRuntime|ProcessBuilder)\b",
                    "Dynamic code loading": r"\b(DexClassLoader|PathClassLoader)\b",
                    "WebView JavaScript": r"\bsetJavaScriptEnabled\s*\(",
                }
                for label, pattern in rules.items():
                    if re.search(pattern, text, re.I):
                        indicators.append({
                            "indicator": label,
                            "file": info.filename,
                        })
    except Exception:
        pass

    return indicators[:50]


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_apk(apk_path):
    if not apk_path or not os.path.isfile(apk_path):
        return None

    result = {
        "apk_name": os.path.basename(apk_path),
        "package": "Unknown",
        "version_name": "Unknown",
        "version_code": "Unknown",
        "min_sdk": "Unknown",
        "target_sdk": "Unknown",
        "permissions": [],
        "suspicious_permissions": [],
        "permission_categories": {
            "common": [],
            "security_relevant": [],
            "high_concern": [],
            "other": [],
        },
        "risk_signal_details": [],
        "background_service": False,
        "boot_receiver": False,
        "risk_score": 0,
        "risk_level": "LOW",
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "urls": [],
        "domains": [],
        "static_indicators": [],
        "apk_files": 0,
        "assets": 0,
        "native_libraries": 0,
        "signature_files": 0,
        "dex_files": [],
        "dex_entropy": [],
    }

    # Metadata
    meta = parse_aapt_badging(apk_path)
    result.update(meta)

    # Permissions
    permissions = get_permissions(apk_path)
    result["permissions"] = permissions

    categories, details = classify_permissions(permissions)
    result["permission_categories"] = categories
    result["risk_signal_details"] = details
    result["suspicious_permissions"] = [
        item["permission"] for item in details
    ]

    result["risk_score"] = sum(
        item["score"] for item in details
    )

    # Manifest/components
    manifest = get_manifest(apk_path)
    components = extract_components(manifest)

    result["activities"] = components["activities"]
    result["services"] = components["services"]
    result["receivers"] = components["receivers"]
    result["providers"] = components["providers"]

    result["background_service"] = bool(result["services"])
    result["boot_receiver"] = detect_boot_receiver(
        manifest,
        result["receivers"],
    )

    # Component signals are only added once, not once per component.
    if result["background_service"]:
        result["risk_score"] += 2
        result["risk_signal_details"].append({
            "permission": "ANDROID_COMPONENT: SERVICE",
            "name": "Background Service",
            "category": "COMPONENT",
            "score": 2,
            "reason": "One or more background services are declared and should be reviewed in application context.",
        })

    if result["boot_receiver"]:
        result["risk_score"] += 2
        result["risk_signal_details"].append({
            "permission": "ANDROID_COMPONENT: BOOT_RECEIVER",
            "name": "Boot Receiver",
            "category": "COMPONENT",
            "score": 2,
            "reason": "The APK registers for device boot events and may start work automatically after boot.",
        })

    # APK inventory
    inventory = inspect_apk_contents(apk_path)
    result.update(inventory)

    # Network indicators
    urls, domains = extract_network_indicators(apk_path)
    result["urls"] = urls
    result["domains"] = domains

    # Conservative static indicators
    result["static_indicators"] = static_code_indicators(apk_path)

    # Final heuristic score
    score = int(result["risk_score"])
    if score >= 10:
        result["risk_level"] = "HIGH"
    elif score >= 4:
        result["risk_level"] = "MEDIUM"
    else:
        result["risk_level"] = "LOW"

    # Useful summary values for the UI.
    result["summary"] = {
        "permissions": len(permissions),
        "risk_signals": len(result["risk_signal_details"]),
        "common_permissions": len(categories["common"]),
        "security_relevant_permissions": len(categories["security_relevant"]),
        "high_concern_permissions": len(categories["high_concern"]),
        "other_permissions": len(categories["other"]),
        "activities": len(result["activities"]),
        "services": len(result["services"]),
        "receivers": len(result["receivers"]),
        "providers": len(result["providers"]),
        "urls": len(urls),
        "domains": len(domains),
    }

    return result


def display_result(result):
    print(json.dumps(result, indent=2, default=str))


def save_result(result, output_path=None):
    if output_path is None:
        project_root = os.path.dirname(os.path.dirname(__file__))
        results_folder = os.path.join(project_root, "results")
        os.makedirs(results_folder, exist_ok=True)
        output_path = os.path.join(results_folder, "analysis_result.json")

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4, default=str)

    return output_path


if __name__ == "__main__":
    apk_path = input("Enter APK path: ").strip()
    result = analyze_apk(apk_path)
    if result:
        display_result(result)
        print("\nSaved:", save_result(result))
