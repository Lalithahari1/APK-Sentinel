import sys
from pathlib import Path

from androguard.misc import AnalyzeAPK


# ============================================================
# PHASE 11B - APK METADATA & PERMISSION ANALYSIS
# ============================================================

print("=" * 60)
print("PHASE 11B - APK METADATA & PERMISSION ANALYSIS")
print("=" * 60)


# ============================================================
# CHECK APK ARGUMENT
# ============================================================

if len(sys.argv) < 2:

    print()
    print("Usage:")
    print(
        "python src/apk_metadata.py "
        "path_to_apk.apk"
    )

    sys.exit(1)


apk_path = Path(sys.argv[1])


if not apk_path.exists():

    print()
    print("ERROR: APK not found:")
    print(apk_path)

    sys.exit(1)


print()
print("APK selected:")
print(apk_path)


# ============================================================
# ANALYZE APK
# ============================================================

print()
print("Analyzing APK with Androguard...")


try:

    a, d, dx = AnalyzeAPK(
        str(apk_path)
    )

except Exception as e:

    print()
    print("ERROR during APK analysis:")
    print(e)

    sys.exit(1)


# ============================================================
# BASIC APK INFORMATION
# ============================================================

print()
print("=" * 60)
print("APK INFORMATION")
print("=" * 60)


package_name = a.get_package()

version_name = a.get_androidversion_name()

version_code = a.get_androidversion_code()

min_sdk = a.get_min_sdk_version()

target_sdk = a.get_target_sdk_version()


print()
print("Package Name :", package_name)

print("Version Name :", version_name)

print("Version Code :", version_code)

print("Minimum SDK  :", min_sdk)

print("Target SDK   :", target_sdk)


# ============================================================
# ACTIVITIES
# ============================================================

activities = a.get_activities()

print()
print("=" * 60)
print("ACTIVITIES")
print("=" * 60)

print()

if activities:

    for activity in activities:

        print("-", activity)

else:

    print("No activities detected.")


# ============================================================
# SERVICES
# ============================================================

services = a.get_services()

print()
print("=" * 60)
print("SERVICES")
print("=" * 60)

print()

if services:

    for service in services:

        print("-", service)

else:

    print("No services detected.")


# ============================================================
# BROADCAST RECEIVERS
# ============================================================

receivers = a.get_receivers()

print()
print("=" * 60)
print("BROADCAST RECEIVERS")
print("=" * 60)

print()

if receivers:

    for receiver in receivers:

        print("-", receiver)

else:

    print("No broadcast receivers detected.")


# ============================================================
# CONTENT PROVIDERS
# ============================================================

providers = a.get_providers()

print()
print("=" * 60)
print("CONTENT PROVIDERS")
print("=" * 60)

print()

if providers:

    for provider in providers:

        print("-", provider)

else:

    print("No content providers detected.")


# ============================================================
# PERMISSIONS
# ============================================================

permissions = a.get_permissions()

print()
print("=" * 60)
print("REQUESTED PERMISSIONS")
print("=" * 60)

print()

if permissions:

    for permission in sorted(
        permissions
    ):

        print("-", permission)

else:

    print("No permissions detected.")


# ============================================================
# SUMMARY
# ============================================================

print()
print("=" * 60)
print("APK ANALYSIS SUMMARY")
print("=" * 60)

print()

print(
    "Package Name       :",
    package_name
)

print(
    "Activities         :",
    len(activities)
)

print(
    "Services           :",
    len(services)
)

print(
    "Broadcast Receivers:",
    len(receivers)
)

print(
    "Content Providers  :",
    len(providers)
)

print(
    "Permissions        :",
    len(permissions)
)

print()
print("=" * 60)
print("PHASE 11B COMPLETED")
print("=" * 60)