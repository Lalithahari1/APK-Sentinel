import sys
import pandas as pd
from pathlib import Path

from androguard.misc import AnalyzeAPK


# ============================================================
# PHASE 10E - REAL APK STATIC FEATURE EXTRACTION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

FEATURE_FILE = (
    BASE_DIR
    / "datasets"
    / "preprocessed_dataset.csv"
)

OUTPUT_DIR = (
    BASE_DIR
    / "results"
    / "apk_analysis"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

OUTPUT_FILE = OUTPUT_DIR / "apk_features.csv"


print("=" * 60)
print("PHASE 10E - REAL APK STATIC FEATURE EXTRACTION")
print("=" * 60)


# ============================================================
# 1. CHECK APK ARGUMENT
# ============================================================

if len(sys.argv) < 2:

    print()
    print("Usage:")
    print(
        "python src/apk_static_analyzer.py "
        "path_to_apk.apk"
    )

    sys.exit(1)


apk_path = Path(sys.argv[1])


if not apk_path.exists():

    print()
    print("APK not found:")
    print(apk_path)

    sys.exit(1)


print()
print("APK selected:")
print(apk_path)


# ============================================================
# 2. LOAD TRAINING FEATURE VOCABULARY
# ============================================================

print()
print("Loading trained feature vocabulary...")

df = pd.read_csv(FEATURE_FILE)

all_features = [
    column
    for column in df.columns
    if column != "Class"
]

static_features = [
    column
    for column in all_features
    if not column.startswith("dynamic_")
]

dynamic_features = [
    column
    for column in all_features
    if column.startswith("dynamic_")
]


print(
    f"Total model features : {len(all_features)}"
)

print(
    f"Static features      : {len(static_features)}"
)

print(
    f"Dynamic features     : {len(dynamic_features)}"
)


# ============================================================
# 3. ANALYZE APK USING ANDROGUARD
# ============================================================

print()
print("Analyzing APK...")

try:

    a, d, dx = AnalyzeAPK(
        str(apk_path)
    )

except Exception as e:

    print()
    print("APK analysis failed:")
    print(e)

    sys.exit(1)


# ============================================================
# 4. COLLECT STATIC APK FEATURES
# ============================================================

detected_features = set()


# ------------------------------------------------------------
# Permissions
# ------------------------------------------------------------

try:

    permissions = a.get_permissions()

    for permission in permissions:

        detected_features.add(permission)

except Exception:

    pass


# ------------------------------------------------------------
# Activities
# ------------------------------------------------------------

try:

    activities = a.get_activities()

    for activity in activities:

        detected_features.add(activity)

except Exception:

    pass


# ------------------------------------------------------------
# Services
# ------------------------------------------------------------

try:

    services = a.get_services()

    for service in services:

        detected_features.add(service)

except Exception:

    pass


# ------------------------------------------------------------
# Receivers
# ------------------------------------------------------------

try:

    receivers = a.get_receivers()

    for receiver in receivers:

        detected_features.add(receiver)

except Exception:

    pass


# ------------------------------------------------------------
# Providers
# ------------------------------------------------------------

try:

    providers = a.get_providers()

    for provider in providers:

        detected_features.add(provider)

except Exception:

    pass


# ------------------------------------------------------------
# Manifest information
# ------------------------------------------------------------

try:

    manifest = a.get_android_manifest_xml()

    manifest_text = str(manifest)

    for feature in static_features:

        if feature in manifest_text:

            detected_features.add(feature)

except Exception:

    pass


# ============================================================
# 5. CREATE 340-FEATURE VECTOR
# ============================================================

feature_vector = {
    feature: 0
    for feature in all_features
}


for feature in detected_features:

    if feature in feature_vector:

        feature_vector[feature] = 1


# ============================================================
# 6. DYNAMIC FEATURES
# ============================================================

# Static APK analysis cannot observe runtime behavior.
# Therefore dynamic features remain 0 unless a runtime
# execution trace is provided.

for feature in dynamic_features:

    feature_vector[feature] = 0


# ============================================================
# 7. CREATE DATAFRAME IN TRAINING ORDER
# ============================================================

result = pd.DataFrame(
    [
        [
            feature_vector[feature]
            for feature in all_features
        ]
    ],
    columns=all_features
)


# ============================================================
# 8. SAVE FEATURE VECTOR
# ============================================================

result.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# 9. RESULTS
# ============================================================

active_features = int(
    result.iloc[0].sum()
)

dynamic_active = int(
    result[dynamic_features].iloc[0].sum()
)

static_active = int(
    result[static_features].iloc[0].sum()
)


print()
print("=" * 60)
print("APK FEATURE EXTRACTION RESULT")
print("=" * 60)

print(
    f"Static features detected : {static_active}"
)

print(
    f"Dynamic features detected: {dynamic_active}"
)

print(
    f"Total active features    : {active_features}"
)

print(
    f"Feature vector shape     : {result.shape}"
)

print()
print(
    "NOTE: Dynamic features were not obtained "
    "from runtime execution."
)

print(
    "They have been set to 0 for this static APK analysis."
)

print()
print("APK feature vector saved to:")
print(OUTPUT_FILE)

print()
print("=" * 60)
print("PHASE 10E COMPLETED")
print("=" * 60)