import sys
import hashlib
from pathlib import Path
from datetime import datetime

import pandas as pd
import tensorflow as tf


# ============================================================
# PHASE 11A - APK SECURITY REPORT
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    BASE_DIR
    / "models"
    / "final_dnn_model.keras"
)

FEATURE_PATH = (
    BASE_DIR
    / "results"
    / "apk_analysis"
    / "apk_features.csv"
)

REPORT_DIR = (
    BASE_DIR
    / "results"
    / "apk_reports"
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


print("=" * 60)
print("PHASE 11A - APK SECURITY REPORT")
print("=" * 60)


# ============================================================
# CHECK APK ARGUMENT
# ============================================================

if len(sys.argv) < 2:

    print()
    print("Usage:")
    print(
        "python src/apk_prediction_report.py "
        "path_to_apk.apk"
    )

    sys.exit(1)


apk_path = Path(sys.argv[1])


if not apk_path.exists():

    print()
    print("ERROR: APK file not found:")
    print(apk_path)

    sys.exit(1)


print()
print("APK selected:")
print(apk_path)


# ============================================================
# APK INFORMATION
# ============================================================

print()
print("Collecting APK information...")


apk_name = apk_path.name

apk_size_bytes = apk_path.stat().st_size

apk_size_mb = (
    apk_size_bytes
    / (1024 * 1024)
)


# ============================================================
# SHA-256 HASH
# ============================================================

print("Calculating SHA-256...")


sha256 = hashlib.sha256()

with open(apk_path, "rb") as f:

    for block in iter(
        lambda: f.read(1024 * 1024),
        b""
    ):

        sha256.update(block)


apk_hash = sha256.hexdigest()


# ============================================================
# LOAD FEATURE VECTOR
# ============================================================

print()
print("Loading APK feature vector...")


if not FEATURE_PATH.exists():

    print()
    print("ERROR: Feature vector not found:")
    print(FEATURE_PATH)

    print()
    print(
        "Run Phase 10E before generating the report."
    )

    sys.exit(1)


X = pd.read_csv(
    FEATURE_PATH
)


print(
    f"Feature vector shape: {X.shape}"
)


# ============================================================
# VERIFY FEATURE COUNT
# ============================================================

if X.shape[1] != 340:

    print()
    print(
        f"ERROR: Expected 340 features, "
        f"but found {X.shape[1]}."
    )

    sys.exit(1)


# ============================================================
# STATIC / DYNAMIC FEATURE INFORMATION
# ============================================================

all_features = list(
    X.columns
)


static_features = [
    feature
    for feature in all_features
    if not feature.startswith("dynamic_")
]


dynamic_features = [
    feature
    for feature in all_features
    if feature.startswith("dynamic_")
]


static_active = int(
    X[static_features]
    .iloc[0]
    .sum()
)


dynamic_active = int(
    X[dynamic_features]
    .iloc[0]
    .sum()
)


total_active = int(
    X.iloc[0]
    .sum()
)


# ============================================================
# LOAD DNN
# ============================================================

print()
print("Loading DNN model...")


model = tf.keras.models.load_model(
    MODEL_PATH
)


print("DNN model loaded successfully.")


# ============================================================
# PREDICTION
# ============================================================

print()
print("Generating malware prediction...")


probability = float(
    model.predict(
        X.astype("float32"),
        verbose=0
    )[0][0]
)


prediction = (
    1
    if probability >= 0.5
    else 0
)


if prediction == 1:

    label = "Malware"

    confidence = probability

else:

    label = "Benign"

    confidence = 1 - probability


# ============================================================
# RISK LEVEL
# ============================================================

if prediction == 0:

    risk = "LOW"

elif probability >= 0.90:

    risk = "HIGH"

elif probability >= 0.70:

    risk = "MEDIUM"

else:

    risk = "LOW"


benign_probability = 1 - probability


# ============================================================
# ACTIVE STATIC FEATURES
# ============================================================

active_static_features = []


for feature in static_features:

    value = float(
        X.loc[0, feature]
    )

    if value != 0:

        active_static_features.append(
            feature
        )


# ============================================================
# REPORT PATH
# ============================================================

timestamp = datetime.now().strftime(
    "%Y%m%d_%H%M%S"
)


report_path = (
    REPORT_DIR
    / f"{apk_path.stem}_security_report_{timestamp}.txt"
)


csv_path = (
    REPORT_DIR
    / f"{apk_path.stem}_prediction_{timestamp}.csv"
)


# ============================================================
# CREATE CSV RESULT
# ============================================================

result = pd.DataFrame(
    [{
        "APK_Name": apk_name,
        "APK_Size_MB": round(
            apk_size_mb,
            2
        ),
        "SHA256": apk_hash,
        "Total_Features": 340,
        "Static_Features": len(
            static_features
        ),
        "Dynamic_Features": len(
            dynamic_features
        ),
        "Static_Active": static_active,
        "Dynamic_Active": dynamic_active,
        "Total_Active": total_active,
        "Prediction": label,
        "Malware_Probability": round(
            probability,
            6
        ),
        "Benign_Probability": round(
            benign_probability,
            6
        ),
        "Confidence": round(
            confidence,
            6
        ),
        "Risk_Level": risk
    }]
)


result.to_csv(
    csv_path,
    index=False
)


# ============================================================
# CREATE TEXT REPORT
# ============================================================

report = f"""
============================================================
        ANDROID MALWARE SECURITY REPORT
============================================================

REPORT GENERATED
------------------------------------------------------------
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}


============================================================
APK INFORMATION
============================================================

APK Name:
{apk_name}

APK Path:
{apk_path}

APK Size:
{apk_size_mb:.2f} MB

SHA-256:
{apk_hash}


============================================================
FEATURE ANALYSIS
============================================================

Total Model Features:
340

Static Features:
{len(static_features)}

Dynamic Features:
{len(dynamic_features)}

Active Static Features:
{static_active}

Active Dynamic Features:
{dynamic_active}

Total Active Features:
{total_active}


============================================================
DETECTED STATIC FEATURES
============================================================
"""


if active_static_features:

    for feature in active_static_features:

        report += (
            f"\n- {feature}"
        )

else:

    report += (
        "\nNo active static features detected."
    )


report += f"""

============================================================
MACHINE LEARNING ANALYSIS
============================================================

Model:
Final DNN

Model Accuracy:
98.17%

ROC-AUC:
99.70%

Prediction:
{label.upper()}

Malware Probability:
{probability * 100:.2f}%

Benign Probability:
{benign_probability * 100:.2f}%

Confidence:
{confidence * 100:.2f}%

Risk Level:
{risk}


============================================================
FINAL ASSESSMENT
============================================================
"""


if prediction == 1:

    report += """
The trained DNN model classified the analyzed APK
as potentially malicious.

The APK should be treated as potentially unsafe.
Additional security analysis is recommended before
installation or deployment.
"""

else:

    report += """
The trained DNN model classified the analyzed APK
as benign based on the extracted feature vector.

This classification does NOT guarantee that the APK
is completely safe. Additional security analysis may
still be required.
"""


if dynamic_active == 0:

    report += """
============================================================
DYNAMIC ANALYSIS NOTE
============================================================

Runtime dynamic analysis was not performed for this APK.

The 161 dynamic feature positions were therefore set
to zero during the current static-analysis pipeline.

Future dynamic-analysis phases can populate these
features using controlled runtime execution.
"""


report += """
============================================================
END OF REPORT
============================================================
"""


# ============================================================
# SAVE REPORT
# ============================================================

with open(
    report_path,
    "w",
    encoding="utf-8"
) as f:

    f.write(report)


# ============================================================
# TERMINAL RESULT
# ============================================================

print()
print("=" * 60)
print("APK SECURITY REPORT RESULT")
print("=" * 60)

print()
print(
    f"APK                 : {apk_name}"
)

print(
    f"SHA-256             : {apk_hash}"
)

print(
    f"Static Active       : {static_active}"
)

print(
    f"Dynamic Active      : {dynamic_active}"
)

print(
    f"Total Active        : {total_active}"
)

print()
print(
    f"Prediction          : {label}"
)

print(
    f"Malware Probability : {probability:.4f}"
)

print(
    f"Benign Probability  : {benign_probability:.4f}"
)

print(
    f"Confidence          : {confidence:.4f}"
)

print(
    f"Risk Level          : {risk}"
)

print()
print("Report saved to:")
print(report_path)

print()
print("CSV result saved to:")
print(csv_path)

print()
print("=" * 60)
print("PHASE 11A COMPLETED")
print("=" * 60)