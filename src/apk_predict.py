import pandas as pd
import tensorflow as tf
from pathlib import Path


# ============================================================
# PHASE 10F - DNN APK PREDICTION
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


print("=" * 60)
print("PHASE 10F - DNN APK PREDICTION")
print("=" * 60)


# ============================================================
# CHECK FILES
# ============================================================

if not MODEL_PATH.exists():

    print()
    print("DNN model not found:")
    print(MODEL_PATH)

    raise SystemExit(1)


if not FEATURE_PATH.exists():

    print()
    print("APK feature vector not found:")
    print(FEATURE_PATH)

    print()
    print(
        "Run the APK static analyzer first."
    )

    raise SystemExit(1)


# ============================================================
# LOAD MODEL
# ============================================================

print()
print("Loading DNN model...")

model = tf.keras.models.load_model(
    MODEL_PATH
)

print("DNN model loaded successfully.")


# ============================================================
# LOAD FEATURE VECTOR
# ============================================================

print()
print("Loading APK feature vector...")

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
        f"but received {X.shape[1]}."
    )

    raise SystemExit(1)


# ============================================================
# PREDICTION
# ============================================================

print()
print("Generating malware prediction...")

probability = float(
    model.predict(
        X,
        verbose=0
    )[0][0]
)


prediction = (
    1
    if probability >= 0.5
    else 0
)


# ============================================================
# CLASSIFICATION
# ============================================================

if prediction == 1:

    label = "Malware"
    confidence = probability

else:

    label = "Benign"
    confidence = 1 - probability


# ============================================================
# RISK LEVEL
# ============================================================

if label == "Malware":

    if probability >= 0.90:
        risk = "HIGH"

    elif probability >= 0.70:
        risk = "MEDIUM"

    else:
        risk = "LOW"

else:

    risk = "LOW"


# ============================================================
# DISPLAY RESULT
# ============================================================

print()
print("=" * 60)
print("APK PREDICTION RESULT")
print("=" * 60)

print(
    f"Prediction          : {label}"
)

print(
    f"Malware Probability : {probability:.4f}"
)

print(
    f"Confidence          : {confidence:.4f}"
)

print(
    f"Risk Level          : {risk}"
)

print("=" * 60)

print("PHASE 10F COMPLETED")

print("=" * 60)