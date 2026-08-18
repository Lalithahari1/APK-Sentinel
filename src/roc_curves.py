import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from pathlib import Path
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_curve, roc_auc_score

import tensorflow as tf
from pytorch_tabnet.tab_model import TabNetClassifier


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

X_TEST_PATH = BASE_DIR / "datasets" / "X_test.csv"
Y_TEST_PATH = BASE_DIR / "datasets" / "y_test.csv"

DNN_MODEL_PATH = BASE_DIR / "models" / "final_dnn_model.keras"
CNN_MODEL_PATH = BASE_DIR / "models" / "final_cnn_model.keras"
TABNET_MODEL_PATH = BASE_DIR / "models" / "final_tabnet_model"

RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


print("=" * 60)
print("PHASE 8B - ROC CURVES")
print("=" * 60)


# =========================================================
# LOAD TEST DATA
# =========================================================

X_test = pd.read_csv(X_TEST_PATH)
y_test = pd.read_csv(Y_TEST_PATH).squeeze()

print("\nTest data:", X_test.shape)
print("Test labels:", y_test.shape)


# =========================================================
# SCALE TEST DATA
# =========================================================

X_test = X_test.astype("float32").values
y_test = y_test.astype("int32").values

# IMPORTANT:
# The scaler must be fitted using training data,
# not the test data.

X_train = pd.read_csv(
    BASE_DIR / "datasets" / "X_final_train.csv"
).astype("float32").values

scaler = StandardScaler()

scaler.fit(X_train)

X_test_scaled = scaler.transform(X_test).astype("float32")


# =========================================================
# DNN
# =========================================================

print("\nLoading DNN model...")

dnn_model = tf.keras.models.load_model(
    DNN_MODEL_PATH
)

dnn_probability = dnn_model.predict(
    X_test_scaled,
    verbose=0
).ravel()

dnn_auc = roc_auc_score(
    y_test,
    dnn_probability
)

dnn_fpr, dnn_tpr, _ = roc_curve(
    y_test,
    dnn_probability
)

print(f"DNN ROC-AUC: {dnn_auc:.4f}")


# =========================================================
# CNN
# =========================================================

print("\nLoading CNN model...")

cnn_model = tf.keras.models.load_model(
    CNN_MODEL_PATH
)

X_test_cnn = X_test_scaled.reshape(
    X_test_scaled.shape[0],
    X_test_scaled.shape[1],
    1
)

cnn_probability = cnn_model.predict(
    X_test_cnn,
    verbose=0
).ravel()

cnn_auc = roc_auc_score(
    y_test,
    cnn_probability
)

cnn_fpr, cnn_tpr, _ = roc_curve(
    y_test,
    cnn_probability
)

print(f"CNN ROC-AUC: {cnn_auc:.4f}")


# =========================================================
# TABNET
# =========================================================

print("\nLoading TabNet model...")

tabnet_model = TabNetClassifier()

tabnet_model.load_model(
    str(TABNET_MODEL_PATH) + ".zip"
)

tabnet_probability = tabnet_model.predict_proba(
    X_test_scaled
)[:, 1]

tabnet_auc = roc_auc_score(
    y_test,
    tabnet_probability
)

tabnet_fpr, tabnet_tpr, _ = roc_curve(
    y_test,
    tabnet_probability
)

print(f"TabNet ROC-AUC: {tabnet_auc:.4f}")


# =========================================================
# ROC CURVE
# =========================================================

plt.figure(figsize=(9, 7))

plt.plot(
    dnn_fpr,
    dnn_tpr,
    label=f"DNN (AUC = {dnn_auc:.4f})"
)

plt.plot(
    cnn_fpr,
    cnn_tpr,
    label=f"CNN (AUC = {cnn_auc:.4f})"
)

plt.plot(
    tabnet_fpr,
    tabnet_tpr,
    label=f"TabNet (AUC = {tabnet_auc:.4f})"
)

plt.plot(
    [0, 1],
    [0, 1],
    linestyle="--",
    label="Random Classifier"
)

plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")

plt.title(
    "ROC Curve Comparison - Android Malware Detection"
)

plt.legend(
    loc="lower right"
)

plt.grid(True)

plt.tight_layout()


# =========================================================
# SAVE GRAPH
# =========================================================

roc_path = RESULTS_DIR / "roc_curves.png"

plt.savefig(
    roc_path,
    dpi=300
)

plt.close()


print("\n✓ ROC curve saved to:")
print(roc_path)

print("\n" + "=" * 60)
print("PHASE 8B COMPLETED")
print("=" * 60)