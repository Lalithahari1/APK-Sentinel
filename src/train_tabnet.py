import pandas as pd
import numpy as np
from pathlib import Path

import torch


from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from pytorch_tabnet.tab_model import TabNetClassifier

# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

X_TRAIN_PATH = BASE_DIR / "datasets" / "X_train.csv"
X_TEST_PATH = BASE_DIR / "datasets" / "X_test.csv"
Y_TRAIN_PATH = BASE_DIR / "datasets" / "y_train.csv"
Y_TEST_PATH = BASE_DIR / "datasets" / "y_test.csv"

MODEL_PATH = BASE_DIR / "models" / "tabnet_model"

MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("PHASE 6C - TABNET")
print("=" * 60)

# ---------------------------------------------------------
# Load data
# ---------------------------------------------------------

X_train = pd.read_csv(X_TRAIN_PATH)
X_test = pd.read_csv(X_TEST_PATH)

y_train = pd.read_csv(Y_TRAIN_PATH).squeeze()
y_test = pd.read_csv(Y_TEST_PATH).squeeze()

print("\nTraining data:", X_train.shape)
print("Testing data:", X_test.shape)

# ---------------------------------------------------------
# Convert to NumPy
# ---------------------------------------------------------

X_train = X_train.astype("float32").values
X_test = X_test.astype("float32").values

y_train = y_train.astype("int64").values
y_test = y_test.astype("int64").values

# ---------------------------------------------------------
# Scale features
# ---------------------------------------------------------

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train).astype("float32")
X_test_scaled = scaler.transform(X_test).astype("float32")

print("\nFeature scaling completed.")

# ---------------------------------------------------------
# Build TabNet
# ---------------------------------------------------------

model = TabNetClassifier(
    n_d=32,
    n_a=32,
    n_steps=5,
    gamma=1.5,
    lambda_sparse=1e-4,
    optimizer_fn=torch.optim.Adam,
    optimizer_params=dict(lr=0.001),
    mask_type="entmax",
    seed=42,
    verbose=10
)

# ---------------------------------------------------------
# Train TabNet
# ---------------------------------------------------------

print("\nStarting TabNet training...")

model.fit(
    X_train_scaled,
    y_train,

    eval_set=[
        (X_train_scaled, y_train),
        (X_test_scaled, y_test)
    ],

    eval_name=[
        "train",
        "test"
    ],

    eval_metric=[
        "accuracy",
        "auc"
    ],

    max_epochs=100,

    patience=15,

    batch_size=256,

    virtual_batch_size=128,

    num_workers=0,

    drop_last=False
)

# ---------------------------------------------------------
# Predictions
# ---------------------------------------------------------

y_probability = model.predict_proba(X_test_scaled)[:, 1]

y_prediction = (y_probability >= 0.5).astype(int)

# ---------------------------------------------------------
# Evaluation
# ---------------------------------------------------------

accuracy = accuracy_score(y_test, y_prediction)
precision = precision_score(y_test, y_prediction)
recall = recall_score(y_test, y_prediction)
f1 = f1_score(y_test, y_prediction)
roc_auc = roc_auc_score(y_test, y_probability)

cm = confusion_matrix(y_test, y_prediction)

print("\n" + "=" * 60)
print("TABNET RESULTS")
print("=" * 60)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_prediction,
        target_names=["Benign", "Malware"]
    )
)

# ---------------------------------------------------------
# Save TabNet model
# ---------------------------------------------------------

model.save_model(str(MODEL_PATH / "tabnet_model"))

print("\n✓ TabNet model saved to:")
print(MODEL_PATH)

print("\n" + "=" * 60)
print("TABNET TRAINING COMPLETED")
print("=" * 60)