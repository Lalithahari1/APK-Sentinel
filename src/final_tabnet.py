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


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

X_TRAIN_PATH = BASE_DIR / "datasets" / "X_final_train.csv"
X_VAL_PATH = BASE_DIR / "datasets" / "X_validation.csv"
X_TEST_PATH = BASE_DIR / "datasets" / "X_test.csv"

Y_TRAIN_PATH = BASE_DIR / "datasets" / "y_final_train.csv"
Y_VAL_PATH = BASE_DIR / "datasets" / "y_validation.csv"
Y_TEST_PATH = BASE_DIR / "datasets" / "y_test.csv"

MODEL_PATH = BASE_DIR / "models" / "final_tabnet_model"

MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("PHASE 7D - FINAL TABNET TRAINING")
print("=" * 60)


# =========================================================
# LOAD DATA
# =========================================================

X_train = pd.read_csv(X_TRAIN_PATH)
X_val = pd.read_csv(X_VAL_PATH)
X_test = pd.read_csv(X_TEST_PATH)

y_train = pd.read_csv(Y_TRAIN_PATH).squeeze()
y_val = pd.read_csv(Y_VAL_PATH).squeeze()
y_test = pd.read_csv(Y_TEST_PATH).squeeze()

print("\nTraining data:", X_train.shape)
print("Validation data:", X_val.shape)
print("Final test data:", X_test.shape)


# =========================================================
# CONVERT TO NUMPY
# =========================================================

X_train = X_train.astype("float32").values
X_val = X_val.astype("float32").values
X_test = X_test.astype("float32").values

y_train = y_train.astype("int64").values
y_val = y_val.astype("int64").values
y_test = y_test.astype("int64").values


# =========================================================
# SCALE FEATURES
# Fit ONLY on training data
# =========================================================

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train).astype("float32")
X_val_scaled = scaler.transform(X_val).astype("float32")
X_test_scaled = scaler.transform(X_test).astype("float32")

print("\nFeature scaling completed.")


# =========================================================
# BUILD TABNET
# =========================================================

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


# =========================================================
# TRAIN
# =========================================================

print("\nStarting final TabNet training...")

model.fit(
    X_train_scaled,
    y_train,

    eval_set=[
        (X_train_scaled, y_train),
        (X_val_scaled, y_val)
    ],

    eval_name=[
        "train",
        "validation"
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


# =========================================================
# FINAL TEST PREDICTION
# =========================================================

print("\nEvaluating on untouched test set...")

y_probability = model.predict_proba(
    X_test_scaled
)[:, 1]

y_prediction = (
    y_probability >= 0.5
).astype(int)


# =========================================================
# METRICS
# =========================================================

accuracy = accuracy_score(
    y_test,
    y_prediction
)

precision = precision_score(
    y_test,
    y_prediction
)

recall = recall_score(
    y_test,
    y_prediction
)

f1 = f1_score(
    y_test,
    y_prediction
)

roc_auc = roc_auc_score(
    y_test,
    y_probability
)

cm = confusion_matrix(
    y_test,
    y_prediction
)


# =========================================================
# RESULTS
# =========================================================

print("\n" + "=" * 60)
print("FINAL TABNET RESULTS")
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
        target_names=[
            "Benign",
            "Malware"
        ]
    )
)


# =========================================================
# SAVE MODEL
# =========================================================

model.save_model(
    str(MODEL_PATH)
)

print("\n✓ Final TabNet model saved to:")
print(MODEL_PATH)

print("\n" + "=" * 60)
print("FINAL TABNET TRAINING COMPLETED")
print("=" * 60)