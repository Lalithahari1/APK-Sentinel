import pandas as pd
import numpy as np
from pathlib import Path

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

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import (
    Input,
    Conv1D,
    MaxPooling1D,
    Flatten,
    Dense,
    Dropout,
    BatchNormalization
)
from tensorflow.keras.callbacks import EarlyStopping

# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

X_TRAIN_PATH = BASE_DIR / "datasets" / "X_train.csv"
X_TEST_PATH = BASE_DIR / "datasets" / "X_test.csv"
Y_TRAIN_PATH = BASE_DIR / "datasets" / "y_train.csv"
Y_TEST_PATH = BASE_DIR / "datasets" / "y_test.csv"

MODEL_PATH = BASE_DIR / "models" / "cnn_model.keras"

MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("PHASE 6B - CONVOLUTIONAL NEURAL NETWORK")
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

y_train = y_train.astype("int32").values
y_test = y_test.astype("int32").values

# ---------------------------------------------------------
# Scale features
# Fit ONLY on training data
# ---------------------------------------------------------

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ---------------------------------------------------------
# Reshape for 1D CNN
# 340 features → sequence length 340, 1 channel
# ---------------------------------------------------------

X_train_cnn = X_train_scaled.reshape(
    X_train_scaled.shape[0],
    X_train_scaled.shape[1],
    1
)

X_test_cnn = X_test_scaled.reshape(
    X_test_scaled.shape[0],
    X_test_scaled.shape[1],
    1
)

print("\nCNN training shape:", X_train_cnn.shape)
print("CNN testing shape:", X_test_cnn.shape)

# ---------------------------------------------------------
# Build 1D CNN
# ---------------------------------------------------------

model = Sequential([
    Input(shape=(X_train_cnn.shape[1], 1)),

    Conv1D(
        filters=64,
        kernel_size=3,
        activation="relu",
        padding="same"
    ),
    BatchNormalization(),

    MaxPooling1D(pool_size=2),

    Conv1D(
        filters=128,
        kernel_size=3,
        activation="relu",
        padding="same"
    ),
    BatchNormalization(),

    MaxPooling1D(pool_size=2),

    Flatten(),

    Dense(128, activation="relu"),
    Dropout(0.30),

    Dense(64, activation="relu"),
    Dropout(0.20),

    Dense(1, activation="sigmoid")
])

# ---------------------------------------------------------
# Compile
# ---------------------------------------------------------

model.compile(
    optimizer="adam",
    loss="binary_crossentropy",
    metrics=["accuracy"]
)

print("\nCNN architecture:")
model.summary()

# ---------------------------------------------------------
# Early stopping
# ---------------------------------------------------------

early_stopping = EarlyStopping(
    monitor="val_loss",
    patience=10,
    restore_best_weights=True
)

# ---------------------------------------------------------
# Train
# ---------------------------------------------------------

print("\nStarting CNN training...")

history = model.fit(
    X_train_cnn,
    y_train,
    validation_split=0.20,
    epochs=100,
    batch_size=32,
    callbacks=[early_stopping],
    verbose=1
)

# ---------------------------------------------------------
# Predictions
# ---------------------------------------------------------

y_probability = model.predict(
    X_test_cnn,
    verbose=0
).ravel()

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
print("CNN RESULTS")
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
# Save model
# ---------------------------------------------------------

model.save(MODEL_PATH)

print("\n✓ CNN model saved to:")
print(MODEL_PATH)

print("\n" + "=" * 60)
print("CNN TRAINING COMPLETED")
print("=" * 60)