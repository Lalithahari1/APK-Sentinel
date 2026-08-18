import pandas as pd
import numpy as np
import tensorflow as tf
import matplotlib.pyplot as plt

from pathlib import Path
from sklearn.preprocessing import StandardScaler


# =========================================================
# PHASE 9A - DNN FEATURE IMPORTANCE
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_PATH = (
    BASE_DIR
    / "datasets"
    / "preprocessed_dataset.csv"
)

TRAIN_PATH = (
    BASE_DIR
    / "datasets"
    / "X_final_train.csv"
)

MODEL_PATH = (
    BASE_DIR
    / "models"
    / "final_dnn_model.keras"
)

RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


print("=" * 60)
print("PHASE 9A - FEATURE IMPORTANCE")
print("=" * 60)


# =========================================================
# LOAD DATA
# =========================================================

data = pd.read_csv(DATA_PATH)

print("\nPreprocessed dataset shape:")
print(data.shape)


# =========================================================
# SEPARATE FEATURES AND TARGET
# =========================================================

if "Class" in data.columns:
    X = data.drop(columns=["Class"])
else:
    # Fallback if the target column is lowercase
    X = data.drop(
        columns=[
            column for column in data.columns
            if column.lower() == "class"
        ]
    )

feature_names = X.columns.tolist()

print("\nNumber of features:")
print(len(feature_names))


# =========================================================
# LOAD TRAINING DATA
# =========================================================

X_train = pd.read_csv(TRAIN_PATH)

print("\nTraining data shape:")
print(X_train.shape)


# =========================================================
# SCALE DATA
# =========================================================

scaler = StandardScaler()

scaler.fit(
    X_train.astype("float32")
)

X_scaled = scaler.transform(
    X.astype("float32")
)


# =========================================================
# LOAD FINAL DNN
# =========================================================

print("\nLoading final DNN model...")

model = tf.keras.models.load_model(
    MODEL_PATH
)

print("✓ DNN model loaded")


# =========================================================
# GRADIENT-BASED FEATURE IMPORTANCE
# =========================================================

print("\nCalculating feature importance...")

X_tensor = tf.convert_to_tensor(
    X_scaled,
    dtype=tf.float32
)

with tf.GradientTape() as tape:

    tape.watch(X_tensor)

    predictions = model(
        X_tensor,
        training=False
    )

gradients = tape.gradient(
    predictions,
    X_tensor
)

importance = tf.reduce_mean(
    tf.abs(gradients),
    axis=0
).numpy()


# =========================================================
# CREATE IMPORTANCE TABLE
# =========================================================

importance_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": importance
})

importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
).reset_index(drop=True)


# =========================================================
# TOP 20 FEATURES
# =========================================================

top_features = importance_df.head(20)

print("\n" + "=" * 60)
print("TOP 20 IMPORTANT FEATURES")
print("=" * 60)

print(
    top_features.to_string(
        index=False
    )
)


# =========================================================
# SAVE FEATURE IMPORTANCE
# =========================================================

csv_path = (
    RESULTS_DIR
    / "dnn_feature_importance.csv"
)

importance_df.to_csv(
    csv_path,
    index=False
)

print("\n✓ Feature importance saved to:")
print(csv_path)


# =========================================================
# PLOT TOP 20 FEATURES
# =========================================================

plot_data = top_features.sort_values(
    by="Importance"
)

plt.figure(
    figsize=(10, 8)
)

plt.barh(
    plot_data["Feature"],
    plot_data["Importance"]
)

plt.xlabel(
    "Average Absolute Gradient"
)

plt.ylabel(
    "Feature"
)

plt.title(
    "Top 20 Features Influencing DNN Malware Detection"
)

plt.tight_layout()


plot_path = (
    RESULTS_DIR
    / "dnn_feature_importance.png"
)

plt.savefig(
    plot_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


print("\n✓ Feature importance graph saved to:")
print(plot_path)


print("\n" + "=" * 60)
print("PHASE 9A COMPLETED")
print("=" * 60)