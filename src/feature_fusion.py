import pandas as pd
from pathlib import Path

# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

STATIC_PATH = BASE_DIR / "datasets" / "dataset1_static.csv"
DYNAMIC_PATH = BASE_DIR / "datasets" / "dataset1_dynamic.csv"
OUTPUT_PATH = BASE_DIR / "datasets" / "fused_dataset.csv"

print("=" * 60)
print("STATIC + DYNAMIC FEATURE FUSION")
print("=" * 60)

# Load datasets
static_df = pd.read_csv(STATIC_PATH)
dynamic_df = pd.read_csv(DYNAMIC_PATH)

print("\nStatic dataset shape:", static_df.shape)
print("Dynamic dataset shape:", dynamic_df.shape)

# Check row count
if len(static_df) != len(dynamic_df):
    raise ValueError("Static and dynamic datasets have different numbers of rows.")

# Check labels
static_labels = static_df["Class"].astype(str).str.upper()
dynamic_labels = dynamic_df["class"].astype(str).str.upper()

if not (static_labels.values == dynamic_labels.values).all():
    raise ValueError("Static and dynamic labels are not aligned.")

print("\n✓ Row counts match")
print("✓ Static and dynamic labels are aligned")

# Remove target columns
static_features = static_df.drop(columns=["Class"])
dynamic_features = dynamic_df.drop(columns=["class"])

# Rename dynamic columns if necessary to avoid duplicate names
dynamic_features.columns = [
    f"dynamic_{i}" for i in range(dynamic_features.shape[1])
]

# Combine features
fused_features = pd.concat(
    [static_features, dynamic_features],
    axis=1
)

# Add target
fused_df = fused_features.copy()
fused_df["Class"] = static_labels

print("\nStatic features:", static_features.shape[1])
print("Dynamic features:", dynamic_features.shape[1])
print("Total fused features:", fused_features.shape[1])
print("Fused dataset shape:", fused_df.shape)

# Class distribution
print("\nClass distribution:")
print(fused_df["Class"].value_counts())

# Save
fused_df.to_csv(OUTPUT_PATH, index=False)

print("\n✓ Fused dataset saved to:")
print(OUTPUT_PATH)