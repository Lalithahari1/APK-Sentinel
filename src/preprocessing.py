import pandas as pd
from pathlib import Path

# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_PATH = BASE_DIR / "datasets" / "fused_dataset.csv"
OUTPUT_PATH = BASE_DIR / "datasets" / "preprocessed_dataset.csv"

print("=" * 60)
print("PHASE 4 - DATA PREPROCESSING")
print("=" * 60)

# Load fused dataset
df = pd.read_csv(INPUT_PATH)

print("\nOriginal dataset shape:", df.shape)

# ---------------------------------------------------------
# 1. Check missing values
# ---------------------------------------------------------
missing = df.isnull().sum().sum()
print("Missing values:", missing)

# ---------------------------------------------------------
# 2. Remove exact duplicate rows
# ---------------------------------------------------------
duplicates = df.duplicated().sum()
print("Duplicate rows:", duplicates)

if duplicates > 0:
    df = df.drop_duplicates().reset_index(drop=True)

print("Shape after removing duplicates:", df.shape)

# ---------------------------------------------------------
# 3. Convert target labels
# B = 0 (Benign)
# M = 1 (Malware)
# ---------------------------------------------------------
df["Class"] = df["Class"].map({
    "B": 0,
    "M": 1
})

# Verify target conversion
if df["Class"].isnull().any():
    raise ValueError("Unexpected values found in Class column.")

print("\nTarget distribution:")
print(df["Class"].value_counts())

# ---------------------------------------------------------
# 4. Separate features and target
# ---------------------------------------------------------
X = df.drop(columns=["Class"])
y = df["Class"]

print("\nFeature shape:", X.shape)
print("Target shape:", y.shape)

# ---------------------------------------------------------
# 5. Check constant features
# ---------------------------------------------------------
constant_features = X.columns[X.nunique() <= 1]

print("\nConstant features:", len(constant_features))

if len(constant_features) > 0:
    X = X.drop(columns=constant_features)

print("Feature shape after removing constant features:", X.shape)

# ---------------------------------------------------------
# 6. Rebuild dataset
# ---------------------------------------------------------
processed_df = X.copy()
processed_df["Class"] = y

# ---------------------------------------------------------
# 7. Save
# ---------------------------------------------------------
processed_df.to_csv(OUTPUT_PATH, index=False)

print("\nPreprocessed dataset saved to:")
print(OUTPUT_PATH)

print("\nFinal dataset shape:", processed_df.shape)

print("\nFinal class distribution:")
print(processed_df["Class"].value_counts())

print("\n" + "=" * 60)
print("PREPROCESSING COMPLETED")
print("=" * 60)