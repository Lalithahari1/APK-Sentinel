import pandas as pd
from pathlib import Path

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Dataset paths
STATIC_PATH = BASE_DIR / "datasets" / "dataset1_static.csv"
DYNAMIC_PATH = BASE_DIR / "datasets" / "dataset1_dynamic.csv"

print("=" * 60)
print("DATASET-1 ANALYSIS")
print("=" * 60)

# -----------------------------
# STATIC DATASET
# -----------------------------

print("\nLoading static dataset...")

static_df = pd.read_csv(STATIC_PATH)

print("\nSTATIC DATASET")
print("-" * 60)
print("Shape:", static_df.shape)

print("\nFirst 5 rows:")
print(static_df.head())

print("\nColumn names:")
print(static_df.columns.tolist())

print("\nData types:")
print(static_df.dtypes)

print("\nMissing values:")
print(static_df.isnull().sum().sum())

print("\nDuplicate rows:")
print(static_df.duplicated().sum())


# -----------------------------
# DYNAMIC DATASET
# -----------------------------

print("\n\nLoading dynamic dataset...")

dynamic_df = pd.read_csv(DYNAMIC_PATH)

print("\nDYNAMIC DATASET")
print("-" * 60)
print("Shape:", dynamic_df.shape)

print("\nFirst 5 rows:")
print(dynamic_df.head())

print("\nColumn names:")
print(dynamic_df.columns.tolist())

print("\nData types:")
print(dynamic_df.dtypes)

print("\nMissing values:")
print(dynamic_df.isnull().sum().sum())

print("\nDuplicate rows:")
print(dynamic_df.duplicated().sum())


# -----------------------------
# SUMMARY
# -----------------------------

print("\n\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)

print("Static dataset:", static_df.shape)
print("Dynamic dataset:", dynamic_df.shape)

print("\nAnalysis completed successfully.")