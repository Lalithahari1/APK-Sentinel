import pandas as pd
from pathlib import Path

# Get the main project folder
BASE_DIR = Path(__file__).resolve().parent.parent

# Build the dataset path
DATASET_PATH = BASE_DIR / "datasets" / "train.csv"

print("Looking for dataset at:")
print(DATASET_PATH)

# Load dataset
df = pd.read_csv(DATASET_PATH, sep=";")

print("\nDataset loaded successfully!")
print("Dataset shape:", df.shape)

print("\nColumn names:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nDataset information:")
print(df.info())

print("\nMissing values:")
print(df.isnull().sum().sum())

print("\nDuplicate rows:")
print(df.duplicated().sum())

print("\nTarget column: type")
print(df["type"].value_counts())

print("\nTarget percentages:")
print(df["type"].value_counts(normalize=True) * 100)

# Separate features and target
X = df.drop("type", axis=1)
y = df["type"]

print("\nFeature shape:", X.shape)
print("Target shape:", y.shape)

# Check duplicate feature vectors
duplicate_features = X.duplicated().sum()

print("\nDuplicate feature rows:", duplicate_features)

# Check whether duplicate feature vectors have conflicting labels
duplicate_groups = df.groupby(X.columns.tolist())["type"].nunique()

conflicting_labels = (duplicate_groups > 1).sum()

print("Feature patterns with conflicting labels:", conflicting_labels)

# Find feature patterns that have more than one target label
duplicate_groups = df.groupby(X.columns.tolist())["type"].nunique()

conflicting_patterns = duplicate_groups[duplicate_groups > 1]

print("\nNumber of conflicting feature patterns:", len(conflicting_patterns))

print("\nConflicting patterns:")
print(conflicting_patterns)

# Find feature patterns that have conflicting target labels
duplicate_groups = df.groupby(X.columns.tolist())["type"].nunique()

conflicting_patterns = duplicate_groups[duplicate_groups > 1]

print("\nNumber of conflicting feature patterns:", len(conflicting_patterns))

# Get the actual rows belonging to conflicting patterns
conflicting_rows = df[
    df.drop(columns=["type"]).duplicated(keep=False)
]

# Keep only groups where the same features have different labels
conflicting_rows = conflicting_rows[
    conflicting_rows.drop(columns=["type"])
    .apply(tuple, axis=1)
    .isin(
        conflicting_patterns.index.map(tuple)
    )
]

print("\nConflicting rows:")
print(conflicting_rows[["type"]].to_string())

# Remove feature patterns with conflicting labels
conflict_mask = (
    df.drop(columns=["type"])
    .apply(tuple, axis=1)
    .isin(conflicting_patterns.index.map(tuple))
)

clean_df = df[~conflict_mask].copy()

print("\nOriginal dataset size:", len(df))
print("Rows removed due to conflicting labels:", conflict_mask.sum())
print("Dataset size after removing conflicts:", len(clean_df))

# Remove exact duplicate rows
clean_df = clean_df.drop_duplicates()

print("Dataset size after removing exact duplicates:", len(clean_df))

print("\nClass distribution after cleaning:")
print(clean_df["type"].value_counts())

# Save cleaned dataset
CLEANED_PATH = BASE_DIR / "datasets" / "cleaned_data.csv"

clean_df.to_csv(CLEANED_PATH, index=False)

print("\nCleaned dataset saved to:")
print(CLEANED_PATH)