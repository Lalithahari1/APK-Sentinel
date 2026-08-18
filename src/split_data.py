import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split

# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_PATH = BASE_DIR / "datasets" / "preprocessed_dataset.csv"

print("=" * 60)
print("PHASE 5 - TRAIN / TEST SPLIT")
print("=" * 60)

# Load preprocessed dataset
df = pd.read_csv(INPUT_PATH)

print("\nDataset shape:", df.shape)

# Separate features and target
X = df.drop(columns=["Class"])
y = df["Class"]

# Stratified 80/20 split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining set:")
print("X_train:", X_train.shape)
print("y_train:", y_train.shape)

print("\nTesting set:")
print("X_test:", X_test.shape)
print("y_test:", y_test.shape)

print("\nTraining class distribution:")
print(y_train.value_counts())

print("\nTesting class distribution:")
print(y_test.value_counts())

# Save the four files
X_train.to_csv(BASE_DIR / "datasets" / "X_train.csv", index=False)
X_test.to_csv(BASE_DIR / "datasets" / "X_test.csv", index=False)
y_train.to_csv(BASE_DIR / "datasets" / "y_train.csv", index=False)
y_test.to_csv(BASE_DIR / "datasets" / "y_test.csv", index=False)

print("\n✓ Training and testing datasets saved.")

print("\n" + "=" * 60)
print("TRAIN / TEST SPLIT COMPLETED")
print("=" * 60)