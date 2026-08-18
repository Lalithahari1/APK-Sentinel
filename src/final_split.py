import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split

# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

X_TRAIN_PATH = BASE_DIR / "datasets" / "X_train.csv"
X_TEST_PATH = BASE_DIR / "datasets" / "X_test.csv"
Y_TRAIN_PATH = BASE_DIR / "datasets" / "y_train.csv"
Y_TEST_PATH = BASE_DIR / "datasets" / "y_test.csv"

# New files
X_FINAL_TRAIN_PATH = BASE_DIR / "datasets" / "X_final_train.csv"
X_VALID_PATH = BASE_DIR / "datasets" / "X_validation.csv"
Y_FINAL_TRAIN_PATH = BASE_DIR / "datasets" / "y_final_train.csv"
Y_VALID_PATH = BASE_DIR / "datasets" / "y_validation.csv"

print("=" * 60)
print("PHASE 7A - VALIDATION SPLIT")
print("=" * 60)

# ---------------------------------------------------------
# Load existing training data
# ---------------------------------------------------------

X_train = pd.read_csv(X_TRAIN_PATH)
y_train = pd.read_csv(Y_TRAIN_PATH).squeeze()

X_test = pd.read_csv(X_TEST_PATH)
y_test = pd.read_csv(Y_TEST_PATH).squeeze()

print("\nOriginal training set:", X_train.shape)
print("Final test set:", X_test.shape)

# ---------------------------------------------------------
# Create validation set
# 80% training / 20% validation
# ---------------------------------------------------------

X_final_train, X_validation, y_final_train, y_validation = train_test_split(
    X_train,
    y_train,
    test_size=0.20,
    random_state=42,
    stratify=y_train
)

# ---------------------------------------------------------
# Save datasets
# ---------------------------------------------------------

X_final_train.to_csv(X_FINAL_TRAIN_PATH, index=False)
X_validation.to_csv(X_VALID_PATH, index=False)

pd.DataFrame({
    "Class": y_final_train
}).to_csv(Y_FINAL_TRAIN_PATH, index=False)

pd.DataFrame({
    "Class": y_validation
}).to_csv(Y_VALID_PATH, index=False)

# ---------------------------------------------------------
# Display results
# ---------------------------------------------------------

print("\nFinal training set:")
print("X_final_train:", X_final_train.shape)
print("y_final_train:", y_final_train.shape)

print("\nValidation set:")
print("X_validation:", X_validation.shape)
print("y_validation:", y_validation.shape)

print("\nFinal training class distribution:")
print(y_final_train.value_counts().sort_index())

print("\nValidation class distribution:")
print(y_validation.value_counts().sort_index())

print("\nTest set remains untouched:")
print("X_test:", X_test.shape)
print("y_test:", y_test.shape)

print("\n✓ Final training and validation datasets saved.")

print("\nFiles created:")
print(X_FINAL_TRAIN_PATH)
print(X_VALID_PATH)
print(Y_FINAL_TRAIN_PATH)
print(Y_VALID_PATH)

print("\n" + "=" * 60)
print("PHASE 7A COMPLETED")
print("=" * 60)