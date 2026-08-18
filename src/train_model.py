import pandas as pd
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.feature_selection import VarianceThreshold

# Project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Load cleaned dataset
DATASET_PATH = BASE_DIR / "datasets" / "cleaned_data.csv"

df = pd.read_csv(DATASET_PATH)

print("Cleaned dataset loaded successfully!")
print("Dataset shape:", df.shape)

# Separate features and target
X = df.drop("type", axis=1)
y = df["type"]

print("\nFeature shape:", X.shape)
print("Target shape:", y.shape)

print("\nTarget distribution:")
print(y.value_counts())

# Split dataset into training and testing sets
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

# Feature selection using Variance Threshold
selector = VarianceThreshold(threshold=0.01)

X_train_selected = selector.fit_transform(X_train)
X_test_selected = selector.transform(X_test)

print("\nFeature selection:")
print("Original number of features:", X_train.shape[1])
print("Selected number of features:", X_train_selected.shape[1])

print("\nAll feature names:")
print(X.columns.tolist())