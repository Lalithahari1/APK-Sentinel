import pandas as pd

# ============================================================
# PHASE 12A.3 - DYNAMIC FEATURE MAPPING
# ============================================================

DYNAMIC_DATASET = r"datasets\dataset1_dynamic.csv"
PREPROCESSED_DATASET = r"datasets\preprocessed_dataset.csv"

print("=" * 70)
print("PHASE 12A.3 - DYNAMIC FEATURE MAPPING")
print("=" * 70)

# Load datasets
dynamic_df = pd.read_csv(DYNAMIC_DATASET)
processed_df = pd.read_csv(PREPROCESSED_DATASET)

# Original dynamic feature names
original_features = list(dynamic_df.columns[:-1])

# Dynamic features actually used by final model
model_dynamic_features = [
    column
    for column in processed_df.columns
    if str(column).startswith("dynamic_")
]

print()
print("Original dynamic features :", len(original_features))
print("Model dynamic features    :", len(model_dynamic_features))

print()
print("=" * 70)
print("DYNAMIC FEATURE MAPPING")
print("=" * 70)

for feature in model_dynamic_features:

    feature_id = int(feature.split("_")[1])

    if feature_id < len(original_features):

        original_name = original_features[feature_id]

        print(
            f"{feature:<15} -> {original_name}"
        )

    else:

        print(
            f"{feature:<15} -> OUT OF RANGE"
        )

print("=" * 70)

print()
print("Total mapped:", len(model_dynamic_features))

print()
print("PHASE 12A.3 COMPLETED")
print("=" * 70)