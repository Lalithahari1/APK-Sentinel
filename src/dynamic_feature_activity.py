import pandas as pd

# ============================================================
# PHASE 12A.4 - DYNAMIC FEATURE ACTIVITY ANALYSIS
# ============================================================

DYNAMIC_DATASET = r"datasets\dataset1_dynamic.csv"
PREPROCESSED_DATASET = r"datasets\preprocessed_dataset.csv"

print("=" * 70)
print("PHASE 12A.4 - DYNAMIC FEATURE ACTIVITY")
print("=" * 70)

dynamic_df = pd.read_csv(DYNAMIC_DATASET)
processed_df = pd.read_csv(PREPROCESSED_DATASET)

original_features = list(dynamic_df.columns[:-1])

model_dynamic_features = [
    column
    for column in processed_df.columns
    if str(column).startswith("dynamic_")
]

print()
print("Checking activity of selected dynamic features...")
print()

for feature in model_dynamic_features:

    feature_id = int(feature.split("_")[1])

    if feature_id < len(original_features):

        original_name = original_features[feature_id]

        active_count = int(
            (dynamic_df.iloc[:, feature_id] != 0).sum()
        )

        print(
            f"{feature:<15} | "
            f"{original_name:<65} | "
            f"active={active_count}"
        )

print()
print("=" * 70)
print("PHASE 12A.4 COMPLETED")
print("=" * 70)