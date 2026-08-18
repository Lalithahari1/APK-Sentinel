import sys
import pandas as pd
import numpy as np
from pathlib import Path


# =========================================================
# PHASE 10B - APK FEATURE VECTOR
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET = (
    BASE_DIR
    / "datasets"
    / "preprocessed_dataset.csv"
)

OUTPUT = (
    BASE_DIR
    / "results"
    / "apk_features.csv"
)


def create_feature_vector(extracted_features):

    print("=" * 60)
    print("PHASE 10B - APK FEATURE VECTOR")
    print("=" * 60)

    # -----------------------------------------------------
    # LOAD TRAINING FEATURE VOCABULARY
    # -----------------------------------------------------

    df = pd.read_csv(DATASET)

    feature_columns = [
        column
        for column in df.columns
        if column != "Class"
    ]

    print(
        f"Expected model features: {len(feature_columns)}"
    )

    # -----------------------------------------------------
    # CREATE EMPTY 340-FEATURE VECTOR
    # -----------------------------------------------------

    vector = pd.DataFrame(
        np.zeros(
            (1, len(feature_columns)),
            dtype=np.float32
        ),
        columns=feature_columns
    )

    # -----------------------------------------------------
    # MAP EXTRACTED APK FEATURES
    # -----------------------------------------------------

    matched_features = []
    unmatched_features = []

    for feature in extracted_features:

        feature = str(feature).strip()

        if feature in vector.columns:

            vector.loc[0, feature] = 1

            matched_features.append(feature)

        else:

            unmatched_features.append(feature)

    # Remove duplicates
    matched_features = sorted(
        set(matched_features)
    )

    unmatched_features = sorted(
        set(unmatched_features)
    )

    # -----------------------------------------------------
    # SAVE VECTOR
    # -----------------------------------------------------

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    vector.to_csv(
        OUTPUT,
        index=False
    )

    # -----------------------------------------------------
    # INFORMATION
    # -----------------------------------------------------

    print(
        f"Created feature vector: {vector.shape}"
    )

    print(
        f"Matched APK features: "
        f"{len(matched_features)}"
    )

    print(
        f"Unmatched APK features: "
        f"{len(unmatched_features)}"
    )

    print(
        f"Non-zero model features: "
        f"{int((vector.iloc[0] != 0).sum())}"
    )

    print(
        f"✓ Saved to: {OUTPUT}"
    )

    # -----------------------------------------------------
    # DISPLAY MATCHED FEATURES
    # -----------------------------------------------------

    if matched_features:

        print("\nMatched features:")

        for feature in matched_features[:20]:

            print(
                f"  ✓ {feature}"
            )

        if len(matched_features) > 20:

            print(
                f"  ... and "
                f"{len(matched_features) - 20} more"
            )

    return vector


# =========================================================
# COMMAND-LINE MODE
# =========================================================

if __name__ == "__main__":

    print(
        "\nThis script expects features from "
        "apk_static_analyzer.py."
    )

    print(
        "Use create_feature_vector() from "
        "the APK analysis pipeline."
    )
    