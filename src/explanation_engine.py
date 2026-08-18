import pandas as pd
import numpy as np

from pathlib import Path


# =========================================================
# PHASE 9C - EXPLANATION ENGINE
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

PREDICTION_PATH = (
    BASE_DIR
    / "results"
    / "dnn_predictions.csv"
)

IMPORTANCE_PATH = (
    BASE_DIR
    / "results"
    / "dnn_feature_importance.csv"
)

OUTPUT_PATH = (
    BASE_DIR
    / "results"
    / "malware_explanations.csv"
)


print("=" * 60)
print("PHASE 9C - MALWARE EXPLANATION ENGINE")
print("=" * 60)


# =========================================================
# LOAD PREDICTIONS
# =========================================================

print("\nLoading DNN predictions...")

predictions = pd.read_csv(
    PREDICTION_PATH
)

print(
    "Prediction records:",
    len(predictions)
)


# =========================================================
# LOAD FEATURE IMPORTANCE
# =========================================================

print("\nLoading feature importance...")

importance_df = pd.read_csv(
    IMPORTANCE_PATH
)

importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
).reset_index(drop=True)

print(
    "Features available:",
    len(importance_df)
)


# =========================================================
# TOP FEATURES
# =========================================================

top_features = (
    importance_df
    .head(10)["Feature"]
    .tolist()
)


print("\nTop model-influencing features:")

for i, feature in enumerate(
    top_features,
    start=1
):
    print(
        f"{i}. {feature}"
    )


# =========================================================
# EXPLANATION FUNCTION
# =========================================================

def generate_explanation(
    prediction,
    probability,
    confidence
):

    if prediction == 1:

        risk_level = "HIGH"

        explanation = (
            "The DNN classified this sample as "
            "potentially malicious. The prediction was "
            "strongly influenced by patterns represented "
            "in the important static and dynamic features. "
            "These features indicate behavioral and "
            "Android API/permission-related patterns "
            "that contributed to the malware classification."
        )

    else:

        risk_level = "LOW"

        explanation = (
            "The DNN classified this sample as benign. "
            "The observed feature pattern did not produce "
            "a sufficiently strong malware signal according "
            "to the trained model."
        )

    return risk_level, explanation


# =========================================================
# GENERATE EXPLANATIONS
# =========================================================

risk_levels = []
explanations = []
important_features = []


for _, row in predictions.iterrows():

    prediction = int(
        row["Prediction"]
    )

    probability = float(
        row["Probability_Malware"]
    )

    confidence = float(
        row["Confidence"]
    )

    risk, explanation = generate_explanation(
        prediction,
        probability,
        confidence
    )

    risk_levels.append(
        risk
    )

    explanations.append(
        explanation
    )

    important_features.append(
        ", ".join(top_features[:5])
    )


# =========================================================
# ADD EXPLANATION COLUMNS
# =========================================================

predictions["Risk_Level"] = (
    risk_levels
)

predictions["Important_Features"] = (
    important_features
)

predictions["Explanation"] = (
    explanations
)


# =========================================================
# SAVE RESULTS
# =========================================================

predictions.to_csv(
    OUTPUT_PATH,
    index=False
)

print("\n✓ Explanation results saved to:")

print(
    OUTPUT_PATH
)


# =========================================================
# DISPLAY SAMPLE EXPLANATIONS
# =========================================================

print("\n" + "=" * 60)
print("SAMPLE EXPLANATIONS")
print("=" * 60)


for _, row in predictions.head(5).iterrows():

    print("\n----------------------------------------")

    print(
        f"Sample: {row['Sample']}"
    )

    print(
        f"Prediction: {row['Class']}"
    )

    print(
        f"Confidence: "
        f"{row['Confidence']:.4f}"
    )

    print(
        f"Risk Level: "
        f"{row['Risk_Level']}"
    )

    print(
        "Important Features:"
    )

    print(
        row["Important_Features"]
    )

    print(
        "Explanation:"
    )

    print(
        row["Explanation"]
    )


print("\n" + "=" * 60)
print("PHASE 9C COMPLETED")
print("=" * 60)