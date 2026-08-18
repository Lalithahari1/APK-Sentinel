import pandas as pd
from pathlib import Path


# =========================================================
# PHASE 10B - FINAL PROJECT REPORT
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

RESULTS_DIR = BASE_DIR / "results"
REPORT_DIR = RESULTS_DIR / "final_report"

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

print("=" * 70)
print("ANDROID MALWARE DETECTION - FINAL PROJECT REPORT")
print("=" * 70)


# =========================================================
# 1. MODEL COMPARISON
# =========================================================

comparison_file = (
    RESULTS_DIR / "model_comparison.csv"
)

if comparison_file.exists():

    comparison = pd.read_csv(
        comparison_file
    )

    print("\nMODEL COMPARISON")
    print("-" * 70)
    print(comparison.to_string(index=False))

else:

    print(
        "\n⚠ Model comparison file not found."
    )


# =========================================================
# 2. DNN PREDICTIONS
# =========================================================

prediction_file = (
    RESULTS_DIR / "dnn_predictions.csv"
)

if prediction_file.exists():

    predictions = pd.read_csv(
        prediction_file
    )

    print("\nPREDICTION SUMMARY")
    print("-" * 70)

    print(
        f"Total samples: {len(predictions)}"
    )

    if "Class" in predictions.columns:

        print(
            predictions["Class"]
            .value_counts()
        )

else:

    print(
        "\n⚠ Prediction file not found."
    )


# =========================================================
# 3. FEATURE IMPORTANCE
# =========================================================

importance_file = (
    RESULTS_DIR
    / "dnn_feature_importance.csv"
)

if importance_file.exists():

    importance = pd.read_csv(
        importance_file
    )

    importance = importance.sort_values(
        "Importance",
        ascending=False
    )

    print("\nTOP 10 IMPORTANT FEATURES")
    print("-" * 70)

    print(
        importance.head(10)
        .to_string(index=False)
    )

else:

    print(
        "\n⚠ Feature importance file not found."
    )


# =========================================================
# 4. DATASET INFORMATION
# =========================================================

dataset_file = (
    BASE_DIR
    / "datasets"
    / "preprocessed_dataset.csv"
)

if dataset_file.exists():

    dataset = pd.read_csv(
        dataset_file
    )

    features = [
        c for c in dataset.columns
        if c != "Class"
    ]

    dynamic_features = [
        c for c in features
        if c.startswith("dynamic_")
    ]

    static_features = [
        c for c in features
        if not c.startswith("dynamic_")
    ]

    print("\nDATASET INFORMATION")
    print("-" * 70)

    print(
        f"Final dataset shape: "
        f"{dataset.shape}"
    )

    print(
        f"Static features: "
        f"{len(static_features)}"
    )

    print(
        f"Dynamic features: "
        f"{len(dynamic_features)}"
    )

    print(
        f"Total model features: "
        f"{len(features)}"
    )

    print(
        f"Samples: "
        f"{len(dataset)}"
    )

else:

    print(
        "\n⚠ Preprocessed dataset not found."
    )


# =========================================================
# 5. FINAL REPORT TEXT
# =========================================================

report_file = (
    REPORT_DIR / "final_project_report.txt"
)

with open(
    report_file,
    "w",
    encoding="utf-8"
) as report:

    report.write(
        "ANDROID MALWARE DETECTION USING "
        "STATIC AND DYNAMIC FEATURES\n"
    )

    report.write("=" * 70 + "\n\n")

    report.write(
        "PROJECT PIPELINE\n"
    )

    report.write(
        "Static Dataset + Dynamic Dataset\n"
    )

    report.write(
        "        ↓\n"
    )

    report.write(
        "Feature Fusion\n"
    )

    report.write(
        "        ↓\n"
    )

    report.write(
        "Data Preprocessing\n"
    )

    report.write(
        "        ↓\n"
    )

    report.write(
        "DNN / CNN / TabNet\n"
    )

    report.write(
        "        ↓\n"
    )

    report.write(
        "Model Comparison\n"
    )

    report.write(
        "        ↓\n"
    )

    report.write(
        "DNN Prediction\n"
    )

    report.write(
        "        ↓\n"
    )

    report.write(
        "Feature Importance + Explanation\n"
    )

    report.write(
        "        ↓\n"
    )

    report.write(
        "AI Agent\n\n"
    )

    report.write(
        "DATASET DETAILS\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    if dataset_file.exists():

        report.write(
            f"Samples: {len(dataset)}\n"
        )

        report.write(
            f"Static features: "
            f"{len(static_features)}\n"
        )

        report.write(
            f"Dynamic features: "
            f"{len(dynamic_features)}\n"
        )

        report.write(
            f"Final features: "
            f"{len(features)}\n"
        )

    report.write("\n")

    report.write(
        "MODEL PERFORMANCE\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    if comparison_file.exists():

        report.write(
            comparison.to_string(
                index=False
            )
        )

    report.write("\n\n")

    report.write(
        "BEST MODEL\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    report.write(
        "DNN\n"
    )

    report.write(
        "Accuracy : 98.17%\n"
    )

    report.write(
        "Precision: 97.73%\n"
    )

    report.write(
        "Recall   : 98.57%\n"
    )

    report.write(
        "F1-score : 98.15%\n"
    )

    report.write(
        "ROC-AUC  : 99.70%\n"
    )

    report.write("\n")

    report.write(
        "EXPLAINABILITY\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    report.write(
        "The DNN prediction is supported by "
        "feature importance analysis and an "
        "explanation engine.\n"
    )

    report.write("\n")

    report.write(
        "AI AGENT\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    report.write(
        "The AI agent converts model predictions "
        "and confidence values into a risk level, "
        "assessment, and security recommendation.\n"
    )


# =========================================================
# 6. COPY EXISTING IMPORTANT RESULTS
# =========================================================

files_to_copy = [
    RESULTS_DIR / "model_comparison.csv",
    RESULTS_DIR / "roc_curves.png",
    RESULTS_DIR / "confusion_matrix_comparison.png",
    RESULTS_DIR / "dnn_feature_importance.csv",
    RESULTS_DIR / "dnn_feature_importance.png",
    RESULTS_DIR / "dnn_predictions.csv",
    RESULTS_DIR / "malware_explanations.csv",
    RESULTS_DIR / "ai_agent_reports.csv"
]


import shutil

for source in files_to_copy:

    if source.exists():

        destination = (
            REPORT_DIR / source.name
        )

        shutil.copy2(
            source,
            destination
        )

        print(
            f"✓ Included: {source.name}"
        )


# =========================================================
# COMPLETION
# =========================================================

print("\n" + "=" * 70)

print(
    "✓ FINAL PROJECT REPORT COMPLETED"
)

print("=" * 70)

print(
    "\nReport folder:"
)

print(
    REPORT_DIR
)

print(
    "\nMain report:"
)

print(
    report_file
)