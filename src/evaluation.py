import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# =========================================================
# PHASE 8 - FINAL MODEL EVALUATION & COMPARISON
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_DIR = BASE_DIR / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("PHASE 8 - FINAL MODEL EVALUATION")
print("=" * 60)

# =========================================================
# FINAL RESULTS FROM THE UNTOUCHED TEST SET
# =========================================================

results = pd.DataFrame({
    "Model": ["DNN", "CNN", "TabNet"],
    "Accuracy": [0.9817, 0.9774, 0.9182],
    "Precision": [0.9773, 0.9717, 0.8965],
    "Recall": [0.9857, 0.9828, 0.9427],
    "F1-Score": [0.9815, 0.9772, 0.9190],
    "ROC-AUC": [0.9970, 0.9967, 0.9690]
})

# =========================================================
# DISPLAY RESULTS
# =========================================================

print("\nFINAL MODEL COMPARISON")
print("-" * 60)

print(
    results.to_string(
        index=False,
        formatters={
            "Accuracy": "{:.4f}".format,
            "Precision": "{:.4f}".format,
            "Recall": "{:.4f}".format,
            "F1-Score": "{:.4f}".format,
            "ROC-AUC": "{:.4f}".format
        }
    )
)

# =========================================================
# SAVE CSV
# =========================================================

csv_path = OUTPUT_DIR / "model_comparison.csv"

results.to_csv(
    csv_path,
    index=False
)

print("\n✓ Comparison table saved to:")
print(csv_path)

# =========================================================
# CONVERT TO PERCENTAGES
# =========================================================

plot_data = results.copy()

metrics = [
    "Accuracy",
    "Precision",
    "Recall",
    "F1-Score",
    "ROC-AUC"
]

for metric in metrics:
    plot_data[metric] = plot_data[metric] * 100

# =========================================================
# GRAPH 1 - ACCURACY
# =========================================================

plt.figure(figsize=(8, 5))

plt.bar(
    plot_data["Model"],
    plot_data["Accuracy"]
)

plt.title("Model Accuracy Comparison")
plt.xlabel("Model")
plt.ylabel("Accuracy (%)")
plt.ylim(0, 100)

for i, value in enumerate(plot_data["Accuracy"]):
    plt.text(
        i,
        value + 1,
        f"{value:.2f}%",
        ha="center"
    )

plt.tight_layout()

accuracy_path = OUTPUT_DIR / "accuracy_comparison.png"

plt.savefig(
    accuracy_path,
    dpi=300
)

plt.close()

print("\n✓ Accuracy graph saved to:")
print(accuracy_path)

# =========================================================
# GRAPH 2 - PRECISION / RECALL / F1
# =========================================================

plt.figure(figsize=(9, 5))

x = range(len(plot_data["Model"]))

width = 0.25

plt.bar(
    [i - width for i in x],
    plot_data["Precision"],
    width=width,
    label="Precision"
)

plt.bar(
    x,
    plot_data["Recall"],
    width=width,
    label="Recall"
)

plt.bar(
    [i + width for i in x],
    plot_data["F1-Score"],
    width=width,
    label="F1-Score"
)

plt.xticks(
    list(x),
    plot_data["Model"]
)

plt.xlabel("Model")
plt.ylabel("Score (%)")
plt.title("Precision, Recall and F1-Score Comparison")
plt.ylim(0, 100)
plt.legend()

plt.tight_layout()

metrics_path = OUTPUT_DIR / "precision_recall_f1_comparison.png"

plt.savefig(
    metrics_path,
    dpi=300
)

plt.close()

print("\n✓ Precision/Recall/F1 graph saved to:")
print(metrics_path)

# =========================================================
# GRAPH 3 - ALL METRICS
# =========================================================

plt.figure(figsize=(10, 6))

x = range(len(plot_data["Model"]))

width = 0.15

for i, metric in enumerate(metrics):

    positions = [
        value + (i - 2) * width
        for value in x
    ]

    plt.bar(
        positions,
        plot_data[metric],
        width=width,
        label=metric
    )

plt.xticks(
    list(x),
    plot_data["Model"]
)

plt.xlabel("Model")
plt.ylabel("Score (%)")
plt.title("Overall Model Performance Comparison")
plt.ylim(0, 100)
plt.legend()

plt.tight_layout()

overall_path = OUTPUT_DIR / "overall_model_comparison.png"

plt.savefig(
    overall_path,
    dpi=300
)

plt.close()

print("\n✓ Overall comparison graph saved to:")
print(overall_path)

# =========================================================
# BEST MODEL
# =========================================================

best_model = results.loc[
    results["Accuracy"].idxmax(),
    "Model"
]

best_accuracy = results.loc[
    results["Accuracy"].idxmax(),
    "Accuracy"
]

print("\n" + "=" * 60)
print("BEST MODEL")
print("=" * 60)

print(f"\nBest model based on accuracy: {best_model}")
print(f"Accuracy: {best_accuracy * 100:.2f}%")

print("\n✓ PHASE 8A COMPLETED")
print("=" * 60)