import matplotlib.pyplot as plt
from pathlib import Path

# =========================================================
# PHASE 8C - CONFUSION MATRIX VISUALIZATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("PHASE 8C - CONFUSION MATRICES")
print("=" * 60)


# =========================================================
# CONFUSION MATRICES
# =========================================================

matrices = {
    "DNN": [
        [352, 8],
        [5, 344]
    ],

    "CNN": [
        [350, 10],
        [6, 343]
    ],

    "TabNet": [
        [322, 38],
        [20, 329]
    ]
}


# =========================================================
# CREATE INDIVIDUAL CONFUSION MATRIX
# =========================================================

for model_name, matrix in matrices.items():

    plt.figure(figsize=(6, 5))

    plt.imshow(
        matrix,
        interpolation="nearest"
    )

    plt.title(
        f"{model_name} Confusion Matrix"
    )

    plt.xlabel("Predicted Class")
    plt.ylabel("Actual Class")

    plt.xticks(
        [0, 1],
        ["Benign", "Malware"]
    )

    plt.yticks(
        [0, 1],
        ["Benign", "Malware"]
    )

    # Add values inside cells
    for i in range(2):
        for j in range(2):

            plt.text(
                j,
                i,
                matrix[i][j],
                ha="center",
                va="center"
            )

    plt.colorbar()

    plt.tight_layout()

    output_path = (
        RESULTS_DIR /
        f"{model_name.lower()}_confusion_matrix.png"
    )

    plt.savefig(
        output_path,
        dpi=300
    )

    plt.close()

    print(
        f"\n✓ {model_name} confusion matrix saved to:"
    )

    print(output_path)


# =========================================================
# COMBINED COMPARISON
# =========================================================

fig, axes = plt.subplots(
    1,
    3,
    figsize=(15, 5)
)

for ax, (model_name, matrix) in zip(
    axes,
    matrices.items()
):

    image = ax.imshow(
        matrix,
        interpolation="nearest"
    )

    ax.set_title(
        model_name
    )

    ax.set_xlabel(
        "Predicted Class"
    )

    ax.set_ylabel(
        "Actual Class"
    )

    ax.set_xticks(
        [0, 1]
    )

    ax.set_xticklabels(
        ["Benign", "Malware"]
    )

    ax.set_yticks(
        [0, 1]
    )

    ax.set_yticklabels(
        ["Benign", "Malware"]
    )

    for i in range(2):
        for j in range(2):

            ax.text(
                j,
                i,
                matrix[i][j],
                ha="center",
                va="center"
            )

fig.suptitle(
    "Confusion Matrix Comparison - Android Malware Detection",
    fontsize=14
)

fig.colorbar(
    image,
    ax=axes,
    shrink=0.8
)

plt.tight_layout()

combined_path = (
    RESULTS_DIR /
    "confusion_matrix_comparison.png"
)

plt.savefig(
    combined_path,
    dpi=300
)

plt.close()

print(
    "\n✓ Combined confusion matrix saved to:"
)

print(combined_path)


print("\n" + "=" * 60)
print("PHASE 8C COMPLETED")
print("=" * 60)