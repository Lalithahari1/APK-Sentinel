import pandas as pd
from pathlib import Path


# =========================================================
# PHASE 9D - ANDROID MALWARE AI AGENT
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

PREDICTION_PATH = (
    BASE_DIR
    / "results"
    / "malware_explanations.csv"
)

OUTPUT_PATH = (
    BASE_DIR
    / "results"
    / "ai_agent_reports.csv"
)


print("=" * 60)
print("ANDROID MALWARE AI AGENT")
print("=" * 60)


# =========================================================
# LOAD EXPLANATION RESULTS
# =========================================================

print("\nLoading prediction and explanation data...")

data = pd.read_csv(
    PREDICTION_PATH
)

print(
    f"✓ Loaded {len(data)} samples"
)


# =========================================================
# AGENT DECISION LOGIC
# =========================================================

def analyze_sample(row):

    prediction = int(
        row["Prediction"]
    )

    confidence = float(
        row["Confidence"]
    )

    if prediction == 1:

        if confidence >= 0.90:
            risk = "HIGH"

        elif confidence >= 0.70:
            risk = "MEDIUM"

        else:
            risk = "LOW"

        assessment = (
            "The analyzed application is classified as "
            "potentially malicious by the trained DNN model."
        )

        recommendation = (
            "Treat the application as potentially unsafe. "
            "Perform additional security analysis before "
            "installation or deployment."
        )

    else:

        if confidence >= 0.90:
            risk = "LOW"

        elif confidence >= 0.70:
            risk = "MEDIUM"

        else:
            risk = "LOW"

        assessment = (
            "The analyzed application is classified as "
            "benign by the trained DNN model."
        )

        recommendation = (
            "No strong malware signal was detected by the "
            "model. However, the result should not be "
            "considered a guarantee of complete safety."
        )

    return (
        risk,
        assessment,
        recommendation
    )


# =========================================================
# RUN AI AGENT
# =========================================================

agent_risks = []
agent_assessments = []
agent_recommendations = []


for _, row in data.iterrows():

    risk, assessment, recommendation = (
        analyze_sample(row)
    )

    agent_risks.append(
        risk
    )

    agent_assessments.append(
        assessment
    )

    agent_recommendations.append(
        recommendation
    )


# =========================================================
# ADD AGENT OUTPUT
# =========================================================

data["Agent_Risk_Level"] = (
    agent_risks
)

data["Agent_Assessment"] = (
    agent_assessments
)

data["Agent_Recommendation"] = (
    agent_recommendations
)


# =========================================================
# SAVE AGENT REPORTS
# =========================================================

data.to_csv(
    OUTPUT_PATH,
    index=False
)

print("\n✓ AI Agent reports saved to:")

print(
    OUTPUT_PATH
)


# =========================================================
# INTERACTIVE AGENT
# =========================================================

print("\n" + "=" * 60)
print("INTERACTIVE MALWARE ANALYSIS")
print("=" * 60)

print(
    "\nAvailable sample IDs:"
)

print(
    "1 to",
    len(data)
)

user_input = input(
    "\nEnter sample ID to analyze "
    "(or type 'exit'): "
).strip()


if user_input.lower() != "exit":

    try:

        sample_id = int(
            user_input
        )

        selected = data[
            data["Sample"] == sample_id
        ]

        if selected.empty:

            print(
                "\n❌ Sample ID not found."
            )

        else:

            row = selected.iloc[0]

            print("\n")
            print("=" * 60)
            print("ANDROID MALWARE AI AGENT REPORT")
            print("=" * 60)

            print(
                f"\nSample ID       : "
                f"{row['Sample']}"
            )

            print(
                f"Prediction      : "
                f"{row['Class'].upper()}"
            )

            print(
                f"Confidence      : "
                f"{row['Confidence']:.2%}"
            )

            print(
                f"Risk Level      : "
                f"{row['Agent_Risk_Level']}"
            )

            print(
                "\nTop Influencing Features:"
            )

            features = str(
                row["Important_Features"]
            ).split(", ")

            for i, feature in enumerate(
                features,
                start=1
            ):

                print(
                    f"{i}. {feature}"
                )

            print(
                "\nAgent Assessment:"
            )

            print(
                row["Agent_Assessment"]
            )

            print(
                "\nSecurity Recommendation:"
            )

            print(
                row["Agent_Recommendation"]
            )

            print(
                "\n" + "=" * 60
            )

    except ValueError:

        print(
            "\n❌ Please enter a valid sample ID."
        )


print("\n" + "=" * 60)
print("PHASE 9D COMPLETED")
print("=" * 60)