# 🛡️ Android Malware Detection Using Deep Learning

A deep-learning-based Android malware detection system that analyzes Android application features and classifies applications as **Benign** or **Malware**.

The project combines **static and dynamic Android application features** and evaluates three machine-learning/deep-learning models:

* **Deep Neural Network (DNN)**
* **Convolutional Neural Network (CNN)**
* **TabNet**

The **DNN achieved the best overall performance** and was selected as the final model.

---

## 📌 Project Overview

Android applications can contain malicious behavior that may compromise user privacy, device security, and sensitive information.

This project aims to detect potentially malicious Android applications by learning patterns from static and dynamic application features.

The system includes:

* Dataset preprocessing
* Feature preparation
* Static and dynamic feature handling
* Deep-learning model training
* Model evaluation
* Malware prediction
* Risk-level assessment
* Feature-importance analysis
* Explainability
* Streamlit-based user interface
* APK analysis using Androguard

---

## 🎯 Objectives

The main objectives of this project are:

1. Detect whether an Android application is **Benign** or **Malware**.
2. Use static and dynamic Android application features for classification.
3. Compare DNN, CNN, and TabNet models.
4. Evaluate the models using standard classification metrics.
5. Select the best-performing model for final prediction.
6. Provide a user-friendly interface for malware prediction and risk assessment.

---

## 📊 Dataset

The final dataset contains:

| Property         |     Value |
| ---------------- | --------: |
| Total Samples    | **3,542** |
| Total Features   |   **340** |
| Static Features  |   **179** |
| Dynamic Features |   **161** |
| Benign Samples   | **1,798** |
| Malware Samples  | **1,744** |

The project processes static and dynamic features and prepares them for machine-learning/deep-learning classification.

---

## 🤖 Models Used

Three models were evaluated:

### 1. Deep Neural Network (DNN)

A fully connected neural network used to learn complex relationships between Android application features and malware labels.

### 2. Convolutional Neural Network (CNN)

A convolution-based deep-learning model evaluated for malware classification using the prepared feature representation.

### 3. TabNet

A tabular deep-learning architecture used to model structured Android application features.

---

## 📈 Model Performance

The evaluated models achieved the following results:

| Model   |   Accuracy |  Precision |     Recall |   F1-Score |    ROC-AUC |
| ------- | ---------: | ---------: | ---------: | ---------: | ---------: |
| **DNN** | **98.17%** | **97.73%** | **98.57%** | **98.15%** | **99.70%** |
| CNN     |     97.74% |     97.17% |     98.28% |     97.72% |     99.67% |
| TabNet  |     91.82% |     89.65% |     94.27% |     91.90% |     96.90% |

### 🏆 Best Model

The **DNN** achieved the highest reported performance:

* **Accuracy:** 98.17%
* **Precision:** 97.73%
* **Recall:** 98.57%
* **F1-Score:** 98.15%
* **ROC-AUC:** 99.70%

Therefore, the DNN is selected as the final model.

---

## ✨ Key Features

### 🔹 Dataset Processing

* Dataset preprocessing
* Duplicate removal
* Constant-feature removal
* Train/test splitting
* Validation splitting

### 🔹 Machine Learning / Deep Learning

* DNN classification
* CNN classification
* TabNet classification
* Model comparison

### 🔹 Evaluation

* Accuracy
* Precision
* Recall
* F1-score
* ROC-AUC
* Confusion matrices
* ROC curves
* Feature-importance analysis

### 🔹 Malware Analysis

* Android APK analysis
* Static feature extraction
* Dynamic feature handling
* Malware/Benign prediction
* Malware probability
* Confidence score
* Risk-level assessment
* Feature information
* Explainability

### 🔹 Web Interface

The project provides a **Streamlit-based interface** for interacting with the malware detection system.

---

## 🧠 System Workflow

```text
Android Application / Dataset
             │
             ▼
     Feature Extraction
             │
             ▼
   Static + Dynamic Features
             │
             ▼
       Data Preprocessing
             │
             ▼
       Feature Preparation
             │
             ▼
     ┌───────┼────────┐
     ▼       ▼        ▼
    DNN     CNN     TabNet
     │       │        │
     └───────┼────────┘
             ▼
       Model Evaluation
             │
             ▼
       Best Model: DNN
             │
             ▼
    Malware / Benign Result
             │
             ▼
       Risk Assessment
             │
             ▼
       Streamlit Interface
```

---

## 🏗️ Project Structure

```text
android-malware-detection/
│
├── .gitignore
├── README.md
├── requirements.txt
│
├── datasets/
│   ├── dataset1_dynamic.csv
│   ├── dataset1_static.csv
│   ├── fused_dataset.csv
│   ├── preprocessed_dataset.csv
│   ├── X_train.csv
│   ├── X_validation.csv
│   ├── X_test.csv
│   ├── X_final_train.csv
│   ├── y_train.csv
│   ├── y_validation.csv
│   ├── y_test.csv
│   └── y_final_train.csv
│
├── models/
│   ├── final_cnn_model.keras
│   ├── final_dnn_model.keras
│   └── final_tabnet_model.zip
│
├── results/
│   ├── accuracy_comparison.png
│   ├── cnn_confusion_matrix.png
│   ├── dnn_confusion_matrix.png
│   ├── tabnet_confusion_matrix.png
│   ├── confusion_matrix_comparison.png
│   ├── roc_curves.png
│   ├── overall_model_comparison.png
│   ├── precision_recall_f1_comparison.png
│   ├── dnn_feature_importance.png
│   ├── dnn_feature_importance.csv
│   ├── dnn_predictions.csv
│   ├── malware_explanations.csv
│   ├── model_comparison.csv
│   └── final_project_report.txt
│
├── samples/
│   └── README.md
│
├── src/
│   ├── ai_agent.py
│   ├── ai_agent_runtime.py
│   ├── apk_feature_vector.py
│   ├── apk_metadata.py
│   ├── apk_predict.py
│   ├── apk_prediction_report.py
│   ├── apk_static_analyzer.py
│   ├── dynamic_feature_activity.py
│   ├── dynamic_feature_mapping.py
│   ├── evaluation.py
│   ├── explainability.py
│   ├── explanation_engine.py
│   ├── feature_fusion.py
│   ├── final_cnn.py
│   ├── final_dnn.py
│   ├── final_report.py
│   ├── final_split.py
│   ├── final_tabnet.py
│   ├── predict_malware.py
│   ├── preprocessing.py
│   ├── roc_curves.py
│   ├── split_data.py
│   ├── train_cnn.py
│   ├── train_dnn.py
│   ├── train_model.py
│   └── train_tabnet.py
│
└── ui/
    ├── app.py
    ├── analyzer.py
    └── assets/
        ├── android_security_view.png
        ├── android_sentinel.png
        ├── apk_sentinel_banner.jpeg
        └── apk_sentinel_hero.png
```

---

## 🛠️ Technologies Used

### Programming Language

* Python

### Deep Learning

* TensorFlow
* Keras
* PyTorch
* PyTorch TabNet

### Data Science

* Pandas
* NumPy
* Scikit-learn
* Matplotlib
* Seaborn

### Android Analysis

* Androguard
* APK feature extraction

### Web Application

* Streamlit

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd android-malware-detection
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

#### Windows

```bash
.venv\Scripts\activate
```

#### Linux / macOS

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

The repository intentionally does **not** include the local `.venv` directory. Dependencies are recreated using `requirements.txt`.

---

## ▶️ Running the Application

From the project root, run the Streamlit application:

```bash
streamlit run ui/app.py
```

The Streamlit interface provides functionality for malware prediction, risk assessment, feature information, and model-related results.

---

## 🔍 Application Output

The application can provide information including:

* Malware / Benign prediction
* Malware probability
* Confidence score
* Risk level
* Feature information
* Dataset label comparison
* Model performance comparison

---

## 📊 Results and Visualizations

The `results/` directory contains evaluation outputs generated during the project, including:

* Confusion matrices
* ROC curves
* Accuracy comparison
* Precision/Recall/F1 comparison
* Model comparison
* DNN feature importance
* Prediction results
* Malware explanations
* APK analysis results

These files provide visual and tabular evidence of the model evaluation.

---

## 🧪 Testing With APK Files

The `samples/` directory is intentionally not used to distribute APK files.

To test the application, provide an Android APK through the application's APK analysis functionality.

APK files are excluded from the Git repository using `.gitignore`.

---

## 🔐 Security Note

This project is intended for **research and educational purposes**.

Do not upload sensitive, private, or confidential APK files to the application.

APK analysis should be performed in an appropriate isolated environment when dealing with unknown or potentially malicious applications.

---

## 🚀 Future Improvements

Possible future improvements include:

* Larger and more diverse Android malware datasets
* Additional malware families
* More advanced dynamic analysis
* Real-time threat intelligence integration
* Additional deep-learning architectures
* Improved explainability
* Automated security reporting
* Deployment as a production security service

---

## 📄 Project Result

The final DNN model achieved:

```text
Accuracy  : 98.17%
Precision : 97.73%
Recall    : 98.57%
F1-Score  : 98.15%
ROC-AUC   : 99.70%
```

The DNN was therefore selected as the final model for the project.

---

## ⚠️ Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes.

The reported model performance is based on the dataset and experimental setup used in this project. Performance on new or unseen Android applications may differ.

---

## 👨‍💻 Author

**HARI PARGYA SAI LALITHA**

Android Malware Detection Using Deep Learning
