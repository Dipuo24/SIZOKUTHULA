# SIZOKUTHULA

## An AI-Powered System for Detecting Insider Threats and Protecting the Integrity of Grade 12 National Senior Certificate Examinations

SIZOKUTHULA is an academic prototype developed to explore the use of data science and machine learning to detect unusual behaviour that may indicate insider threats in a simulated examination administration environment.

The project focuses on the protection of the integrity and confidentiality of Grade 12 National Senior Certificate (NSC) examinations. It uses employee activity data, machine-learning models and rule-based risk scoring to identify activities that may require further investigation.

## Project Aim

The main aim of SIZOKUTHULA is to develop and evaluate an insider threat detection system that can identify unusual user behaviour and provide security personnel with information that can support further investigation.

## Main Objectives

The project aims to:

1. Identify unusual employee behaviour using behavioural and examination-security-related indicators.
2. Evaluate Isolation Forest and K-Means for detecting unusual activity.
3. Combine machine-learning outputs with a transparent rule-based risk score.
4. Develop a role-based web application that displays alerts and supports security monitoring and verification.

## Technologies Used

* Python
* Jupyter Notebook
* Pandas
* NumPy
* Scikit-learn
* Flask
* SQLite
* HTML
* CSS
* JavaScript
* Git
* GitHub

## Machine Learning Methods

The project uses the following methods:

* Isolation Forest
* K-Means Clustering
* Rule-based risk scoring

Isolation Forest is used as the main anomaly detection method. K-Means is used as a secondary clustering method. The model outputs are combined with behavioural and examination-security indicators to help identify activities that may require attention.

## Data

The project uses the CERT Insider Threat Dataset as the behavioural foundation for the prototype.

The dataset contains simulated employee activity from different sources, including:

* Logon and logoff activity
* File activity
* Removable device activity
* Email activity
* Web activity

The project adapts this behavioural information to a simulated South African examination administration environment.

Additional simulated information, such as employee roles, departments, provinces and subject permissions, is used to represent the examination environment.

Real Department of Basic Education employee information, learner information and real examination papers were not used in this prototype.

## Project Structure

The repository is organised as follows:

```text
sizokuthola_system/
│
├── README.md
├── requirements.txt
├── app.py
├── scoring.py
│
├── data/
│   └── SIZOKUTHOLA_Final_Dataset.csv
│
├── models/
│   ├── IsolationForest_Model.pkl
│   ├── KMeans_Model.pkl
│   └── Scaler.pkl
│
├── notebooks/
│   ├── CTGAN_MODEL_PROOF.ipynb
│   ├── DBE_Employee_Activities.ipynb
│   ├── DBE_Employee_Behaviour.ipynb
│   ├── Final_Model.ipynb
│   ├── GAUSSIAN_COPULA_MODEL.ipynb
│   ├── Inject_Insider_Threat_Scenarios.ipynb
│   ├── Sizokuthula_final_dataset.ipynb
│   ├── Standalone_Model_Evaluation.ipynb
│   ├── TVAE_MODEL.ipynb
│   └── code_preprocessing_Cert.ipynb
│
├── reports/
│   ├── Department_Risk_Report.csv
│   ├── Province_Risk_Report.csv
│   └── Security_Alerts.csv
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── images/
│       └── logo.png
│
└── templates/
    ├── 404.html
    ├── 500.html
    ├── alerts.html
    ├── analytics.html
    ├── base.html
    ├── dashboard.html
    ├── employee_detail.html
    ├── employee_login.html
    ├── employee_portal.html
    ├── employees.html
    ├── login.html
    ├── profile.html
    ├── reports.html
    ├── settings.html
    └── staff_login.html
```

### Main Files and Folders

* **`app.py`** – contains the main Flask web application.
* **`scoring.py`** – contains the risk-scoring logic used by the system.
* **`data/`** – contains the final dataset used by the application.
* **`models/`** – contains the trained machine-learning models and scaler.
* **`notebooks/`** – contains the Jupyter Notebooks used for data preparation, synthetic data generation, modelling, scenario creation and evaluation.
* **`reports/`** – contains generated risk and security reports.
* **`templates/`** – contains the HTML pages used by the Flask application.
* **`static/`** – contains the CSS and image files used by the web application.
* **`requirements.txt`** – contains the Python packages required to run the project.

## Web Application

The SIZOKUTHULA prototype was developed using Flask.

The application provides different functions for different types of users.

### Administrator

The Administrator can access administrative functions, employee information and system-level monitoring features.

### Security Analyst

The Security Analyst can view security alerts, review suspicious activities and carry out verification actions.

### Employee

Employees can access their own portal and perform activities based on their assigned role and permissions.

## Risk Scoring

The system uses a transparent rule-based risk score to help interpret suspicious behaviour.

The score considers indicators such as:

* After-hours activity
* Weekend activity
* High-volume record access
* Subject-permission mismatch
* Examination-paper handling
* USB activity
* Download activity

The resulting score is used to assign different threat levels and support further human review.

## Model Results

The final evaluation compared the machine-learning approaches used in the project, including Isolation Forest, K-Means and the combined approach.

The combined approach achieved the following results on the experimental dataset:

* Accuracy: 97.66%
* Precision: 100.00%
* Recall: 46.12%
* F1-score: 0.631

The evaluation also showed that Isolation Forest provided most of the detection signal, while K-Means contributed additional detections.

These results are specific to the experimental dataset and simulated threat scenarios. They should therefore not be interpreted as evidence of production-level performance.

## Ethical and Privacy Considerations

SIZOKUTHULA is an academic prototype.

Real employee or learner personal information and real examination papers were not used in the development of the system.

A system of this type would require appropriate ethical approval, privacy assessment, security testing, stakeholder involvement and compliance with applicable South African data-protection requirements before being considered for use in a real examination environment.

## Repository Contents

This repository contains:

* Flask application source code
* Jupyter Notebooks
* Machine-learning models
* Final dataset
* Risk and security reports
* HTML templates
* CSS and image files
* Project documentation
* Python package requirements

The repository is intended to document the development and implementation of the SIZOKUTHULA academic prototype.

## Academic Project

**Author:** Dipuo Princess Masoga
**Institution:** Sol Plaatje University
**Programme:** BSc Data Science
**Year:** 2026
