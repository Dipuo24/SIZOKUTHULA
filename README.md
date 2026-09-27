# SIZOKUTHULA

## An AI-Powered System for Detecting Insider Threats and Protecting the Integrity of Grade 12 National Senior Certificate Examinations

SIZOKUTHULA is an academic prototype developed to explore the use of data science and machine learning for detecting unusual behaviour by authorised users in a simulated examination administration environment.

The project focuses on protecting the integrity and confidentiality of Grade 12 National Senior Certificate (NSC) examinations by identifying behavioural patterns that may indicate potential insider threats.

## Project Aim

The main aim of SIZOKUTHULA is to design, develop and evaluate an AI-powered insider threat detection system that can identify unusual user behaviour and provide security personnel with information that can support further investigation.

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

The project uses the following techniques:

* Isolation Forest
* K-Means Clustering
* Rule-based risk scoring

Isolation Forest is used as the main unsupervised anomaly detection method. K-Means is used as a secondary clustering-based method. The outputs are combined with examination-security-related behavioural indicators to support the identification of suspicious activity.

## Data

The project uses the CERT Insider Threat Dataset as the behavioural foundation for the prototype.

The dataset contains different types of simulated employee activity, including:

* Logon and logoff activity
* File activity
* Removable device activity
* Email activity
* Web activity

The project adapts this behavioural information to a simulated South African examination administration environment.

Simulated roles, departments, provinces and subject permissions are used to represent an examination administration environment.

Real Department of Basic Education employee information, learner information and real examination papers were not used in this prototype.

## Project Structure

```text
SIZOKUTHULA/
│
├── app.py
├── README.md
├── requirements.txt
│
├── notebooks/
│   ├── Data_Preprocessing.ipynb
│   ├── Feature_Engineering.ipynb
│   ├── Synthetic_Data.ipynb
│   ├── Isolation_Forest.ipynb
│   ├── KMeans.ipynb
│   └── Model_Evaluation.ipynb
│
├── models/
│
├── templates/
│
├── static/
│
└── screenshots/
```

The notebook names above are examples. The actual repository structure may contain additional notebooks and files used during the project.

## Web Application

The SIZOKUTHULA prototype was developed using Flask.

The application includes role-based access for:

### Administrator

The Administrator can access administrative functions, employee information and system-level monitoring features.

### Security Analyst

The Security Analyst can access security alerts, review suspicious activity and verify or silence alerts after completing the required verification process.

### Employee

Employees can access their own work portal and perform role-related activities.

## Risk Scoring

The prototype uses a transparent rule-based risk score to support the interpretation of suspicious behaviour.

The risk score considers indicators such as:

* After-hours activity
* Weekend activity
* High-volume record access
* Subject-permission mismatch
* Unauthorised examination-paper handling
* USB activity
* Download activity

The resulting score is mapped to different threat levels to support human review.

## Model Results

The final evaluation compared Isolation Forest, K-Means and the combined approach.

The combined approach achieved:

* Accuracy: 97.66%
* Precision: 100.00%
* Recall: 46.12%
* F1-score: 0.631

The results also showed that Isolation Forest provided most of the detection signal, while K-Means contributed a small additional number of detections.

The results are specific to the experimental dataset and simulated threat scenarios and should not be interpreted as evidence of production-level performance.

## Ethical and Privacy Considerations

This project is an academic prototype.

Real employee or learner personal information and real examination papers were not used.

The use of such a system in a real examination environment would require appropriate ethical approval, privacy assessment, security testing, stakeholder engagement and compliance with applicable South African data-protection requirements.

## Repository Contents

This repository contains:

* Flask application source code
* Jupyter Notebooks
* Machine-learning implementation
* Model-related files
* HTML templates
* Static files
* Supporting project documentation

Sensitive information and restricted datasets should not be included in the public repository.

## Academic Project

**Author:** Dipuo Princess Masoga

**Institution:** Sol Plaatje University

**Programme:** BSc Data Science

**Year:** 2026

## GitHub Repository

This repository contains the source code and supporting files for the SIZOKUTHULA capstone project.
