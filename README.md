# Hybrid Domain-Adaptive Framework for Cross-System Log Anomaly Detection

A cybersecurity-focused log anomaly detection framework that combines machine learning, rule-based detection, hybrid anomaly analysis, and domain-adaptive Transformer architectures for detecting suspicious behavior across heterogeneous system logs.

This project was developed as part of internship/research work at the Center for Information Security, Forensics and Cyber Resilience (C-ISFCR), PES University.

---

# Team Members

- Spoorthi V Pai
- Lahari L M

---

# Project Overview

Modern computing infrastructures such as Linux servers, cloud platforms, distributed systems, enterprise environments, and supercomputers continuously generate massive volumes of runtime logs. These logs contain valuable information regarding authentication events, abnormal system behavior, failed login attempts, unauthorized access, privilege escalation, and security incidents.

Manual inspection of such large-scale logs is inefficient and difficult. This project implements a unified hybrid and domain-adaptive framework for automated log anomaly detection using:

- Machine Learning-based sequence analysis
- Rule-based cybersecurity detection
- Hybrid anomaly detection
- Transformer-based sequential learning
- Domain adaptation using Gradient Reversal Layer (GRL)

The framework focuses on identifying suspicious activities such as:

- Brute-force login attacks
- Invalid user enumeration
- Excessive sudo usage
- Authentication anomalies
- Cross-system log anomalies

---

# Important Note

This repository contains a simplified reproducible implementation of the Linux-based log anomaly detection workflow.

The complete research work included:

- Large-scale datasets
- Advanced preprocessing pipelines
- HDFS, BGL, Windows, and Linux log experiments
- Transformer-based anomaly detection
- Domain-adaptive learning using Gradient Reversal Layer (GRL)
- Cross-domain transfer learning experiments

The final complete experimental implementation could not be fully recovered. However, this repository includes the reproducible Linux-based implementation, notebook experiments, project report, and research paper documenting the complete methodology and results.

---

# Key Features

- Linux authentication log parsing
- Event abstraction using structured event IDs
- Sliding-window sequence generation
- Frequency-based anomaly detection
- Rule-based cybersecurity alert generation
- Hybrid ML + rule-based detection framework
- DeepLog-inspired sequence learning
- Transformer-based sequential log modeling
- Gradient Reversal Layer (GRL) based domain adaptation
- Cross-system anomaly detection experiments
- Evaluation using Accuracy, Precision, Recall, F1-score, ROC curves, and Confusion Matrices

---

# Datasets Used

| Dataset | Description | Purpose |
|---|---|---|
| HDFS | Hadoop Distributed File System logs | Sequence learning and Transformer experiments |
| BGL | Blue Gene/L supercomputer logs | Cross-domain transfer evaluation |
| Windows Event Logs | Windows security/system logs | Cross-system generalization |
| Linux Authentication Logs | auth.log and Linux LogHub datasets | Practical cybersecurity anomaly detection |

---

# Event Mapping for Linux Logs

Linux authentication logs were converted into structured event IDs for sequence learning.

| Event ID | Meaning |
|---|---|
| E0 | Normal/background/unclassified event |
| E1 | Failed password authentication |
| E2 | Successful login |
| E3 | Sudo command usage |
| E4 | Invalid user attempt |
| E5 | Session closed |
| E6 | Connection closed |
| E7 | PAM authentication event |

---

# Methodology

## 1. Log File Loading

Raw Linux authentication logs are loaded from:

- `/var/log/auth.log`
- Linux LogHub datasets
- custom Linux security logs

Example:

```python
with open("linux.log", "r") as file:
    logs = file.readlines()
```

---

## 2. Event Parsing and Abstraction

Raw log lines are converted into structured event IDs using keyword-based pattern matching.

Example:

```python
if "failed password" in line:
    return "E1"
elif "accepted password" in line:
    return "E2"
elif "sudo" in line:
    return "E3"
elif "invalid user" in line:
    return "E4"
else:
    return "E0"
```

This abstraction reduces textual complexity and enables efficient sequence modeling.

---

## 3. Sequence Generation

Sliding-window techniques are used to generate fixed-length event sequences.

Example:

```text
Event Stream:
E2 → E3 → E1 → E1 → E4 → E2 → E3

Generated Sequences:
[E2, E3, E1]
[E3, E1, E1]
[E1, E1, E4]
[E1, E4, E2]
[E4, E2, E3]
```

This allows the model to learn temporal relationships between events.

---

## 4. Machine Learning-Based Anomaly Detection

A frequency-based sequence learning model was implemented.

The model:

- learns probabilities of observed event sequences
- identifies low-probability sequences
- flags rare or suspicious sequences as anomalies

Low-frequency event patterns are treated as abnormal behavior.

---

## 5. Rule-Based Cybersecurity Detection

A rule engine was implemented to detect known attack signatures.

### Rules Included

### Brute-Force Attack Detection

Triggered when repeated failed password attempts occur consecutively.

### User Enumeration Detection

Triggered when multiple invalid-user attempts are detected.

### Excessive Sudo Usage Detection

Triggered when abnormal sudo activity or privilege escalation behavior is observed.

---

## 6. Hybrid Detection Framework

The hybrid framework combines:

- Machine Learning predictions
- Rule-based alerts

A sequence is classified as anomalous if:

- the ML module detects a low-probability sequence, OR
- the rule engine detects a suspicious pattern

This improves overall anomaly coverage and detection balance.

---

# System Architecture

The proposed framework consists of the following major modules:

1. Data Collection
2. Log Preprocessing
3. Event Extraction
4. Sequence Generation
5. Machine Learning Module
6. Rule-Based Detection Module
7. Hybrid Detection Framework
8. Transformer-Based Sequential Learning
9. Domain-Adaptive Transformer using GRL
10. Evaluation and Visualization

---

# Domain-Adaptive Transformer Framework

The advanced phase of the project focused on deep learning-based cross-system anomaly detection.

## Transformer Components

- Embedding Layer
- Positional Encoding
- Multi-Head Self-Attention
- Layer Normalization
- Feed-Forward Networks
- Sigmoid Classification Layer

## Gradient Reversal Layer (GRL)

A Gradient Reversal Layer was integrated for domain adaptation.

GRL enables the model to learn:

- domain-invariant representations
- shared anomaly patterns
- cross-system behavioral relationships

This improves transfer learning between heterogeneous log systems.

---

# Cross-Domain Experiments

Experiments performed:

- HDFS → BGL
- HDFS → Windows
- Multi-domain training across HDFS, BGL, and Windows

The GRL-based domain-adaptive Transformer significantly improved cross-system generalization.

---

# Linux-Based Model Results

| Model | Accuracy | Precision | Recall |
|---|---:|---:|---:|
| ML-Only Frequency Model | 0.715 | 0.214 | 0.068 |
| Rule-Based Model | 0.920 | 1.000 | 0.668 |
| Hybrid Model | 0.876 | 0.745 | 0.737 |

---

# Result Analysis

## ML-Only Model

The ML-only model successfully learned normal sequence behavior but struggled with unseen anomalies and rare attack patterns.

This resulted in low recall.

## Rule-Based Model

The rule-based model achieved very high precision because cybersecurity rules are deterministic and highly specific.

However, it could miss anomalies that do not match predefined attack signatures.

## Hybrid Model

The hybrid framework achieved balanced detection performance by combining:

- ML adaptability
- rule-based reliability

This improved anomaly coverage while maintaining strong precision.

---

# Transformer-Based Cross-Domain Results

| Model Setup | F1-Score | Observation |
|---|---:|---|
| Plain Transformer: HDFS → BGL | 0.15 | Severe domain shift failure |
| Regularized Transformer: HDFS → BGL | 0.20 | Minor improvement |
| Domain-Adaptive Transformer with GRL | 0.93 | Strong cross-domain generalization |
| Domain-Adaptive Transformer: HDFS → Windows | 0.97 | Best result achieved |

---

# Technologies Used

- Python
- Scikit-learn
- TensorFlow / Keras
- NumPy
- Pandas
- Matplotlib
- Jupyter Notebook
- Linux Logs
- LogHub datasets
- Transformer models
- Gradient Reversal Layer
- Machine Learning
- Cybersecurity rule-based detection

---

# Repository Structure

```text
hybrid-log-anomaly-detection/
│
├── README.md
├── requirements.txt
├── main.py
├── .gitignore
├── LICENSE
│
├── docs/
│   ├── Report-Final.docx
│   └── Internship Research Paper.pdf
│
├── notebooks/
│   └── hdfs-log-anomaly-detection.ipynb
│
├── results/
│   └── result images
│
├── diagrams/
│   └── architecture diagrams
│
└── sample-data/
    └── sample-auth.log
```

---

# How to Run

## 1. Clone the Repository

```bash
git clone https://github.com/your-username/hybrid-log-anomaly-detection.git
cd hybrid-log-anomaly-detection
```

---

## 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 3. Run the Linux Log Detection Script

```bash
python main.py
```

---

## 4. Run the Notebook

Open:

```text
notebooks/hdfs-log-anomaly-detection.ipynb
```

and execute the cells to study the HDFS-based anomaly detection workflow.

---

# Sample Output

```text
Total logs: 20

ML Detected Anomalies:
Anomaly detected due to low-probability sequence

RULE-BASED ALERTS:
Brute Force Attack Detected
User Enumeration Attack Detected
Excessive Sudo Usage / Possible Privilege Escalation Detected
```

---

# Visual Results

The project includes:

- System architecture diagram
- Linux log parsing workflow
- Sliding-window sequence generation
- Performance comparison graphs
- Confusion matrices
- ROC curve comparison
- Domain-Adaptive Transformer architecture

---

# Limitations

- Some anomaly labels were generated using heuristic logic.
- Real-time streaming deployment was not implemented.
- The Linux ML module uses frequency-based sequence learning.
- Log datasets are highly imbalanced.
- Cross-domain performance depends heavily on preprocessing quality.
- The final experimental code version could not be fully recovered.

---

# Future Scope

- Real-time streaming anomaly detection
- SIEM integration with Splunk or Elastic SIEM
- Docker deployment
- Cloud deployment on AWS/Azure
- Transformer-LSTM hybrid architectures
- Self-supervised log representation learning
- Federated anomaly detection
- Real-time SOC dashboard integration

---

# Conclusion

This project demonstrates that robust log anomaly detection requires the integration of multiple complementary approaches.

- Rule-based systems provide strong precision for known attacks
- Machine learning enables adaptive anomaly identification
- Hybrid frameworks improve balanced detection performance
- Domain-adaptive Transformers improve cross-system generalization

The proposed framework provides a scalable and practical foundation for cybersecurity monitoring, SOC operations, SIEM analytics, and automated threat detection in heterogeneous computing environments.

---

# Keywords

Log Anomaly Detection, Cybersecurity, SOC, SIEM, Machine Learning, Deep Learning, Transformer, Gradient Reversal Layer, Domain Adaptation, Linux Logs, HDFS Logs, BGL Logs, Windows Event Logs, Hybrid Detection, DeepLog, Threat Detection
