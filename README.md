# 🛡️ AWS IAM Policy Guard: Agentic Analysis & Remediation

[![Security: Least Privilege](https://img.shields.io/badge/Security-Least%20Privilege-green)](https://aws.amazon.com/iam/)
[![Model: GPT-4o](https://img.shields.io/badge/Model-GPT--4o-blue)](https://openai.com/)
[![Cloud: Multi-Cloud Ready](https://img.shields.io/badge/Cloud-Multi--Cloud%20Ready-orange)](#-multi-cloud--scalability)

An automated, **Scalable** AI-driven security engine designed to perform static analysis on Cloud Identity policies. The system identifies over-permissive configurations and automatically generates **Least-Privilege** remediations.

---

## 🏗️ System Architecture & Scalability

The engine is engineered for horizontal scalability and high-throughput analysis, making it suitable for enterprise-level security auditing.

### 🚀 Scalability Highlights
* **Batch Processing:** Designed to process hundreds of policies simultaneously via directory-wide scanning, perfect for large-scale cloud environments.
* **Decoupled Logic:** The architecture separates the **Analyst** (Logic) from the **Validator** (Syntactic Check), allowing for rapid scaling of the analysis engine without compromising reliability.

### 🌐 Multi-Cloud & Cross-Platform Support (Bonus)
The core engine is designed to be **Cloud-Agnostic**:
* **GCP Integration:** Capable of ingesting **GCP IAM Bindings** and analyzing service account permissions.
* **Azure Integration:** Ready to evaluate **Azure RBAC Role Definitions**, identifying "Owner" or "Contributor" risks.
* **Scalable Adaptation:** By simply updating the `CLASSIFICATION_CRITERIA` module, the same agentic flow can be extended to any JSON-based policy format (Kubernetes RBAC, Okta, etc.).

## 🧠 Why GPT-4o? (Model Selection Rationale)

The system utilizes **OpenAI's GPT-4o** as its core reasoning engine. The choice was based on three critical factors for Security Engineering:

1. **Native JSON Mode:** High-fidelity adherence to structured outputs, which is essential for generating valid IAM policies that don't break infrastructure.
2. **Context Window & Reasoning:** GPT-4o excels at understanding the "intent" behind complex IAM Statements, allowing it to distinguish between necessary administrative tasks and dangerous misconfigurations.
3. **Low Latency for Scalability:** Provides the speed required for batch processing large directories of policies without causing bottlenecks in the security audit flow.
4. **Had Some Credits Left:** Thats the only vaiable option i had :) 
---

## 🔍 Security Classification Logic

The system evaluates policies based on the **Blast Radius** potential, following Senior Security Researcher standards:

### 🔴 Weak Policy Indicators
* **Wildcard Overuse:** Using `*` in sensitive Actions or Resources, violating **Zero Trust** principles.
* **Privilege Escalation (PrivEsc):** Detection of dangerous permissions like `iam:PassRole`, `iam:CreatePolicyVersion`, or `iam:AttachUserPolicy`.
* **Destructive Combinations:** Permissions that allow for data exfiltration or infrastructure deletion (e.g., `s3:Delete*` or `rds:DeleteDBInstance`).

### 🟢 Strong Policy Indicators
* **Granular Actions:** Explicitly defined methods (e.g., `s3:GetObject` instead of `s3:*`).
* **Resource Pinning:** Explicit ARNs (e.g., `arn:aws:s3:::production-data/*`).
* **Contextual Constraints:** Use of `Condition` keys to restrict access based on IP, MFA, or Tags.

---

## 🔄 The Agentic Feedback Loop

The system operates as an iterative loop to ensure the highest quality of remediation:

1.  **Analysis:** The `gpt-4o` agent flags the policy as `STRONG` or `WEAK` with a detailed justification.
2.  **Remediation:** For `WEAK` policies, the **Remediator** drafts a hardened version.
3.  **Validation:** A deterministic Python script validates the JSON. If the AI makes a syntax error, the agent **self-corrects** (up to 3 retries).
4.  **Output:** A final evaluation report is generated, containing the analysis and the secured policy.

---

![System Architecture](/assets/graph.png)


---

## 🚀 Getting Started
### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/idoelarat/AWS-IAM-Policy-Classification-Engine.git
   cd AWS-IAM-Policy-Classification-Engine
   ```
2. **Create a virtual environment Linux / Windows:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
### Configuration
   The application requires an API key to communicate with your ai agent.
   ```bash
   touch .env
   ```
   Open the .env file and add your OpenAI credentials:
   ```Code Snippet
   API_KEY=your_api_key_here
   ```

### Running The App
   with one example:
   ```bash
   python main.py
   ```
   with uploaded file to the same dir
   ```bash
   python main.py --file file_name
   ```
   with banch of json file with the same dir (will create final_evaluation_report.json file)
   ```bash
   python main.py --dir dir_location
   ```
---
