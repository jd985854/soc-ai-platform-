# 🧠 AI-Assisted SOC Vulnerability & Log Correlation Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## 🔥 The Problem

Security Operations Center (SOC) analysts are drowning.  
They receive **4,500+ alerts daily**, and **83% are false positives**. Burnout is at 71%, and real threats get buried in the noise.

## 💡 The Solution

A **vendor-independent, AI-powered triage platform** that:
- Parses **Nessus XML** and **Apache access logs**
- Applies **deterministic filters** (CVSS, environment context)
- Correlates **suspicious log patterns** (SQLi, XSS, Log4Shell, Path Traversal)
- Runs a **Multi-Agent AI Consensus** using **Ollama + Llama 3.2** locally
- Generates a **clean, prioritized PDF report** with **evidence & reasoning**

**No cloud costs. No vendor lock-in. Runs entirely offline.**

---

## 🛠️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Backend** | Python 3.10+, Flask |
| **AI Engine** | LangChain + Ollama (Llama 3.2:3b) |
| **Parsing** | xmltodict, Python Regex |
| **Database** | SQLite (for memory/feedback) |
| **Sandbox** | Docker SDK (optional) |
| **Reporting** | ReportLab |
| **Frontend** | HTML, CSS (Bootstrap) |

---

## 🚀 Quick Start (Installation)

### 1. Clone the Repository
```
git clone https://github.com/yourusername/soc-ai-platform.git](https://github.com/jd985854/soc-ai-platform-.git
cd soc-ai-platform
```
2. Set Up Python Virtual Environment
```
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. Install Dependencies
```
pip install -r requirements.txt
```
4. Install Ollama (Local LLM)
```
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the model (2GB download)
ollama pull llama3.2:3b
```
5. Run the Application
```
python app.py
```
6. Open Your Browser
```
Navigate to: http://127.0.0.1:5000
```
Upload a .nessus file and an Apache .log file, then click "Triage & Generate Report".

🔮 Roadmap (Future Features)

    □

    Replace simulated AI with real Ollama agents (already coded)
    □

    Add SQLite feedback memory (learn from analyst corrections)
    □

    Support multiple log formats (Syslog, JSON, Windows Event Logs)
    □

    Add MITRE ATT&CK mapping
    □

    Build a real-time dashboard with WebSockets
    □

    Create Docker deployment for easy setup

🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

    Fork the repository

    Create your feature branch (git checkout -b feature/amazing)

    Commit your changes (git commit -m 'Add some amazing feature')

    Push to the branch (git push origin feature/amazing)

    Open a Pull Request

📄 License

This project is licensed under the MIT License. See the LICENSE file for details.
🙏 Acknowledgments

    LangChain for LLM orchestration

    Ollama for local LLM inference

    ReportLab for PDF generation

    Nessus for vulnerability scanning

📬 Contact

    LinkedIn: https://www.linkedin.com/in/john-daniel-s-p-210331291/

