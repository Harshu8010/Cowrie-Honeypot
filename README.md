# 🐍 Cowrie SSH Honeypot Intrusion Monitoring Lab

A virtual lab project designed to deploy and simulate an **SSH Honeypot** using **Cowrie**. This project captures and analyzes unauthorized access attempts including brute-force attacks, file uploads, and command executions. It showcases attacker behavior in a safe, controlled environment—perfect for SOC and threat intelligence use cases.

---

## 🎯 Project Objectives

- ✅ Deploy Cowrie honeypot on **Kali Linux**
- ✅ Simulate attacks from **Parrot OS** attacker machine
- ✅ Capture full SSH sessions including login attempts and commands
- ✅ Analyze logs (`.log`, `.json`, `tty/`) for behavioral patterns
- ✅ Optionally forward logs to **Splunk SIEM** for alerting and dashboards
- ✅ Document deception techniques and log analysis methodology

---

## 🖥️ Lab Architecture

```plaintext
Parrot OS (Attacker)
       ↓
Cowrie Honeypot on Kali Linux (Port 2222)
       ↓
(Optional) Splunk (Log Aggregation and Alerting)
```
---

## 🧪 Simulated Attacks

| Attack Type           | Tool Used     | Log Events Captured             |
|-----------------------|---------------|----------------------------------|
| Manual SSH Login      | OpenSSH	      | cowrie.session.connect, login.success   |
| Brute Force           | Login         |	Hydra	cowrie.login.failed, login.success      |
| File Upload (malware.sh)    | SCP   | cowrie.session.file_upload |
| Command Execution     | SSH Shell     | cowrie.command.input |
| Network Scanning      | Nmap          |	SSH connect/disconnect logs |

➡️ All logs and screenshots available in /screenshots/
➡️ Detailed session analysis available in /report.md

---

## 📦 Project Structure

├── setup.md               # Installation & Configuration of Cowrie

├── report.md              # Attack simulation, logs, analysis, findings

├── screenshots/           # Log screenshots and TTY captures

└── README.md              # Project overview

---

## 🛠️ Tools & Technologies

Cowrie – SSH honeypot (low interaction)

Kali Linux – Honeypot host machine

Parrot OS – Simulated attacker machine

Hydra – Brute-force login testing

SCP – File upload (malware.sh simulation)

Splunk – (Optional) SIEM for log ingestion and dashboarding

jq, tail, ttyplay – Log parsing and session analysis

---

## 📈 Why This Project Matters

- Cowrie is an effective tool to safely study attacker behavior without putting real infrastructure at risk. This project demonstrates:

- SSH attack simulation and deception

- Full session logging and forensic replay

- SIEM-ready log formats (JSON)

- Application of honeypots in threat detection and SOC workflows
  
---

## 📚 References

- Cowrie GitHub Repo

- Cowrie Documentation

- Hydra GitHub

- SANS: Introduction to Honeypots
