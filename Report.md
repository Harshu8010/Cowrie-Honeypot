# 🐍 Cowrie SSH Honeypot for Intrusion Monitoring

---

## 1. Introduction

### What is a Honeypot?

A honeypot is a decoy system designed to appear vulnerable and attract cyber attackers. Its purpose is to monitor, detect, and analyze malicious activity without risking actual production systems.

### Why Are Honeypots Useful in Cybersecurity?

Honeypots:
- Collect real-world data on attacker behavior
- Identify new exploits or malware
- Improve intrusion detection systems
- Provide intelligence without affecting real assets

They act as early-warning systems and research tools in threat intelligence and cybersecurity defense.

### Why Cowrie?

Cowrie is a popular low-interaction honeypot focused on SSH and Telnet services. It allows:
- Full session logging of attacker commands
- File upload/download emulation
- Fake file systems and user accounts
- JSON and text log outputs for SIEM integration

Cowrie was chosen due to its rich logging features, ease of deployment, and compatibility with monitoring tools like Splunk and Wazuh.

---

## 2. Project Objectives

-  **Simulate an exposed SSH service** Host a fake SSH server to lure attackers.

-  **Attract unauthorized access attempts** Deploy Cowrie in a visible IP range or test lab to receive intrusion attempts.

-  **Collect attacker commands and artifacts** Log all session activity, including entered commands, attempted downloads, and scanned ports.

-  **Analyze threat behavior** Study collected logs to understand attacker patterns, tools, and techniques.

-  **Optionally forward logs to SIEM** Integrate with platforms like Splunk or Wazuh for real-time alerting and visualization.

---

## 3. Tools and Technologies Used

This project utilized a combination of open-source tools and technologies to simulate an SSH honeypot, collect attacker data, and enable log analysis. Each tool served a distinct role in the architecture.

### i. Cowrie

- **Type**: SSH/Telnet Honeypot (Low-Interaction)
- **Purpose**: Simulates an SSH service to capture attacker commands, session behavior, and file downloads
- **Source**: [https://github.com/cowrie/cowrie](https://github.com/cowrie/cowrie)

### ii. Kali Linux

- **Type**: Host Operating System
- **Purpose**: Base platform for deploying Cowrie
- **Version**: Latest stable version at time of deployment (2025)
- **Reason for Use**: Comes with pre-installed tools and Python support. Easy to manage network interfaces and routing for honeypot labs

### iii. Python 3 & Virtualenv

- **Python Version**: 3.9+
- **Virtual Environment Tool**: `venv`
- **Purpose**: Create an isolated environment for Cowrie and its dependencies. Avoid conflicts with system-wide Python packages

### iv. ParrotOs

- **Type**: Attacker's System
- **Purpose**: Simulate real world attacks

### v. Splunk (Optional)

- **Type**: Security Information and Event Management (SIEM)
- **Purpose**: Centralized log collection and visualization
- **Integration**: Cowrie logs were forwarded using the HTTP Event Collector (HEC), Dashboards and alerts were created to analyze real-time attacker data

### vi. Other Utilities

| Tool       | Purpose                                    |
|------------|--------------------------------------------|
| `jq`       | JSON parsing and log formatting            |
| `tail`     | Real-time log monitoring                   |
| `nano`     | Editing Cowrie config files (`cowrie.cfg`) |
| `netstat`  | Verifying active services and ports        |
| `wget`/`curl` | Simulated file downloads by attackers  |

These tools together formed a complete honeypot lab environment that was lightweight, modular, and effective for capturing attacker telemetry.

---

## 4. Execution Strategy

The Cowrie honeypot was deployed on a Kali Linux virtual machine to emulate a vulnerable SSH environment. The following strategic decisions and configurations were made during execution:

### i. Ports and Services Exposed

- **Primary exposed service**: SSH (simulated by Cowrie)
- **Port used**: Port `2222` was chosen instead of the default port `22` to avoid the need for `authbind` or elevated privileges. This also helps avoid conflicts with any real SSH service running on the host.

- **Telnet service**: Disabled, Focus was kept on SSH to reduce noise and maintain a focused attack surface.

### ii. Network Exposure

- **Deployment mode**: Internal/controlled lab environment
- **Internet exposure**:  *Not publicly exposed* The honeypot was **not made accessible from the public internet** for safety and control. Instead, simulated attacks were performed from an internal Kali Linux VM acting as an attacker.
- **Visibility**: The honeypot was placed on a local virtual network shared between attacker and defender VMs (using VirtualBox Host-Only or Internal Adapter). This allowed for controlled testing of brute-force login attempts, command execution, and logging.

---

## 5. Deception Tactics Employed

Cowrie is a low-interaction honeypot designed to simulate a real Linux system and mislead attackers into believing they have successfully gained shell access. The following deception techniques were used during this project:

### i. Fake File System

- **Description**: Cowrie emulates a complete Linux file system structure.
- **Purpose**: Allows attackers to navigate directories, run commands like `ls`, `cd`, `cat`, etc., and believe they are interacting with a real machine.
- **Location**: Defined in the `share/cowrie/fs.pickle` file and extended by symbolic links.

### ii. Fake User Credentials

- **Description**: A predefined list of usernames and passwords is stored in `etc/userdb.txt`.
- **Purpose**: Allows attackers to "successfully" authenticate and gain shell access, increasing interaction time.
- **Example**: `root:password123` could be configured to always succeed.

### iii. Command Emulation

- **Description**: Cowrie simulates output for commonly used Linux commands (e.g., `ls`, `uname`, `cat`, `top`, `ps`).
- **Purpose**: Keeps attackers engaged by mimicking a functional shell environment.
- **Logged**: All commands and their fake outputs are logged in `cowrie.log` and `cowrie.json`.

### iv. Session Logging (TTY & JSON)

- **Description**: Full session logging, including keystrokes and terminal outputs.
- **Purpose**: Enables forensic analysis and replay of attacker activity.
- **Storage**:
  - Text logs: `var/log/cowrie/cowrie.log`
  - JSON logs: `var/log/cowrie/cowrie.json`
  - TTY logs: `var/log/cowrie/tty/`

### v. File Download Interception

- **Description**: Commands like `wget` and `curl` are intercepted.
- **Purpose**: Captures any files an attacker attempts to download for later analysis.
- **Storage Location**: `dl/` directory inside the Cowrie root.

### vi. Shell Prompt Emulation

- **Description**: Presents a fake shell prompt to attackers.
- **Purpose**: Makes attackers believe they have real access.
- **Behavior**: Responds to standard shell interactions and command structures.

### vii. Fake Network Configuration

- **Description**: Emulated outputs for `ifconfig`, `ip a`, and other network-related commands.
- **Purpose**: Prevents attackers from discovering it's a honeypot by hiding the real network state.

These tactics make Cowrie highly effective for capturing attacker behavior while ensuring the host system remains safe and isolated.

---

