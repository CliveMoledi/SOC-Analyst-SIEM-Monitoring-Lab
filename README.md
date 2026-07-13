# SOC Investigation Report: Suspected VPN Compromise Leading to Lateral Movement and Data Exfiltration

**Analyst:** Kgalalelo Clive Moledi

**Date:** 2026-06-18

**Tools Used:** Splunk (SIEM)

**Log Sources:** `firewall_logs`, `vpn_logs` (`vpn_auth.json`), `ids_alerts.json`

**Classification:** Internal Use / Training Lab

**Severity:** High (simulated)

---

## 1. Executive Summary

Analysis of network, VPN, and IDS logs in Splunk reveals a multi-stage attack chain consistent with **external reconnaissance → VPN credential compromise → lateral movement via SMB → command-and-control (C2) beaconing → data exfiltration**.

The activity originated from external IP `203.0.113.45`, which conducted heavy scanning against internal host `10.0.0.20` and repeatedly targeted the VPN service account `svc_backup`. A successful VPN authentication for this account was observed from the same external IP, granting internal access via `10.8.0.23`. Two successful logins occurred within 10 seconds of each other — behavior inconsistent with normal human login patterns and more consistent with scripted/automated access. From there, internal SMB traffic, IDS-flagged C2 beaconing from `10.0.0.60`, and a large HTTP POST upload from `10.0.0.51` indicate the intrusion progressed from initial access to lateral movement and likely exfiltration.

**Bottom line:** A single external actor is the common thread across every stage of this investigation, and the evidence supports escalation as a credential-compromise incident with confirmed lateral movement and suspected data loss.

<img width="1748" height="1056" alt="Splunk startup" src="https://github.com/user-attachments/assets/910db4e6-efda-4686-8434-269217c9621b" />

*Figure 1: Splunk interface, initial state.*

<img width="945" height="540" alt="index=network_logs results" src="https://github.com/user-attachments/assets/83e9a8de-1eef-48bd-ac5d-1e84847ceac7" />

*Figure 2: Search scope set to `index="network_logs"`, confirming log availability across sources.*

---

## 2. Attack Timeline (Reconstructed)

| Stage | Observed Activity | Key Indicator | MITRE ATT&CK |
|---|---|---|---|
| 1. Reconnaissance | External IP scans internal network | `203.0.113.45` generated 297 firewall events | T1595 – Active Scanning |
| 2. Target Identification | Scanning concentrates on one host | `10.0.0.20` received 351 firewall events | T1595.002 – Vulnerability Scanning |
| 3. Credential Targeting | VPN brute-force / spraying against service account | `svc_backup` targeted 135 times | T1110 – Brute Force |
| 4. Initial Access | Successful VPN auth from attacker IP; anomalous double-login in 10s | `203.0.113.45` → `svc_backup` → assigned `10.8.0.23` | T1078.004 – Valid Accounts (Cloud/VPN) |
| 5. Lateral Movement | Internal SMB (port 445) traffic observed | SMB traffic post-VPN access | T1021.002 – SMB/Windows Admin Shares |
| 6. Command & Control | Beaconing to external host | `10.0.0.60` → `198.51.100.77` (ET TROJAN alert) | T1071 – Application Layer Protocol (C2) |
| 7. Exfiltration | Large outbound HTTP POST | `10.0.0.51` (ET INFO Large Upload alert) | T1041 – Exfiltration Over C2 Channel |

This timeline is the core value-add over a raw lab writeup — it shows *why* each query mattered and how the individual findings connect into one incident rather than seven disconnected facts.

---

## 3. Detailed Findings

### 3.1 Reconnaissance
```spl
index="network_logs" sourcetype="firewall_logs"
| stats count by src_ip
| sort - count
```
**Finding:** `203.0.113.45` generated 297 firewall events — far above baseline — indicating scanning/probing behavior against the internal network.

<img width="946" height="541" alt="Top source IPs by firewall event count" src="https://github.com/user-attachments/assets/e02c215a-5209-4ebe-9a59-a1c78346b66f" />

*Figure 3: `stats count by src_ip` showing `203.0.113.45` as the top source of firewall events.*

### 3.2 Scan Target
```spl
index="network_logs" sourcetype="firewall_logs"
| stats count by dst_ip
| sort - count
```
**Finding:** `10.0.0.20` absorbed 351 events, making it the most-scanned internal asset. This host should be prioritized for vulnerability assessment and forensic imaging.

<img width="1438" height="588" alt="Top destination IPs by firewall event count" src="https://github.com/user-attachments/assets/eedd08fc-c3d4-4003-8e02-ce2025ca6f53" />

*Figure 4: `stats count by dst_ip` showing `10.0.0.20` as the most-targeted internal host.*

### 3.3 VPN Targeting
```spl
index="network_logs" sourcetype="vpn_logs"
| stats count by username
| sort - count
```
**Finding:** The service account `svc_backup` was targeted 135 times. Service accounts are high-value targets because they're often exempt from MFA and use static, rarely-rotated credentials.

<img width="945" height="579" alt="Top VPN usernames by event count" src="https://github.com/user-attachments/assets/67923a1f-a821-4825-b219-04892e637f54" />

*Figure 5: `stats count by username` on VPN logs, showing `svc_backup` as the most-targeted account.*

### 3.4 Successful Authentication
```spl
index="network_logs" source="vpn_auth.json" result=SUCCESS username=svc_backup src_ip="203.0.113.45"
| table _time assigned_ip
| sort _time
```
**Finding:** Authentication succeeded, assigning `10.8.0.23`. Two successful logins 10 seconds apart is the key anomaly here — it suggests either a scripted reconnect (e.g., a C2 agent re-establishing a tunnel) or session replay, not a human typing a password twice.

<img width="947" height="539" alt="Successful VPN authentication table" src="https://github.com/user-attachments/assets/05ee86ca-4dda-4b05-9f41-2691a701f725" />

*Figure 6: Successful VPN authentication for `svc_backup` from `203.0.113.45`, assigned `10.8.0.23`, with two logins recorded within 10 seconds.*

### 3.5 Lateral Movement
**Finding:** SMB traffic (port 445) was observed following VPN access — consistent with an attacker using the compromised session to browse shares or move between hosts internally.

<img width="945" height="534" alt="SMB traffic on port 445" src="https://github.com/user-attachments/assets/c039dac5-4ada-484a-8d58-6dee19184545" />

*Figure 7: Internal SMB (port 445) traffic observed following the compromised VPN session.*

### 3.6 C2 Beaconing
```spl
index="network_logs" source="ids_alerts.json" alert="ET TROJAN Possible C2 Beaconing"
| stats count by src_ip,dst_ip,dst_port
```
**Finding:** `10.0.0.60` communicated with external IP `198.51.100.77`, flagged by IDS signature as probable C2 beaconing.

<img width="946" height="417" alt="C2 beaconing IDS alert" src="https://github.com/user-attachments/assets/6882cc78-5e91-40d9-9e16-528dccb03a1f" />

*Figure 8: IDS alert "ET TROJAN Possible C2 Beaconing" — `10.0.0.60` communicating with `198.51.100.77`.*

### 3.7 Exfiltration
```spl
index="network_logs" source="ids_alerts.json" alert="ET INFO Possible HTTP POST Large Upload"
| stats count by src_ip,dst_ip,dst_port
```
**Finding:** `10.0.0.51` triggered a large-upload alert, consistent with staged data being exfiltrated over HTTP.

<img width="1068" height="300" alt="Large HTTP POST upload alert" src="https://github.com/user-attachments/assets/59536fd2-5505-4798-86bb-c6bd87e446cf" />

*Figure 9: IDS alert "ET INFO Possible HTTP POST Large Upload" from `10.0.0.51`, consistent with data exfiltration.*

---

## 4. Indicators of Compromise (IOC Summary)

| Indicator | Type | Role in Incident |
|---|---|---|
| `203.0.113.45` | External IP | Source of recon + VPN brute force + successful auth |
| `10.0.0.20` | Internal IP | Primary scan target |
| `svc_backup` | VPN account | Compromised credential |
| `10.8.0.23` | Internal IP | VPN-assigned address post-compromise |
| `10.0.0.60` | Internal IP | C2 beaconing host |
| `198.51.100.77` | External IP | Suspected C2 server |
| `10.0.0.51` | Internal IP | Suspected exfiltration source |
| Port 445 | Protocol | Lateral movement (SMB) |

---

## 5. Recommendations

1. **Disable/rotate `svc_backup` immediately** and enforce MFA on all VPN service accounts.
2. **Isolate and forensically image** `10.0.0.20`, `10.0.0.60`, and `10.0.0.51`.
3. **Block `203.0.113.45` and `198.51.100.77`** at the perimeter firewall.
4. **Hunt for persistence** on hosts that authenticated via `10.8.0.23`'s VPN session.
5. **Alert tuning:** create a correlation rule for "VPN success + duplicate login <30s apart" — this pattern was the clearest anomaly in the whole chain and isn't caught by any single alert above.
6. **Review SMB share permissions** for the service account to determine what lateral movement was actually possible vs. attempted.
7. **Data loss assessment:** work with data owners to determine what was in scope for the large upload from `10.0.0.51`.

---

## 6. Lessons Learned

- Service accounts were the weakest link — they lacked MFA and were the only credential targeted at volume.
- No single alert told the full story; the incident only becomes clear when firewall, VPN, and IDS logs are correlated on a common pivot (the external IP and the compromised account).
- Timing anomalies (the 10-second double-login) were more diagnostic than volume-based alerts and should be built into detection logic going forward.

---

*This report was produced as part of a SOC analyst training lab using Splunk against simulated network, VPN, and IDS log data.*
