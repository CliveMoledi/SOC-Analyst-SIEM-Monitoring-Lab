# SOC-Analyst-SIEM-Monitoring-Lab

This lab demonstrates a SOC-style investigation using Splunk to analyze network, VPN, and IDS logs. The objective is to identify reconnaissance activity, targeted systems, VPN authentication behavior, lateral movement, command-and-control (C2) communication, and possible data exfiltration.

Right now we have Splunk open and we are performing log analysis.

<img width="1748" height="1056" alt="609395306-af7afd82-17b0-4e41-933c-b7a1050c7a25-2" src="https://github.com/user-attachments/assets/910db4e6-efda-4686-8434-269217c9621b" />

We first set the search scope to network logs:

index="network_logs"

<img width="945" height="540" alt="Screenshot 2026-06-17 at 22 01 18" src="https://github.com/user-attachments/assets/83e9a8de-1eef-48bd-ac5d-1e84847ceac7" />

## Identifying the IP that performed the most reconnaissance

index="network_logs" sourcetype="firewall_logs"
| stats count by src_ip
| sort - count

Result: 203.0.113.45 generated 297 firewall events.

<img width="946" height="541" alt="Screenshot 2026-06-17 at 22 22 44" src="https://github.com/user-attachments/assets/e02c215a-5209-4ebe-9a59-a1c78346b66f" />

## Identifying the IP targeted by scans

index="network_logs" sourcetype="firewall_logs"
| stats count by dst_ip
| sort - count

Result: 10.0.0.20 received 351 firewall events.

<img width="1438" height="588" alt="Screenshot 2026-06-17 at 22 50 50" src="https://github.com/user-attachments/assets/eedd08fc-c3d4-4003-8e02-ce2025ca6f53" />

## Identifying the most targeted VPN username

index="network_logs" sourcetype="vpn_logs"
| stats count by username
| sort - count

Result: svc_backup was targeted 135 times.

<img width="945" height="579" alt="Screenshot 2026-06-17 at 23 03 04" src="https://github.com/user-attachments/assets/67923a1f-a821-4825-b219-04892e637f54" />

## Identifying internal IP after successful VPN login

index="network_logs" source="vpn_auth.json" result=SUCCESS username=svc_backup src_ip="203.0.113.45"
| table _time assigned_ip
| sort _time

Result: 10.8.0.23 was assigned after successful VPN authentication. This IP showed two successful logins within 10 seconds, indicating abnormal session behavior or possible automated reconnect activity.

<img width="947" height="539" alt="Screenshot 2026-06-17 at 23 37 30" src="https://github.com/user-attachments/assets/05ee86ca-4dda-4b05-9f41-2691a701f725" />

## Identifying lateral movement (SMB)

Result: SMB traffic observed on port 445.

<img width="945" height="534" alt="Screenshot 2026-06-17 at 23 50 06" src="https://github.com/user-attachments/assets/c039dac5-4ada-484a-8d58-6dee19184545" />

## Identifying C2 beaconing

index="network_logs" source="ids_alerts.json" alert="ET TROJAN Possible C2 Beaconing"
| stats count by src_ip,dst_ip,dst_port

Result: 10.0.0.60 communicated with 198.51.100.77, consistent with possible C2 beaconing.

<img width="946" height="417" alt="Screenshot 2026-06-18 at 00 02 49" src="https://github.com/user-attachments/assets/6882cc78-5e91-40d9-9e16-528dccb03a1f" />

## Identifying possible exfiltration activity

index="network_logs" source="ids_alerts.json" alert="ET INFO Possible HTTP POST Large Upload"
| stats count by src_ip,dst_ip,dst_port

Result: 10.0.0.51 showed activity consistent with possible data exfiltration.

<img width="1068" height="300" alt="Screenshot 2026-06-18 at 00 29 00" src="https://github.com/user-attachments/assets/59536fd2-5505-4798-86bb-c6bd87e446cf" />
