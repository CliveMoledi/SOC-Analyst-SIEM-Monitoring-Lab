
# SOC-Analyst-SIEM-Monitoring-Lab

right now we have splunk open we are going to do some log analysis. below here is splunk opening.

<img width="1748" height="1056" alt="609395306-af7afd82-17b0-4e41-933c-b7a1050c7a25-2" src="https://github.com/user-attachments/assets/910db4e6-efda-4686-8434-269217c9621b" />

I search index="network_logs" so that we only query network-related logs and retrieve relevant events for analysis.
<img width="945" height="540" alt="Screenshot 2026-06-17 at 22 01 18" src="https://github.com/user-attachments/assets/83e9a8de-1eef-48bd-ac5d-1e84847ceac7" />
## finding the the ip that performed the most reconnaissance
in the screenshot below you can see i used the spl query:

index="network_logs" sourcetype="firewall_logs"
| stats count by src_ip
| sort - count

This query filters firewall logs, counts how many events each source IP generated, then ranks them to identify the most active (potentially scanning) external IP.

to find this ip that performed the most reconnaissance
Which is 203.0.113.45 with 297 firewall events. 

<img width="946" height="541" alt="Screenshot 2026-06-17 at 22 22 44" src="https://github.com/user-attachments/assets/e02c215a-5209-4ebe-9a59-a1c78346b66f" />

---
## finding the ip that was targeted by scans

i ran this query to find it. As seen in the screenshot below

index="network_logs" sourcetype="firewall_logs"
| stats count by dst_ip
| sort - count

Which is 10.0.0.20 with 351 firewall events

<img width="1438" height="588" alt="Screenshot 2026-06-17 at 22 50 50" src="https://github.com/user-attachments/assets/eedd08fc-c3d4-4003-8e02-ce2025ca6f53" />

---
Right now we are going to find which username was targeted in VPN logs

from the query:

index="network_logs" sourcetype="vpn_logs"
| stats count by username
| sort - count

we can see svc_backup is the most targeted with 135 counts

<img width="945" height="579" alt="Screenshot 2026-06-17 at 23 03 04" src="https://github.com/user-attachments/assets/67923a1f-a821-4825-b219-04892e637f54" />

---
Right now we are going to find which internal IP was assigned after successful VPN login
using the query 

index="network_logs" sourcetype="vpn_logs"
| search result="success"
| table username, src_ip, dst_ip



---
Right now we are going to find which
using the query 

---
Right now we are going to find which
using the query 

---
Right now we are going to find which
using the query 

---
