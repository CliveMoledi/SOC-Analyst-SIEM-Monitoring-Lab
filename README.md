
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

index="network_logs" source="vpn_auth.json" result=SUCCESS username=svc_backup src_ip="203.0.113.45"
| table _time assigned_ip
| sort _time

i have concluded that 10.8.0.23 is the  internal IP was assigned after successful VPN login on the basis that The IP 10.8.0.23 stands out because it shows two successful authentications exactly 10 seconds apart. Normally, a single login establishes a continuous VPN session, so rapid, back-to-back connections for the same account are highly anomalous. From a security perspective, this pattern typically indicates a misconfigured automated script stuck in a reconnect loop or an attacker attempting to establish concurrent sessions to maintain access.

<img width="947" height="539" alt="Screenshot 2026-06-17 at 23 37 30" src="https://github.com/user-attachments/assets/05ee86ca-4dda-4b05-9f41-2691a701f725" />


---
Right now we are going to find which port was used for lateral SMB attempts?
using the query 
<img width="945" height="534" alt="Screenshot 2026-06-17 at 23 50 06" src="https://github.com/user-attachments/assets/c039dac5-4ada-484a-8d58-6dee19184545" />

 port 445
 
---
Right now we are going to find in the IDS logs, which host beaconed to the C2?
using the query 

the host 10.0.0.60,
 IP was observed to be associated with C2:  198.51.100.77

index="network_logs" source="ids_alerts.json" alert="ET TROJAN Possible C2 Beaconing"
| stats count by src_ip,dst_ip,dst_port


<img width="946" height="417" alt="Screenshot 2026-06-18 at 00 02 49" src="https://github.com/user-attachments/assets/6882cc78-5e91-40d9-9e16-528dccb03a1f" />



---
Right now we are going to find Which host showed the exfiltration attempts

with the query

index="network_logs" source="ids_alerts.json" alert="ET INFO Possible HTTP POST Large Upload"
| stats count by src_ip,dst_ip,dst_port

we can clearly see it is 10.0.0.51

<img width="946" height="502" alt="Screenshot 2026-06-18 at 00 04 27" src="https://github.com/user-attachments/assets/a64feaf0-c019-4694-816e-71271218d3d2" />



