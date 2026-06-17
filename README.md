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
Which is 203.0.113.45, 
