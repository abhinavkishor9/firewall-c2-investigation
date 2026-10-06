# Investigation Timeline

| Time / Phase | Activity | Evidence / Result | Assessment |
|---|---|---|---|
| Initial setup | Firewall C2 investigation workspace established | `C:\FirewallC2Lab\Evidence` | Confirmed |
| Baseline | Windows host and user context reviewed | `DESKTOP-9MMM37V`, Windows 11 Pro | Confirmed |
| Firewall review | Windows Firewall profiles checked | Domain, Private, and Public profiles enabled | Confirmed |
| Firewall logging review | Allow/block logging checked | `LogAllowed=False`, `LogBlocked=False` for all profiles | Confirmed |
| Firewall log validation | `pfirewall.log` checked | File did not exist | Telemetry limitation |
| Destination setup | Controlled destination selected | `127.0.0.1:8080` | Controlled test |
| Connectivity test | TCP connection tested | `TcpTestSucceeded=False` | Failed connection |
| Repeated test | Ten TCP attempts generated | All ten returned `TcpTestSucceeded=False` | Confirmed |
| Firewall rule review | Enabled firewall rules inspected | Multiple inbound/outbound rules observed | Baseline evidence |
| Sysmon review | Event ID 3 searched for `127.0.0.1:8080` | No matching event identified | Telemetry limitation |
| Sysmon review | Other Event ID 3 activity reviewed | Zoho Mail Desktop outbound TCP/443 observed | Separate network activity |
| Process review | Sysmon Event ID 1 reviewed | PowerShell/WMI activity observed | Separate activity |
| Wazuh review | Endpoint-scoped searches performed | Firewall/network/process telemetry investigated | Correlation attempt |
| Correlation | Controlled connection compared with endpoint telemetry | No process-to-network attribution established | Inconclusive |
| Final assessment | Evidence reviewed collectively | Failed TCP attempts; firewall decision and C2 not established | No confirmed C2 |

