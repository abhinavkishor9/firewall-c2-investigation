# Troubleshooting Notes

## Firewall Log File Was Missing

### Symptom

The expected Windows Firewall log could not be read:

```text
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

The command returned:

```text
Cannot find path
'C:\Windows\System32\LogFiles\Firewall\pfirewall.log'
because it does not exist.
```

### Validation

The file was checked directly:

```powershell
Test-Path "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
```

Result:

```text
False
```

### Cause / Explanation

The Windows Firewall profiles showed:

```text
LogAllowed : False
LogBlocked : False
```

for Domain, Private, and Public profiles.

Therefore, firewall traffic logging was not enabled during the investigation.

### Investigation Impact

The missing log prevented direct analysis of whether the controlled connection attempts were recorded as allowed or blocked.

The failed TCP connection was therefore not classified as a confirmed firewall block.

---

## TCP Port 8080 Connection Failed

### Symptom

The controlled destination was:

```text
127.0.0.1:8080
```

The connectivity test returned:

```text
TcpTestSucceeded : False
```

The same result occurred during all ten repeated attempts.

### Validation

```powershell
Test-NetConnection 127.0.0.1 -Port 8080
```

The output showed:

```text
PingSucceeded    : True
TcpTestSucceeded : False
```

### Interpretation

The loopback address was reachable, but TCP port `8080` did not accept the connection.

This does not by itself prove that Windows Firewall blocked the connection.

A listener may not have been active on port `8080`, and the available firewall telemetry could not identify the actual reason for the failure.

### Investigation Impact

The activity was recorded as:

```text
Failed controlled TCP connection attempt
```

rather than:

```text
Firewall-blocked C2 connection
```

---

## Ten Repeated Connection Attempts Failed

### Symptom

The controlled test generated ten attempts:

```powershell
1..10 | ForEach-Object {
    Test-NetConnection 127.0.0.1 -Port 8080 -WarningAction SilentlyContinue |
    Select-Object ComputerName, RemotePort, TcpTestSucceeded

    Start-Sleep -Seconds 5
}
```

All ten returned:

```text
TcpTestSucceeded : False
```

### Interpretation

The repeated pattern demonstrated that the test was executed consistently, but it did not demonstrate successful beaconing.

A repeated failed connection attempt is still different from a successful C2 session.

---

## No Matching Sysmon Event ID 3 for 8080

### Symptom

The following query was used:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 3
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "127.0.0.1" -and
    $_.Message -match "8080"
} |
Select-Object TimeCreated, Id, Message |
Format-List
```

No matching event was returned.

### Important Observation

Sysmon Event ID 3 was not completely unavailable on the endpoint.

Other network events were present, including outbound HTTPS activity from Zoho Mail Desktop.

Therefore, the correct conclusion is not:

```text
Sysmon network monitoring is disabled.
```

The appropriate conclusion is:

```text
No matching Sysmon Event ID 3 for 127.0.0.1:8080 was identified in the reviewed data.
```

### Investigation Impact

The missing event prevented process-to-network correlation for the controlled destination.

---

## Wazuh Firewall Search

### Approach

Wazuh Discover was scoped to the endpoint:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

Firewall event IDs were then investigated:

```text
5152
5154
5156
5157
```

Additional searches targeted:

```text
8080
127.0.0.1
```

Sysmon Event ID 3 and Event ID 1 were also reviewed.

### Important Lesson

Wazuh manager events must not be interpreted as endpoint firewall activity.

Endpoint-specific filtering was therefore retained throughout the investigation.

### Investigation Impact

The available evidence did not establish a confirmed Wazuh firewall event corresponding to the controlled connection attempts.

---

## Unrelated Process Activity

### Observation

Sysmon Event ID 1 showed PowerShell executing:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File
"C:\WMIPermanentEventLab\Payload\wmi-payload.ps1"
```

The parent process was:

```text
C:\Windows\System32\wbem\WmiPrvSE.exe
```

The process ran as:

```text
NT AUTHORITY\SYSTEM
```

### Interpretation

This is potentially significant endpoint activity, but it belongs to a WMI-related execution context.

There was insufficient evidence to connect it to the controlled `127.0.0.1:8080` connection attempts.

### Investigation Rule

Temporal proximity alone was not used to attribute the process to the network activity.

---

## Normal Network Activity Observed

Sysmon Event ID 3 showed legitimate-looking outbound HTTPS activity from:

```text
C:\Users\Dell\AppData\Local\Programs\Zoho Mail - Desktop\Zoho Mail - Desktop.exe
```

The observed destination used:

```text
DestinationPort: 443
DestinationPortName: https
```

This event was kept separate from the controlled C2 simulation.

The presence of normal network activity demonstrates that network telemetry was available for at least some connections, but it does not explain the missing `127.0.0.1:8080` event.

---

## Key Troubleshooting Lessons

- Check firewall logging configuration before expecting `pfirewall.log` evidence.
- Do not interpret a failed TCP connection as proof of firewall blocking.
- Verify that the intended destination actually has a listening service.
- Treat missing Sysmon events as telemetry limitations.
- Confirm that Sysmon is generating other network events before concluding that Event ID 3 is unavailable.
- Keep Wazuh searches scoped to the actual endpoint agent.
- Do not use manager-side Wazuh events as endpoint evidence.
- Do not attribute unrelated PowerShell/WMI activity to the C2 test solely because timestamps are close.
- Separate failed connection attempts from successful network sessions.
- Separate beacon-like behavior from confirmed C2.
- Document telemetry gaps instead of filling them with assumptions.

## Final Troubleshooting Principle

> **When the telemetry does not show why a connection failed, document the failed connection and the visibility gap rather than inventing the firewall decision.**
