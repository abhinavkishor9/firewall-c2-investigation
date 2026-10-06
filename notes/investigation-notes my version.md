# Investigation Notes

## Host and Investigation Context

```text
Host: DESKTOP-9MMM37V
OS: Windows 11 Pro
PowerShell: 7.6.6
Sysmon: 4.91
Wazuh Agent: 001
Destination: 127.0.0.1:8080
Protocol: TCP
```

The endpoint was investigated using both local Windows telemetry and Wazuh Discover.

## Firewall Profile State

The Windows Firewall profiles were enabled:

```text
Domain  : Enabled
Private : Enabled
Public  : Enabled
```

The default inbound and outbound actions were reported as `NotConfigured`.

The firewall configuration therefore confirmed that Windows Firewall was active, but the profile output alone did not identify the final decision for the controlled connection attempts.

## Firewall Logging State

The firewall logging configuration was checked before reviewing the expected firewall log.

The results were:

```text
Domain:
LogAllowed = False
LogBlocked = False

Private:
LogAllowed = False
LogBlocked = False

Public:
LogAllowed = False
LogBlocked = False
```

The configured log path was:

```text
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

The file did not exist.

The following validation returned `False`:

```powershell
Test-Path "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
```

This established an important telemetry limitation before interpreting the failed TCP connections.

## Controlled Destination

The investigation used:

```text
127.0.0.1:8080
```

The destination was intentionally local.

The initial connectivity test returned:

```text
PingSucceeded    : True
TcpTestSucceeded : False
```

This showed that the local loopback address was reachable at the IP layer while TCP connectivity to port `8080` was unsuccessful.

## Repeated Connection Attempts

Ten connection attempts were generated using:

```powershell
1..10 | ForEach-Object {
    Test-NetConnection 127.0.0.1 -Port 8080 -WarningAction SilentlyContinue |
    Select-Object ComputerName, RemotePort, TcpTestSucceeded

    Start-Sleep -Seconds 5
}
```

All ten attempts returned:

```text
TcpTestSucceeded : False
```

Therefore, the controlled C2-like connection sequence did not establish a successful TCP session.

The result was recorded as failed connection attempts rather than firewall blocks because the firewall decision was not directly available.

## Firewall Log Investigation

The expected firewall log was queried:

```powershell
Get-Content "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" -Tail 100
```

Windows returned:

```text
Cannot find path
'C:\Windows\System32\LogFiles\Firewall\pfirewall.log'
because it does not exist.
```

A targeted search for `127.0.0.1` therefore could not be performed against the firewall log.

This prevented direct confirmation of whether the failed connection attempts were logged as `ALLOW` or `DROP`.

## Firewall Rules

Enabled Windows Firewall rules were reviewed.

Examples observed included:

```text
Wi-Fi Direct Spooler Use (Out)
Remote Assistance (TCP-Out)
Network Discovery (SSDP-Out)
Network Discovery (WSD Events-Out)
Connected Devices Platform (UDP-Out)
mDNS (UDP-Out)
Remote Assistance (DCOM-In)
Network Discovery (UPnP-Out)
```

The existence of enabled firewall rules demonstrates that the host has active filtering policy, but individual rule presence was not sufficient to attribute the failed `8080` connection to a particular rule.

## Sysmon Network Investigation

Sysmon Event ID 3 was reviewed for network connection telemetry.

The targeted search was:

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

No matching result was returned.

The correct interpretation is:

```text
No matching Sysmon Event ID 3 was observed
```

rather than:

```text
No network activity occurred
```

The distinction is important because endpoint telemetry coverage is not necessarily complete for every connection type.

## Other Sysmon Network Evidence

Sysmon Event ID 3 telemetry was available for other network activity.

One observed event showed:

```text
Image: C:\Users\Dell\AppData\Local\Programs\Zoho Mail - Desktop\Zoho Mail - Desktop.exe
Protocol: tcp
Initiated: true
SourceIp: 192.168.1.6
SourcePort: 34610
DestinationIp: 169.148.146.188
DestinationPort: 443
DestinationPortName: https
```

This demonstrates that Sysmon was recording network connections on the endpoint.

However, this event was unrelated to the controlled `127.0.0.1:8080` activity and was not treated as C2 evidence.

## Process Telemetry

Sysmon Event ID 1 process creation telemetry was also available.

A separate event showed:

```text
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NT AUTHORITY\SYSTEM
ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
CommandLine:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File
"C:\WMIPermanentEventLab\Payload\wmi-payload.ps1"
```

This activity was observed during the investigation period but belongs to a separate WMI-related execution context.

There was not enough evidence to connect this PowerShell/WMI activity to the failed `127.0.0.1:8080` connection attempts.

It was therefore kept separate from the firewall C2 assessment.

## Wazuh Investigation

Wazuh Discover was scoped to:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

The investigation then searched for:

```text
5152
5154
5156
5157
8080
127.0.0.1
Sysmon Event ID 3
Sysmon Event ID 1
```

The purpose was to determine whether Wazuh contained Windows Firewall or endpoint network telemetry corresponding to the controlled activity.

No confirmed firewall decision was established from the available evidence.

The Wazuh endpoint filter was retained throughout the investigation to avoid incorrectly using manager-side telemetry as endpoint evidence.

