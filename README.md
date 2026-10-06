# Firewall C2 Investigation

## Overview

This lab investigates how Windows Firewall telemetry can be used during a suspected command-and-control (C2) investigation. The investigation focuses on firewall configuration, allowed and blocked network activity, controlled connection attempts, Sysmon network telemetry, and Wazuh endpoint correlation.

A controlled destination of `127.0.0.1:8080` was selected to simulate a potential C2 destination without communicating with real external infrastructure. The investigation attempted repeated TCP connections to the destination and examined whether Windows Firewall or endpoint telemetry provided evidence of the activity.

The investigation followed an evidence-driven approach. Firewall configuration and telemetry availability were validated before interpreting network activity. Missing firewall logs or Sysmon events were treated as visibility limitations rather than evidence that network activity could not have occurred.

## Environment

- Host: `DESKTOP-9MMM37V`
- Operating System: Windows 11 Pro
- PowerShell: 7.6.6
- Sysmon: 4.91
- Wazuh Agent: `001`
- Controlled destination: `127.0.0.1:8080`
- Protocol: TCP
- Investigation type: Windows Firewall / C2 investigation

## Investigation Objectives

- Establish the Windows Firewall configuration and logging state.
- Determine whether Windows Firewall logging was available for the investigation.
- Validate the controlled destination `127.0.0.1:8080`.
- Generate repeated controlled TCP connection attempts.
- Determine whether the connection attempts succeeded or failed.
- Search for corresponding Windows Firewall telemetry.
- Search for Sysmon Event ID 3 network connection telemetry.
- Use Wazuh Discover to investigate endpoint firewall and network events.
- Correlate network activity with process telemetry where sufficient evidence exists.
- Distinguish confirmed activity from unavailable telemetry and unrelated events.
- Document limitations encountered during the investigation.
- Assess whether the available evidence supports C2 activity.

## Controlled Destination

The investigation used:

```text
Destination: 127.0.0.1
Port: 8080
Protocol: TCP
```

The destination was intentionally local so that the investigation would not interact with real external infrastructure.

A connectivity test showed:

```text
ComputerName      : 127.0.0.1
RemoteAddress     : 127.0.0.1
RemotePort        : 8080
InterfaceAlias    : Loopback Pseudo-Interface 1
SourceAddress     : 127.0.0.1
PingSucceeded     : True
TcpTestSucceeded  : False
```

The TCP connection to port `8080` was therefore not established during the test.

## Firewall Configuration

Windows Firewall was enabled for the Domain, Private, and Public profiles.

The profiles reported:

```text
Domain     True
Private    True
Public     True
```

However, firewall logging was disabled for all three profiles:

```text
Domain     LogAllowed: False    LogBlocked: False
Private    LogAllowed: False    LogBlocked: False
Public     LogAllowed: False    LogBlocked: False
```

The configured firewall log path was:

```text
%systemroot%\system32\LogFiles\Firewall\pfirewall.log
```

The expected log file was not present on the endpoint.

## Controlled Connection Attempts

Ten TCP connection attempts were made against `127.0.0.1:8080` with a five-second interval between attempts.

All ten attempts returned:

```text
TcpTestSucceeded : False
```

This confirms that the controlled TCP connection was unsuccessful.

The result does not by itself establish that Windows Firewall blocked the connection. Because firewall logging was disabled and the expected firewall log was unavailable, the specific reason for the failed connection could not be established from firewall telemetry.

## Sysmon Correlation

Sysmon Event ID 3 was reviewed for network connection telemetry.

A targeted search for both `127.0.0.1` and port `8080` produced no matching event in the reviewed data.

This means that a corresponding Sysmon network event was not established for the controlled connection attempts.

The absence of a matching Sysmon event was treated as a telemetry limitation rather than proof that no connection attempt occurred.

Other Sysmon network telemetry was available. For example, an Event ID 3 record showed `Zoho Mail - Desktop.exe` communicating over TCP/443 with an external destination. This was separate from the controlled `127.0.0.1:8080` test and was not attributed to the C2 simulation.

## Wazuh Correlation

Wazuh Discover was used to investigate the endpoint using:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

Additional searches were performed for Windows Firewall event IDs, port `8080`, `127.0.0.1`, Sysmon Event ID 3, and Sysmon Event ID 1.

The investigation did not establish a confirmed Windows Firewall event corresponding to the controlled `127.0.0.1:8080` attempts.

Manager-side Wazuh events were intentionally excluded from endpoint conclusions.

## Evidence Assessment

| Finding | Assessment |
|---|---|
| Windows Firewall profiles enabled | Confirmed |
| Firewall allow logging enabled | No |
| Firewall block logging enabled | No |
| `pfirewall.log` available | No |
| TCP `127.0.0.1:8080` reachable | No |
| Ten controlled TCP attempts | Confirmed |
| Ten TCP attempts succeeded | No |
| Sysmon Event ID 3 for `127.0.0.1:8080` | Not observed |
| Process attribution for the controlled traffic | Not established |
| Confirmed firewall block | Not established |
| Confirmed C2 communication | Not established |

## Important Limitation

The investigation could not determine whether Windows Firewall specifically blocked the controlled TCP connections.

The TCP tests failed, but firewall logging was disabled and the expected firewall log was absent. Therefore, the evidence supports **failed connection attempts**, not a confirmed firewall block.

Similarly, the absence of a Sysmon Event ID 3 record for `127.0.0.1:8080` does not prove that the connection attempts were invisible to every network control or that no network activity occurred.

## Final Assessment

The investigation successfully demonstrated how firewall configuration and telemetry availability affect C2 investigations. Windows Firewall was enabled, but firewall allow/block logging was disabled, preventing direct analysis of firewall decisions. Ten controlled TCP attempts to `127.0.0.1:8080` failed, and no corresponding Sysmon Event ID 3 for the destination was identified.

No evidence from this lab establishes successful C2 communication, a confirmed firewall block, or malicious network activity.

The main investigative conclusion is:

> **A failed connection attempt is not proof of C2, and the absence of firewall telemetry is a visibility limitation rather than proof that the firewall did not act.**
