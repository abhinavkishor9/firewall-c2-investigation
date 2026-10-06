# firewall-c2-investigation
## Overview

A firewall C2 investigation examines network connections that are allowed, blocked, or otherwise filtered by a host or network firewall.

From a SOC perspective, useful evidence includes:

Source and destination IP addresses
Source and destination ports
Protocol
Direction of traffic
Allow/block action
Application or process context, where available
Connection frequency and timing
Repeated connections to the same destination
Firewall rule responsible for the decision

The investigation should answer:

Did the endpoint attempt the connection?
        ↓
What destination and port were involved?
        ↓
Was the connection allowed or blocked?
        ↓
How frequently did it occur?
        ↓
Can the connection be associated with a process?
        ↓
Is there enough evidence to call it C2?

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

## Lab Objectives

- Establish a documented baseline of the Windows endpoint, user context, network configuration, and firewall state.
- Verify whether Windows Firewall is enabled across the Domain, Private, and Public profiles.
- Examine the configured firewall logging state for allowed and blocked network traffic.
- Determine whether the expected Windows Firewall log file is available for investigation.
- Define a controlled local destination using `127.0.0.1:8080` without communicating with external infrastructure.
- Validate TCP connectivity to the controlled destination before generating repeated connection attempts.
- Generate controlled TCP connection attempts at fixed intervals to simulate C2-like network behavior.
- Record whether each connection attempt succeeds or fails.
- Examine enabled Windows Firewall rules and identify relevant inbound and outbound filtering policies.
- Investigate available Windows Firewall telemetry for evidence of allowed or blocked connections.
- Search for firewall-related Windows event IDs through Wazuh Discover.
- Search Wazuh endpoint telemetry specifically for the controlled destination and port `8080`.
- Review Sysmon Event ID 3 for network connection evidence associated with the controlled destination.
- Review Sysmon Event ID 1 for potential process context around the network activity.
- Correlate firewall, network, process, and Wazuh evidence only when sufficient supporting information is available.
- Distinguish a failed TCP connection from a confirmed firewall block.
- Distinguish repeated connection attempts from successful C2 communication.
- Document missing firewall logs, unavailable events, and other telemetry limitations encountered during the investigation.
- Keep unrelated endpoint activity separate from the controlled firewall C2 test unless a defensible correlation can be established.
- Assess whether the available evidence supports normal activity, failed controlled communication, suspicious behavior, or confirmed C2.
- Preserve the investigation evidence and maintain a chronological record of the activities performed.
- Apply the principle that **network connection attempts and firewall events are evidence for investigation, not proof of malicious C2 by themselves**.

## Lab Scenario

A Windows endpoint is being investigated for network activity that may resemble command-and-control (C2) communication. The investigation focuses on whether Windows Firewall configuration and endpoint telemetry can provide evidence of connection attempts, filtering decisions, and potential process involvement.

A controlled local destination, `127.0.0.1:8080`, is used to safely simulate C2-like TCP communication without connecting to real external infrastructure. Repeated connection attempts are generated at controlled intervals, and the results are examined to determine whether the destination is reachable and whether the activity produces observable firewall or endpoint telemetry.

The investigation will examine several areas:

- Windows Firewall profile and rule configuration.
- Firewall allow/block logging status.
- Availability of the configured `pfirewall.log`.
- Success or failure of controlled TCP connections.
- Sysmon Event ID 3 network connection telemetry.
- Sysmon Event ID 1 process creation telemetry.
- Wazuh endpoint telemetry and firewall-related events.
- Correlation between network activity and process execution.

A key part of the scenario is determining what can and cannot be concluded from the available evidence. A failed TCP connection does not automatically mean that Windows Firewall blocked the connection. Similarly, the absence of a matching Sysmon or Wazuh event does not prove that no network activity occurred.

The investigation must therefore distinguish between confirmed connection attempts, confirmed firewall decisions, available endpoint telemetry, and visibility gaps. Unrelated process or network activity should remain separate unless sufficient evidence establishes a relationship with the controlled test.

The final assessment should determine whether the available evidence supports a normal controlled test, failed network communication, suspicious behavior, or confirmed C2 activity.

The core investigation principle is:

> **A failed connection or firewall-related indicator is evidence for investigation, not proof of malicious C2 by itself.**

  
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

