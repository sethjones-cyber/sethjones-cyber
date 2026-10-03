# Wazuh 4.14 Detection and Investigation — Labs 5–9

Author: Seth Jones | Performed: October 1–3, 2026 | Controlled home lab

## Scope and results

I tested privileged group membership changes, scheduled task auditing, and PowerShell script block logging on a Windows 11 workstation monitored by Wazuh 4.14 in Proxmox. I also reviewed QEMU vulnerability findings and tested domain account monitoring on a Windows Server 2025 domain controller. These were deliberate, benign actions. The review focused on who acted, what changed, when it happened, the affected system, and whether the activity matched an approved purpose. Logs alone do not establish a person's intent or CAB approval.

| Lab | Verified result | Limitations |
| --- | --- | --- |
| 5 — Administrator membership | Wazuh events 4732 and 4733; disabled test account added and removed | No login or use of elevated privileges tested |
| 6 — Scheduled task | Creation 4698 in Wazuh after enabling auditing; deletion command succeeded; local 4699 observed | Deletion not found in Wazuh; no execution evidence |
| 7 — PowerShell | Plain marker captured locally; revised marker with environment query captured in Wazuh | Initial marker absent from Wazuh searches; cause not established |
| 8 — Vulnerability triage | Package and VM device configuration checked | Applicability and vendor patch status not confirmed; no exploit or patch performed |
| 9 — Domain account monitoring | Wazuh events 4720 and 4726 for the same test account; cleanup detected | Original DC timestamps affected by a three-hour clock error, corrected afterward |

Public documentation omits private network addresses, workstation names, administrator usernames, and full SIDs. Screenshot identifiers are described in text rather than publishing original identifying screenshots.

## Lab 5 — Local administrator membership changes

I created a disabled temporary account and added it to the local Administrators group:

```powershell
New-LocalUser -Name WazuhLab5 -NoPassword -Disabled
Add-LocalGroupMember -Group Administrators -Member WazuhLab5
Get-LocalUser WazuhLab5 | Select Name,Enabled,SID
```

The account remained disabled. Its SID matched the member SID in the group-change event. Wazuh showed Security Event 4732, record 88100, with Windows timestamp 2026-10-01T22:37:49.1233727Z. The target was BUILTIN Administrators (well-known group SID S-1-5-32-544), and the Subject identified the local lab administrator account used for the operation.

I removed the membership and account:

```powershell
Remove-LocalGroupMember -Group Administrators -Member WazuhLab5
Remove-LocalUser -Name WazuhLab5
Get-LocalUser -Name WazuhLab5
```

Wazuh Event 4733, record 88102, showed removal of the same member from the same group by the same acting account. The removal timestamp and Wazuh rule details were not captured. The final lookup returned UserNotFound, confirming account cleanup. Membership removal was confirmed separately before deletion.

For an unexpected administrator addition, I would check the approved change request, requested access, acting account and session, membership duration, and subsequent logins or privileged activity. Elevated access increases the potential impact; an administrator account performing the action does not prove authorization. The Subject identifies an account, not necessarily the human controlling it.

## Lab 6 — Scheduled task creation and deletion

I created a harmless one-time task scheduled for 23:59:

```powershell
schtasks /create /tn WazuhLab6 /tr "cmd.exe /c exit" /sc ONCE /st 23:59
```

The command succeeded, but the first searches found no 4698 event in Wazuh or the local Security log. Audit policy inspection showed Other Object Access Events set to No Auditing. I enabled success auditing, deleted the first task, and recreated it:

```powershell
auditpol /get /subcategory:"Other Object Access Events"
auditpol /set /subcategory:"Other Object Access Events" /success:enable
schtasks /delete /tn WazuhLab6 /f
schtasks /create /tn WazuhLab6 /tr "cmd.exe /c exit" /sc ONCE /st 23:59
```

Wazuh then showed Security Event 4698, record 88127, for task \WazuhLab6. The task XML contained registration date 2026-10-01T19:09:45 and start boundary 2026-10-01T23:59:00. These XML values have no timezone offset and are not presented as UTC event timestamps. The XML Author referenced the lab administrator account; Author metadata alone does not conclusively identify the creator. The event's Subject username was not captured in the supplied view.

```powershell
(Get-ScheduledTask WazuhLab6).Actions
schtasks /delete /tn WazuhLab6 /f
```

The action query confirmed cmd.exe with arguments /c exit and an empty working directory. The deletion command succeeded before the scheduled time. A subsequent local Security query returned Event 4699 at October 1, 2026, 7:15:58 PM as displayed. Its message was truncated, so the task name was not independently confirmed from that event. No deletion alert appeared in the Wazuh searches. No task execution was verified. Success auditing remained enabled.

For unexpected tasks, I would compare the creator, execution identity, privileges, command and arguments, trigger, and creation time with the approved change. I would also inspect execution history and related process events. A task's presence alone does not establish malicious persistence.

## Lab 7 — PowerShell script block logging

The first controlled test printed a marker:

```powershell
powershell -NoProfile -Command "Write-Output 'WazuhLab7'"
```

The Group Policy setting Turn on PowerShell Script Block Logging was initially Not Configured. I enabled it under Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell. Invocation start/stop logging was left unchecked.

After rerunning the test, a local Operational Event 4104 at 19:32:01 as displayed contained Write-Output 'WazuhLab7'. The script block ID was 3fc00920-8a39-48e9-9ba6-053e764b1303 and Path was blank. This confirmed local script block capture, but searches for the marker and Event 4104 initially returned no Wazuh results.

The agent configuration already collected Microsoft-Windows-PowerShell/Operational through eventchannel, with no query filter in that block. Agent logs showed the channel being analyzed. I restarted WazuhSvc and verified that the service was Running; no configuration edit was needed.

Later Wazuh searches returned eight 4104 alerts under rule 91816, level 4, describing environment-variable queries. One inspected script exported local security policy through secedit. It did not contain my marker and was not treated as proof that the controlled test reached Wazuh. Its actor and origin were not established.

I revised the benign test to include an environment-variable query:

```powershell
powershell -NoProfile -Command 'Write-Output WazuhLab7; $env:TEMP'
```

The expanded Wazuh result confirmed scriptBlockText Write-Output WazuhLab7; $env:TEMP and the PowerShell Operational channel. The final captured view did not include the rule ID, level, or timestamp, so I do not assign the earlier rule details to this marker. The command only printed the marker and temporary-directory path; it did not write a file. The initial plain marker was logged locally but was not observed in Wazuh searches. The restart is not claimed as the proven cause of recovery; timing and alert rule matching were not isolated.

Script block logging remained enabled and WazuhSvc was Running. This lab created no account, task, or file requiring cleanup. In an investigation, I would correlate script text with account/session, process ancestry, timestamps, host, and approved purpose. A log can show what ran; authorization and intent need additional evidence.

## Operational note — Proxmox storage interruption

At the end of the session, the Wazuh VM showed an I/O error while backup storage was reported full. Reported usage later reached approximately 82%. The VM's 80 GB virtual disk was verified to reside on the storage named Backups, meaning that storage was also serving a VM disk.

The backup job selected VMs 100, 101, and 102 and had Keep Daily set to 5; other retention fields were blank. Reducing Keep Daily to 2 was the recommended adjustment, but a saved final value was not independently captured. The VM returned to a green state after the resume step. Storage exhaustion is consistent with the interruption, but the exact cause was not proven from logs, and post-resume service health and filesystem integrity were not verified.

Follow-up: verify retention was saved, review actual available storage and pruning behavior, confirm Wazuh services and dashboard after recovery, and consider separating backup storage from active VM disks. A green VM indicator alone is not a full application health check.

## Outcome and remaining work

These labs demonstrated membership-change triage, the effect of audit policy on task visibility, and the distinction between local PowerShell logging and SIEM alert visibility. Test accounts and tasks were removed. Two visibility gaps remain documented rather than reported as resolved: task deletion in Wazuh and the initial plain PowerShell marker.

Labs 8–9 are documented below. Lab 10, a combined investigation, remains planned and has no completed results.

## Lab 8 — Validate vulnerability findings before escalation

Performed: October 2, 2026.

I reviewed two QEMU findings in Wazuh instead of treating the scanner labels as proof of exposure. The Windows inventory showed QEMU guest-agent package version 110.0.2 as reported. On the Proxmox host, a package query confirmed pve-qemu-kvm version 11.0.0-3. These are distinct inventory entries; the guest-agent version alone does not establish the host emulator's vulnerability status.

| Finding | Reported issue | Configuration evidence | Disposition |
| --- | --- | --- | --- |
| CVE-2023-1386 — High | QEMU 9pfs SUID/SGID handling with potential privilege escalation | Inspected Windows lab VM configuration had no 9p shared filesystem and no custom args entry | Relevant device not configured in the inspected VM; applicability remains unconfirmed |
| CVE-2021-20255 — Medium | eepro100 i8255x device emulator recursion/DMA reentry with denial-of-service impact | Inspected Windows lab VM used a virtio network adapter | Named emulator not configured in the inspected VM; applicability remains unconfirmed |

I did not validate an exploit, map the installed Proxmox build to vendor fixes or backports, or apply a patch during this lab. A newer version number alone does not prove a fix, and these results do not establish that every VM or the entire host is unaffected. I did not label either finding a confirmed false positive.

My next checks would be the affected package/component, vendor advisory and fixed build, enabled devices across other VMs, and any required attack conditions. I would record the evidence, actual exposure, and remediation decision before escalating a scanner finding as a confirmed vulnerability.

## Lab 9 — Domain account creation and deletion

Performed: October 3, 2026.

I enrolled the Windows Server domain controller into Wazuh and generated a benign domain-account lifecycle. The test account was created disabled, without a password, and was not enabled or added to privileged groups. No login was attempted with it.

Connectivity troubleshooting included a temporary route, host-specific pfSense rules for dashboard TCP 443 and agent TCP 1514–1515, and correcting a malformed manager address in the agent configuration. Connectivity succeeded after saving and applying the firewall rule, but the exact initial rule mismatch was not established. The temporary route was not made persistent. After the address correction and agent restart, Wazuh showed the domain-controller agent active, and the agent log showed connection to the manager and analysis of the Security channel. The service's Running state alone was not considered proof of event delivery.

I checked User Account Management auditing, then created the account:

```powershell
auditpol /get /subcategory:"User Account Management"
New-ADUser -Name WazuhLab9
```

Initial narrow time-range searches returned no results. A local Security query confirmed Event 4720. Wazuh subsequently returned the creation event with a 24-hour search using data.win.system.eventID:4720. The captured dashboard showed alert level 8. The creation rule ID and event record ID were not captured.

The expanded event identified the acting domain administrator account, the target WazuhLab9, its domain, and target SID. The account-control fields supported the disabled account state. The Subject identifies the account used to perform the action, not independently the human operating it.

I deleted the test account:

```powershell
Remove-ADUser WazuhLab9
```

Wazuh captured Security Event 4726, record 175276, identifying the same acting account and target account. Its target SID matched the creation event, and the event reported AUDIT_SUCCESS. This confirmed deletion; no separate post-deletion directory lookup was captured.

| Evidence | Original Windows systemTime recorded in Wazuh | Verification |
| --- | --- | --- |
| Account creation — 4720 | 2026-10-03T18:58:27.1798922Z | Target WazuhLab9; acting domain administrator; alert level 8 |
| Account deletion — 4726 | 2026-10-03T19:15:27.4877259Z | Same target SID and actor; event record 175276; audit success |

These are the original recorded values, not validated real-world UTC times. During follow-up, the DC was configured for Pacific time, and its actual clock was confirmed approximately three hours ahead. The timezone explains the seven-hour local-display/UTC difference at that date; it does not explain away the separate clock error. This discrepancy could affect time-range searches, although it was not isolated as the sole cause of the initial missing results. Original evidence timestamps are preserved rather than silently rewritten.

### Time configuration follow-up

I changed the timezone to Eastern and corrected the current clock. Automatic resynchronization initially failed because no time data was available. The active source was Local CMOS Clock, and the peer query showed a blank pending peer. An FSMO query confirmed this DC held the PDC emulator role.

```powershell
Set-TimeZone -Id "Eastern Standard Time"
w32tm /query /source
w32tm /query /peers
netdom query fsmo
w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /reliable:yes /update
Restart-Service w32time
w32tm /resync
w32tm /query /source
```

Configuration and resynchronization returned success. The final source query was confirmed as time.windows.com. This verifies the immediate correction and successful synchronization; long-term drift and behavior after reboot were not tested. The correction does not retroactively repair earlier event timestamps.

### Investigation approach and outcome

For an unexpected account creation, I would verify the approved change/CAB request, requested purpose and owner, acting account and session, creation time, group memberships and privileges, and subsequent logins or activity. Administrative credentials do not by themselves prove approval. In this controlled lab, creation and deletion were intentional test actions; no external CAB record was supplied or verified.

The domain-controller agent delivered both creation and deletion events to Wazuh, and the temporary account was removed. The lab also demonstrated why accurate clocks, audit policy, working connectivity, and matching target identifiers matter when reconstructing an account lifecycle.
