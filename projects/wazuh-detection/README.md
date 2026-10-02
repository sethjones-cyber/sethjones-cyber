# Wazuh 4.14 Detection and Investigation — Labs 5–7

Author: Seth Jones | Performed: October 1, 2026 | Controlled home lab

## Scope and results

I tested privileged group membership changes, scheduled task auditing, and PowerShell script block logging on a Windows 11 workstation monitored by Wazuh 4.14 in Proxmox. These were deliberate, benign actions. The review focused on who acted, what changed, when it happened, the affected system, and whether the activity matched an approved purpose. Logs alone do not establish a person's intent or CAB approval.

| Lab | Verified result | Limitations |
| --- | --- | --- |
| 5 — Administrator membership | Wazuh events 4732 and 4733; disabled test account added and removed | No login or use of elevated privileges tested |
| 6 — Scheduled task | Creation 4698 in Wazuh after enabling auditing; deletion command succeeded; local 4699 observed | Deletion not found in Wazuh; no execution evidence |
| 7 — PowerShell | Plain marker captured locally; revised marker with environment query captured in Wazuh | Initial marker absent from Wazuh searches; cause not established |

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

Planned next labs: Lab 8 vulnerability triage, Lab 9 domain account monitoring, and Lab 10 a combined investigation. These are not completed results.
