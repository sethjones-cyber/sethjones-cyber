# Windows Systems Administration Home Lab

**Author:** Seth Jones  
**Completed:** October 4–5, 2026  
**Scope:** Five controlled exercises using Windows Server 2025, Windows 11, Active Directory, pfSense, and Proxmox in my own lab.

## Overview

I practiced account administration, domain connectivity troubleshooting, Group Policy deployment, file recovery, and Windows service recovery. I worked through the failures, checked the results, and recorded what each test actually proved. These are administration exercises, separate from my Wazuh detection project.

Internal addresses, the private domain name, host identifiers, credentials, and raw screenshots are omitted from this report. Commands using `<internal-domain>` or `<DC-IP>` are templates rather than literal commands from the lab. Results include reviewed screenshots and confirmations I supplied during the exercises; not every result has an exported log.

## Results at a glance

| Lab | Verified result | Boundary of the test |
| --- | --- | --- |
| 1. AD accounts and groups | Created a user and security group, verified membership, reset the password, then disabled the user and removed the added membership | No user login or resource permission test |
| 2. DNS and domain connectivity | Restored internal DNS resolution, joined Windows 11, and verified domain membership and the secure channel after restart | DC address stability and broader domain health remain separate checks |
| 3. Group Policy | Linked a computer policy to the lab OU, verified it in gpresult, and saw the configured login banner | One computer and two banner settings tested |
| 4. File recovery | Deleted a test file, restored it from a copy, and read the expected text | Same-disk copy; no full VM restore or disk-failure protection |
| 5. Service recovery | Observed Print Spooler Running → Stopped → Running | Controlled stop; no real crash or actual print job tested |

## Lab 1 — Active Directory account lifecycle

### Objective

Practice creating an account, assigning group membership, resetting a password, and removing access during offboarding.

### Work performed

1. Created the protected **Interview-Lab** organizational unit.
2. Created **interview.user** with a temporary private password and a requirement to change it at the next sign-in.
3. Created **Interview-Lab-Users** as a Global Security group.
4. Added the user and verified the membership from the group and user properties.
5. Reset the password with another private temporary password and retained the next-sign-in change requirement.
6. Disabled the account and removed its Interview-Lab-Users membership for the offboarding exercise.

### Outcome and limitations

The account, OU, and empty security group were retained for later lab work. The account remained disabled and retained its normal Domain Users membership. I did not assign resource permissions or test a sign-in, so group membership alone does not demonstrate access to a resource. Disabling an account also does not prove every existing session or token has ended.

### Interview takeaway

Groups let administrators manage approved access consistently for multiple people. Offboarding includes disabling the account, reviewing memberships, and addressing active sessions and other access paths according to the organization's process.

## Lab 2 — DNS, firewall troubleshooting, and domain join

### Initial problem

Windows 11 was still in WORKGROUP. Its configured DNS server could not resolve the private AD domain. A query sent directly to the DC timed out, and a TCP port 53 test failed.

### Investigation and changes

On the DC, I checked DNS resolution, domain-controller discovery, the DNS service, listening sockets, and firewall rules. The DNS service was running. Connectivity and DNS tests in dcdiag passed, with a warning about the DC's dynamically assigned address.

The workstation and DC were on different network segments. A pfSense block rule covering the DC's network was above the general allow rule. I added narrowly scoped workstation-to-DC exceptions above that block:

| Protocol | Destination ports | Purpose in the lab |
| --- | --- | --- |
| TCP/UDP | 53 | DNS |
| TCP | 88, 135, 389, 445, 464, 3268, 49152–65535 | AD service connectivity, including RPC |
| UDP | 88, 123, 389, 464 | AD service connectivity and time |

The exceptions used one workstation as the source and one DC as the destination. Logging was enabled, and the broader block rule was retained. These ports describe this lab configuration, not a universal firewall prescription.

After the DNS exception, the direct lookup succeeded. I configured Windows 11 to use the DC for DNS, and its default lookup succeeded too. A TCP LDAP test initially failed, then succeeded after the AD TCP exception. An LDAP SRV lookup returned the DC, and forced DC discovery succeeded.

### Validation commands

```powershell
nslookup <internal-domain> <DC-IP>
Test-NetConnection <DC-IP> -Port 53
Test-NetConnection <DC-IP> -Port 389
nslookup -type=SRV _ldap._tcp.<internal-domain>
nltest /dsgetdc:<internal-domain> /force
Get-CimInstance Win32_ComputerSystem | select Domain,PartOfDomain
Test-ComputerSecureChannel
```

I joined Windows 11 using a domain administrator credential, restarted it, and signed in with its local lab administrator account. The membership check reported True, and Test-ComputerSecureChannel also returned True.

### Outcome and limitations

The workstation's domain membership and trust connection were verified after restart. The before/after DNS and LDAP results support the effectiveness of the firewall changes. I did not export packet captures or firewall block logs to prove the cause of every timeout. The DC's dynamic addressing warning remains a follow-up item; I did not change its address in this exercise.

### Interview takeaway

AD clients need DNS that can resolve the domain's internal service records. DNS, network reachability, DC discovery, membership, and trust are related checks, but each establishes a different part of the connection.

## Lab 3 — Group Policy deployment and verification

### Objective and configuration

Moved the Windows 11 computer object into **Interview-Lab**. Created **Interview-Lab-Policy** and linked it to that OU. Under Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options, defined:

| Setting | Value |
| --- | --- |
| Interactive logon: Message title for users attempting to log on | Interview Lab |
| Interactive logon: Message text for users attempting to log on | Authorized lab use only. |

### Validation

```powershell
gpupdate /force
gpresult /r /scope computer
```

I confirmed Interview-Lab-Policy under Applied Group Policy Objects. After signing out, I confirmed the configured banner appeared at sign-in. This checked both policy application and the visible result.

### Interview takeaway

If a setting does not appear, first check the computer's OU, the GPO link and scope, and gpresult. Then investigate filtering, processing errors, and competing settings as needed. The lab GPO and computer placement were retained.

## Lab 4 — Controlled file backup and restore

### Scope decision

VM 105 had no listed backups. Proxmox backup storage was reported as approximately 212 GB used out of 245 GB, leaving about 33 GB. I used a small file recovery exercise rather than creating a full VM backup on that constrained storage.

### Work performed

Created a Desktop test file containing **Restore lab test** and copied it to a .bak file. A filename typo involving `=` and `-` caused Get-Content to report that the expected path did not exist. Directory listing and checking the actual name resolved the mismatch. I read the backup contents before deleting the original.

After deleting the original .txt file, I restored the copy and read the recovered file:

```powershell
# Intended creation and copy commands
"Restore lab test" | Set-Content "$env:USERPROFILE\Desktop\Restore-Test.txt"
cd "$env:USERPROFILE\Desktop"
Copy-Item .\Restore-Test.txt .\Restore-Test.bak

# Restore command used after checking the actual backup filename
Copy-Item .\Restore*.bak .\Restore-Test.txt
Get-Content .\Restore-Test.txt
```

The restored file displayed **Restore lab test**. The wildcard was used in this controlled folder with the identified lab backup; production restores should select the exact intended source.

### Outcome and limitations

This verified readable content recovery for one test file. The backup copy was on the same disk. It did not test full VM recovery, permissions, application consistency, offsite retention, disk-failure recovery, or recovery-time objectives. No hash comparison was performed.

### Interview takeaway

A successful backup job is only part of recovery assurance. Restore testing checks that the required data can actually be recovered and used. Restoring one file does not establish that an entire system can be recovered.

## Lab 5 — Windows service status and recovery

### Objective and commands

Used administrator PowerShell on the Windows 11 lab workstation to check, stop, and restore the Print Spooler:

```powershell
Get-Service Spooler
Stop-Service Spooler
Get-Service Spooler
Start-Service Spooler
Get-Service Spooler
```

### Verified outcome

The reported status changed **Running → Stopped → Running**. The service was left running. Its startup configuration was not changed.

### Limitations and interview takeaway

The stop was intentional. No spontaneous service failure, log analysis, driver repair, queue cleanup, or actual print job was tested. If a service stops repeatedly, verify its status, review relevant System and Application events around the failure time, and investigate dependencies, recent changes, and service-specific causes before repeatedly restarting it.

## Remaining follow-up work

- Review backup capacity and retention, then perform an isolated full VM restore when sufficient storage is available.
- Review stable DC addressing before changing DHCP or network settings.
- Test sign-in and explicitly assigned resource permissions with an enabled disposable standard domain account in a separate exercise.
- Test printing if validating end-to-end Print Spooler functionality.

## Interview summary

I practiced AD account lifecycle tasks, diagnosed internal DNS and firewall connectivity problems, joined a Windows workstation and verified its secure channel, deployed and verified a computer GPO, recovered a deleted test file, and restored a stopped Windows service. I checked the actual results and recorded the limits of each test.
