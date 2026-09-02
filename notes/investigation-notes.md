# Lab 69 Investigation Notes – RegAsm / RegSvcs Abuse Investigation

## 1. Investigation Objective

The purpose of this investigation was to examine RegAsm.exe and RegSvcs.exe from a Windows DFIR perspective.

Both utilities are legitimate Microsoft .NET Framework components. The investigation therefore focused on distinguishing normal trusted-binary activity from evidence that could indicate abuse.

The exercise was intentionally performed using a harmless local lab artifact rather than a malicious assembly.

## 2. Initial Binary Discovery

The .NET Framework directory structure was inspected first.

Framework versions identified:

- `C:\Windows\Microsoft.NET\Framework\v1.0.3705`
- `C:\Windows\Microsoft.NET\Framework\v1.1.4322`
- `C:\Windows\Microsoft.NET\Framework\v2.0.50727`
- `C:\Windows\Microsoft.NET\Framework\v4.0.30319`

Framework64:

- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319`

Targeted recursive searches identified both RegAsm.exe and RegSvcs.exe.

## 3. RegAsm.exe Findings

### 32-bit RegAsm

Path:

`C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe`

Metadata:

- Length: 58,864 bytes
- CreationTime: `02-08-2026 06:30:14`
- LastWriteTime: `25-06-2022 07:48:50`

SHA256:

`BD02B877C14DDC1E2DB118F32730B73B2E5AE792A84AC48F28957BEAFF2B83F9`

Signature:

- Status: Valid
- Signer certificate:
  `8870483E0E833965A53F422494F1614F79286851`

### 64-bit RegAsm

Path:

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`

Metadata:

- Length: 57,816 bytes
- CreationTime: `02-08-2026 06:30:14`
- LastWriteTime: `25-06-2022 07:46:50`

SHA256:

`7ACD65117EE6AC8BD996562C51B078C6DFA77E83125D948E6CA6418602CBE43C`

Signature:

- Status: Valid
- Signer certificate:
  `8870483E0E833965A53F422494F1614F79286851`

## 4. RegSvcs.exe Findings

### 32-bit RegSvcs

Path:

`C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`

Metadata:

- Length: 39,408 bytes
- LastWriteTime: `25-06-2022 07:48:50`

SHA256:

`F87D514B3322810463655473D2D7C704D3405C1C9DD81F0D4D423518EF416987`

Signature:

- Status: Valid
- Signer certificate:
  `8870483E0E833965A53F422494F1614F79286851`

### 64-bit RegSvcs

Path:

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe`

Metadata:

- Length: 38,872 bytes
- LastWriteTime: `25-06-2022 07:46:50`

SHA256:

`392E80F96DD8E817B2DF6BF8F63D82904F7530C3B25B3D447E2E171382E6A093`

Signature:

- Status: Valid
- Signer certificate:
  `8870483E0E833965A53F422494F1614F79286851`

## 5. Utility Identification

The help output confirmed:

RegAsm:

`Microsoft .NET Framework Assembly Registration Utility version 4.8.9037.0`

RegSvcs:

`Microsoft (R) .NET Framework Services Installation Utility Version 4.8.9037.0`

The RegAsm help output also exposed functionality including:

- assembly registration
- unregistering types
- type library generation
- registration file generation
- `/codebase`
- `/registered`
- `/asmpath`
- `/verbose`

The presence of these capabilities explains why these binaries may require additional scrutiny during an investigation.

## 6. SafeTest.cs Creation

A controlled source file was created at:

`C:\RegAsmRegSvcsLab\SafeTest.cs`

The source contained only a simple console application and no malicious functionality.

Observed metadata:

- Length: 134 bytes
- CreationTime: `02-09-2026 07:23:06`
- LastWriteTime: `02-09-2026 07:23:06`
- SHA256:
  `9AD01F0BB5A6B13CBE2091115CDA4F27D93018476F95B1A1A74482717C0A3157`

The source file returned:

`UnknownError`

from `Get-AuthenticodeSignature`.

The file was a source-code artifact rather than a signed executable.

## 7. Compilation Check

The environment was checked for `csc.exe`.

The command returned no result:

`Get-Command csc.exe -ErrorAction SilentlyContinue`

A subsequent attempt to inspect:

`C:\RegAsmRegSvcsLab\SafeTest.dll`

returned:

`Cannot find path ... SafeTest.dll because it does not exist.`

Therefore, no compiled DLL was established during the exercise.

This is important because the collected execution evidence should not be described as evidence of malicious DLL registration.

## 8. RegAsm Execution

A Sysmon Event ID 1 record was identified for RegAsm.

Confirmed values:

- Event ID: 1
- Process ID: 3516
- Image:
  `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe`
- User:
  `DESKTOP-GVRECLF\abhin`
- FileVersion:
  `4.8.9037.0 built by: NET481REL1`
- OriginalFileName:
  `RegAsm.exe`
- Company:
  `Microsoft Corporation`
- Current directory:
  `C:\Windows\system32\`

Command line:

`"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe" C:\RegAsmRegSvcsLab\SafeTest.cs /verbose`

Event time:

`02-09-2026 07:31:15`

This is the clearest process-level evidence collected during the lab.

## 9. RegSvcs Execution Search

The following targeted searches returned no result:

- Sysmon Event ID 1 containing `RegSvcs.exe` or `RegSvcs`
- PowerShell Event ID 4104 containing `RegSvcs`

Therefore:

- RegSvcs was not observed through those searches.
- This should not be interpreted as proof that RegSvcs was never executed.
- The correct conclusion is that no matching event was available from the queried telemetry.

## 10. PowerShell Event 4104 Investigation

PowerShell Operational logging contained 461 Event ID 4104 records in the filtered view.

A targeted search for:

- `RegAsm`
- `RegSvcs`

returned no matching event.

The displayed Event ID 4104 record from:

`02-09-2026 06:33:26`

contained unrelated system script content.

Therefore, PowerShell Script Block Logging was active, but it did not provide supporting evidence for RegAsm/RegSvcs execution in the targeted search.

## 11. Registry Investigation

A targeted search was performed under:

`HKCU:\Software\Classes`

The query searched for:

- `Lab69`
- `SafeTest`

No matching registry entries were returned.

This did not establish a suspicious per-user registry artifact associated with the lab.

## 12. Process Investigation

The process list was searched for:

- `RegAsm`
- `RegSvcs`

No currently running process matched either name at the time of the query.

This is expected because the RegAsm activity had already completed.

## 13. Security Event 4688 Investigation

Security Event ID 4688 was queried for:

- `RegAsm.exe`
- `RegSvcs.exe`

The targeted search returned no results.

As a result, the Sysmon Event ID 1 record became the primary direct process-creation evidence for the observed RegAsm execution.

## 14. Network Investigation

Sysmon Event ID 3 produced many network connection events.

The visible results showed network activity from the host, but no displayed event established a direct network connection associated with RegAsm.exe or RegSvcs.exe.

Therefore, no utility-specific network activity was confirmed.

## 15. Evidence Assessment

### Confirmed

- RegAsm.exe exists in expected .NET Framework locations.
- RegSvcs.exe exists in expected .NET Framework locations.
- The identified binaries have valid Authenticode signatures.
- The binaries identify as Microsoft .NET Framework components.
- A harmless SafeTest.cs file was created.
- SafeTest.cs was hashed successfully.
- Sysmon Event ID 1 recorded RegAsm.exe execution against SafeTest.cs.
- PowerShell Event ID 4104 logging is active.
- Sysmon Event ID 3 logging is active.

### Not Established

- Malicious assembly execution.
- Malicious DLL registration.
- RegSvcs execution.
- Suspicious registry persistence.
- RegAsm/RegSvcs network communication.
- Security Event 4688 evidence for the observed RegAsm process.

### Telemetry Limitations

The investigation was limited by the absence of matching results from several targeted searches.

In particular:

- No matching Event ID 4688 result.
- No matching RegSvcs Event ID 1 result.
- No matching RegAsm/RegSvcs Event ID 4104 result.
- No utility-specific Sysmon Event ID 3 result.

These limitations must remain part of the investigative conclusion.

## 16. Final Assessment

The evidence supports a controlled RegAsm execution involving a harmless local source artifact.

The trusted binary itself was not suspicious based on the available path, metadata, version information, and signature validation.

The investigation did not establish malicious RegAsm/RegSvcs abuse.

The primary DFIR lesson is that signed system binaries should be assessed through execution context, command line, parent process, referenced files, registry effects, and additional telemetry rather than being classified as malicious solely because they are commonly discussed in LOLBin or signed-binary abuse scenarios.
