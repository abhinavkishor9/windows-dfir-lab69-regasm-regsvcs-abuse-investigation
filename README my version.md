# windows-dfir-lab69-regasm-regsvcs-abuse-investigation
# Overview

RegAsm.exe is the Assembly Registration Tool. It can register metadata from a managed assembly so that COM clients can use the assembly.

RegSvcs.exe is a .NET utility associated with registering assemblies and services.

From a SOC/DFIR perspective, the concern is not:

RegAsm.exe exists

or:

RegSvcs.exe exists

The concern is:

Unexpected RegAsm / RegSvcs execution
        ↓
Unusual assembly
        ↓
Suspicious path or arguments
        ↓
Potential registration activity
        ↓
Possible persistence / execution

This is why these utilities can be investigated as potential LOLBin-style abuse.

A legitimate administrator or application may use these utilities.

More suspicious combinations include:

RegAsm.exe
    +
Unknown DLL
    +
User-writable directory

or:

RegSvcs.exe
    +
Unusual command line
    +
Recently created assembly

A stronger chain might be:

Unknown File
      ↓
RegAsm / RegSvcs
      ↓
Registry Change
      ↓
Unexpected Process
      ↓
Follow-on Activity

The important DFIR principle is:

The trusted Windows utility is not inherently malicious; the context in which it is used determines its investigative significance.

On modern Windows systems, .NET tooling may exist in different framework directories and architectures.

You may find paths such as:

C:\Windows\Microsoft.NET\Framework\

and:

C:\Windows\Microsoft.NET\Framework64\

Do not assume a single fixed path before checking your machine.

This lab investigates `RegAsm.exe` and `RegSvcs.exe`, legitimate Microsoft .NET Framework utilities that may be relevant during investigations because trusted system binaries can potentially be misused to execute or register unauthorized .NET assemblies.

The investigation was performed as a controlled, non-destructive lab exercise. Instead of modifying real Windows registration settings or using a malicious assembly, a harmless C# source file named `SafeTest.cs` was created in a dedicated lab directory and used to study the surrounding execution evidence.

The objective was to determine whether RegAsm and RegSvcs existed in their expected locations, whether their files appeared legitimate, whether their execution could be observed through Windows telemetry, and whether any related suspicious registry artifacts could be established.

## Environment

- Operating System: Windows
- Hostname: DESKTOP-GVRECLF
- User: DESKTOP-GVRECLF\abhin
- .NET Framework: 4.8.9037.0
- Lab directory: `C:\RegAsmRegSvcsLab`
- Monitoring:
  - Windows Event Viewer
  - Sysmon
  - PowerShell Operational Logging
  - Windows Security logging

## Investigation Objectives

- Identify the legitimate RegAsm.exe and RegSvcs.exe binaries on the Windows host.
- Examine their file metadata, hashes, versions, and Authenticode signatures.
- Create and track a harmless SafeTest.cs investigation artifact.
- Investigate RegAsm/RegSvcs execution through available Windows and Sysmon telemetry.
- Analyze Sysmon Event ID 1 for process creation and command-line evidence.
- Search PowerShell Event ID 4104 for related execution evidence.
- Check Security Event ID 4688 for additional process-creation visibility.
- Review registry and network telemetry for supporting artifacts.
- Correlate the collected evidence into a simple investigative timeline.
- Determine whether the available evidence supports legitimate execution, suspicious behavior, or confirmed abuse.
- Document telemetry gaps and avoid treating missing events as proof that an activity did not occur.

## Investigation Sceanrio

A Windows workstation is being investigated for possible misuse of legitimate .NET Framework utilities, specifically RegAsm.exe and RegSvcs.exe. Although both are trusted Microsoft binaries, their assembly-related functionality can make their execution relevant during a DFIR investigation.

The analyst performs a controlled investigation using a harmless SafeTest.cs file placed in a dedicated lab directory. The investigation focuses on:

- Verifying the expected location and integrity of RegAsm.exe and RegSvcs.exe.
- Determining whether either utility was executed and examining the associated command line.
- Correlating Sysmon, PowerShell, Windows Security, registry, and network telemetry.
- Identifying any supporting artifacts that could indicate suspicious activity.
- Separating confirmed evidence from unavailable or inconclusive telemetry.

The objective is not to assume that the presence or execution of a signed Microsoft binary is malicious, but to determine what actually occurred on the workstation based on the available evidence.


## RegAsm and RegSvcs Locations

The following legitimate Microsoft .NET Framework binaries were identified:

- `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe`
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`
- `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe`

The binaries were located beneath the expected Microsoft .NET Framework directories.

## File Integrity Findings

### RegAsm.exe

32-bit path:

`C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe`

- Length: 58,864 bytes
- SHA256: `BD02B877C14DDC1E2DB118F32730B73B2E5AE792A84AC48F28957BEAFF2B83F9`
- LastWriteTime: `25-06-2022 07:48:50`
- Authenticode status: `Valid`
- Signer certificate fingerprint:
  `8870483E0E833965A53F422494F1614F79286851`

64-bit path:

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`

- Length: 57,816 bytes
- SHA256: `7ACD65117EE6AC8BD996562C51B078C6DFA77E83125D948E6CA6418602CBE43C`
- LastWriteTime: `25-06-2022 07:46:50`
- Authenticode status: `Valid`
- Signer certificate fingerprint:
  `8870483E0E833965A53F422494F1614F79286851`

### RegSvcs.exe

32-bit path:

`C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`

- Length: 39,408 bytes
- SHA256: `F87D514B3322810463655473D2D7C704D3405C1C9DD81F0D4D423518EF416987`
- LastWriteTime: `25-06-2022 07:48:50`
- Authenticode status: `Valid`
- Signer certificate fingerprint:
  `8870483E0E833965A53F422494F1614F79286851`

64-bit path:

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe`

- Length: 38,872 bytes
- SHA256: `392E80F96DD8E817B2DF6BF8F63D82904F7530C3B25B3D447E2E171382E6A093`
- LastWriteTime: `25-06-2022 07:46:50`
- Authenticode status: `Valid`
- Signer certificate fingerprint:
  `8870483E0E833965A53F422494F1614F79286851`

The observed binaries therefore showed valid Microsoft Authenticode signatures and were located within the expected .NET Framework directories.

## Safe Test Artifact

A harmless C# source file was created:

`C:\RegAsmRegSvcsLab\SafeTest.cs`

Its contents were limited to a simple console output statement.

Observed metadata:

- Length: 134 bytes
- CreationTime: `02-09-2026 07:23:06`
- LastWriteTime: `02-09-2026 07:23:06`
- SHA256:
  `9AD01F0BB5A6B13CBE2091115CDA4F27D93018476F95B1A1A74482717C0A3157`

`Get-AuthenticodeSignature` returned `UnknownError` for the `.cs` source file. This does not establish that the source file itself was malicious; it simply means it was not validated as a signed executable or signed code artifact through that command.

No `SafeTest.dll` was present. The `csc.exe` discovery command also returned no result, so no local C# compilation step was established.

## RegAsm Execution Evidence

Sysmon Event ID 1 recorded execution of RegAsm:

- Process ID: 3516
- Image:
  `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe`
- FileVersion: `4.8.9037.0 built by: NET481REL1`
- Description: Microsoft .NET Assembly Registration Utility
- Product: Microsoft .NET Framework
- Company: Microsoft Corporation
- OriginalFileName: `RegAsm.exe`
- Command line:
  `"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe" C:\RegAsmRegSvcsLab\SafeTest.cs /verbose`
- Current directory: `C:\Windows\system32\`
- User: `DESKTOP-GVRECLF\abhin`
- Event time: `02-09-2026 07:31:15`

This provides direct evidence that the legitimate RegAsm binary was executed against the harmless lab source file.

## RegSvcs Execution Evidence

A targeted search of Sysmon Event ID 1 for `RegSvcs.exe` returned no matching event.

A targeted PowerShell Operational Event ID 4104 search for `RegSvcs` also returned no matching event.

Therefore, RegSvcs execution was not established from the available telemetry.

## PowerShell Evidence

PowerShell Operational logging contained Event ID 4104 records, confirming that Script Block Logging was active.

However, the targeted search for:

- `RegAsm`
- `RegSvcs`

did not return matching PowerShell script blocks.

One observed Event ID 4104 from `02-09-2026 06:33:26` contained unrelated system script content and did not establish RegAsm or RegSvcs activity.

## Registry Evidence

The following targeted registry search was performed:

`HKCU:\Software\Classes`

The search looked for names containing:

- `Lab69`
- `SafeTest`

No matching registry artifact was returned.

This means no suspicious per-user registry artifact matching those lab indicators was established through this query.

## Network Evidence

Sysmon Event ID 3 contained numerous network connection events.

The collected output showed regular network telemetry, but no connection could be directly tied to RegAsm or RegSvcs from the displayed evidence.

Therefore, network activity associated with these utilities was not established.

