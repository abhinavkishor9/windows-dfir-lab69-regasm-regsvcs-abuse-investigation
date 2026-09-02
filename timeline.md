# Lab 69 Timeline – RegAsm / RegSvcs Abuse Investigation

| Time | Evidence Source | Event / Activity | Assessment |
|---|---|---|---|
| 02-08-2026 06:30:14 | File metadata | RegAsm.exe and RegSvcs.exe files show lab-environment CreationTime | Metadata observation only |
| 25-06-2022 07:46:50 | File metadata | Framework64 RegAsm.exe last-write timestamp | Historical file metadata |
| 25-06-2022 07:46:50 | File metadata | Framework64 RegSvcs.exe last-write timestamp | Historical file metadata |
| 25-06-2022 07:48:50 | File metadata | Framework RegAsm.exe last-write timestamp | Historical file metadata |
| 25-06-2022 07:48:50 | File metadata | Framework RegSvcs.exe last-write timestamp | Historical file metadata |
| 02-09-2026 07:23:06 | File metadata | SafeTest.cs created in `C:\RegAsmRegSvcsLab` | Confirmed harmless lab artifact |
| 02-09-2026 07:23:06 | File metadata | SafeTest.cs last modified | Confirmed |
| 02-09-2026 07:23:06 | File hashing | SHA256 calculated for SafeTest.cs | Confirmed |
| 02-09-2026 07:31:15 | Sysmon Event ID 1 | RegAsm.exe process created | Confirmed |
| 02-09-2026 07:31:15 | Sysmon Event ID 1 | RegAsm executed from `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe` | Expected trusted path |
| 02-09-2026 07:31:15 | Sysmon Event ID 1 | RegAsm command line referenced `C:\RegAsmRegSvcsLab\SafeTest.cs /verbose` | Controlled lab execution |
| 02-09-2026 07:31:15 | Sysmon Event ID 1 | RegAsm executed as `DESKTOP-GVRECLF\abhin` | Confirmed |
| 02-09-2026 07:31:54 | Sysmon Event ID 1 | Additional process creation events observed | General telemetry |
| 02-09-2026 06:33:26 | PowerShell Event ID 4104 | Script Block Logging event observed | Unrelated system content |
| 02-09-2026 | Sysmon Event ID 1 search | RegSvcs.exe targeted search returned no match | Not established |
| 02-09-2026 | Security Event ID 4688 search | RegAsm.exe / RegSvcs.exe targeted search returned no match | Not established |
| 02-09-2026 | PowerShell Event ID 4104 search | RegAsm / RegSvcs targeted search returned no match | Not established |
| 02-09-2026 | Registry search | HKCU Software\Classes search for Lab69 / SafeTest returned no match | Not established |
| 02-09-2026 | Process inspection | No currently running RegAsm or RegSvcs process | Point-in-time observation |
| 02-09-2026 | Sysmon Event ID 3 | Numerous network connection events observed | No RegAsm/RegSvcs correlation established |
| 02-09-2026 | File inspection | SafeTest.dll check failed because file did not exist | No compiled DLL established |
| 02-09-2026 | Cleanup | SafeTest.cs removed from lab directory | Confirmed cleanup |
| 02-09-2026 | Cleanup verification | `Test-Path "C:\RegAsmRegSvcsLab\SafeTest.cs"` returned `False` | Confirmed artifact removal |

## Timeline Assessment

The timeline establishes a controlled sequence:

1. Legitimate RegAsm and RegSvcs binaries were identified in expected Microsoft .NET Framework directories.
2. Their integrity and signatures were checked.
3. A harmless SafeTest.cs source artifact was created.
4. RegAsm.exe was executed against the harmless source artifact.
5. Sysmon Event ID 1 captured the execution with the full image path and command line.
6. Targeted searches for RegSvcs, PowerShell support, Security Event 4688, and registry artifacts did not produce matching evidence.
7. The SafeTest.cs artifact was removed during cleanup.

The strongest evidence in the timeline is the Sysmon Event ID 1 record at `02-09-2026 07:31:15`, which directly establishes RegAsm execution.

## Final Timeline Conclusion

The collected timeline demonstrates legitimate RegAsm execution within a controlled lab scenario.

No evidence in the collected timeline establishes malicious assembly registration, RegSvcs execution, persistence, or external network activity associated with the investigated utilities.

Negative search results are retained as telemetry limitations rather than interpreted as proof that the corresponding activities were impossible.
