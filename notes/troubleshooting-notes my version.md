# Troubleshooting Notes

## 1. RegAsm Search Command Line-Break Error

### Problem

The initial PowerShell command was entered across multiple lines without a continuation character after the directory path.

Example:

`Get-ChildItem "$env:windir\Microsoft.NET"`
`-Recurse`

PowerShell interpreted `-Recurse` as a new command and returned:

`The term '-Recurse' is not recognized...`

### Cause

Windows PowerShell does not automatically continue a command simply because the next line contains another parameter.

### Fix

Use a single-line command:

`Get-ChildItem "$env:windir\Microsoft.NET" -Recurse -Filter "RegAsm.exe" -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime`

For RegSvcs:

`Get-ChildItem "$env:windir\Microsoft.NET" -Recurse -Filter "RegSvcs.exe" -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime`

### Lesson

For Windows PowerShell lab work, single-line commands are safer when long commands are involved and reduce accidental parsing errors.

---

## 2. Initial RegAsm Discovery Appeared to Return Only Directory Listings

### Problem

The first attempt produced framework directory listings but did not return RegAsm.exe results.

### Cause

The command had terminated early because of the line-break issue described above.

### Fix

The recursive search was rerun as a single command.

This successfully returned:

- `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe`
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`

### Lesson

When a recursive search appears incomplete, first verify that PowerShell actually executed the complete command.

---

## 3. SafeTest.dll Was Missing

### Problem

The following command returned an error:

`Get-Item "C:\RegAsmRegSvcsLab\SafeTest.dll"`

The error stated that the file did not exist.

### Cause

No compiled `SafeTest.dll` was created.

The local `csc.exe` discovery command also returned no result.

### Fix

The investigation was not changed into a forced compilation workflow.

Instead, the evidence was kept accurate:

- SafeTest.cs existed.
- SafeTest.dll did not exist.
- A RegAsm process event referenced the `.cs` file.
- No claim of successful DLL compilation was made.

### Lesson

Do not manufacture missing artifacts simply because the original lab concept expects them. Record what actually happened.

---

## 4. AuthenticodeSignature Returned UnknownError for SafeTest.cs

### Problem

Running:

`Get-AuthenticodeSignature "C:\RegAsmRegSvcsLab\SafeTest.cs"`

returned:

`Status : UnknownError`

### Interpretation

The file was a source-code text file, not a signed Windows executable.

Therefore, the result does not establish that the file was malicious.

The RegAsm and RegSvcs binaries themselves returned:

`Status : Valid`

### Lesson

Signature validation must be interpreted according to the type of file being investigated.

---

## 5. Targeted Event 4104 Search Returned Nothing

### Problem

The PowerShell Operational log contained many Event ID 4104 records, but this query returned no RegAsm/RegSvcs match:

`Where-Object { $_.Message -match "RegAsm|RegSvcs" }`

### Interpretation

This means no matching Script Block Logging event was found in the queried records.

It does not prove that PowerShell never interacted with RegAsm or RegSvcs.

### Lesson

A negative telemetry search should be reported as:

"No matching event was identified"

rather than:

"This activity never happened."

---

## 6. Targeted Event 4688 Search Returned Nothing

### Problem

A Security Event 4688 search for RegAsm.exe and RegSvcs.exe returned no results.

### Interpretation

The investigation therefore relied on Sysmon Event ID 1 for direct process-creation evidence.

### Lesson

When multiple process-creation sources exist, absence from one source does not invalidate evidence from another source.

---

## 7. RegSvcs Event Search Returned No Match

### Problem

Sysmon Event ID 1 was queried for:

`RegSvcs.exe`

No matching events were returned.

### Interpretation

RegSvcs execution was not established from the available Sysmon process events.

### Lesson

Do not infer RegSvcs execution simply because RegSvcs exists on the system or because the lab focuses on both binaries.

---

## 8. Current Process Search Returned No RegAsm/RegSvcs Process

### Problem

The following query returned no result:

`Get-Process | Where-Object { $_.ProcessName -in ("RegAsm", "RegSvcs") }`

### Cause

The search was performed after the process had completed.

### Interpretation

A process list is a point-in-time observation. It cannot prove historical process execution.

Historical execution evidence should come from sources such as:

- Sysmon Event ID 1
- Security Event ID 4688
- EDR telemetry
- other process-audit logs

---

## 9. Registry Search Returned No Lab69 or SafeTest Entries

### Problem

The recursive HKCU search produced no matching results.

### Interpretation

No matching registry artifact was established by that specific query.

This does not mean the entire registry was proven clean.

### Lesson

Always distinguish between:

- "No matching artifact found in this search"

and:

- "No registry persistence exists."

The first statement is supported by evidence. The second is not.

---

## 10. Many Sysmon Event ID 3 Network Events

### Problem

Sysmon Event ID 3 returned a large number of network connection events.

### Interpretation

Event ID 3 is general host network telemetry.

The presence of many connections does not establish that RegAsm or RegSvcs generated them.

### Fix

The correct investigative approach is to correlate network events with:

- process image
- process ID
- destination IP
- destination port
- timestamp

No such utility-specific connection was established in the displayed evidence.

---

