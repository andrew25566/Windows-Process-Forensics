# Windows Process Forensics Tool

A Python-based Windows process investigation tool built as a cybersecurity/forensics lab project.

The program collects detailed information about a selected Windows process and helps investigate its parent/child relationships, executable file, loaded modules, and network connections.

## Features

For a supplied Process ID (PID), the tool can collect:

- Process name and PID
- Parent Process ID (PPID)
- Executable path
- Command line
- Process creation time
- Process description
- Handle and thread counts
- Priority and session ID
- Working-set and virtual memory information
- Read/write operation counts and transferred bytes
- Process owner
- Executable file size
- File creation and modification times
- SHA-256 hash of the executable
- Parent process information
- Child processes
- Loaded modules
- TCP network connections
- Parent process chain

The tool uses Windows PowerShell/CIM commands from Python to obtain process information.

## Requirements

- Windows
- Python 3
- PowerShell (included with modern Windows installations)
- No third-party Python packages are required

The program uses Python's standard library modules:

- `subprocess`
- `json`
- `os`
- `hashlib`
- `datetime`

## Installation

1. Install Python if it is not already installed.
2. Download or clone this repository.
3. Open Command Prompt or PowerShell in the project directory.

Check that Python is available:

```powershell
python --version
```

## Running the Tool

Run:

```powershell
python process_tree_forensics.py
```

The program will ask:

```text
Enter PID to investigate:
```

Enter the PID of the Windows process you want to investigate.

For example:

```text
Enter PID to investigate: 7172
```

The program will then collect the available forensic information.

## Running as Administrator

Running Command Prompt or PowerShell as **Administrator** is recommended.

Some Windows processes restrict access to information such as:

- Loaded modules
- Process ownership
- Certain system process details
- Network information

If access is denied, the program will report that information as unavailable rather than treating the process as malicious.

## What the Output Means

### Process Information

Shows basic information about the selected process, including its PID, name, executable path, command line, owner, memory information and timestamps.

### Executable Information

The program checks the executable on disk and calculates a SHA-256 hash.

The hash can be used to identify the exact file version and can later be compared against known-good or threat-intelligence sources.

### Parent Process

Shows which process created/launched the process being investigated.

This is useful when investigating suspicious process chains.

For example:

```text
explorer.exe
    -> powershell.exe
        -> python.exe
```

A parent-child relationship by itself does **not** prove malware. It is evidence that should be investigated in context.

### Child Processes

Shows processes currently associated with the selected process as their parent.

### Loaded Modules

Lists DLLs/modules loaded by the process where Windows allows access.

### Network Connections

Shows TCP connections associated with the selected PID, including:

- Local address
- Local port
- Remote address
- Remote port
- Connection state

### Parent Process Chain

Walks backwards through the process hierarchy to show the chain of parent processes.

This can be useful for investigating how a suspicious process was launched.

## Example Investigation

Suppose you see a suspicious process:

```text
PID: 2068
Name: python.exe
```

Run the tool and enter:

```text
2068
```

You can then examine:

1. Where the executable is located
2. Which process launched it
3. What command line was used
4. Which children it created
5. Which modules it loaded
6. Whether it has TCP connections
7. Its SHA-256 hash
8. The full parent process chain

## Important

This tool is an **investigation and learning tool**, not a malware detector.

A suspicious-looking process does not automatically mean malware.

For proper investigation, findings should be compared with additional evidence such as:

- File signatures
- File hashes
- Windows Event Logs
- Microsoft Defender results
- Process Explorer
- Autoruns
- Wireshark
- Network connection information
- Threat-intelligence databases

## Security Note

The program launches PowerShell to query Windows process information. It uses PowerShell's `-NoProfile` option and supplies the commands directly from the Python program.

It does not intentionally modify Windows configuration, terminate processes, or delete files.

## Project Purpose

This project was created as a practical cybersecurity learning exercise focused on Windows process investigation and basic digital forensics.

It demonstrates how Python can interact with Windows system information and how process relationships can be used during an incident investigation.

## Future Improvements

Possible future versions could add:

- Automatic suspicious-process scoring
- Digital signature verification
- VirusTotal hash lookups
- CSV/JSON report export
- Persistent investigation logs
- More detailed network analysis
- Real-time process monitoring
- Detection of unusual parent-child relationships
- Better handling of terminated processes
- A graphical interface

## License

This project is intended for educational and defensive cybersecurity use.
