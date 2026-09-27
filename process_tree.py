import subprocess
import json
import os
import hashlib
from datetime import datetime


# ============================================================
# WINDOWS PROCESS FORENSICS TOOL
# ============================================================

def run_powershell(command):
    """Run a PowerShell command and return its output."""
    
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command", command
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("\n[PowerShell ERROR]")
        print(result.stderr)
        return ""

    return result.stdout


def get_process(pid):
    """Retrieve detailed process information."""

    command = f'''
    $p = Get-CimInstance Win32_Process -Filter "ProcessId={pid}"

    if ($null -eq $p) {{
        Write-Output "PROCESS_NOT_FOUND"
        exit
    }}

    $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner

    $obj = [PSCustomObject]@{{
        ProcessId       = $p.ProcessId
        Name            = $p.Name
        ParentProcessId = $p.ParentProcessId
        ExecutablePath  = $p.ExecutablePath
        CommandLine     = $p.CommandLine
        CreationDate    = $p.CreationDate
        Description     = $p.Description
        HandleCount     = $p.HandleCount
        ThreadCount     = $p.ThreadCount
        Priority        = $p.Priority
        SessionId       = $p.SessionId
        WorkingSet      = $p.WorkingSetSize
        VirtualSize     = $p.VirtualSize
        ReadOperations  = $p.ReadOperationCount
        WriteOperations = $p.WriteOperationCount
        ReadBytes       = $p.ReadTransferCount
        WriteBytes      = $p.WriteTransferCount
        User            = "$($owner.Domain)\\$($owner.User)"
    }}

    $obj | ConvertTo-Json
    '''

    output = run_powershell(command)

    if not output.strip():
        return None

    if "PROCESS_NOT_FOUND" in output:
        return None

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        print("Could not parse Windows response.")
        print(output)
        return None


def get_file_information(path):
    """Collect information about the executable on disk."""

    if not path:
        return None

    if not os.path.exists(path):
        return None

    information = {}

    try:
        information["Size"] = os.path.getsize(path)
        information["Created"] = datetime.fromtimestamp(
            os.path.getctime(path)
        )
        information["Modified"] = datetime.fromtimestamp(
            os.path.getmtime(path)
        )

        sha256 = hashlib.sha256()

        with open(path, "rb") as file:
            for block in iter(lambda: file.read(1024 * 1024), b""):
                sha256.update(block)

        information["SHA256"] = sha256.hexdigest()

    except PermissionError:
        information["Error"] = "Permission denied"

    except Exception as error:
        information["Error"] = str(error)

    return information


def get_parent(pid):
    """Find the parent process."""

    process = get_process(pid)

    if process:
        return process

    return None


def get_children(pid):
    """Find processes whose parent is the supplied PID."""

    command = f'''
    Get-CimInstance Win32_Process |
    Where-Object {{ $_.ParentProcessId -eq {pid} }} |
    Select-Object ProcessId, Name, ParentProcessId, ExecutablePath, CommandLine |
    ConvertTo-Json
    '''

    output = run_powershell(command)

    if not output.strip():
        return []

    try:
        data = json.loads(output)

        if isinstance(data, dict):
            return [data]

        return data

    except json.JSONDecodeError:
        return []


def get_modules(pid):
    """Retrieve loaded modules."""

    command = f'''
    Get-Process -Id {pid} -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Modules |
    Select-Object ModuleName, FileName, FileVersion |
    ConvertTo-Json
    '''

    output = run_powershell(command)

    if not output.strip():
        return []

    try:
        data = json.loads(output)

        if isinstance(data, dict):
            return [data]

        return data

    except json.JSONDecodeError:
        return []


def get_network_connections(pid):
    """Retrieve network connections belonging to the process."""

    command = f'''
    Get-NetTCPConnection -OwningProcess {pid} -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort,
                  RemoteAddress, RemotePort,
                  State, OwningProcess |
    ConvertTo-Json
    '''

    output = run_powershell(command)

    if not output.strip():
        return []

    try:
        data = json.loads(output)

        if isinstance(data, dict):
            return [data]

        return data

    except json.JSONDecodeError:
        return []


def print_section(title):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


# ============================================================
# MAIN PROGRAM
# ============================================================

print("=" * 70)
print("              WINDOWS PROCESS FORENSICS TOOL")
print("=" * 70)

print()
pid = input("Enter PID to investigate: ")

if not pid.isdigit():
    print("Invalid PID.")
    input("Press Enter to exit...")
    exit()

pid = int(pid)

print()
print("Collecting forensic information...")
print("This may take a little while.")
print()

process = get_process(pid)

if process is None:
    print(f"Process {pid} could not be found.")
    input("Press Enter to exit...")
    exit()


# ============================================================
# BASIC PROCESS INFORMATION
# ============================================================

print_section("1. PROCESS INFORMATION")

for key, value in process.items():
    print(f"{key:<20}: {value}")


# ============================================================
# EXECUTABLE INFORMATION
# ============================================================

print_section("2. EXECUTABLE INFORMATION")

path = process.get("ExecutablePath")

print(f"Executable Path : {path}")

file_info = get_file_information(path)

if file_info:

    for key, value in file_info.items():
        print(f"{key:<16}: {value}")

else:

    print("Could not obtain executable information.")


# ============================================================
# PARENT PROCESS
# ============================================================

print_section("3. PARENT PROCESS")

parent_pid = process.get("ParentProcessId")

print(f"Parent PID: {parent_pid}")

if parent_pid:

    parent = get_parent(parent_pid)

    if parent:

        print(f"Parent Name          : {parent.get('Name')}")
        print(f"Parent Executable    : {parent.get('ExecutablePath')}")
        print(f"Parent Command Line  : {parent.get('CommandLine')}")
        print(f"Parent User         : {parent.get('User')}")

    else:

        print("Parent process no longer exists.")


# ============================================================
# CHILD PROCESSES
# ============================================================

print_section("4. CHILD PROCESSES")

children = get_children(pid)

if children:

    for child in children:

        print()
        print(f"PID       : {child.get('ProcessId')}")
        print(f"Name      : {child.get('Name')}")
        print(f"Parent PID: {child.get('ParentProcessId')}")
        print(f"Path      : {child.get('ExecutablePath')}")
        print(f"Command   : {child.get('CommandLine')}")

else:

    print("No child processes found.")


# ============================================================
# LOADED MODULES
# ============================================================

print_section("5. LOADED MODULES")

modules = get_modules(pid)

if modules:

    print(f"Modules loaded: {len(modules)}")

    for module in modules:

        print()
        print(f"Module : {module.get('ModuleName')}")
        print(f"Path   : {module.get('FileName')}")
        print(f"Version: {module.get('FileVersion')}")

else:

    print("Modules unavailable or access denied.")


# ============================================================
# NETWORK CONNECTIONS
# ============================================================

print_section("6. NETWORK CONNECTIONS")

connections = get_network_connections(pid)

if connections:

    for connection in connections:

        print()
        print(f"Local Address : {connection.get('LocalAddress')}")
        print(f"Local Port    : {connection.get('LocalPort')}")
        print(f"Remote Address: {connection.get('RemoteAddress')}")
        print(f"Remote Port   : {connection.get('RemotePort')}")
        print(f"State         : {connection.get('State')}")

else:

    print("No TCP connections found.")


# ============================================================
# PROCESS TREE
# ============================================================

print_section("7. PARENT PROCESS CHAIN")

current_pid = pid
visited = set()

while current_pid and current_pid not in visited:

    visited.add(current_pid)

    current = get_process(current_pid)

    if current is None:
        break

    print(
        f"{current.get('ProcessId')} "
        f"-> {current.get('Name')}"
    )

    current_pid = current.get("ParentProcessId")


# ============================================================
# END
# ============================================================

print_section("INVESTIGATION COMPLETE")

print()
print("The information above represents the evidence")
print("Windows exposed for the selected process.")

input("Press Enter to exit...")
