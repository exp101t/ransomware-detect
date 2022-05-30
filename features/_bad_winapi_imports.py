_bad_functions = [
    # Traditional Code Injection
    "ReadProcessMemory",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtWriteVirtualMemory",
    # Memory allocation in foreign process
    "VirtualAllocEx",
    "VirtualQueryEx",
    "VirtualProtectEx",
    # APC Injection
    "QueueUserAPC",
    # Atom Bombing
    "GlobalAddAtom",
    "NtQueueApcThread",
    # Process Hollowing
    "ZwUnmapViewOfSection",
    "NtUnmapViewOfSection",
    "SetThreadContext",
    # Debugger detection
    "IsDebugged",
    "IsDebuggerPresent",
    "QueryInformationProcess",
    "NtGlobalFlags",
    "CheckRemoteDebuggerPresent",
    "SetInformationThread",
    "DebugActiveProcess",
    # Dynamic DLL Loading
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
]


def get_bad_imports_num(pe_bytes: bytes) -> int:
    return sum(1 for sym in _bad_functions if sym.encode() in pe_bytes)
