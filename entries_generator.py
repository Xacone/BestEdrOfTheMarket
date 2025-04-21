import random
import json
import argparse
from datetime import datetime, timedelta

def random_protect_flag():
    return random.choice(["X", "WX", "RX", "RWX", "NX"])

def random_level():
    return random.choice(["Info", "Warning", "Critical"])

def generate_address(prefix="0x"):
    return prefix + ''.join(random.choices("0123456789ABCDEF", k=16))

def random_yara_rule():
    return f"Windows_Hacktool_Mimikatz_{''.join(random.choices('abcdef0123456789', k=8))}"

def random_datetime_this_year():
    start = datetime(datetime.now().year, 1, 1)
    end = datetime.now()
    delta = end - start
    random_seconds = random.randint(0, int(delta.total_seconds()))
    rand_datetime = start + timedelta(seconds=random_seconds)
    return rand_datetime.isoformat(sep=' ', timespec='seconds')

REGISTRY_KEYS = [
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\BadDriver",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SOFTWARE\\MalwareInc\\Persistence",
    "HKLM\\SYSTEM\\ControlSet001\\Services\\EvilService",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU\\Software\\SuspiciousApp",
    "HKLM\\SYSTEM\\FakeControl\\FakeKey",
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Suspicious",
    "HKLM\\SYSTEM\\Setup\\SetupClé"
]

PROCESS_NAMES = ["Malware.exe", "TrojanLoader.exe", "BackdoorAgent.exe", "Stealer.exe", "Dropper.exe"]
VICTIM_NAMES = ["Explorer.exe", "svchost.exe", "lsass.exe", "chrome.exe", "cmd.exe"]

def generate_system_call_info():
    syscall_map = {
        1: "NtWriteVirtualMemory",
        2: "NtWriteFile",
        3: "NtProtectVirtualMemory"
    }

    syscall_id = random.randint(1, 3)
    syscall_name = syscall_map[syscall_id]

    data = {
        "InvolvedSystemCall": syscall_name,
        "InvolvedSystemCallId": syscall_id
    }

    if syscall_id == 1:
        data["NtWriteVmInfo"] = {
            "SourceAddress": generate_address(),
            "TargetAddress": generate_address(),
            "Size": random.choice([1024, 2048, 4096])
        }
    elif syscall_id == 2:
        data["NtWriteFileInfo"] = {
            "BufferAddress": generate_address(),
            "BufferLength": random.choice([1024, 2048, 4096])
        }
    elif syscall_id == 3:
        data["NtProtectVmInfo"] = {
            "BaseAddress": generate_address(),
            "NumberOfBytesToProtect": random.choice([1024, 2048, 4096]),
            "Protection": random.randint(1, 128)
        }

    return { "SystemCallInfo": data }

def generate_ghost_info():
    return {
        "GhostProcessInfo": {
            "Hollowed": random.choice([True, False]),
            "ProcessVadRootAddress": generate_address(),
            "ProcessBaseAddressVad": generate_address(),
            "ProcessBaseAddressLdr": generate_address()
        }
    }

def generate_hollowed_vad_info():
    return {
        "HollowedVadTreeInfo": {
            "Hollowed": random.choice([True, False]),
            "ProcessVadRootAddress": generate_address(),
            "ProcessBaseAddressVad": generate_address(),
            "ProcessBaseAddressLdr": generate_address()
        }
    }

def generate_code_injection_info():
    return {
        "CodeInjectionInfo": {
            "SuspiciousStartAddress": generate_address(),
            "OriginMemoryRegionProtect": random_protect_flag()
        }
    }

def generate_registry_operation_info():
    return {
        "RegistryOperationInfo": {
            "SuspiciousRegistryKey": random.choice(REGISTRY_KEYS),
            "SuspiciousRegistryValue": random.choice(PROCESS_NAMES)
        }
    }

def generate_credential_dump_info():
    return {
        "CredentialDumpInfo": {
            "OperationType": random.choice(["VM Read", "Memory Scan", "Handle Duplication"])
        }
    }

def generate_shadow_stack_info():
    return {
        "ShadowStackInfo": {
            "AbnormalStackFrame": generate_address()
        }
    }

def generate_abnormal_syscall_info():
    return {
        "AbnormalNtSyscallInfo": {
            "UserSyscallAddress": generate_address()
        }
    }

def generate_logical_event():
    method_id = random.randint(1, 8)
    event_map = {
        1: ("System Call Check", generate_system_call_info),
        2: ("Ghost Process", generate_ghost_info),
        3: ("Hollowed Process", generate_hollowed_vad_info),
        4: ("Code Injection", generate_code_injection_info),
        5: ("Suspicious Reg Key", generate_registry_operation_info),
        6: ("Credential Dump", generate_credential_dump_info),
        7: ("Thread Stack Corruption", generate_shadow_stack_info),
        8: ("Abnormal NT Syscall", generate_abnormal_syscall_info)
    }

    method_name, generator = event_map[method_id]
    origin_process = random.choice(PROCESS_NAMES)
    victim_process = random.choice(VICTIM_NAMES)

    return {
        "Version": 3,
        "GlobalDefensiveMethod": method_name,
        "GlobalDefensiveMethodId": method_id,
        "Level": random_level(),
        "isCodeInjection": method_id == 4,
        "OriginProcess": origin_process,
        "OriginPID": random.randint(500, 5000),
        "VictimProcess": victim_process,
        "TargetPID": random.randint(5000, 10000),
        "OriginProcessImagePath": f"C:\\Users\\User\\Downloads\\Malwares\\{origin_process}",
        "InvolvedYaraRule": random_yara_rule(),
        "DateAndTime": random_datetime_this_year(),
        "SpecificEventsInfo": [generator()]
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate logical detection events.")
    parser.add_argument("--count", type=int, required=True, help="Number of events to generate")
    args = parser.parse_args()

    events = [generate_logical_event() for _ in range(args.count)]
    print(json.dumps(events, indent=2))
