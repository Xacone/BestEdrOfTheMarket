import requests
import re
from bs4 import BeautifulSoup

windows_10_kernel_versions = {
    "1507": 10240,
    "1511": 10586,
    "1607": 14393,
    "1703": 15063,
    "1709": 16299,
    "1803": 17134,
    "1809": 17763,
    "1903": 18362,
    "1909": 18363,
    "2004": 19041,
    "20h2": 19042,
    "21h1": 19043,
    "21h2": 19044,
    "22h2": 19045,
}

windows_11_kernel_versions = {
    "21h2": 22000,
    "22h2": 22631,
    "23h2": 22632,
}

structs_to_parse = {
    '_EPROCESS': [
        "ActiveProcessLinks",
        "SeAuditProcessCreationInfo",
        "VadRoot",
        "MitigationFlags2Values",
        "ThreadListHead",
        "Flags3"
    ],
    '_MMVAD': [
        "Subsection",
    ],
    '_CONTROL_AREA': [
        "Segment",
        "FilePointer"
    ],
    '_ETHREAD': [
        "ThreadListEntry",
    ],
    '_KTHREAD': [
        "Header",
        "TrapFrame"
    ],
}

base_url = "https://www.vergiliusproject.com/kernels/x64/windows-11"

def parse_structure_offsets(version, structure, members):
    url = f"{base_url}/{version}/{structure}"
    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        raw_text = soup.get_text()

        pattern = re.compile(rf"\b({'|'.join(map(re.escape, members))})\b.*?//0x([0-9a-fA-F]+)")

        matches = pattern.findall(raw_text)

        results = {name: f"0x{offset}" for name, offset in matches}
        return results
    else:
        print(f"Failed to retrieve data for {structure} on version {version}. Status code: {response.status_code}")
        return {}

def generate_switch_code():
    switch_code = "switch (versionInfo.dwBuildNumber) {\n\n"

    for version, build_number in windows_11_kernel_versions.items():
        switch_code += f"  case {build_number}: {{\n\n"

        for structure, members in structs_to_parse.items():
            offsets = parse_structure_offsets(version, structure, members)
            if offsets:
                for member, offset in offsets.items():
                    switch_code += f"    offsets->{member} = {offset};\n"
            else:
                switch_code += f"    // No offsets found for {structure}\n"

        switch_code += "    break;\n  }\n\n"

    switch_code += "  default: {\n    // Unsupported version\n  }\n\n"
    switch_code += "}\n\nreturn TRUE;"
    return switch_code

if __name__ == "__main__":
    print(generate_switch_code())
