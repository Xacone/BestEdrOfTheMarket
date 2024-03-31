rule Windows_Trojan_Metasploit_a6e956c9 {
    meta:
        author = "Elastic Security"
        id = "a6e956c9-799e-49f9-b5c5-ac68aaa2dc21"
        fingerprint = "21855599bc51ec2f71d694d4e0f866f815efe54a42842dfe5f8857811530a686"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies the API address lookup function leverage by metasploit shellcode"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF AC 3C 61 7C 02 2C 20 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_38b8ceec {
    meta:
        author = "Elastic Security"
        id = "38b8ceec-601c-4117-b7a0-74720e26bf38"
        fingerprint = "44b9022d87c409210b1d0807f5a4337d73f19559941660267d63cd2e4f2ff342"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies the API address lookup function used by metasploit. Also used by other tools (like beacon)."
        threat_name = "Windows.Trojan.Metasploit"
        severity = 85
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_7bc0f998 {
    meta:
        author = "Elastic Security"
        id = "7bc0f998-7014-4883-8a56-d5ee00c15aed"
        fingerprint = "fdb5c665503f07b2fc1ed7e4e688295e1222a500bfb68418661db60c8e75e835"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies the API address lookup function leverage by metasploit shellcode"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 84
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 48 8B 72 50 48 0F B7 4A 4A 4D 31 C9 48 31 C0 AC 3C 61 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_f7f826b4 {
    meta:
        author = "Elastic Security"
        id = "f7f826b4-6456-4819-bc0c-993aeeb7e325"
        fingerprint = "9b07dc54d5015d0f0d84064c5a989f94238609c8167cae7caca8665930a20f81"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies metasploit kernel->user shellcode. Likely used in ETERNALBLUE and BlueKeep exploits."
        threat_name = "Windows.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 92 31 C9 51 51 49 89 C9 4C 8D 05 0? 00 00 00 89 CA 48 83 EC 20 FF D0 48 83 C4 30 C3 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_24338919 {
    meta:
        author = "Elastic Security"
        id = "24338919-8efe-4cf2-a23a-a3f22095b42d"
        fingerprint = "ac76190a84c4bdbb6927c5ad84a40e2145ca9e76369a25ac2ffd727eefef4804"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies metasploit wininet reverse shellcode. Also used by other tools (like beacon)."
        threat_name = "Windows.Trojan.Metasploit"
        severity = 80
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_0f5a852d {
    meta:
        author = "Elastic Security"
        id = "0f5a852d-cacd-43d7-8754-204b09afba2f"
        fingerprint = "97daac4249e85a73d4e6a4450248e59e0d286d5e7c230cf32a38608f8333f00d"
        creation_date = "2021-04-07"
        last_modified = "2021-08-23"
        description = "Identifies 64 bit metasploit wininet reverse shellcode. May also be used by other malware families."
        threat_name = "Windows.Trojan.Metasploit"
        severity = 80
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 49 BE 77 69 6E 69 6E 65 74 00 41 56 48 89 E1 49 C7 C2 4C 77 26 07 FF D5 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_c9773203 {
    meta:
        author = "Elastic Security"
        id = "c9773203-6d1e-4246-a1e0-314217e0207a"
        fingerprint = "afde93eeb14b4d0c182f475a22430f101394938868741ffa06445e478b6ece36"
        creation_date = "2021-04-07"
        last_modified = "2021-08-23"
        description = "Identifies the 64 bit API hashing function used by Metasploit. This has been re-used by many other malware families."
        threat_name = "Windows.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/04e8752b9b74cbaad7cb0ea6129c90e3172580a2/external/source/shellcode/windows/x64/src/block/block_api.asm"
        severity = 10
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 31 C0 AC 41 C1 C9 0D 41 01 C1 38 E0 75 F1 4C 03 4C 24 08 45 39 D1 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_dd5ce989 {
    meta:
        author = "Elastic Security"
        id = "dd5ce989-3925-4e27-97c1-3b8927c557e9"
        fingerprint = "4fc7c309dca197f4626d6dba8afcd576e520dbe2a2dd6f7d38d7ba33ee371d55"
        creation_date = "2021-04-14"
        last_modified = "2021-08-23"
        description = "Identifies Meterpreter DLL used by Metasploit"
        threat_name = "Windows.Trojan.Metasploit"
        reference = "https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/"
        reference_sample = "86cf98bf854b01a55e3f306597437900e11d429ac6b7781e090eeda3a5acb360"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "metsrv.x64.dll" fullword
        $a2 = "metsrv.dll" fullword
        $b1 = "ReflectiveLoader"
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_Metasploit_96233b6b {
    meta:
        author = "Elastic Security"
        id = "96233b6b-d95a-4e0e-8f83-f2282a342087"
        fingerprint = "40032849674714bc9eb020971dd9f27a07b53b8ff953b793cb3aad136256fd70"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        description = "Identifies another 64 bit API hashing function used by Metasploit."
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "e7a2d966deea3a2df6ce1aeafa8c2caa753824215a8368e0a96b394fb46b753b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 31 FF 0F B7 4A 26 31 C0 AC 3C 61 7C 02 2C 20 C1 CF 0D }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_4a1c4da8 {
    meta:
        author = "Elastic Security"
        id = "4a1c4da8-837d-4ad1-a672-ddb8ba074936"
        fingerprint = "7a31ce858215f0a8732ce6314bfdbc3975f1321e3f87d7f4dc5a525f15766987"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        description = "Identifies Metasploit 64 bit reverse tcp shellcode."
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "9582d37ed9de522472abe615dedef69282a40cfd58185813c1215249c24bbf22"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 6A 10 56 57 68 99 A5 74 61 FF D5 85 C0 74 0A FF 4E 08 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_91bc5d7d {
    meta:
        author = "Elastic Security"
        id = "91bc5d7d-31e3-4c02-82b3-a685194981f3"
        fingerprint = "8848a3de66a25dd98278761a7953f31b7995e48621dec258f3d92bd91a4a3aa3"
        creation_date = "2021-08-02"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "0dd993ff3917dc56ef02324375165f0d66506c5a9b9548eda57c58e041030987"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 49 BE 77 73 32 5F 33 32 00 00 41 56 49 89 E6 48 81 EC A0 01 00 00 49 89 E5 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_a91a6571 {
    meta:
        author = "Elastic Security"
        id = "a91a6571-ae2d-4ab4-878b-38b455f42c01"
        fingerprint = "e372484956eab80e4bf58f4ae1031de705cb52eaefa463aa77af7085c463638d"
        creation_date = "2022-06-08"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "ff7795edff95a45b15b03d698cbdf70c19bc452daf4e2d5e86b2bbac55494472"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 51 56 65 48 8B 52 60 48 8B 52 18 48 8B 52 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_b29fe355 {
    meta:
        author = "Elastic Security"
        id = "b29fe355-b7f8-4325-bf06-7975585f3888"
        fingerprint = "a943325b7a227577ccd45748b4e705288c5b7d91d0e0b2a115daeea40e1a2148"
        creation_date = "2022-06-08"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "4f0ab4e42e6c10bc9e4a699d8d8819b04c17ed1917047f770dc6980a0a378a68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%04x-%04x:%s" fullword
        $a2 = "\\\\%s\\pipe\\%s" fullword
        $a3 = "PACKET TRANSMIT" fullword
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_66140f58 {
    meta:
        author = "Elastic Security"
        id = "66140f58-1815-4e21-8544-24fed74194f1"
        fingerprint = "79879b2730e98f3eddeca838dff438d75a43ac20c0da6a4802474ff05f9cc7a3"
        creation_date = "2022-08-15"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "01a0c5630fbbfc7043d21a789440fa9dadc6e4f79640b370f1a21c6ebf6a710a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 51 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_2092c42a {
    meta:
        author = "Elastic Security"
        id = "2092c42a-793b-4b0e-868b-9a39c926f44c"
        fingerprint = "4f17bfb02d3ac97e48449b6e30c9b07f604c13d5e12a99af322853c5d656ee88"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "e47d88c11a89dcc84257841de0c9f1ec388698006f55a0e15567354b33f07d3c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 65 6E 61 62 6C 65 5F 6B 65 79 62 6F 61 72 64 5F 69 6E 70 75 74 }
        $a2 = { 01 04 10 49 83 C2 02 4D 85 C9 75 9C 41 8B 43 04 4C 03 D8 48 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_46e1c247 {
    meta:
        author = "Elastic Security"
        id = "46e1c247-1ebb-434f-835f-faf421b35169"
        fingerprint = "6cd37d32976add38d7165f8088f38f4854b59302d6adf20db5c46cd3e8c7d9e7"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "ef70e1faa3b1f40d92b0a161c96e13c96c43ec6651e7c87ee3977ed07b950bab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 73 74 64 61 70 69 5F 66 73 5F 66 69 6C 65 }
        $a2 = { 85 D2 74 0E 8B F3 2B 75 F8 8A 01 88 04 0E 41 4A 75 F7 0F B7 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_b62aac1e {
    meta:
        author = "Elastic Security"
        id = "b62aac1e-2ce8-4803-90ee-138b509e814d"
        fingerprint = "58340ea67e2544d22adba3317350150c61c84fba1d16c7c9f8d0c626c3421296"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "af9af81f7e46217330b447900f80c9ce38171655becb3b63e51f913b95c71e70"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 42 3C 8B AC 10 88 00 00 00 44 8B 54 15 20 44 8B 5C 15 24 4C }
        $a2 = { CB 4D 85 D2 74 10 41 8A 00 4D 03 C3 88 02 49 03 D3 4D 2B D3 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_47f5d54a {
    meta:
        author = "Elastic Security"
        id = "47f5d54a-2578-4bbd-b157-8b225f6d34b3"
        fingerprint = "b6dbc1b273bc9a328d5c437d11db23e8f1d3bf764bb624aa4f552c14b3dc5260"
        creation_date = "2023-11-13"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "bc3754cf4a04491a7ad7a75f69dd3bb2ddf0d8592ce078b740d7c9c7bc85a7e1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a32 = { 89 45 F8 FF 15 [11] 8B D8 85 DB 74 76 6A 00 6A 04 6A 00 FF 35 [4] 6A 00 6A 00 FF 15 }
        $a64 = { 48 89 7C 24 48 FF 15 [4] 33 D2 44 8B C0 B9 40 00 10 00 FF 15 [4] 48 8B F8 48 85 C0 74 55 48 8B 15 [10] 4C 8B C0 48 8B CB 48 C7 44 24 20 }
    condition:
        any of them
}

