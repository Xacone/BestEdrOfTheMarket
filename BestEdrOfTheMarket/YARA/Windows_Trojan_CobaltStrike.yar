rule Windows_Trojan_CobaltStrike_c851687a {
    meta:
        author = "Elastic Security"
        id = "c851687a-aac6-43e7-a0b6-6aed36dcf12e"
        fingerprint = "70224e28a223d09f2211048936beb9e2d31c0312c97a80e22c85e445f1937c10"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies UAC Bypass module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "bypassuac.dll" ascii fullword
        $a2 = "bypassuac.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\bypassuac" ascii fullword
        $b1 = "\\System32\\sysprep\\sysprep.exe" wide fullword
        $b2 = "[-] Could not write temp DLL to '%S'" ascii fullword
        $b3 = "[*] Cleanup successful" ascii fullword
        $b4 = "\\System32\\cliconfg.exe" wide fullword
        $b5 = "\\System32\\eventvwr.exe" wide fullword
        $b6 = "[-] %S ran too long. Could not terminate the process." ascii fullword
        $b7 = "[*] Wrote hijack DLL to '%S'" ascii fullword
        $b8 = "\\System32\\sysprep\\" wide fullword
        $b9 = "[-] COM initialization failed." ascii fullword
        $b10 = "[-] Privileged file copy failed: %S" ascii fullword
        $b11 = "[-] Failed to start %S: %d" ascii fullword
        $b12 = "ReflectiveLoader"
        $b13 = "[-] '%S' exists in DLL hijack location." ascii fullword
        $b14 = "[-] Cleanup failed. Remove: %S" ascii fullword
        $b15 = "[+] %S ran and exited." ascii fullword
        $b16 = "[+] Privileged file copy success! %S" ascii fullword
    condition:
        2 of ($a*) or 10 of ($b*)
}

rule Windows_Trojan_CobaltStrike_0b58325e {
    meta:
        author = "Elastic Security"
        id = "0b58325e-2538-434d-9a2c-26e2c32db039"
        fingerprint = "8ecd5bdce925ae5d4f90cecb9bc8c3901b54ba1c899a33354bcf529eeb2485d4"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Keylogger module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "keylogger.dll" ascii fullword
        $a2 = "keylogger.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\keylogger" ascii fullword
        $a4 = "%cE=======%c" ascii fullword
        $a5 = "[unknown: %02X]" ascii fullword
        $b1 = "ReflectiveLoader"
        $b2 = "%c2%s%c" ascii fullword
        $b3 = "[numlock]" ascii fullword
        $b4 = "%cC%s" ascii fullword
        $b5 = "[backspace]" ascii fullword
        $b6 = "[scroll lock]" ascii fullword
        $b7 = "[control]" ascii fullword
        $b8 = "[left]" ascii fullword
        $b9 = "[page up]" ascii fullword
        $b10 = "[page down]" ascii fullword
        $b11 = "[prtscr]" ascii fullword
        $b12 = "ZRich9" ascii fullword
        $b13 = "[ctrl]" ascii fullword
        $b14 = "[home]" ascii fullword
        $b15 = "[pause]" ascii fullword
        $b16 = "[clear]" ascii fullword
    condition:
        1 of ($a*) and 14 of ($b*)
}

rule Windows_Trojan_CobaltStrike_2b8cddf8 {
    meta:
        author = "Elastic Security"
        id = "2b8cddf8-ca7a-4f85-be9d-6d8534d0482e"
        fingerprint = "0d7d28d79004ca61b0cfdcda29bd95e3333e6fc6e6646a3f6ba058aa01bee188"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies dll load module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x86.o" ascii fullword
        $b1 = "__imp_BeaconErrorDD" ascii fullword
        $b2 = "__imp_BeaconErrorNA" ascii fullword
        $b3 = "__imp_BeaconErrorD" ascii fullword
        $b4 = "__imp_BeaconDataInt" ascii fullword
        $b5 = "__imp_KERNEL32$WriteProcessMemory" ascii fullword
        $b6 = "__imp_KERNEL32$OpenProcess" ascii fullword
        $b7 = "__imp_KERNEL32$CreateRemoteThread" ascii fullword
        $b8 = "__imp_KERNEL32$VirtualAllocEx" ascii fullword
        $c1 = "__imp__BeaconErrorDD" ascii fullword
        $c2 = "__imp__BeaconErrorNA" ascii fullword
        $c3 = "__imp__BeaconErrorD" ascii fullword
        $c4 = "__imp__BeaconDataInt" ascii fullword
        $c5 = "__imp__KERNEL32$WriteProcessMemory" ascii fullword
        $c6 = "__imp__KERNEL32$OpenProcess" ascii fullword
        $c7 = "__imp__KERNEL32$CreateRemoteThread" ascii fullword
        $c8 = "__imp__KERNEL32$VirtualAllocEx" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59b44767 {
    meta:
        author = "Elastic Security"
        id = "59b44767-c9a5-42c0-b177-7fe49afd7dfb"
        fingerprint = "882886a282ec78623a0d3096be3d324a8a1b8a23bcb88ea0548df2fae5e27aa5"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies getsystem module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x86.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x64.o" ascii fullword
        $b1 = "getsystem failed." ascii fullword
        $b2 = "_isSystemSID" ascii fullword
        $b3 = "__imp__NTDLL$NtQuerySystemInformation@16" ascii fullword
        $c1 = "getsystem failed." ascii fullword
        $c2 = "$pdata$isSystemSID" ascii fullword
        $c3 = "$unwind$isSystemSID" ascii fullword
        $c4 = "__imp_NTDLL$NtQuerySystemInformation" ascii fullword
    condition:
        1 of ($a*) or 3 of ($b*) or 3 of ($c*)
}

rule Windows_Trojan_CobaltStrike_7efd3c3f {
    meta:
        author = "Elastic Security"
        id = "7efd3c3f-1104-4b46-9d1e-dc2c62381b8c"
        fingerprint = "9e7c7c9a7436f5ee4c27fd46d6f06e7c88f4e4d1166759573cedc3ed666e1838"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Hashdump module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 70
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "hashdump.dll" ascii fullword
        $a2 = "hashdump.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\hashdump" ascii fullword
        $a4 = "ReflectiveLoader"
        $a5 = "Global\\SAM" ascii fullword
        $a6 = "Global\\FREE" ascii fullword
        $a7 = "[-] no results." ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_CobaltStrike_6e971281 {
    meta:
        author = "Elastic Security"
        id = "6e971281-3ee3-402f-8a72-745ec8fb91fb"
        fingerprint = "62d97cf73618a1b4d773d5494b2761714be53d5cda774f9a96eaa512c8d5da12"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Interfaces module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x86.o" ascii fullword
        $b1 = "__imp_BeaconFormatAlloc" ascii fullword
        $b2 = "__imp_BeaconFormatPrintf" ascii fullword
        $b3 = "__imp_BeaconOutput" ascii fullword
        $b4 = "__imp_KERNEL32$LocalAlloc" ascii fullword
        $b5 = "__imp_KERNEL32$LocalFree" ascii fullword
        $b6 = "__imp_LoadLibraryA" ascii fullword
        $c1 = "__imp__BeaconFormatAlloc" ascii fullword
        $c2 = "__imp__BeaconFormatPrintf" ascii fullword
        $c3 = "__imp__BeaconOutput" ascii fullword
        $c4 = "__imp__KERNEL32$LocalAlloc" ascii fullword
        $c5 = "__imp__KERNEL32$LocalFree" ascii fullword
        $c6 = "__imp__LoadLibraryA" ascii fullword
    condition:
        1 of ($a*) or 4 of ($b*) or 4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_09b79efa {
    meta:
        author = "Elastic Security"
        id = "09b79efa-55d7-481d-9ee0-74ac5f787cef"
        fingerprint = "04ef6555e8668c56c528dc62184331a6562f47652c73de732e5f7c82779f2fd8"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Invoke Assembly module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "invokeassembly.x64.dll" ascii fullword
        $a2 = "invokeassembly.dll" ascii fullword
        $b1 = "[-] Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $b2 = "[-] Failed to load the assembly w/hr 0x%08lx" ascii fullword
        $b3 = "[-] Failed to create the runtime host" ascii fullword
        $b4 = "[-] Invoke_3 on EntryPoint failed." ascii fullword
        $b5 = "[-] CLR failed to start w/hr 0x%08lx" ascii fullword
        $b6 = "ReflectiveLoader"
        $b7 = ".NET runtime [ver %S] cannot be loaded" ascii fullword
        $b8 = "[-] No .NET runtime found. :(" ascii fullword
        $b9 = "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }
    condition:
        1 of ($a*) or 3 of ($b*) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_6e77233e {
    meta:
        author = "Elastic Security"
        id = "6e77233e-7fb4-4295-823d-f97786c5d9c4"
        fingerprint = "cef2949eae78b1c321c2ec4010749a5ac0551d680bd5eb85493fc88c5227d285"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Kerberos module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x64.o" ascii fullword
        $a2 = "$unwind$command_kerberos_ticket_use" ascii fullword
        $a3 = "$pdata$command_kerberos_ticket_use" ascii fullword
        $a4 = "command_kerberos_ticket_use" ascii fullword
        $a5 = "$pdata$command_kerberos_ticket_purge" ascii fullword
        $a6 = "command_kerberos_ticket_purge" ascii fullword
        $a7 = "$unwind$command_kerberos_ticket_purge" ascii fullword
        $a8 = "$unwind$kerberos_init" ascii fullword
        $a9 = "$unwind$KerberosTicketUse" ascii fullword
        $a10 = "KerberosTicketUse" ascii fullword
        $a11 = "$unwind$KerberosTicketPurge" ascii fullword
        $b1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x86.o" ascii fullword
        $b2 = "_command_kerberos_ticket_use" ascii fullword
        $b3 = "_command_kerberos_ticket_purge" ascii fullword
        $b4 = "_kerberos_init" ascii fullword
        $b5 = "_KerberosTicketUse" ascii fullword
        $b6 = "_KerberosTicketPurge" ascii fullword
        $b7 = "_LsaCallKerberosPackage" ascii fullword
    condition:
        5 of ($a*) or 3 of ($b*)
}

rule Windows_Trojan_CobaltStrike_de42495a {
    meta:
        author = "Elastic Security"
        id = "de42495a-0002-466e-98b9-19c9ebb9240e"
        fingerprint = "dab3c25809ec3af70df5a8a04a2efd4e8ecb13a4c87001ea699e7a1512973b82"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Mimikatz module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\\\.\\pipe\\mimikatz" ascii fullword
        $b1 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
        $b2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" wide fullword
        $b3 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" wide fullword
        $b4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" wide fullword
        $b5 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" wide fullword
        $b6 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" wide fullword
        $b7 = "mimikatz(powershell) # %s" wide fullword
        $b8 = "powershell_reflective_mimikatz" ascii fullword
        $b9 = "mimikatz_dpapi_cache.ndr" wide fullword
        $b10 = "mimikatz.log" wide fullword
        $b11 = "ERROR mimikatz_doLocal" wide
        $b12 = "mimikatz_x64.compressed" wide
    condition:
        1 of ($a*) and 7 of ($b*)
}

rule Windows_Trojan_CobaltStrike_72f68375 {
    meta:
        author = "Elastic Security"
        id = "72f68375-35ab-49cc-905d-15302389a236"
        fingerprint = "ecc28f414b2c347722b681589da8529c6f3af0491845453874f8fd87c2ae86d7"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Netdomain module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x86.o" ascii fullword
        $b1 = "__imp_BeaconPrintf" ascii fullword
        $b2 = "__imp_NETAPI32$NetApiBufferFree" ascii fullword
        $b3 = "__imp_NETAPI32$DsGetDcNameA" ascii fullword
        $c1 = "__imp__BeaconPrintf" ascii fullword
        $c2 = "__imp__NETAPI32$NetApiBufferFree" ascii fullword
        $c3 = "__imp__NETAPI32$DsGetDcNameA" ascii fullword
    condition:
        1 of ($a*) or 2 of ($b*) or 2 of ($c*)
}

rule Windows_Trojan_CobaltStrike_15f680fb {
    meta:
        author = "Elastic Security"
        id = "15f680fb-a04f-472d-a182-0b9bee111351"
        fingerprint = "0ecb8e41c01bf97d6dea4cf6456b769c6dd2a037b37d754f38580bcf561e1d2c"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Netview module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "netview.x64.dll" ascii fullword
        $a2 = "netview.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\netview" ascii fullword
        $b1 = "Sessions for \\\\%s:" ascii fullword
        $b2 = "Account information for %s on \\\\%s:" ascii fullword
        $b3 = "Users for \\\\%s:" ascii fullword
        $b4 = "Shares at \\\\%s:" ascii fullword
        $b5 = "ReflectiveLoader" ascii fullword
        $b6 = "Password changeable" ascii fullword
        $b7 = "User's Comment" wide fullword
        $b8 = "List of hosts for domain '%s':" ascii fullword
        $b9 = "Password changeable" ascii fullword
        $b10 = "Logged on users at \\\\%s:" ascii fullword
    condition:
        2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_5b4383ec {
    meta:
        author = "Elastic Security"
        id = "5b4383ec-3c93-4e91-850e-d43cc3a86710"
        fingerprint = "283d3d2924e92b31f26ec4fc6b79c51bd652fb1377b6985b003f09f8c3dba66c"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Portscan module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "portscan.x64.dll" ascii fullword
        $a2 = "portscan.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\portscan" ascii fullword
        $b1 = "(ICMP) Target '%s' is alive. [read %d bytes]" ascii fullword
        $b2 = "(ARP) Target '%s' is alive. " ascii fullword
        $b3 = "TARGETS!12345" ascii fullword
        $b4 = "ReflectiveLoader" ascii fullword
        $b5 = "%s:%d (platform: %d version: %d.%d name: %S domain: %S)" ascii fullword
        $b6 = "Scanner module is complete" ascii fullword
        $b7 = "pingpong" ascii fullword
        $b8 = "PORTS!12345" ascii fullword
        $b9 = "%s:%d (%s)" ascii fullword
        $b10 = "PREFERENCES!12345" ascii fullword
    condition:
        2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_91e08059 {
    meta:
        author = "Elastic Security"
        id = "91e08059-46a8-47d0-91c9-e86874951a4a"
        fingerprint = "d8baacb58a3db00489827275ad6a2d007c018eaecbce469356b068d8a758634b"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Post Ex module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "postex.x64.dll" ascii fullword
        $a2 = "postex.dll" ascii fullword
        $a3 = "RunAsAdminCMSTP" ascii fullword
        $a4 = "KerberosTicketPurge" ascii fullword
        $b1 = "GetSystem" ascii fullword
        $b2 = "HelloWorld" ascii fullword
        $b3 = "KerberosTicketUse" ascii fullword
        $b4 = "SpawnAsAdmin" ascii fullword
        $b5 = "RunAsAdmin" ascii fullword
        $b6 = "NetDomain" ascii fullword
    condition:
        2 of ($a*) or 4 of ($b*)
}

rule Windows_Trojan_CobaltStrike_ee756db7 {
    meta:
        author = "Elastic Security"
        id = "ee756db7-e177-41f0-af99-c44646d334f7"
        fingerprint = "e589cc259644bc75d6c4db02a624c978e855201cf851c0d87f0d54685ce68f71"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Attempts to detect Cobalt Strike based on strings found in BEACON"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a2 = "%s.3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a3 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." ascii fullword
        $a4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" ascii fullword
        $a5 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii fullword
        $a6 = "%s.2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a7 = "could not run command (w/ token) because of its length of %d bytes!" ascii fullword
        $a8 = "%s.2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a9 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a10 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii fullword
        $a11 = "Could not open service control manager on %s: %d" ascii fullword
        $a12 = "%d is an x64 process (can't inject x86 content)" ascii fullword
        $a13 = "%d is an x86 process (can't inject x64 content)" ascii fullword
        $a14 = "Failed to impersonate logged on user %d (%u)" ascii fullword
        $a15 = "could not create remote thread in %d: %d" ascii fullword
        $a16 = "%s.1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a17 = "could not write to process memory: %d" ascii fullword
        $a18 = "Could not create service %s on %s: %d" ascii fullword
        $a19 = "Could not delete service %s on %s: %d" ascii fullword
        $a20 = "Could not open process token: %d (%u)" ascii fullword
        $a21 = "%s.1%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a22 = "Could not start service %s on %s: %d" ascii fullword
        $a23 = "Could not query service %s on %s: %d" ascii fullword
        $a24 = "Could not connect to pipe (%s): %d" ascii fullword
        $a25 = "%s.1%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a26 = "could not spawn %s (token): %d" ascii fullword
        $a27 = "could not open process %d: %d" ascii fullword
        $a28 = "could not run %s as %s\\%s: %d" ascii fullword
        $a29 = "%s.1%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a30 = "kerberos ticket use failed:" ascii fullword
        $a31 = "Started service %s on %s" ascii fullword
        $a32 = "%s.1%08x%08x%08x.%x%x.%s" ascii fullword
        $a33 = "I'm already in SMB mode" ascii fullword
        $a34 = "could not spawn %s: %d" ascii fullword
        $a35 = "could not open %s: %d" ascii fullword
        $a36 = "%s.1%08x%08x.%x%x.%s" ascii fullword
        $a37 = "Could not open '%s'" ascii fullword
        $a38 = "%s.1%08x.%x%x.%s" ascii fullword
        $a39 = "%s as %s\\%s: %d" ascii fullword
        $a40 = "%s.1%x.%x%x.%s" ascii fullword
        $a41 = "beacon.x64.dll" ascii fullword
        $a42 = "%s on %s: %d" ascii fullword
        $a43 = "www6.%x%x.%s" ascii fullword
        $a44 = "cdn.%x%x.%s" ascii fullword
        $a45 = "api.%x%x.%s" ascii fullword
        $a46 = "%s (admin)" ascii fullword
        $a47 = "beacon.dll" ascii fullword
        $a48 = "%s%s: %s" ascii fullword
        $a49 = "@%d.%s" ascii fullword
        $a50 = "%02d/%02d/%02d %02d:%02d:%02d" ascii fullword
        $a51 = "Content-Length: %d" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_CobaltStrike_9c0d5561 {
    meta:
        author = "Elastic Security"
        id = "9c0d5561-5b09-44ae-8e8c-336dee606199"
        fingerprint = "01d53fcdb320f0cd468a2521c3e96dcb0b9aa00e7a7a9442069773c6b3759059"
        creation_date = "2021-03-23"
        last_modified = "2021-10-04"
        description = "Identifies PowerShell Runner module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PowerShellRunner.dll" wide fullword
        $a2 = "powershell.x64.dll" ascii fullword
        $a3 = "powershell.dll" ascii fullword
        $a4 = "\\\\.\\pipe\\powershell" ascii fullword
        $b1 = "PowerShellRunner.PowerShellRunner" ascii fullword
        $b2 = "Failed to invoke GetOutput w/hr 0x%08lx" ascii fullword
        $b3 = "Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $b4 = "ICLRMetaHost::GetRuntime (v4.0.30319) failed w/hr 0x%08lx" ascii fullword
        $b5 = "CustomPSHostUserInterface" ascii fullword
        $b6 = "RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x%08lx" ascii fullword
        $b7 = "ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $c1 = { 8B 08 50 FF 51 08 8B 7C 24 1C 8D 4C 24 10 51 C7 }
        $c2 = "z:\\devcenter\\aggressor\\external\\PowerShellRunner\\obj\\Release\\PowerShellRunner.pdb" ascii fullword
    condition:
        (1 of ($a*) and 4 of ($b*)) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59ed9124 {
    meta:
        author = "Elastic Security"
        id = "59ed9124-bc20-4ea6-b0a7-63ee3359e69c"
        fingerprint = "7823e3b98e55a83bf94b0f07e4c116dbbda35adc09fa0b367f8a978a80c2efff"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies PsExec module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x86.o" ascii fullword
        $b1 = "__imp_BeaconDataExtract" ascii fullword
        $b2 = "__imp_BeaconDataParse" ascii fullword
        $b3 = "__imp_BeaconDataParse" ascii fullword
        $b4 = "__imp_BeaconDataParse" ascii fullword
        $b5 = "__imp_ADVAPI32$StartServiceA" ascii fullword
        $b6 = "__imp_ADVAPI32$DeleteService" ascii fullword
        $b7 = "__imp_ADVAPI32$QueryServiceStatus" ascii fullword
        $b8 = "__imp_ADVAPI32$CloseServiceHandle" ascii fullword
        $c1 = "__imp__BeaconDataExtract" ascii fullword
        $c2 = "__imp__BeaconDataParse" ascii fullword
        $c3 = "__imp__BeaconDataParse" ascii fullword
        $c4 = "__imp__BeaconDataParse" ascii fullword
        $c5 = "__imp__ADVAPI32$StartServiceA" ascii fullword
        $c6 = "__imp__ADVAPI32$DeleteService" ascii fullword
        $c7 = "__imp__ADVAPI32$QueryServiceStatus" ascii fullword
        $c8 = "__imp__ADVAPI32$CloseServiceHandle" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_8a791eb7 {
    meta:
        author = "Elastic Security"
        id = "8a791eb7-dc0c-4150-9e5b-2dc21af0c77d"
        fingerprint = "4967886ba5e663f2e2dc0631939308d7d8f2194a30590a230973e1b91bd625e1"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Registry module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x86.o" ascii fullword
        $b1 = "__imp_ADVAPI32$RegOpenKeyExA" ascii fullword
        $b2 = "__imp_ADVAPI32$RegEnumKeyA" ascii fullword
        $b3 = "__imp_ADVAPI32$RegOpenCurrentUser" ascii fullword
        $b4 = "__imp_ADVAPI32$RegCloseKey" ascii fullword
        $b5 = "__imp_BeaconFormatAlloc" ascii fullword
        $b6 = "__imp_BeaconOutput" ascii fullword
        $b7 = "__imp_BeaconFormatFree" ascii fullword
        $b8 = "__imp_BeaconDataPtr" ascii fullword
        $c1 = "__imp__ADVAPI32$RegOpenKeyExA" ascii fullword
        $c2 = "__imp__ADVAPI32$RegEnumKeyA" ascii fullword
        $c3 = "__imp__ADVAPI32$RegOpenCurrentUser" ascii fullword
        $c4 = "__imp__ADVAPI32$RegCloseKey" ascii fullword
        $c5 = "__imp__BeaconFormatAlloc" ascii fullword
        $c6 = "__imp__BeaconOutput" ascii fullword
        $c7 = "__imp__BeaconFormatFree" ascii fullword
        $c8 = "__imp__BeaconDataPtr" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_d00573a3 {
    meta:
        author = "Elastic Security"
        id = "d00573a3-db26-4e6b-aabf-7af4a818f383"
        fingerprint = "b6fa0792b99ea55f359858d225685647f54b55caabe53f58b413083b8ad60e79"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Screenshot module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "screenshot.x64.dll" ascii fullword
        $a2 = "screenshot.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\screenshot" ascii fullword
        $b1 = "1I1n1Q3M5Q5U5Y5]5a5e5i5u5{5" ascii fullword
        $b2 = "GetDesktopWindow" ascii fullword
        $b3 = "CreateCompatibleBitmap" ascii fullword
        $b4 = "GDI32.dll" ascii fullword
        $b5 = "ReflectiveLoader"
        $b6 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii fullword
    condition:
        2 of ($a*) or 5 of ($b*)
}

rule Windows_Trojan_CobaltStrike_7bcd759c {
    meta:
        author = "Elastic Security"
        id = "7bcd759c-8e3d-4559-9381-1f4fe8b3dd95"
        fingerprint = "553085f1d1ca8dcd797360b287951845753eee7370610a1223c815a200a5ed20"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies SSH Agent module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "sshagent.x64.dll" ascii fullword
        $a2 = "sshagent.dll" ascii fullword
        $b1 = "\\\\.\\pipe\\sshagent" ascii fullword
        $b2 = "\\\\.\\pipe\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii fullword
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_CobaltStrike_a56b820f {
    meta:
        author = "Elastic Security"
        id = "a56b820f-0a20-4054-9c2d-008862646a78"
        fingerprint = "5418e695bcb1c37e72a7ff24a39219dc12b3fe06c29cedefd500c5e82c362b6d"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Timestomp module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x86.o" ascii fullword
        $b1 = "__imp_KERNEL32$GetFileTime" ascii fullword
        $b2 = "__imp_KERNEL32$SetFileTime" ascii fullword
        $b3 = "__imp_KERNEL32$CloseHandle" ascii fullword
        $b4 = "__imp_KERNEL32$CreateFileA" ascii fullword
        $b5 = "__imp_BeaconDataExtract" ascii fullword
        $b6 = "__imp_BeaconPrintf" ascii fullword
        $b7 = "__imp_BeaconDataParse" ascii fullword
        $b8 = "__imp_BeaconDataExtract" ascii fullword
        $c1 = "__imp__KERNEL32$GetFileTime" ascii fullword
        $c2 = "__imp__KERNEL32$SetFileTime" ascii fullword
        $c3 = "__imp__KERNEL32$CloseHandle" ascii fullword
        $c4 = "__imp__KERNEL32$CreateFileA" ascii fullword
        $c5 = "__imp__BeaconDataExtract" ascii fullword
        $c6 = "__imp__BeaconPrintf" ascii fullword
        $c7 = "__imp__BeaconDataParse" ascii fullword
        $c8 = "__imp__BeaconDataExtract" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_92f05172 {
    meta:
        author = "Elastic Security"
        id = "92f05172-f15c-4077-a958-b8490378bf08"
        fingerprint = "09b1f7087d45fb4247a33ae3112910bf5426ed750e1e8fe7ba24a9047b76cc82"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies UAC cmstp module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x86.o" ascii fullword
        $b1 = "elevate_cmstp" ascii fullword
        $b2 = "$pdata$elevate_cmstp" ascii fullword
        $b3 = "$unwind$elevate_cmstp" ascii fullword
        $c1 = "_elevate_cmstp" ascii fullword
        $c2 = "__imp__OLE32$CoGetObject@16" ascii fullword
        $c3 = "__imp__KERNEL32$GetModuleFileNameA@12" ascii fullword
        $c4 = "__imp__KERNEL32$GetSystemWindowsDirectoryA@8" ascii fullword
        $c5 = "OLDNAMES"
        $c6 = "__imp__BeaconDataParse" ascii fullword
        $c7 = "_willAutoElevate" ascii fullword
    condition:
        1 of ($a*) or 3 of ($b*) or 4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_417239b5 {
    meta:
        author = "Elastic Security"
        id = "417239b5-cf2d-4c85-a022-7a8459c26793"
        fingerprint = "292afee829e838f9623547f94d0561e8a9115ce7f4c40ae96c6493f3cc5ffa9b"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies UAC token module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x86.o" ascii fullword
        $a3 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x64.o" ascii fullword
        $a4 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x86.o" ascii fullword
        $b1 = "$pdata$is_admin_already" ascii fullword
        $b2 = "$unwind$is_admin" ascii fullword
        $b3 = "$pdata$is_admin" ascii fullword
        $b4 = "$unwind$is_admin_already" ascii fullword
        $b5 = "$pdata$RunAsAdmin" ascii fullword
        $b6 = "$unwind$RunAsAdmin" ascii fullword
        $b7 = "is_admin_already" ascii fullword
        $b8 = "is_admin" ascii fullword
        $b9 = "process_walk" ascii fullword
        $b10 = "get_current_sess" ascii fullword
        $b11 = "elevate_try" ascii fullword
        $b12 = "RunAsAdmin" ascii fullword
        $b13 = "is_ctfmon" ascii fullword
        $c1 = "_is_admin_already" ascii fullword
        $c2 = "_is_admin" ascii fullword
        $c3 = "_process_walk" ascii fullword
        $c4 = "_get_current_sess" ascii fullword
        $c5 = "_elevate_try" ascii fullword
        $c6 = "_RunAsAdmin" ascii fullword
        $c7 = "_is_ctfmon" ascii fullword
        $c8 = "_reg_query_dword" ascii fullword
        $c9 = ".drectve" ascii fullword
        $c10 = "_is_candidate" ascii fullword
        $c11 = "_SpawnAsAdmin" ascii fullword
        $c12 = "_SpawnAsAdminX64" ascii fullword
    condition:
        1 of ($a*) or 9 of ($b*) or 7 of ($c*)
}

rule Windows_Trojan_CobaltStrike_29374056 {
    meta:
        author = "Elastic Security"
        id = "29374056-03ce-484b-8b2d-fbf75be86e27"
        fingerprint = "4cd7552a499687ac0279fb2e25722f979fc5a22afd1ea4abba14a2ef2002dd0f"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Cobalt Strike MZ Reflective Loader."
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
        $a2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_949f10e3 {
    meta:
        author = "Elastic Security"
        id = "949f10e3-68c9-4600-a620-ed3119e09257"
        fingerprint = "34e04901126a91c866ebf61a61ccbc3ce0477d9614479c42d8ce97a98f2ce2a7"
        creation_date = "2021-03-25"
        last_modified = "2021-08-23"
        description = "Identifies the API address lookup function used by Cobalt Strike along with XOR implementation by Cobalt Strike."
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
        $a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_8751cdf9 {
    meta:
        author = "Elastic Security"
        id = "8751cdf9-4038-42ba-a6eb-f8ac579a4fbb"
        fingerprint = "0988386ef4ba54dd90b0cf6d6a600b38db434e00e569d69d081919cdd3ea4d3f"
        creation_date = "2021-03-25"
        last_modified = "2021-08-23"
        description = "Identifies Cobalt Strike wininet reverse shellcode along with XOR implementation by Cobalt Strike."
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 99
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
        $a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_663fc95d {
    meta:
        author = "Elastic Security"
        id = "663fc95d-2472-4d52-ad75-c5d86cfc885f"
        fingerprint = "d0f781d7e485a7ecfbbfd068601e72430d57ef80fc92a993033deb1ddcee5c48"
        creation_date = "2021-04-01"
        last_modified = "2021-12-17"
        description = "Identifies CobaltStrike via unidentified function code"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_b54b94ac {
    meta:
        author = "Elastic Security"
        id = "b54b94ac-6ef8-4ee9-a8a6-f7324c1974ca"
        fingerprint = "2344dd7820656f18cfb774a89d89f5ab65d46cc7761c1f16b7e768df66aa41c8"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon sleep obfuscation routine"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a_x64 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
        $a_x64_smbtcp = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
        $a_x86 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
        $a_x86_2 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
        $a_x86_smbtcp = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_f0b627fc {
    meta:
        author = "Elastic Security"
        id = "f0b627fc-97cd-42cb-9eae-1efb0672762d"
        fingerprint = "fbc94bedd50b5b943553dd438a183a1e763c098a385ac3a4fc9ff24ee30f91e1"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon reflective loader"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "b362951abd9d96d5ec15d281682fa1c8fe8f8e4e2f264ca86f6b061af607f79b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $beacon_loader_x64 = { 25 FF FF FF 00 3D 41 41 41 00 75 [5-10] 25 FF FF FF 00 3D 42 42 42 00 75 }
        $beacon_loader_x86 = { 25 FF FF FF 00 3D 41 41 41 00 75 [4-8] 81 E1 FF FF FF 00 81 F9 42 42 42 00 75 }
        $beacon_loader_x86_2 = { 81 E1 FF FF FF 00 81 F9 41 41 41 00 75 [4-8] 81 E2 FF FF FF 00 81 FA 42 42 42 00 75 }
        $generic_loader_x64 = { 89 44 24 20 48 8B 44 24 40 0F BE 00 8B 4C 24 20 03 C8 8B C1 89 44 24 20 48 8B 44 24 40 48 FF C0 }
        $generic_loader_x86 = { 83 C4 04 89 45 FC 8B 4D 08 0F BE 11 03 55 FC 89 55 FC 8B 45 08 83 C0 01 89 45 08 8B 4D 08 0F BE }
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_dcdcdd8c {
    meta:
        author = "Elastic Security"
        id = "dcdcdd8c-7395-4453-a74a-60ab8e251a5a"
        fingerprint = "8aed1ae470d06a7aac37896df22b2f915c36845099839a85009212d9051f71e9"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon sleep PDB"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x86.o" ascii fullword
        $a3 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x64.o" ascii fullword
        $a4 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x86.o" ascii fullword
        $a5 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x64.o" ascii fullword
        $a6 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x86.o" ascii fullword
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_a3fb2616 {
    meta:
        author = "Elastic Security"
        id = "a3fb2616-b03d-4399-9342-0fc684fb472e"
        fingerprint = "c15cf6aa7719dac6ed21c10117f28eb4ec56335f80a811b11ab2901ad36f8cf0"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for browser pivot "
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "browserpivot.dll" ascii fullword
        $a2 = "browserpivot.x64.dll" ascii fullword
        $b1 = "$$$THREAD.C$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" ascii fullword
        $b2 = "COBALTSTRIKE" ascii fullword
    condition:
        1 of ($a*) and 2 of ($b*)
}

rule Windows_Trojan_CobaltStrike_8ee55ee5 {
    meta:
        author = "Elastic Security"
        id = "8ee55ee5-67f1-4f94-ab93-62bb5cfbeee9"
        fingerprint = "7e7ed4f00d0914ce0b9f77b6362742a9c8b93a16a6b2a62b70f0f7e15ba3a72b"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for wmi exec module"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x64.o" ascii fullword
        $a2 = "z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x86.o" ascii fullword
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_8d5963a2 {
    meta:
        author = "Elastic Security"
        id = "8d5963a2-54a9-4705-9f34-0d5f8e6345a2"
        fingerprint = "228cd65380cf4b04f9fd78e8c30c3352f649ce726202e2dac9f1a96211925e1c"
        creation_date = "2022-08-10"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "9fe43996a5c4e99aff6e2a1be743fedec35e96d1e6670579beb4f7e7ad591af9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D8 48 81 EC 28 01 00 00 45 33 F6 48 8B D9 48 }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_1787eef5 {
    meta:
        author = "Elastic Security"
        id = "1787eef5-ff00-4e19-bd22-c5dfc9488c7b"
        fingerprint = "292f15bdc978fc29670126f1bdc72ade1e7faaf1948653f70b6789a82dbee67f"
        creation_date = "2022-08-29"
        last_modified = "2022-09-29"
        description = "CS shellcode variants"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 31 C0 C9 C3 55 }
        $a2 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 31 C0 C9 C3 55 89 E5 83 EC ?? 83 7D ?? ?? }
        $a3 = { 55 89 E5 8B 45 ?? 5D FF E0 55 8B 15 ?? ?? ?? ?? 89 E5 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $a4 = { 55 89 E5 8B 45 ?? 5D FF E0 55 89 E5 83 EC ?? 8B 15 ?? ?? ?? ?? 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $a5 = { 4D 5A 41 52 55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ?? 48 89 DF 48 81 C3 ?? ?? ?? ?? }
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_4106070a {
    meta:
        author = "Elastic Security"
        id = "4106070a-24e2-421b-ab83-67b817a9f019"
        fingerprint = "c12b919064a9cd2a603c134c5f73f6d05ffbf4cbed1e5b5246687378102e4338"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "98789a11c06c1dfff7e02f66146afca597233c17e0d4900d6a683a150f16b3a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 8B 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 }
        $a2 = { 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 F8 0A }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_3dc22d14 {
    meta:
        author = "Elastic Security"
        id = "3dc22d14-a2f4-49cd-a3a8-3f071eddf028"
        fingerprint = "0e029fac50ffe8ea3fc5bc22290af69e672895eaa8a1b9f3e9953094c133392c"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "7898194ae0244611117ec948eb0b0a5acbc15cd1419b1ecc553404e63bc519f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
        $a2 = "%s as %s\\%s: %d" fullword
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_7f8da98a {
    meta:
        author = "Elastic Security"
        id = "7f8da98a-3336-482b-91da-82c7cef34c62"
        fingerprint = "c375492960a6277bf665bea86302cec774c0d79506e5cb2e456ce59f5e68aa2e"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "e3bc2bec4a55ad6cfdf49e5dbd4657fc704af1758ca1d6e31b83dcfb8bf0f89d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4D 53 53 45 2D 25 64 2D 73 65 72 76 65 72 }
    condition:
        all of them
}

