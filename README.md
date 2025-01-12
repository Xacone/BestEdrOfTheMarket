
# <a href="https://xacone.github.io/BestEdrOfTheMarketV3.html"> Best EDR Of The Market (BEOTM) V3 🐲🏴‍☠️ </a>

<br>
<img src="Assets/beotm_banner.png">

Best Edr Of The Market is an open-source lab designed to implement and understand, from a low-level perspective, the detection methods used by Endpoints Detection & Response security products and their workarounds. These techniques are mainly based on the exploitation of Windows NT's telemetric capabilities to dynamically analyze process behavior.


<h2>Defensive Capabilities</h2>
This current version (v3) focuses on some of the interception capabilities offered by the Windows kernel. These include

- [x] <a href="#"> System Calls Interception via Alternative System Call Handlers  </a><br>
- [x] <a href="#"> 
Exploitation of the Virtual Address Descriptor (VAD) Tree for Image Integrity Checking  </a><br>
- [x] <a href="#"> Using kernel callbacks to capture events related to thread creation, process creation, image loading into memory, registry operations, and object operations. </a><br>
- [x] <a href="#"> Leverage of the Shadow Stack to Verify Thread Call Stacks Integrity </a><br>
- [x] <a href="#"> Code injection detection by validating the integrity of thread call stacks. </a><br>
- [x] <a href="#"> Integration of Yara rules for rapid pattern detection in memory buffers/files </a><br>
- [x] <a href="#"> Integrity checking of system calls </a><br>


Thus, this 3rd version makes it possible to detect a bunch of TTPs such as PPID Spoofing (<a href="https://attack.mitre.org/techniques/T1134/004/">T1134.004</a>), Credential Dumping (<a href="https://attack.mitre.org/techniques/T1003/001/">T1003.001</a>), process Hollowing/Ghosting/Tampering (<a href="https://attack.mitre.org/techniques/T1055/012/">T1055.012</a>), memory code injection (<a href="https://attack.mitre.org/techniques/T1055/">T1055</a>) methods including APC queuing (<a href="https://attack.mitre.org/techniques/T1055/004/">T1055.004</a>) & Thread Hijacking (<a href="https://attack.mitre.org/techniques/T1055/003/">T1055.003</a>), Abnormal System Calls (<a href="https://attack.mitre.org/techniques/T1106/">T1106</a>), Registry Persistence Operations (<a href="https://attack.mitre.org/techniques/T1547/001/">T1547.001</a>) and more...

<h2>Release Structure</h2>

```
📁 BEOTM
    ⚙️ beotm.sys
    📄 beotm.exe
    📁 protection-artifacts/
        📄 Metasploit_Artefacts_Rule.yara
        📄 Metasploit_Artefacts_Rule.yara
        ...
```

<h2>Usage</h2>

```
beotm.exe <path to driver> <path to Yara rules folder>
```

```
beotm.sys .\beotm.sys .\protection-artifacts
```

<h2>Building the Project</h2>

<h2>Issue Reporting</h2>

<h2>Disclaimer ⚠️</h2>


