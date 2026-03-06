/*
 * WRAITH Bundled YARA Rules - Generic Threat Detection
 * Sources: Public domain / community contributed
 * Covers: PowerShell evasion, process injection, RAT patterns,
 *         npm supply chain attacks, suspicious installers
 */

rule WRAITH_PowerShell_EncodedCommand
{
    meta:
        description = "Detects PowerShell with encoded command (common evasion)"
        severity = "HIGH"
        author = "WRAITH"
    strings:
        $e1 = "-EncodedCommand" nocase
        $e2 = "-enc " nocase
        $e3 = "-e " nocase wide ascii
        $ps = "powershell" nocase
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/ ascii
    condition:
        $ps and ($e1 or $e2 or $e3) and $b64
}

rule WRAITH_PowerShell_DownloadCradle
{
    meta:
        description = "Detects PowerShell download-and-execute (common dropper pattern)"
        severity = "CRITICAL"
        author = "WRAITH"
    strings:
        $d1 = "DownloadString" nocase
        $d2 = "DownloadFile" nocase
        $d3 = "WebClient" nocase
        $d4 = "Net.WebRequest" nocase
        $iex = "Invoke-Expression" nocase
        $iex2 = "IEX(" nocase
        $iex3 = "IEX (" nocase
    condition:
        ($d1 or $d2 or $d3 or $d4) and ($iex or $iex2 or $iex3)
}

rule WRAITH_PowerShell_HiddenExecution
{
    meta:
        description = "Detects PowerShell hidden window execution"
        severity = "HIGH"
        author = "WRAITH"
    strings:
        $h1 = "-WindowStyle Hidden" nocase
        $h2 = "-W Hidden" nocase
        $h3 = "-NonInteractive" nocase
        $h4 = "-NoProfile" nocase
        $h5 = "bypass" nocase
    condition:
        3 of ($h1, $h2, $h3, $h4, $h5)
}

rule WRAITH_ProcessInjection_Indicators
{
    meta:
        description = "Detects process injection API calls"
        severity = "CRITICAL"
        author = "WRAITH"
    strings:
        $i1 = "VirtualAllocEx" ascii wide
        $i2 = "WriteProcessMemory" ascii wide
        $i3 = "CreateRemoteThread" ascii wide
        $i4 = "NtCreateThreadEx" ascii wide
        $i5 = "RtlCreateUserThread" ascii wide
        $i6 = "QueueUserAPC" ascii wide
        $i7 = "SetWindowsHookEx" ascii wide
    condition:
        2 of them
}

rule WRAITH_Reflective_DLL_Injection
{
    meta:
        description = "Detects reflective DLL injection pattern"
        severity = "CRITICAL"
        author = "WRAITH"
        fp_note = "$r4 (bare MZ header) removed — it matched every legitimate DLL"
    strings:
        $r1 = "ReflectiveDLLInjection" nocase ascii wide
        $r2 = "Invoke-ReflectivePEInjection" nocase
        $r3 = "ReflectiveLoader" ascii wide
        // Reflective loader bootstrap shellcode (Stephen Fewer's canonical bytes)
        // Only fires when the full 64-byte bootstrap stub is present, not on any MZ header
        $r4 = { 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 8B 72 28 }
    condition:
        $r1 or $r2 or $r3 or $r4
}

rule WRAITH_Mimikatz
{
    meta:
        description = "Detects Mimikatz credential dumper"
        severity = "CRITICAL"
        author = "WRAITH"
    strings:
        $m1 = "mimikatz" nocase ascii wide
        $m2 = "sekurlsa" ascii wide
        $m3 = "lsadump" ascii wide
        $m4 = "privilege::debug" nocase
        $m5 = "sekurlsa::logonpasswords" nocase
        $m6 = "kerberos::golden" nocase
        $m7 = "Pass-The-Hash" nocase
        $m8 = "Benjamin DELPY" ascii wide
    condition:
        2 of them
}

rule WRAITH_Cobalt_Strike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon artifacts"
        severity = "CRITICAL"
        author = "WRAITH"
    strings:
        $c1 = "CobaltStrike" nocase ascii wide
        $c2 = "cobaltstrike" nocase
        $c3 = "%s (admin)" ascii
        $c4 = "beacon.dll" nocase
        $c5 = "BeaconJitter" nocase
        $c6 = { 4D 5A 41 52 55 48 89 E5 48 83 EC 20 48 8B F1 }  // CS shellcode header
        $c7 = "http-get" ascii
        $sleep = "sleep" ascii
        $pipe = "\\\\.\\pipe\\" ascii
    condition:
        2 of ($c1,$c2,$c3,$c4,$c5,$c6) or ($c7 and $sleep and $pipe)
}

rule WRAITH_NPM_Supply_Chain_Attack
{
    meta:
        description = "Detects npm supply chain attack patterns in JS files"
        severity = "CRITICAL"
        author = "WRAITH"
    strings:
        $n1 = "require('child_process')" ascii
        $n2 = "require(\"child_process\")" ascii
        $n3 = "execSync" ascii
        $n4 = "spawnSync" ascii
        $n5 = "process.env.npm_lifecycle_event" ascii
        $n6 = "Buffer.from(" ascii
        $n7 = "'base64'" ascii
        $n8 = "\"base64\"" ascii
        $n9 = "postinstall" ascii
        // Specific cline-attack pattern
        $cline1 = "cline" nocase ascii
        $cline2 = "anthropic" nocase ascii
        $steal = "HOME" ascii
        $steal2 = "USERPROFILE" ascii
        $steal3 = ".ssh" ascii
        $steal4 = ".aws" ascii
        $steal5 = "credentials" nocase ascii
    condition:
        ($n1 or $n2) and ($n3 or $n4) and (
            ($n6 and ($n7 or $n8)) or ($steal3 or $steal4 or $steal5) or
            ($cline1 and $cline2) or $n5 or $n9 or $steal or $steal2
        )
}

rule WRAITH_NPM_Exfiltration
{
    meta:
        description = "Detects npm package attempting data exfiltration"
        severity = "CRITICAL"
        author = "WRAITH"
    strings:
        $ex1 = "https://" ascii
        $ex2 = "http://" ascii
        $ex3 = "fetch(" ascii
        $ex4 = "axios" ascii
        $enc = "Buffer.from" ascii
        $b64 = ".toString('base64')" ascii
        $cred1 = "password" nocase ascii
        $cred2 = "secret" nocase ascii
        $cred3 = "token" nocase ascii
        $cred4 = "api_key" nocase ascii
        $cred5 = "private_key" nocase ascii
        $env = "process.env" ascii
    condition:
        ($ex1 or $ex2 or $ex3 or $ex4) and ($enc or $b64) and
        $env and 2 of ($cred1,$cred2,$cred3,$cred4,$cred5)
}

rule WRAITH_CryptoMiner
{
    meta:
        description = "Detects cryptocurrency mining software"
        severity = "HIGH"
        author = "WRAITH"
        fp_note = "Bare $wallet regex (/[0-9a-zA-Z]{95}/) removed — matched any long base64/hash string. Monero wallet format requires '4' prefix + 94 alphanumeric chars in context of other miner signals."
    strings:
        $m1 = "stratum+tcp" nocase ascii wide
        $m2 = "stratum+ssl" nocase ascii wide
        $m3 = "xmrig" nocase ascii wide
        $m4 = "minerd" nocase ascii wide
        $m5 = "cgminer" nocase ascii wide
        $m6 = "monero" nocase ascii wide
        $m7 = "CryptoNight" ascii wide
        $m8 = "nicehash" nocase ascii wide
        $pool = ".pool." ascii wide
        // Monero wallet: starts with '4', exactly 95 chars — only score when paired with miner keyword
        $wallet = /4[0-9A-Za-z]{94}/ ascii
    condition:
        2 of ($m1,$m2,$m3,$m4,$m5,$m6,$m7,$m8) or
        ($m1 and $pool) or
        ($wallet and 1 of ($m1,$m2,$m3,$m4,$m5,$m6,$m7,$m8,$pool))
}

rule WRAITH_RAT_Generic
{
    meta:
        description = "Detects generic Remote Access Trojan patterns"
        severity = "CRITICAL"
        author = "WRAITH"
        fp_note = "Generic string threshold raised 4->6/7 and scoped to PE files only. Browser JS legitimately contains screenshot/clipboard/webcam for browser APIs. Named families still 1-of."
    strings:
        // Named RAT families — high confidence, keep at 1-of
        $r1 = "njRAT" nocase ascii wide
        $r2 = "DarkComet" nocase ascii wide
        $r3 = "NanoCore" nocase ascii wide
        $r4 = "AsyncRAT" nocase ascii wide
        $r5 = "QuasarRAT" nocase ascii wide
        $r6 = "Remcos" nocase ascii wide
        $r7 = "BitRAT" nocase ascii wide
        $r8 = "AgentTesla" nocase ascii wide
        $r9 = "XWorm" nocase ascii wide
        $r10 = "RedLine" nocase ascii wide
        // Generic capability strings — individually found in many legit apps;
        // require 6 of 7 AND the file must be a PE (MZ header)
        $g1 = "keylogger" nocase ascii wide
        $g2 = "screenshot" nocase ascii wide
        $g3 = "clipboard" nocase ascii wide
        $g4 = "webcam" nocase ascii wide
        $g5 = "microphone" nocase ascii wide
        $g6 = "reverse shell" nocase ascii wide
        $g7 = "bind shell" nocase ascii wide
        $mz = { 4D 5A }  // PE file guard
    condition:
        1 of ($r1,$r2,$r3,$r4,$r5,$r6,$r7,$r8,$r9,$r10) or
        ($mz at 0 and 6 of ($g1,$g2,$g3,$g4,$g5,$g6,$g7))
}

rule WRAITH_Registry_Persistence_Script
{
    meta:
        description = "Detects scripts writing registry run keys for persistence"
        severity = "HIGH"
        author = "WRAITH"
    strings:
        $reg1 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg3 = "CurrentVersion\\Run" nocase
        $ps_reg = "Set-ItemProperty" nocase
        $reg_add = "reg add" nocase
        $net_reg = "Registry.SetValue" nocase
    condition:
        ($reg1 or $reg2 or $reg3) and ($ps_reg or $reg_add or $net_reg)
}

rule WRAITH_OpenClaw_Suspicious
{
    meta:
        description = "Detects OpenClaw-related suspicious activity"
        severity = "HIGH"
        author = "WRAITH"
    strings:
        $o1 = "openclaw" nocase ascii wide
        $o2 = "open-claw" nocase ascii wide
        $o3 = "OpenClawUpdater" nocase ascii wide
        $meta1 = "MetaQuest" nocase ascii wide
        $meta2 = "meta-quest" nocase ascii wide
        $meta3 = "OculusXR" nocase ascii wide
        $meta4 = "quest-access" nocase ascii wide
        $access = "requestAccess" nocase ascii wide
        $auto = "autostart" nocase ascii wide
        $inject = "inject" nocase ascii wide
    condition:
        ($o1 or $o2 or $o3) or
        (($meta1 or $meta2 or $meta3 or $meta4) and ($access or $auto or $inject))
}

rule WRAITH_Suspicious_LNK_Target
{
    meta:
        description = "Detects .lnk shortcuts with suspicious targets"
        severity = "HIGH"
        author = "WRAITH"
    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }  // LNK magic bytes
        $ps  = "powershell" nocase ascii wide
        $cmd = "cmd.exe" nocase ascii wide
        $enc = "-enc" nocase ascii wide
        $hidden = "-hidden" nocase ascii wide
        $bypass = "bypass" nocase ascii wide
    condition:
        $lnk and ($ps or $cmd) and ($enc or $hidden or $bypass)
}

rule WRAITH_AMSI_Bypass
{
    meta:
        description = "Detects AMSI bypass attempts"
        severity = "CRITICAL"
        author = "WRAITH"
    strings:
        $a1 = "amsiInitFailed" nocase ascii wide
        $a2 = "AmsiScanBuffer" ascii wide
        $a3 = "amsi.dll" nocase ascii wide
        $a4 = "AmsiContext" ascii wide
        $patch = { 31 C0 }  // xor eax,eax (common AMSI patch)
        $patch2 = { B8 57 00 07 80 C3 }  // ret AMSI bypass
    condition:
        2 of ($a1,$a2,$a3,$a4) or (($a2 or $a3) and ($patch or $patch2))
}

rule WRAITH_ETW_Tampering
{
    meta:
        description = "Detects ETW (Event Tracing) tampering to evade logging"
        severity = "CRITICAL"
        author = "WRAITH"
    strings:
        $e1 = "EtwEventWrite" ascii wide
        $e2 = "NtTraceEvent" ascii wide
        $e3 = "EtwNotificationRegister" ascii wide
        $patch = { C2 14 00 }  // ret 14h - ETW patch
        $patch2 = { 33 C0 C3 } // xor eax,eax; ret
    condition:
        ($e1 or $e2 or $e3) and ($patch or $patch2)
}
