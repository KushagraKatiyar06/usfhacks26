/*
   Agent Tesla YARA Rules
   Covers versions 2, 3, and 5 of the Agent Tesla infostealer/keylogger
*/

rule AgentTesla_v2 {
    meta:
        description = "Detects Agent Tesla v2 infostealer"
        threat_level = "critical"
    strings:
        $s1 = "get_Clipboard" ascii
        $s2 = "GetKeyState" ascii
        $s3 = "smtp.gmail.com" ascii nocase
        $s4 = "AgentTesla" ascii nocase
        $s5 = "get_ScreenCapture" ascii
        $s6 = "FileZilla" ascii
        $s7 = "credential" ascii nocase
    condition:
        4 of them
}

rule AgentTesla_v3 {
    meta:
        description = "Detects Agent Tesla v3 with SMTP exfil"
        threat_level = "critical"
    strings:
        $s1 = "SmtpClient" ascii
        $s2 = "MailMessage" ascii
        $s3 = "NetworkCredential" ascii
        $s4 = "GetKeyboardState" ascii
        $s5 = "get_Clipboard" ascii
        $s6 = "WinSCP" ascii nocase
        $s7 = "ip-api.com" ascii nocase
    condition:
        4 of them
}

rule AgentTesla_v5 {
    meta:
        description = "Detects Agent Tesla v5 with Telegram/FTP exfil"
        threat_level = "critical"
    strings:
        $s1 = "Telegram" ascii nocase
        $s2 = "FtpWebRequest" ascii
        $s3 = "GetKeyState" ascii
        $s4 = "Clipboard" ascii
        $s5 = "WebClient" ascii
        $s6 = "keylog" ascii nocase
        $s7 = "screenshot" ascii nocase
    condition:
        4 of them
}

rule AgentTesla_Dropper_JS {
    meta:
        description = "Detects JS dropper that delivers Agent Tesla"
        threat_level = "high"
    strings:
        $s1 = "ADODB.Stream" ascii nocase
        $s2 = "WScript.Shell" ascii nocase
        $s3 = "powershell" ascii nocase
        $s4 = "FromBase64String" ascii nocase
        $s5 = "Reflection.Assembly" ascii nocase
        $s6 = "%PUBLIC%" ascii nocase
    condition:
        4 of them
}

rule Infostealer_Credential_Harvester {
    meta:
        description = "Generic credential harvesting behavior"
        threat_level = "high"
    strings:
        $browser1 = "Opera" ascii
        $browser2 = "Chrome" ascii
        $ftp1     = "FileZilla" ascii
        $ftp2     = "WinSCP" ascii
        $email1   = "Outlook" ascii
        $email2   = "Foxmail" ascii
        $vpn1     = "OpenVPN" ascii
        $wallet1  = "Bitcoin" ascii nocase
    condition:
        4 of them
}

rule AntiAnalysis_VM_Detection {
    meta:
        description = "Anti-VM and anti-sandbox evasion strings"
        threat_level = "high"
    strings:
        $vm1   = "vmware" ascii nocase
        $vm2   = "VirtualBox" ascii nocase
        $vm3   = "vbox" ascii nocase
        $sand1 = "SbieDll" ascii
        $sand2 = "snxhk" ascii
        $sand3 = "cuckoomon" ascii
        $dbg1  = "IsDebuggerPresent" ascii
        $dbg2  = "CheckRemoteDebuggerPresent" ascii
    condition:
        3 of them
}

rule Keylogger_SetWindowsHookEx {
    meta:
        description = "Keylogger using SetWindowsHookEx / input capture"
        threat_level = "high"
    strings:
        $s1 = "SetWindowsHookEx" ascii
        $s2 = "CallNextHookEx" ascii
        $s3 = "GetKeyState" ascii
        $s4 = "GetAsyncKeyState" ascii
    condition:
        2 of them
}
