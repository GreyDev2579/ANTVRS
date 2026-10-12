rule Suspicious_PowerShell_Download
{
    meta:
        description = "PowerShell downloading and executing remote content"
        severity = "high"

    strings:
        $ps   = "powershell" nocase
        $dl1  = "DownloadString" nocase
        $dl2  = "Invoke-WebRequest" nocase
        $exec = "Invoke-Expression" nocase
        $b64  = "-enc" nocase

    condition:
        $ps and (1 of ($dl*)) and ($exec or $b64)
}