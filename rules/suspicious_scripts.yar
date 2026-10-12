rule EICAR_Test_String
{
    meta:
        description = "EICAR antivirus test string (harmless)"
        severity = "low"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

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

rule Suspicious_VBA_Downloader
{
    meta:
        description = "Script that auto-runs, launches a shell, and downloads files"
        severity = "high"

    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $sh1   = "WScript.Shell" nocase
        $sh2   = "Shell(" nocase
        $dl1   = "URLDownloadToFile" nocase
        $dl2   = "XMLHTTP" nocase

    condition:
        (1 of ($auto*)) and (1 of ($sh*)) and (1 of ($dl*))
}

rule Suspicious_Certutil_Download
{
    meta:
        description = "certutil used to download a file (common living-off-the-land trick)"
        severity = "medium"

    strings:
        $c1 = "certutil" nocase
        $c2 = "-urlcache" nocase
        $c3 = "-split" nocase   
        $c4 = "http" nocase

    condition:
        $c1 and $c2 and ($c3 or $c4)
}