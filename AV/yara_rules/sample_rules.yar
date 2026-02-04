
rule EICAR_Test {
    meta:
        description = "EICAR test file"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell {
    meta:
        description = "Suspicious PowerShell"
    strings:
        $ps1 = "IEX" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "DownloadString" nocase
    condition:
        2 of them
}
