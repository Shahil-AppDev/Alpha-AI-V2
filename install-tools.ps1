# Installation des outils de sécurité - Alpha AI Platform
Write-Host "Installation des outils de securite..." -ForegroundColor Cyan

Set-Location tools

$tools = @{
    "metasploit-framework" = "https://github.com/rapid7/metasploit-framework.git"
    "sqlmap" = "https://github.com/sqlmapproject/sqlmap.git"
    "PowerSploit" = "https://github.com/PowerShellMafia/PowerSploit.git"
    "beef" = "https://github.com/beefproject/beef.git"
    "nmap" = "https://github.com/nmap/nmap.git"
    "nikto" = "https://github.com/sullo/nikto.git"
    "recon-ng" = "https://github.com/lanmaster53/recon-ng.git"
    "spiderfoot" = "https://github.com/smicallef/spiderfoot.git"
    "theHarvester" = "https://github.com/laramies/theHarvester.git"
    "zmap" = "https://github.com/zmap/zmap.git"
    "john" = "https://github.com/openwall/john.git"
    "hashcat" = "https://github.com/hashcat/hashcat.git"
    "thc-hydra" = "https://github.com/vanhauser-thc/thc-hydra.git"
    "XSStrike" = "https://github.com/s0md3v/XSStrike.git"
    "zaproxy" = "https://github.com/zaproxy/zaproxy.git"
    "aircrack-ng" = "https://github.com/aircrack-ng/aircrack-ng.git"
    "gophish" = "https://github.com/gophish/gophish.git"
    "volatility" = "https://github.com/volatilityfoundation/volatility.git"
    "mimikatz" = "https://github.com/gentilkiwi/mimikatz.git"
    "openvas" = "https://github.com/greenbone/openvas-scanner.git"
}

$count = 0
foreach ($tool in $tools.GetEnumerator()) {
    $count++
    Write-Host "[$count/20] Cloning $($tool.Key)..." -ForegroundColor Yellow
    git clone --depth 1 $tool.Value 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  OK" -ForegroundColor Green
    }
}

# Créer répertoires personnalisés
New-Item -ItemType Directory -Path "scanners" -Force | Out-Null
New-Item -ItemType Directory -Path "wordlists" -Force | Out-Null
New-Item -ItemType Directory -Path "anydesk-backdoor" -Force | Out-Null
New-Item -ItemType Directory -Path "rustdesk" -Force | Out-Null
New-Item -ItemType Directory -Path "reverse-engineer-tool" -Force | Out-Null

Set-Location ..

Write-Host ""
Write-Host "Installation terminee!" -ForegroundColor Green
