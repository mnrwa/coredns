# Настройка Windows-клиента: имена зоны из inventory.json резолвить через все DNS-серверы.
# Запускать в PowerShell ОТ АДМИНИСТРАТОРА:
#   powershell -ExecutionPolicy Bypass -File .\client-dns.ps1
# Убрать правило:  .\client-dns.ps1 -Remove

param(
    [string]$Inventory = (Join-Path $PSScriptRoot 'inventory.json'),
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\inventory.ps1')
$inv = Read-Inventory $Inventory
$zone = $inv.zone
$dns = @($inv.servers | Where-Object { $_.dns } | ForEach-Object { $_.ip })

# старые правила под эту зону убираем
Get-DnsClientNrptRule | Where-Object { $_.Namespace -match [regex]::Escape($zone) } |
    ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }

if (-not $Remove) {
    # и само имя, и все поддомены; серверов несколько: если первый молчит, Windows спросит следующий
    Add-DnsClientNrptRule -Namespace $zone, ".$zone" -NameServers $dns
}

Clear-DnsClientCache
Get-DnsClientNrptRule | Where-Object { $_.Namespace -match [regex]::Escape($zone) } |
    Format-Table Namespace, NameServers -AutoSize

if (-not $Remove) {
    foreach ($name in $inv.records.PSObject.Properties.Name) {
        try { Resolve-DnsName $name -Type A -DnsOnly | Format-Table Name, IPAddress -AutoSize }
        catch { Write-Host "$name не резолвится: $($_.Exception.Message). VPN выключен?" -ForegroundColor Yellow }
    }
}
