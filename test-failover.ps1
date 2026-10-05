# Автотест отказоустойчивости по inventory.json.
#
# Для каждого сервера по очереди:
#   app     приложение упало: его IP пропадает из ответа ВСЕХ DNS, сайт по имени открывается,
#           после старта IP возвращается. Проверяется для каждой записи из inventory.json.
#   dns     CoreDNS упал: имена всё равно резолвятся через другой DNS.
#   server  сервер лёг целиком (стоп всех приложений, CoreDNS и health-check разом):
#           имена резолвятся, IP этого сервера в ответах нет, сайты открываются.
# После каждого теста всё поднимается обратно, даже если тест упал.
#
# Перед запуском: раскатан deploy.ps1, выполнен client-dns.ps1, VPN выключен.
# SSH лучше по ключу, иначе пароль спросят много раз.
#
#   powershell -ExecutionPolicy Bypass -File .\test-failover.ps1
#   .\test-failover.ps1 -Only app            только падения приложений
#   .\test-failover.ps1 -Server srv1         только один сервер

param(
    [string]$Inventory = (Join-Path $PSScriptRoot 'inventory.json'),
    [ValidateSet('app', 'dns', 'server')]
    [string[]]$Only = @('app', 'dns', 'server'),
    [string]$Server = '',
    [int]$WaitSec = 40
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\inventory.ps1')
$inv = Read-Inventory $Inventory
$User = $inv.ssh_user
$ByName = $inv.ByName
$Records = @($inv.records.PSObject.Properties | ForEach-Object {
    [pscustomobject]@{
        Name  = $_.Name
        Rec   = $_.Value
        Ips   = @($_.Value.servers | ForEach-Object { $ByName[$_].ip } | Sort-Object)
    }
})
$DnsServers = @($inv.servers | Where-Object { $_.dns })
$DnsDir = $inv.paths.dns
$Targets = @($inv.servers)
if ($Server) { $Targets = @($Targets | Where-Object { $_.name -eq $Server }) }
$Results = New-Object System.Collections.Generic.List[object]

# --- helpers -------------------------------------------------------------------

function Get-Answer([string]$name, [string]$dnsIp) {
    # ответ конкретного DNS (отсортированный) или $null
    try {
        $a = Resolve-DnsName $name -Server $dnsIp -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
             Where-Object Type -eq 'A' | Select-Object -ExpandProperty IPAddress
        return @($a | Sort-Object)
    } catch { return $null }
}

function Get-SystemAnswer([string]$name) {
    # как резолвит сама Windows: NRPT -> любой живой DNS
    Clear-DnsClientCache
    try {
        $a = Resolve-DnsName $name -Type A -DnsOnly -ErrorAction Stop |
             Where-Object Type -eq 'A' | Select-Object -ExpandProperty IPAddress
        return @($a | Sort-Object)
    } catch { return $null }
}

function Test-ByName($r) {
    # открывается ли сайт по имени, как у юзера; 3 попытки
    for ($i = 0; $i -lt 3; $i++) {
        Clear-DnsClientCache
        try {
            $null = Invoke-WebRequest "http://$($r.Name):$($r.Rec.port)$($r.Rec.path)" -UseBasicParsing -TimeoutSec 5
            return $true
        } catch { Start-Sleep -Seconds 1 }
    }
    return $false
}

function Invoke-Remote([string]$ip, [string]$cmd) {
    ssh "${User}@${ip}" $cmd | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "ssh $ip '$cmd' завершилось с кодом $LASTEXITCODE" }
}

function Wait-Until([scriptblock]$cond) {
    # секунды до выполнения условия или -1 по таймауту
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $WaitSec) {
        if (& $cond) { return [math]::Round($sw.Elapsed.TotalSeconds, 1) }
        Start-Sleep -Milliseconds 700
    }
    return -1
}

function Add-Result([string]$test, [string]$check, [bool]$ok, $sec) {
    $t = ''
    if ($null -ne $sec -and $sec -ge 0) { $t = "$sec с" }
    $mark = 'FAIL'; $color = 'Red'
    if ($ok) { $mark = 'PASS'; $color = 'Green' }
    $Results.Add([pscustomobject]@{ Тест = $test; Проверка = $check; Итог = $mark; Время = $t })
    Write-Host ("  {0} {1} {2}" -f $mark, $check, $t) -ForegroundColor $color
}

function Test-Excluded($r, [string]$ip, $dnsList) {
    # во всех ответах этих DNS нет $ip, но ответ не пустой
    foreach ($d in $dnsList) {
        $a = Get-Answer $r.Name $d.ip
        if ($null -eq $a -or $a.Count -eq 0 -or $a -contains $ip) { return $false }
    }
    return $true
}

function Test-AllFull {
    # все DNS отдают по всем записям полный набор IP
    foreach ($r in $Records) {
        foreach ($d in $DnsServers) {
            $a = Get-Answer $r.Name $d.ip
            if ($null -eq $a -or $a.Count -eq 0 -or (Compare-Object $a $r.Ips)) { return $false }
        }
    }
    return $true
}

function Stop-Apps($s) {
    foreach ($r in $Records) { if ($r.Ips -contains $s.ip) { Invoke-Remote $s.ip $r.Rec.stop } }
}

function Start-Apps($s) {
    foreach ($r in $Records) { if ($r.Ips -contains $s.ip) { Invoke-Remote $s.ip $r.Rec.start } }
}

# --- исходное состояние --------------------------------------------------------------

$nrpt = Get-DnsClientNrptRule | Where-Object { $_.Namespace -match [regex]::Escape($inv.zone) }
if (-not $nrpt) { Write-Host "Нет NRPT-правила для $($inv.zone): сначала запусти client-dns.ps1 от администратора" -ForegroundColor Yellow }

foreach ($r in $Records) {
    foreach ($d in $DnsServers) {
        $a = Get-Answer $r.Name $d.ip
        if ($null -eq $a -or $a.Count -eq 0) { throw "DNS $($d.ip) не отвечает про $($r.Name). VPN включён? Раскатан ли deploy.ps1?" }
        if (Compare-Object $a $r.Ips) {
            throw "DNS $($d.ip) отдаёт для $($r.Name): $($a -join ', '), а ожидается $($r.Ips -join ', '). Подними всё (см. админку) и запусти тест снова."
        }
    }
    if (-not (Test-ByName $r)) { throw "http://$($r.Name):$($r.Rec.port)$($r.Rec.path) не открывается ещё до тестов" }
}
Write-Host "Исходное состояние ок: все DNS отдают все IP, все сайты открываются`n" -ForegroundColor Green

# --- app: падение приложения ------------------------------------------------------------

if ('app' -in $Only) {
    foreach ($s in $Targets) {
        foreach ($r in @($Records | Where-Object { $_.Ips -contains $s.ip })) {
            $name = "$($r.Name) на $($s.name) упал"
            Write-Host "=== $name" -ForegroundColor Cyan
            try {
                Invoke-Remote $s.ip $r.Rec.stop
                $t = Wait-Until { Test-Excluded $r $s.ip $DnsServers }
                Add-Result $name "$($s.ip) пропал из ответа всех DNS" ($t -ge 0) $t
                Add-Result $name "сайт по имени открывается" (Test-ByName $r) $null
            }
            catch { Add-Result $name "ошибка: $($_.Exception.Message)" $false $null }
            finally {
                try { Invoke-Remote $s.ip $r.Rec.start } catch { Write-Host "  не смог поднять: $($_.Exception.Message)" -ForegroundColor Red }
                $t = Wait-Until { Test-AllFull }
                Add-Result $name "после старта всё вернулось в DNS" ($t -ge 0) $t
            }
        }
    }
}

# --- dns: падение CoreDNS ----------------------------------------------------------------

if ('dns' -in $Only) {
    foreach ($s in @($Targets | Where-Object { $_.dns })) {
        $name = "CoreDNS на $($s.name) упал"
        Write-Host "=== $name" -ForegroundColor Cyan
        try {
            Invoke-Remote $s.ip "cd $DnsDir && docker compose stop coredns"
            foreach ($r in $Records) {
                $t = Wait-Until { $a = Get-SystemAnswer $r.Name; $null -ne $a -and $a.Count -gt 0 }
                Add-Result $name "$($r.Name) резолвится через другой DNS" ($t -ge 0) $t
                Add-Result $name "$($r.Name) открывается" (Test-ByName $r) $null
            }
        }
        catch { Add-Result $name "ошибка: $($_.Exception.Message)" $false $null }
        finally {
            try { Invoke-Remote $s.ip "cd $DnsDir && docker compose start coredns" } catch { Write-Host "  не смог поднять: $($_.Exception.Message)" -ForegroundColor Red }
            $t = Wait-Until { Test-AllFull }
            Add-Result $name "после старта DNS на $($s.ip) отвечает" ($t -ge 0) $t
        }
    }
}

# --- server: сервер лёг целиком ------------------------------------------------------------

if ('server' -in $Only) {
    foreach ($s in $Targets) {
        $name = "Сервер $($s.name) лёг целиком"
        Write-Host "=== $name" -ForegroundColor Cyan
        try {
            Stop-Apps $s
            if ($s.dns) { Invoke-Remote $s.ip "cd $DnsDir && docker compose stop coredns healthcheck" }
            foreach ($r in $Records) {
                $hasIt = $r.Ips -contains $s.ip
                $t = Wait-Until {
                    $a = Get-SystemAnswer $r.Name
                    $null -ne $a -and $a.Count -gt 0 -and -not ($hasIt -and ($a -contains $s.ip))
                }
                $what = "$($r.Name) резолвится"
                if ($hasIt) { $what += ", $($s.ip) в ответе нет" }
                Add-Result $name $what ($t -ge 0) $t
                Add-Result $name "$($r.Name) открывается" (Test-ByName $r) $null
            }
        }
        catch { Add-Result $name "ошибка: $($_.Exception.Message)" $false $null }
        finally {
            try {
                if ($s.dns) { Invoke-Remote $s.ip "cd $DnsDir && docker compose start healthcheck coredns" }
                Start-Apps $s
            } catch { Write-Host "  не смог поднять: $($_.Exception.Message)" -ForegroundColor Red }
            $t = Wait-Until { Test-AllFull }
            Add-Result $name "после подъёма всё вернулось" ($t -ge 0) $t
        }
    }
}

# --- итог --------------------------------------------------------------------------------

Write-Host "`n=== Итог" -ForegroundColor Cyan
$Results | Format-Table -AutoSize -Wrap
$bad = @($Results | Where-Object { $_.Итог -eq 'FAIL' }).Count
if ($bad -gt 0) {
    Write-Host "Провалено проверок: $bad из $($Results.Count)" -ForegroundColor Red
    exit 1
}
Write-Host "Все $($Results.Count) проверок пройдены" -ForegroundColor Green
