# Раскатка CoreDNS + health-check + админки и тестового WhoAmI на серверы из inventory.json.
#
# Запуск из корня репозитория:
#   powershell -ExecutionPolicy Bypass -File .\deploy.ps1
#   .\deploy.ps1 -Only dns                 только DNS
#   .\deploy.ps1 -Only whoami              только WhoAmI
#   .\deploy.ps1 -Nodes 10.0.0.13          только указанные серверы (например, новый)
#   .\deploy.ps1 -Only dns -ResetConfig    перезаписать конфиг записей на нодах из inventory.json
#
# Откуда что берётся:
#   inventory.json   серверы, записи, порты, образы (окружение, не секреты; в git не коммитится)
#   .env             ADMIN_PASSWORD (секрет; в git не коммитится; нет файла, сгенерируется)
#   на сервере       ~/coredns/.env с правами 600 собирается из этих двух файлов
#
# Конфиг записей на DNS-нодах (config/records.json) живёт своей жизнью: его правит админка.
# Раскатка его не затирает, а только ДОЛИВАЕТ новое из inventory.json (новые серверы,
# записи, DNS). Удалять серверы из записей нужно в админке (или -ResetConfig).

param(
    [ValidateSet('all', 'whoami', 'dns')]
    [string]$Only = 'all',
    [string[]]$Nodes = @(),
    [switch]$ResetConfig,
    [switch]$NoSync,
    [string]$Inventory = (Join-Path $PSScriptRoot 'inventory.json'),
    [string]$EnvFile = (Join-Path $PSScriptRoot '.env')
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
. (Join-Path $Root 'scripts\inventory.ps1')

$inv = Read-Inventory $Inventory
$User = $inv.ssh_user
$ByName = $inv.ByName
$Dns = $inv.dns

$AllDns        = @($inv.servers | Where-Object { $_.dns })
$DnsServers    = $AllDns
$WhoamiServers = @($inv.servers | Where-Object { $_.whoami })
if ($Nodes.Count -gt 0) {
    $DnsServers    = @($DnsServers    | Where-Object { $_.ip -in $Nodes })
    $WhoamiServers = @($WhoamiServers | Where-Object { $_.ip -in $Nodes })
}

$Failed = New-Object System.Collections.Generic.List[string]

# --- helpers -------------------------------------------------------------------

function Assert-Exit([string]$what) {
    if ($LASTEXITCODE -ne 0) { throw "$what завершилось с кодом $LASTEXITCODE" }
}

function Write-Utf8([string]$path, [string]$text) {
    # без BOM и с LF: файлы уезжают на Linux
    [IO.File]::WriteAllText($path, ($text -replace "`r`n", "`n"), (New-Object System.Text.UTF8Encoding $false))
}

function New-TempDir {
    $d = Join-Path $env:TEMP ("coredns-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $d | Out-Null
    return $d
}

function Send-Bundle([string]$ip, [string]$srcDir, [string]$remoteDir, [string]$postCmd) {
    # пакует папку в tar, кидает по scp, распаковывает в $remoteDir и выполняет $postCmd там же
    $tar = Join-Path $env:TEMP ("deploy-" + [guid]::NewGuid().ToString('N') + ".tar")
    try {
        tar -cf $tar -C $srcDir .
        Assert-Exit "tar"
        scp -q $tar "${User}@${ip}:/tmp/coredns-deploy.tar"
        Assert-Exit "scp на $ip"
        $cmd = "mkdir -p $remoteDir && tar -xf /tmp/coredns-deploy.tar -C $remoteDir && rm -f /tmp/coredns-deploy.tar && cd $remoteDir && $postCmd"
        ssh "${User}@${ip}" $cmd
        Assert-Exit "ssh на $ip"
    }
    finally {
        Remove-Item $tar -ErrorAction SilentlyContinue
    }
}

function Get-RecordIps($r) {
    return @($r.servers | ForEach-Object { $ByName[$_].ip })
}

function New-RecordsConfig {
    # стартовый config/records.json для health-check из inventory.json
    $ns = [ordered]@{}
    $i = 1
    foreach ($s in $AllDns) { $ns["ns$i"] = $s.ip; $i++ }
    $labels = [ordered]@{}
    foreach ($s in $inv.servers) { $labels[$s.ip] = $s.name }
    $records = [ordered]@{}
    foreach ($p in $inv.records.PSObject.Properties) {
        $r = $p.Value
        $ips = @(Get-RecordIps $r | ForEach-Object { [ordered]@{ ip = $_; enabled = $true } })
        $expect = ''
        if ($r.expect) { $expect = $r.expect }
        $records[$p.Name] = [ordered]@{ port = $r.port; path = $r.path; expect = $expect; ips = $ips }
    }
    $cfg = [ordered]@{
        zone = $inv.zone; ttl = $Dns.ttl; interval = $Dns.interval; timeout = $Dns.timeout
        nameservers = $ns; labels = $labels; records = $records
    }
    return ($cfg | ConvertTo-Json -Depth 10)
}

function Sync-Inventory([string]$password) {
    # доливает в живой конфиг то, что появилось в inventory.json; ничего не удаляет
    $auth = Get-AuthHeader $Dns.admin_user $password
    $state = $null; $api = $null
    foreach ($s in $AllDns) {
        try {
            $state = Invoke-RestMethod "http://$($s.ip):$($Dns.admin_port)/api/state" -Headers $auth -TimeoutSec 5
            $api = $s.ip; break
        } catch { }
    }
    if (-not $state -or -not $state.config) {
        Write-Host "Синхронизация inventory: ни одна админка не ответила, пропускаю" -ForegroundColor Yellow
        return
    }
    $cfg = $state.config
    $changes = New-Object System.Collections.Generic.List[string]

    $nsIps = @($cfg.nameservers.PSObject.Properties | ForEach-Object { $_.Value })
    foreach ($s in $AllDns) {
        if ($nsIps -notcontains $s.ip) {
            $n = 1
            while ($cfg.nameservers.PSObject.Properties.Name -contains "ns$n") { $n++ }
            $cfg.nameservers | Add-Member -NotePropertyName "ns$n" -NotePropertyValue $s.ip
            $changes.Add("DNS ns$n = $($s.ip)")
        }
    }
    foreach ($s in $inv.servers) {
        if (-not $cfg.labels.PSObject.Properties[$s.ip]) {
            $cfg.labels | Add-Member -NotePropertyName $s.ip -NotePropertyValue $s.name
        }
    }
    foreach ($p in $inv.records.PSObject.Properties) {
        $want = Get-RecordIps $p.Value
        $cur = $cfg.records.PSObject.Properties[$p.Name]
        if (-not $cur) {
            $expect = ''
            if ($p.Value.expect) { $expect = $p.Value.expect }
            $rec = [pscustomobject]@{
                port = $p.Value.port; path = $p.Value.path; expect = $expect
                ips = @($want | ForEach-Object { [pscustomobject]@{ ip = $_; enabled = $true } })
            }
            $cfg.records | Add-Member -NotePropertyName $p.Name -NotePropertyValue $rec
            $changes.Add("запись $($p.Name)")
            continue
        }
        $have = @($cur.Value.ips | ForEach-Object { $_.ip })
        foreach ($ip in $want) {
            if ($have -notcontains $ip) {
                $cur.Value.ips = @($cur.Value.ips) + [pscustomobject]@{ ip = $ip; enabled = $true }
                $changes.Add("$($p.Name) + $ip")
            }
        }
    }

    if ($changes.Count -eq 0) {
        Write-Host "Синхронизация inventory: всё уже есть в конфиге" -ForegroundColor Green
        return
    }
    $body = [Text.Encoding]::UTF8.GetBytes(($cfg | ConvertTo-Json -Depth 10))
    $res = Invoke-RestMethod "http://${api}:$($Dns.admin_port)/api/config" -Method Put -Headers $auth `
        -Body $body -ContentType 'application/json; charset=utf-8' -TimeoutSec 15
    Write-Host "Синхронизация inventory через $api, добавлено: $($changes -join '; ')" -ForegroundColor Green
    foreach ($peer in $res.peers.PSObject.Properties) {
        $color = 'Green'
        if ($peer.Value -ne 'ok') { $color = 'Red' }
        Write-Host "  рассылка на $($peer.Name): $($peer.Value)" -ForegroundColor $color
    }
}

# --- 1. WhoAmI -----------------------------------------------------------------
if (($Only -in @('all', 'whoami')) -and $WhoamiServers.Count -gt 0) {
    $stage = New-TempDir
    try {
        Copy-Item (Join-Path $Root 'whoami\*') $stage -Recurse
        Copy-Item (Join-Path $Root 'whoami\.dockerignore') $stage -ErrorAction SilentlyContinue
        Write-Utf8 (Join-Path $stage '.env') "WHOAMI_PORT=$($inv.whoami.port)`n"
        foreach ($s in $WhoamiServers) {
            Write-Host "`n=== WhoAmI -> $($s.name) $($s.ip)" -ForegroundColor Cyan
            try { Send-Bundle $s.ip $stage $inv.paths.whoami 'chmod 600 .env && docker compose up -d --build && docker compose ps' }
            catch { Write-Host "!!! $($s.ip) : $($_.Exception.Message)" -ForegroundColor Red; $Failed.Add("whoami $($s.ip)") }
        }
    }
    finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
}

# --- 2. CoreDNS + health-check + админка ---------------------------------------
$AdminPassword = $null
if (($Only -in @('all', 'dns')) -and $DnsServers.Count -gt 0) {
    $AdminPassword = Get-AdminPassword $EnvFile -CreateIfMissing

    $stage = New-TempDir
    try {
        foreach ($f in 'Corefile', 'docker-compose.yml', 'healthcheck.py', 'admin.html') {
            Copy-Item (Join-Path $Root "dns\$f") $stage
        }
        Write-Utf8 (Join-Path $stage 'records.default.json') (New-RecordsConfig)
        # общая часть .env; NODE_IP и RUN_UID/GID допишутся на каждой ноде
        Write-Utf8 (Join-Path $stage '.env') (@(
            "DNS_ZONE=$($inv.zone)"
            "DNS_UPSTREAM=$($Dns.upstream)"
            "ADMIN_USER=$($Dns.admin_user)"
            "ADMIN_PORT=$($Dns.admin_port)"
            "ADMIN_PASSWORD=$AdminPassword"
            "COREDNS_IMAGE=$($Dns.coredns_image)"
            "PYTHON_IMAGE=$($Dns.python_image)"
        ) -join "`n")

        $cfgCmd = '([ -f config/records.json ] || cp records.default.json config/records.json)'
        if ($ResetConfig) { $cfgCmd = 'cp records.default.json config/records.json' }

        foreach ($s in $DnsServers) {
            $ip = $s.ip
            Write-Host "`n=== CoreDNS -> $($s.name) $ip" -ForegroundColor Cyan
            $post = @(
                "printf '\nNODE_IP=%s\nRUN_UID=%s\nRUN_GID=%s\n' $ip `$(id -u) `$(id -g) >> .env"
                'chmod 600 .env'
                'rm -f node.env admin.env Corefile.tmpl records.json'
                'mkdir -p zones config'
                $cfgCmd
                'docker compose pull -q'
                # папки могли остаться от root-версии: отдаём их пользователю, от которого крутится health-check
                'docker compose run --rm --no-deps --user 0 --entrypoint chown healthcheck -R $(id -u):$(id -g) /zones /app/config'
                'docker compose up -d --force-recreate'
                'docker compose ps'
            ) -join ' && '
            try { Send-Bundle $ip $stage $inv.paths.dns $post }
            catch { Write-Host "!!! $ip : $($_.Exception.Message)" -ForegroundColor Red; $Failed.Add("dns $ip") }
        }
    }
    finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
}

# --- 3. Проверка ----------------------------------------------------------------
Write-Host "`n=== Проверка" -ForegroundColor Cyan
Start-Sleep -Seconds 8

if ($AdminPassword -and -not $NoSync -and -not $ResetConfig) { Sync-Inventory $AdminPassword; Start-Sleep -Seconds 4 }

foreach ($p in $inv.records.PSObject.Properties) {
    foreach ($ip in (Get-RecordIps $p.Value)) {
        try {
            $resp = Invoke-WebRequest "http://${ip}:$($p.Value.port)$($p.Value.path)" -UseBasicParsing -TimeoutSec 3
            Write-Host ("app {0,-28} {1,-15} OK  {2}" -f $p.Name, $ip, $resp.StatusCode) -ForegroundColor Green
        }
        catch {
            Write-Host ("app {0,-28} {1,-15} FAIL {2}" -f $p.Name, $ip, $_.Exception.Message) -ForegroundColor Red
        }
    }
}

foreach ($s in $AllDns) {
    foreach ($name in $inv.records.PSObject.Properties.Name) {
        try {
            $a = Resolve-DnsName $name -Server $s.ip -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
                 Where-Object Type -eq 'A' | Select-Object -ExpandProperty IPAddress
            Write-Host ("dns {0,-15} {1,-28} {2}" -f $s.ip, $name, ($a -join ', ')) -ForegroundColor Green
        }
        catch {
            Write-Host ("dns {0,-15} {1,-28} FAIL (VPN включён? порт 53 закрыт?)" -f $s.ip, $name) -ForegroundColor Red
        }
    }
}

if ($AdminPassword) {
    $auth = Get-AuthHeader $Dns.admin_user $AdminPassword
    foreach ($s in $AllDns) {
        $url = "http://$($s.ip):$($Dns.admin_port)/"
        try {
            $null = Invoke-WebRequest "${url}api/state" -Headers $auth -UseBasicParsing -TimeoutSec 3
            Write-Host ("admin {0,-15} OK  {1}" -f $s.ip, $url) -ForegroundColor Green
        }
        catch {
            Write-Host ("admin {0,-15} FAIL {1}" -f $s.ip, $_.Exception.Message) -ForegroundColor Red
        }
    }
    Write-Host "`nАдминка: логин $($Dns.admin_user), пароль в $EnvFile" -ForegroundColor Cyan
}

if ($Failed.Count -gt 0) {
    Write-Host "`nНе раскаталось: $($Failed -join ', ')" -ForegroundColor Yellow
    Write-Host "Повторить только их:  .\deploy.ps1 -Nodes <ip>,<ip>" -ForegroundColor Yellow
}
