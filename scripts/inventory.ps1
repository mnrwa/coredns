# Общие функции для deploy.ps1, test-failover.ps1 и client-dns.ps1:
# чтение inventory.json (с проверкой и значениями по умолчанию) и секретов из .env.
# Подключается через dot-source:  . (Join-Path $PSScriptRoot 'scripts\inventory.ps1')

$script:Defaults = @{
    paths  = @{ dns = '~/coredns'; whoami = '~/whoami' }
    dns    = @{
        ttl = 10; interval = 3; timeout = 2
        admin_port = 9053; admin_user = 'admin'
        upstream = '/etc/resolv.conf'
        coredns_image = 'coredns/coredns:1.12.0'
        python_image = 'python:3.12-slim'
    }
    whoami = @{ port = 8001 }
}

function Set-Defaults($obj, [hashtable]$defaults) {
    foreach ($k in $defaults.Keys) {
        if ($null -eq $obj.$k -or $obj.$k -eq '') {
            $obj | Add-Member -NotePropertyName $k -NotePropertyValue $defaults[$k] -Force
        }
    }
}

function Read-Inventory([string]$path) {
    if (-not (Test-Path $path)) {
        $example = Join-Path (Split-Path $path -Parent) 'inventory.example.json'
        throw "Не найден $path. Скопируй $example в inventory.json и впиши свои серверы."
    }
    $inv = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json

    foreach ($section in 'paths', 'dns', 'whoami') {
        if ($null -eq $inv.$section) { $inv | Add-Member -NotePropertyName $section -NotePropertyValue ([pscustomobject]@{}) -Force }
        Set-Defaults $inv.$section $script:Defaults[$section]
    }

    $errs = New-Object System.Collections.Generic.List[string]
    if (-not $inv.ssh_user) { $errs.Add("ssh_user: не задан пользователь для SSH") }
    if (-not $inv.zone) { $errs.Add("zone: не задана зона") }

    $byName = @{}
    foreach ($s in @($inv.servers)) {
        if (-not $s.name) { $errs.Add("servers: у сервера нет name"); continue }
        if ($byName.ContainsKey($s.name)) { $errs.Add("servers: имя $($s.name) повторяется") }
        $ip = $null
        if (-not [System.Net.IPAddress]::TryParse([string]$s.ip, [ref]$ip) -or $s.ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            $errs.Add("servers.$($s.name): IP '$($s.ip)' не задан или кривой (замени x.x.x.x на реальный адрес)")
        }
        $byName[$s.name] = $s
    }
    if (@($inv.servers).Count -lt 1) { $errs.Add("servers: список пуст") }
    if (@($inv.servers | Where-Object { $_.dns }).Count -lt 1) { $errs.Add("servers: нужен хотя бы один сервер с dns: true") }

    foreach ($p in @($inv.records.PSObject.Properties)) {
        $r = $p.Value
        if (-not ($p.Name -eq $inv.zone -or $p.Name.EndsWith(".$($inv.zone)"))) { $errs.Add("records.$($p.Name): имя должно быть $($inv.zone) или *.$($inv.zone)") }
        if (-not $r.port) { $errs.Add("records.$($p.Name): не задан port") }
        if (-not $r.path -or -not ([string]$r.path).StartsWith('/')) { $errs.Add("records.$($p.Name): path должен начинаться с /") }
        foreach ($n in @($r.servers)) {
            if (-not $byName.ContainsKey($n)) { $errs.Add("records.$($p.Name): неизвестный сервер '$n'") }
        }
    }

    if ($errs.Count -gt 0) { throw ("inventory.json:`n  " + ($errs -join "`n  ")) }
    $inv | Add-Member -NotePropertyName ByName -NotePropertyValue $byName -Force
    return $inv
}

function Read-DotEnv([string]$path) {
    # простой парсер KEY=VALUE, комментарии и пустые строки пропускаются
    $vars = @{}
    if (Test-Path $path) {
        foreach ($line in Get-Content $path -Encoding UTF8) {
            if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
            $k, $v = $line -split '=', 2
            $vars[$k.Trim()] = $v.Trim().Trim('"').Trim("'")
        }
    }
    return $vars
}

function Get-AdminPassword([string]$envPath, [switch]$CreateIfMissing) {
    # пароль админки: переменная окружения DNS_ADMIN_PASSWORD, иначе .env в корне репо
    if ($env:DNS_ADMIN_PASSWORD) { return $env:DNS_ADMIN_PASSWORD }
    $vars = Read-DotEnv $envPath
    if ($vars['ADMIN_PASSWORD'] -and $vars['ADMIN_PASSWORD'] -ne 'change-me') { return $vars['ADMIN_PASSWORD'] }
    if (-not $CreateIfMissing) { throw "Нет пароля админки: задай ADMIN_PASSWORD в $envPath (пример в .env.example)" }
    $alphabet = [char[]]'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $pw = -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
    [IO.File]::WriteAllText($envPath, "ADMIN_PASSWORD=$pw`n", (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Сгенерирован пароль админки и сохранён в $envPath" -ForegroundColor Yellow
    return $pw
}

function Get-AuthHeader([string]$user, [string]$password) {
    return @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${user}:${password}")) }
}
