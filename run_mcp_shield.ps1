$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Get-HealthyMcpShield([int]$Port) {
    try {
        $candidate = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/health" -TimeoutSec 1
        if ($candidate.status -eq 'ready' -and $candidate.mcp_endpoint -eq '/mcp') {
            return $candidate
        }
    } catch {
        return $null
    }
    return $null
}

function Test-LocalListener([int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connection = $client.ConnectAsync('127.0.0.1', $Port)
        return $connection.Wait(200) -and $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function New-ShieldToken {
    $tokenBytes = [byte[]]::new(32)
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($tokenBytes) } finally { $random.Dispose() }
    return [Convert]::ToBase64String($tokenBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$venv = Join-Path $PSScriptRoot '.venv'
$venvPython = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    $pythonCommand = Get-Command python -ErrorAction Stop
    & $pythonCommand.Source -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the project virtual environment.' }
    & $venvPython -m pip install -r (Join-Path $PSScriptRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed; see the pip output above.' }
}

$port = $null
for ($candidatePort = 8765; $candidatePort -le 8775; $candidatePort++) {
    $healthy = Get-HealthyMcpShield $candidatePort
    if ($healthy) {
        $port = $candidatePort
        Write-Host "MCP Shield is already running at http://127.0.0.1:$port" -ForegroundColor Green
        Start-Process "http://127.0.0.1:$port"
        exit 0
    }
    if (-not (Test-LocalListener $candidatePort)) {
        $port = $candidatePort
        break
    }
    Write-Host "Port $candidatePort is occupied by another local process; checking the next port." -ForegroundColor Yellow
}
if ($null -eq $port) { throw 'No free local port was found between 8765 and 8775.' }

$generatedClientToken = $false
$generatedApproverToken = $false
if ([string]::IsNullOrWhiteSpace($env:SHIELD_CLIENT_TOKEN)) {
    $env:SHIELD_CLIENT_TOKEN = New-ShieldToken
    $generatedClientToken = $true
}
if ([string]::IsNullOrWhiteSpace($env:SHIELD_APPROVER_TOKENS)) {
    $operatorToken = New-ShieldToken
    $env:SHIELD_APPROVER_TOKENS = '{"local-admin":"' + $operatorToken + '"}'
    $generatedApproverToken = $true
}

if ($generatedClientToken -or $generatedApproverToken) {
    Write-Host ''
    Write-Host 'One-time local credentials for this launch. Copy them into your local Codex MCP configuration and approval panel; they are not saved to a file.' -ForegroundColor Yellow
    if ($generatedClientToken) { Write-Host "SHIELD_CLIENT_TOKEN=$($env:SHIELD_CLIENT_TOKEN)" -ForegroundColor Yellow }
    if ($generatedApproverToken) { Write-Host "SHIELD_APPROVER_TOKEN=$operatorToken" -ForegroundColor Yellow }
}

$url = "http://127.0.0.1:$port"
$stdoutLog = Join-Path $PSScriptRoot 'mcp-shield.stdout.log'
$stderrLog = Join-Path $PSScriptRoot 'mcp-shield.stderr.log'
$server = Start-Process -FilePath $venvPython `
    -ArgumentList @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', "$port") `
    -WorkingDirectory $PSScriptRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutLog `
    -RedirectStandardError $stderrLog `
    -PassThru

try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($server.HasExited) {
            throw "MCP Shield exited during startup. Check $stderrLog."
        }
        $health = Get-HealthyMcpShield $port
        if ($health) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) { throw "MCP Shield did not become ready. Check $stderrLog." }

    Write-Host "MCP Shield is running at $url (MCP endpoint: $url/mcp)" -ForegroundColor Green
    Start-Process $url
    Write-Host 'Press Ctrl+C here to stop MCP Shield.' -ForegroundColor DarkGray
    while (-not $server.HasExited) { Start-Sleep -Milliseconds 500 }
} finally {
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}
