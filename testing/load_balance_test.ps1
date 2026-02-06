# Load Balance Test Script
# Forces fresh descriptor fetch (HSFORGET) + unique circuit per request to ensure
# Tor picks from the LATEST merged descriptor on HSDirs, then randomly selects
# an intro point — testing that traffic distributes across RustBalance nodes.

param(
    [Parameter(Mandatory=$true)]
    [string]$OnionAddress,
    
    [Parameter(Mandatory=$false)]
    [int]$NumRequests = 10,
    
    [Parameter(Mandatory=$false)]
    [string]$TorProxy = "127.0.0.1:9150",
    
    [Parameter(Mandatory=$false)]
    [int]$DelaySeconds = 5,

    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 60,

    [Parameter(Mandatory=$false)]
    [switch]$CheckLogs,

    [Parameter(Mandatory=$false)]
    [int]$TorControlPort = 9151,

    [Parameter(Mandatory=$false)]
    [string]$TorControlPassword = "",

    [Parameter(Mandatory=$false)]
    [string]$TorCookieFile = ""
)

$masterOnion = $OnionAddress
$torProxy = $TorProxy
$testCount = $NumRequests
$sshKey = "$env:USERPROFILE\.ssh\rustbalance_test"

# --- Descriptor refresh helper ---
# Uses HSFETCH to force Tor to re-fetch the descriptor from HSDirs.
# This ensures the client gets the latest merged descriptor with all nodes' intro points.
# Also sends SIGNAL NEWNYM to clear existing circuits.
function Send-DescriptorRefresh {
    param(
        [string]$Address,
        [int]$ControlPort,
        [string]$Password,
        [string]$CookieFile
    )
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect("127.0.0.1", $ControlPort)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        # Authenticate - prefer cookie auth, fall back to password
        if ($CookieFile -ne "" -and (Test-Path $CookieFile)) {
            $cookieBytes = [System.IO.File]::ReadAllBytes($CookieFile)
            $cookieHex = ($cookieBytes | ForEach-Object { $_.ToString("X2") }) -join ''
            $writer.WriteLine("AUTHENTICATE $cookieHex")
        } elseif ($Password -ne "") {
            $writer.WriteLine("AUTHENTICATE `"$Password`"")
        } else {
            $writer.WriteLine('AUTHENTICATE ""')
        }
        $authReply = $reader.ReadLine()
        if ($authReply -notmatch "^250") {
            $client.Close()
            return "AUTH_FAIL: $authReply"
        }

        # SIGNAL NEWNYM to clear all existing circuits first
        $writer.WriteLine("SIGNAL NEWNYM")
        $nymReply = $reader.ReadLine()

        # HSFETCH forces Tor to fetch a fresh descriptor from HSDirs
        # Since our merged descriptor has a higher revision counter,
        # it should replace any cached stale descriptor
        $addrNoOnion = $Address -replace '\.onion$', ''
        $writer.WriteLine("HSFETCH $addrNoOnion")
        $fetchReply = $reader.ReadLine()

        $writer.WriteLine("QUIT")
        $client.Close()

        if ($fetchReply -match "^250") {
            return "OK"
        } else {
            return "FETCH_FAIL: $fetchReply"
        }
    } catch {
        return "ERROR: $_"
    }
}

# Track results
$successes = 0
$failures = 0
$results = @()

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  RustBalance Load Balancing Test" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Master onion : $masterOnion"
Write-Host "  Tor proxy    : $torProxy"
Write-Host "  Control port : 127.0.0.1:$TorControlPort"
Write-Host "  Requests     : $testCount"
Write-Host "  Delay        : ${DelaySeconds}s between requests"
Write-Host "  Timeout      : ${TimeoutSeconds}s per request"
Write-Host ""
Write-Host "  Each request: HSFETCH (fresh descriptor) + NEWNYM (new circuits)"
Write-Host "  + unique SOCKS username (circuit isolation)."
Write-Host ""

# Auto-detect cookie file if not specified
if ($TorCookieFile -eq "") {
    # Common Tor Browser locations on Windows
    $candidatePaths = @(
        "$env:USERPROFILE\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\control_auth_cookie",
        "$env:APPDATA\Tor Browser\Browser\TorBrowser\Data\Tor\control_auth_cookie",
        "$env:USERPROFILE\OneDrive\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\control_auth_cookie"
    )
    foreach ($path in $candidatePaths) {
        if (Test-Path $path) {
            $TorCookieFile = $path
            break
        }
    }
}
if ($TorCookieFile -ne "" -and (Test-Path $TorCookieFile)) {
    Write-Host "  Cookie file  : Found (using cookie auth)" -ForegroundColor Green
} else {
    Write-Host "  Cookie file  : Not found (using password auth)" -ForegroundColor Yellow
}

# Pre-flight: verify control port access
$preflight = Send-DescriptorRefresh -Address $masterOnion -ControlPort $TorControlPort -Password $TorControlPassword -CookieFile $TorCookieFile
if ($preflight -eq "OK") {
    Write-Host "  Control port : Connected OK (HSFETCH + NEWNYM works)" -ForegroundColor Green
} else {
    Write-Host "  Control port : $preflight" -ForegroundColor Red
    Write-Host "  WARNING: Cannot send HSFETCH - stale descriptor cache may cause skewed results." -ForegroundColor Yellow
    Write-Host "  Tip: Tor Browser control port is usually 9151. Use -TorControlPort to set." -ForegroundColor Yellow
    Write-Host "  Tip: If auth fails, set -TorControlPassword or ensure CookieAuth is enabled." -ForegroundColor Yellow
}
Write-Host ""

# Record start time for log queries
$testStart = [DateTimeOffset]::UtcNow

for ($i = 1; $i -le $testCount; $i++) {
    # Step 1: HSFETCH to force fresh descriptor fetch from HSDirs + NEWNYM to clear circuits
    $forgetResult = Send-DescriptorRefresh -Address $masterOnion -ControlPort $TorControlPort -Password $TorControlPassword -CookieFile $TorCookieFile
    
    # Step 2: Wait for async HSFETCH to complete and NEWNYM to take effect
    Start-Sleep -Seconds 3
    
    # Step 3: Unique username per request = unique Tor circuit = new intro point selection
    $randomUser = "lbtest_" + (Get-Random -Maximum 999999)
    $timestamp = Get-Date -Format "HH:mm:ss"
    
    $forgetStatus = if ($forgetResult -eq "OK") { "fresh desc" } else { "cached" }
    Write-Host "[$timestamp] Request #$i/$testCount ($forgetStatus, circuit: $randomUser)... " -NoNewline
    
    try {
        $result = curl.exe --socks5-hostname "${randomUser}:pass@${torProxy}" `
            "http://${masterOnion}/" `
            -s -o NUL -w "%{http_code}|%{time_total}" `
            --max-time $TimeoutSeconds 2>&1
        
        $parts = $result -split '\|'
        $httpCode = $parts[0]
        $duration = if ($parts.Count -gt 1) { $parts[1] } else { "?" }
        
        # Any HTTP response means a node handled it (200, 301, 302 are all valid)
        if ($httpCode -match '^\d{3}$') {
            $successes++
            $results += $httpCode
            if ($httpCode -eq "200") {
                Write-Host "OK (HTTP $httpCode, ${duration}s)" -ForegroundColor Green
            } else {
                Write-Host "Reached node (HTTP $httpCode, ${duration}s)" -ForegroundColor Yellow
            }
        } else {
            $failures++
            $results += "FAIL"
            Write-Host "FAILED: $result" -ForegroundColor Red
        }
    } catch {
        $failures++
        $results += "ERROR"
        Write-Host "ERROR: $_" -ForegroundColor Red
    }
    
    if ($i -lt $testCount) {
        Write-Host "  Waiting ${DelaySeconds}s before next request..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $DelaySeconds
    }
}

# Summary
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Results Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Successful : $successes / $testCount" -ForegroundColor $(if ($successes -eq $testCount) { "Green" } else { "Yellow" })
Write-Host "  Failed     : $failures / $testCount" -ForegroundColor $(if ($failures -eq 0) { "Green" } else { "Red" })
Write-Host "  Responses  : $($results -join ', ')"
Write-Host ""

# Automated log check
if ($CheckLogs -or ($successes -gt 0)) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Checking VM Logs for Distribution" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Give a moment for logs to flush
    Start-Sleep -Seconds 2
    
    $vm1Sessions = ssh -i $sshKey hlu1@192.168.40.144 "journalctl -u rustbalance --since '10 min ago' --no-pager 2>/dev/null | grep -c 'Session #'" 2>$null
    $vm2Sessions = ssh -i $sshKey hlu1@192.168.40.145 "journalctl -u rustbalance --since '10 min ago' --no-pager 2>/dev/null | grep -c 'Session #'" 2>$null
    
    $vm1Count = if ($vm1Sessions -match '^\d+$') { [int]$vm1Sessions } else { 0 }
    $vm2Count = if ($vm2Sessions -match '^\d+$') { [int]$vm2Sessions } else { 0 }
    $totalSessions = $vm1Count + $vm2Count
    
    Write-Host "  VM1 (hlsn1) handled : $vm1Count sessions" -ForegroundColor Cyan
    Write-Host "  VM2 (hlsn2) handled : $vm2Count sessions" -ForegroundColor Cyan
    Write-Host "  Total               : $totalSessions sessions"
    Write-Host ""
    
    if ($totalSessions -gt 0) {
        $vm1Pct = [math]::Round(($vm1Count / $totalSessions) * 100, 1)
        $vm2Pct = [math]::Round(($vm2Count / $totalSessions) * 100, 1)
        
        # Visual bar
        $barLen = 40
        $vm1Bar = [math]::Round($vm1Pct / 100 * $barLen)
        $vm2Bar = $barLen - $vm1Bar
        
        Write-Host "  Distribution:" -ForegroundColor White
        $vm1BarStr = "#" * $vm1Bar + "-" * $vm2Bar
        $vm2BarStr = "-" * $vm1Bar + "#" * $vm2Bar
        Write-Host "  VM1 [$vm1BarStr] ${vm1Pct}%" -ForegroundColor Cyan
        Write-Host "  VM2 [$vm2BarStr] ${vm2Pct}%" -ForegroundColor Cyan
        Write-Host ""
        
        if ($vm1Count -gt 0 -and $vm2Count -gt 0) {
            Write-Host "  LOAD BALANCING CONFIRMED - Both nodes received traffic!" -ForegroundColor Green
        } elseif ($totalSessions -lt $successes) {
            Write-Host "  Fewer sessions than successes - some may have hit the same node" -ForegroundColor Yellow
        } else {
            Write-Host "  WARNING: All traffic went to one node. With $testCount requests this" -ForegroundColor Yellow
            Write-Host "     can happen by chance. Try more requests (-NumRequests 20)." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  WARNING: No sessions found in logs. Sessions may predate the log window." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Test Complete" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
