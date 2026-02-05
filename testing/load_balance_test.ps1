# Load Balance Test Script
# Uses Tor stream isolation to force new circuits for each request

param(
    [Parameter(Mandatory=$true)]
    [string]$OnionAddress,
    
    [Parameter(Mandatory=$false)]
    [int]$NumRequests = 10,
    
    [Parameter(Mandatory=$false)]
    [string]$TorProxy = "127.0.0.1:9150",
    
    [Parameter(Mandatory=$false)]
    [int]$DelaySeconds = 1
)

$masterOnion = $OnionAddress
$torProxy = $TorProxy
$testCount = $NumRequests
$delaySeconds = $DelaySeconds

Write-Host "Testing load balancing with $testCount requests, $delaySeconds second intervals"
Write-Host "Master onion: $masterOnion"
Write-Host "Using Tor SOCKS proxy: $torProxy"
Write-Host ""

for ($i = 1; $i -le $testCount; $i++) {
    $randomUser = "user" + (Get-Random -Maximum 999999)
    $timestamp = Get-Date -Format "HH:mm:ss"
    
    Write-Host "[$timestamp] Request #$i (circuit: $randomUser)... " -NoNewline
    
    try {
        $result = curl.exe --socks5-hostname "${randomUser}:pass@${torProxy}" `
            "http://${masterOnion}/" `
            -s -o NUL -w "%{http_code}" `
            --max-time 30 2>&1
        
        if ($result -eq "200") {
            Write-Host "OK (HTTP $result)" -ForegroundColor Green
        } else {
            Write-Host "Response: $result" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
    }
    
    if ($i -lt $testCount) {
        Start-Sleep -Seconds $delaySeconds
    }
}

Write-Host ""
Write-Host "Test complete. Check VM logs to see distribution:"
Write-Host "  VM1: ssh -i ~/.ssh/rustbalance_test hlu1@192.168.40.144 'journalctl -u rustbalance --since \"5 min ago\" | grep Session'"
Write-Host "  VM2: ssh -i ~/.ssh/rustbalance_test hlu1@192.168.40.145 'journalctl -u rustbalance --since \"5 min ago\" | grep Session'"
