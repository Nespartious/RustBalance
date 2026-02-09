# RustBalance Deployment Verification Script
# Run this from the Windows development machine after every deployment.
# It SSHs into both VMs and collects health data in a single pass.
#
# Usage:
#   .\testing\verify_deployment.ps1
#   .\testing\verify_deployment.ps1 -Detailed
#   .\testing\verify_deployment.ps1 -VM1Only
#   .\testing\verify_deployment.ps1 -VM2Only

param(
    [switch]$Detailed,
    [switch]$VM1Only,
    [switch]$VM2Only
)

$sshKey = "$env:USERPROFILE\.ssh\rustbalance_test"
$vm1 = "hlu1@192.168.40.144"
$vm2 = "hlu1@192.168.40.145"
$sudoPass = "pass"

# Colors
$C_HEAD  = "Cyan"
$C_OK    = "Green"
$C_WARN  = "Yellow"
$C_FAIL  = "Red"
$C_DIM   = "DarkGray"
$C_WHITE = "White"

$totalChecks = 0
$passedChecks = 0
$failedChecks = 0
$warnings = 0

function Write-Check {
    param([string]$Label, [string]$Value, [string]$Status)
    $script:totalChecks++
    $icon = switch ($Status) {
        "pass" { $script:passedChecks++; "  [PASS]" }
        "warn" { $script:warnings++;     "  [WARN]" }
        "fail" { $script:failedChecks++; "  [FAIL]" }
    }
    $color = switch ($Status) { "pass" { $C_OK } "warn" { $C_WARN } "fail" { $C_FAIL } }
    Write-Host "$icon " -ForegroundColor $color -NoNewline
    Write-Host "$Label : " -ForegroundColor $C_WHITE -NoNewline
    Write-Host "$Value" -ForegroundColor $color
}

function Get-Section {
    param([string]$Text, [string]$Start, [string]$End)
    $pattern = "(?s)===${Start}===\s*(\r?\n)+(.*?)(\r?\n)===${End}==="
    if ($Text -match $pattern) {
        return ($Matches[2]).Trim()
    }
    return ""
}

function Get-VMHealth {
    param([string]$VMHost, [string]$VMName)

    Write-Host ""
    Write-Host "  -- $VMName ($VMHost) --" -ForegroundColor $C_HEAD
    Write-Host ""

    # Single SSH call - run all checks in one shot, parse the output
    $checkScript = @"
echo $sudoPass | sudo -S bash -c '
echo "===SERVICE_STATUS==="
systemctl is-active rustbalance 2>/dev/null || echo "inactive"

echo "===UPTIME==="
ps -eo etime,comm 2>/dev/null | grep rustbalance | head -1 | sed "s/rustbalance//" | xargs || echo "not-running"

echo "===WG_PEERS==="
wg show wg-rb 2>/dev/null | grep -c "peer:" || echo "0"

echo "===WG_HANDSHAKES==="
wg show wg-rb latest-handshakes 2>/dev/null || echo "none"

echo "===TOR_STATUS==="
systemctl is-active tor@default 2>/dev/null || systemctl is-active tor 2>/dev/null || echo "inactive"

echo "===ERROR_COUNT==="
journalctl -u rustbalance --no-pager -n 500 2>/dev/null | grep -ciE "error" || echo "0"

echo "===WARN_COUNT==="
journalctl -u rustbalance --no-pager -n 500 2>/dev/null | grep -ciE "warn" || echo "0"

echo "===PEER_HEALTH==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -iE "peer.*healthy|peer.*lifecycle" | tail -3

echo "===PUBLISH_STATUS==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -iE "HSPOST.*accepted|published.*descriptor|Successfully published" | tail -3

echo "===ELECTION==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -iE "Publisher is now|became publisher|election|Taking over" | tail -3

echo "===INTRO_POINTS==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -iE "introduction points|intro.*point" | tail -3

echo "===RECENT_ERRORS==="
journalctl -u rustbalance --no-pager -n 500 2>/dev/null | grep -iE "error" | tail -5

# OB config presence and ControlPort GETCONF check
echo "===OB_CONFIG==="
HS_DIR="/var/lib/tor/rustbalance_node_hs"
if [ -f "$HS_DIR/ob_config" ]; then echo "present"; sed -n '1,5p' "$HS_DIR/ob_config"; else echo "missing"; fi

echo "===GETCONF_OBINSTANCE==="
python3 - <<'PY'
import socket, time, binascii
try:
    cookie = binascii.hexlify(open('/run/tor/control.authcookie','rb').read()).decode()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 9051))
    def send(cmd):
        s.sendall((cmd + '\r\n').encode())
        time.sleep(0.3)
        data = b''
        while True:
            try:
                s.settimeout(1.0)
                chunk = s.recv(65536)
                if not chunk: break
                data += chunk
            except: break
        return data.decode(errors='replace')
    print(send('AUTHENTICATE ' + cookie).strip().splitlines()[-1])
    print(send('GETCONF HiddenServiceOnionbalanceInstance').strip())
    s.close()
except Exception as e:
    print('ERROR:'+str(e))
PY

echo "===END==="
' 2>/dev/null
"@

    $enc = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($checkScript))
    $raw = ssh -i $sshKey $VMHost "echo $enc | base64 -d | bash" 2>&1

    if ($LASTEXITCODE -ne 0 -and -not $raw) {
        Write-Check "SSH Connection" "FAILED - cannot reach $VMHost" "fail"
        return
    }

    $output = ($raw | Out-String)

    $serviceStatus = Get-Section $output "SERVICE_STATUS" "UPTIME"
    $uptime        = Get-Section $output "UPTIME" "WG_PEERS"
    $wgPeers       = Get-Section $output "WG_PEERS" "WG_HANDSHAKES"
    $wgHandshakes  = Get-Section $output "WG_HANDSHAKES" "TOR_STATUS"
    $torStatus     = Get-Section $output "TOR_STATUS" "ERROR_COUNT"
    $errorCount    = Get-Section $output "ERROR_COUNT" "WARN_COUNT"
    $warnCount     = Get-Section $output "WARN_COUNT" "PEER_HEALTH"
    $peerHealth    = Get-Section $output "PEER_HEALTH" "PUBLISH_STATUS"
    $publishStatus = Get-Section $output "PUBLISH_STATUS" "ELECTION"
    $election      = Get-Section $output "ELECTION" "INTRO_POINTS"
    $introPoints   = Get-Section $output "INTRO_POINTS" "RECENT_ERRORS"
    $recentErrors  = Get-Section $output "RECENT_ERRORS" "OB_CONFIG"
    $obConfig      = Get-Section $output "OB_CONFIG" "GETCONF_OBINSTANCE"
    $getconfOb     = Get-Section $output "GETCONF_OBINSTANCE" "END"

    # --- Evaluate each check ---

    # 1. Service status
    $svcClean = ($serviceStatus -split "`n" | Select-Object -Last 1).Trim()
    if ($svcClean -eq "active") {
        Write-Check "RustBalance service" "active" "pass"
    } else {
        Write-Check "RustBalance service" "$svcClean" "fail"
    }

    # 2. Uptime
    $uptimeClean = ($uptime -split "`n" | Select-Object -Last 1).Trim()
    if ($uptimeClean -and $uptimeClean -ne "not-running") {
        Write-Check "Process uptime" "$uptimeClean" "pass"
    } else {
        Write-Check "Process uptime" "not running" "fail"
    }

    # 3. Tor status
    $torClean = ($torStatus -split "`n" | Select-Object -Last 1).Trim()
    if ($torClean -eq "active") {
        Write-Check "Tor daemon" "active" "pass"
    } else {
        Write-Check "Tor daemon" "$torClean" "fail"
    }

    # 4. WireGuard peers
    $peerCountClean = ($wgPeers -split "`n" | Select-Object -Last 1).Trim()
    $peerCount = 0
    if ($peerCountClean -match '^\d+$') { $peerCount = [int]$peerCountClean }
    if ($peerCount -ge 1) {
        Write-Check "WireGuard peers" "$peerCount connected" "pass"
    } else {
        Write-Check "WireGuard peers" "0 (no peers)" "warn"
    }

    # 5. WG handshake recency
    if ($wgHandshakes -and $wgHandshakes -ne "none") {
        $handshakeLines = $wgHandshakes -split "`n" | Where-Object { $_ -match '\d+' }
        $stale = $false
        foreach ($line in $handshakeLines) {
            if ($line -match '(\d+)\s*$') {
                $secs = [int]$Matches[1]
                if ($secs -gt 300) { $stale = $true }
            }
        }
        if ($stale) {
            Write-Check "WG handshake" "stale (>5 min)" "warn"
        } else {
            Write-Check "WG handshake" "recent" "pass"
        }
    } elseif ($peerCount -gt 0) {
        Write-Check "WG handshake" "no data" "warn"
    }

    # 6. Error count
    $errClean = ($errorCount -split "`n" | Select-Object -Last 1).Trim()
    $errNum = 0
    if ($errClean -match '^\d+$') { $errNum = [int]$errClean }
    if ($errNum -eq 0) {
        Write-Check "Errors (last 500 log lines)" "0" "pass"
    } elseif ($errNum -le 5) {
        Write-Check "Errors (last 500 log lines)" "$errNum" "warn"
    } else {
        Write-Check "Errors (last 500 log lines)" "$errNum" "fail"
    }

    # 7. Warning count
    $warnClean = ($warnCount -split "`n" | Select-Object -Last 1).Trim()
    $warnNum = 0
    if ($warnClean -match '^\d+$') { $warnNum = [int]$warnClean }
    if ($warnNum -eq 0) {
        Write-Check "Warnings (last 500 log lines)" "0" "pass"
    } else {
        Write-Check "Warnings (last 500 log lines)" "$warnNum" "warn"
    }

    # 8. Peer health
    if ($peerHealth) {
        $healthLines = ($peerHealth -split "`n") | Where-Object { $_.Trim() }
        $lastHealth = ($healthLines | Select-Object -Last 1).Trim()
        if ($lastHealth -match "Healthy") {
            Write-Check "Peer health" "Healthy" "pass"
        } elseif ($lastHealth -match "Initializing|Joining") {
            Write-Check "Peer health" "Initializing (may need time)" "warn"
        } else {
            Write-Check "Peer health" "$lastHealth" "warn"
        }
    } else {
        if ($peerCount -gt 0) {
            Write-Check "Peer health" "no health log found" "warn"
        }
    }

    # 9. Publishing status
    if ($publishStatus) {
        $lastPublish = ($publishStatus -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1).Trim()
        if ($lastPublish -match "accepted|Successfully published") {
            Write-Check "Descriptor publishing" "OK" "pass"
        } else {
            Write-Check "Descriptor publishing" "see logs" "warn"
        }
    } else {
        # Not all nodes publish - only the elected publisher
        if ($election -match "Publisher is now.*$VMName") {
            Write-Check "Descriptor publishing" "elected but no publish found" "warn"
        }
    }

    # 10. Election
    if ($election) {
        $lastElection = ($election -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1).Trim()
        if ($lastElection -match "Publisher is now: (\S+)") {
            Write-Check "Election" "Publisher: $($Matches[1])" "pass"
        } elseif ($lastElection -match "Taking over as publisher") {
            Write-Check "Election" "This node is publisher" "pass"
        } else {
            Write-Check "Election" "$lastElection" "pass"
        }
    }

    # 11. ob_config file present
    if ($obConfig) {
        $firstLine = ($obConfig -split "`n" | Select-Object -First 1).Trim()
        if ($firstLine -match "^present") {
            # next non-empty line should contain MasterOnionAddress
            $contentLine = ($obConfig -split "`n" | Where-Object { $_ -match 'MasterOnionAddress' } | Select-Object -First 1)
            if ($contentLine -and $contentLine -match "MasterOnionAddress\s+\S+") {
                Write-Check "ob_config" "present and contains MasterOnionAddress" "pass"
            } else {
                Write-Check "ob_config" "present but missing MasterOnionAddress" "warn"
            }
        } elseif ($firstLine -match "missing") {
            Write-Check "ob_config" "missing from HS dir" "warn"
        } else {
            Write-Check "ob_config" "unknown state" "warn"
        }
    } else {
        Write-Check "ob_config" "no data returned" "warn"
    }

    # 12. Tor GETCONF HiddenServiceOnionbalanceInstance
    if ($getconfOb) {
        $got = ($getconfOb -split "`n" | Where-Object { $_ -match 'HiddenServiceOnionbalanceInstance' } | Select-Object -First 1).Trim()
        if ($got -match "HiddenServiceOnionbalanceInstance\s*=\s*1" -or $got -match "HiddenServiceOnionbalanceInstance\s*1") {
            Write-Check "GETCONF HiddenServiceOnionbalanceInstance" "1" "pass"
        } elseif ($got -match "ERROR:") {
            Write-Check "GETCONF HiddenServiceOnionbalanceInstance" "control port error" "warn"
        } else {
            Write-Check "GETCONF HiddenServiceOnionbalanceInstance" "$got" "warn"
        }
    } else {
        Write-Check "GETCONF HiddenServiceOnionbalanceInstance" "no response" "warn"
    }

    # Detailed output
    if ($Detailed) {
        Write-Host ""
        Write-Host "  -- Detailed Logs --" -ForegroundColor $C_DIM

        if ($introPoints) {
            Write-Host "  Intro points:" -ForegroundColor $C_DIM
            $introPoints -split "`n" | ForEach-Object {
                if ($_.Trim()) { Write-Host "    $($_.Trim())" -ForegroundColor $C_DIM }
            }
        }

        if ($recentErrors -and $errNum -gt 0) {
            Write-Host "  Recent errors:" -ForegroundColor $C_FAIL
            $recentErrors -split "`n" | ForEach-Object {
                if ($_.Trim()) { Write-Host "    $($_.Trim())" -ForegroundColor $C_FAIL }
            }
        }

        if ($wgHandshakes -and $wgHandshakes -ne "none") {
            Write-Host "  WG handshakes:" -ForegroundColor $C_DIM
            $wgHandshakes -split "`n" | ForEach-Object {
                if ($_.Trim()) { Write-Host "    $($_.Trim())" -ForegroundColor $C_DIM }
            }
        }

        # OB config diagnostic
        if ($obConfig) {
            Write-Host "  ob_config:" -ForegroundColor $C_DIM
            $obConfig -split "`n" | ForEach-Object {
                if ($_.Trim()) { Write-Host "    $($_.Trim())" -ForegroundColor $C_DIM }
            }
        }

        if ($getconfOb) {
            Write-Host "  Tor GETCONF HiddenServiceOnionbalanceInstance:" -ForegroundColor $C_DIM
            $getconfOb -split "`n" | ForEach-Object {
                if ($_.Trim()) { Write-Host "    $($_.Trim())" -ForegroundColor $C_DIM }
            }
        }
    }
}

# -- Main --

Write-Host ""
Write-Host "============================================" -ForegroundColor $C_HEAD
Write-Host "  RustBalance Deployment Verification" -ForegroundColor $C_HEAD
Write-Host "============================================" -ForegroundColor $C_HEAD
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $C_DIM
Write-Host "  Mode: $(if ($Detailed) { 'Detailed' } else { 'Standard' })" -ForegroundColor $C_DIM

if (-not $VM2Only) {
    Get-VMHealth -VMHost $vm1 -VMName "VM1-hlsn1"
}

if (-not $VM1Only) {
    Get-VMHealth -VMHost $vm2 -VMName "VM2-hlsn2"
}

# -- Summary --

Write-Host ""
Write-Host "============================================" -ForegroundColor $C_HEAD
Write-Host "  Summary" -ForegroundColor $C_HEAD
Write-Host "============================================" -ForegroundColor $C_HEAD

$resultColor = if ($failedChecks -eq 0 -and $warnings -eq 0) { $C_OK }
               elseif ($failedChecks -eq 0) { $C_WARN }
               else { $C_FAIL }

Write-Host "  Passed  : $passedChecks" -ForegroundColor $C_OK
if ($warnings -gt 0) {
    Write-Host "  Warnings: $warnings" -ForegroundColor $C_WARN
}
if ($failedChecks -gt 0) {
    Write-Host "  Failed  : $failedChecks" -ForegroundColor $C_FAIL
}
Write-Host "  Total   : $totalChecks checks" -ForegroundColor $C_WHITE
Write-Host ""

if ($failedChecks -eq 0 -and $warnings -eq 0) {
    Write-Host "  RESULT: ALL CHECKS PASSED" -ForegroundColor $C_OK
} elseif ($failedChecks -eq 0) {
    Write-Host "  RESULT: PASSED WITH WARNINGS" -ForegroundColor $C_WARN
} else {
    Write-Host "  RESULT: DEPLOYMENT HAS ISSUES" -ForegroundColor $C_FAIL
}

Write-Host ""
Write-Host "  Next step: Run .\testing\load_balance_test.ps1 to verify traffic distribution" -ForegroundColor $C_DIM
Write-Host ""

# Exit code for CI
if ($failedChecks -gt 0) {
    exit 1
} else {
    exit 0
}
