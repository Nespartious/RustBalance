# ============================================================================
#  RustBalance Post-Deployment Report
# ============================================================================
#  Generates a comprehensive system report after deployment.
#  Run from the Windows dev machine with Tor Browser open for session tests.
#
#  Usage:
#    .\testing\post_deployment_report.ps1
#    .\testing\post_deployment_report.ps1 -SkipSessions
#    .\testing\post_deployment_report.ps1 -SessionCount 15
# ============================================================================

param(
    [switch]$SkipSessions,
    [int]$SessionCount = 9,
    [string]$TorProxy = "127.0.0.1:9150",
    [int]$TorControlPort = 9151,
    [string]$TorCookieFile = ""
)

# -- Config --
$sshKey      = "$env:USERPROFILE\.ssh\rustbalance_test"
$vm1Host     = "hlu1@192.168.40.144"
$vm2Host     = "hlu1@192.168.40.145"
$sudoPass    = "pass"
$masterOnion = "bubheitejvryvqi3jpw6emd7sand4y7xynb2u2yzaqr3kbaotjq34kad.onion"

# -- Colors --
$C_TITLE = "Cyan"
$C_HEAD  = "White"
$C_OK    = "Green"
$C_WARN  = "Yellow"
$C_FAIL  = "Red"
$C_DIM   = "DarkGray"
$C_DATA  = "White"

$reportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ============================================================================
#  Helpers
# ============================================================================

function Write-Title {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor $C_TITLE
    Write-Host "  $Text" -ForegroundColor $C_TITLE
    Write-Host ("=" * 70) -ForegroundColor $C_TITLE
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "  --- $Text ---" -ForegroundColor $C_HEAD
}

function Write-Item {
    param([string]$Label, [string]$Value, [string]$Status = "info")
    $padded = $Label.PadRight(28)
    switch ($Status) {
        "pass" { Write-Host "    [OK]   " -ForegroundColor $C_OK -NoNewline; Write-Host "$padded $Value" -ForegroundColor $C_DATA }
        "warn" { Write-Host "    [WARN] " -ForegroundColor $C_WARN -NoNewline; Write-Host "$padded $Value" -ForegroundColor $C_WARN }
        "fail" { Write-Host "    [FAIL] " -ForegroundColor $C_FAIL -NoNewline; Write-Host "$padded $Value" -ForegroundColor $C_FAIL }
        default { Write-Host "    [----] " -ForegroundColor $C_DIM -NoNewline; Write-Host "$padded $Value" -ForegroundColor $C_DATA }
    }
}

function Get-Section {
    param([string]$Text, [string]$Start, [string]$End)
    $pattern = "(?s)===${Start}===\s*(\r?\n)+(.*?)(\r?\n)===${End}==="
    if ($Text -match $pattern) {
        return ($Matches[2]).Trim()
    }
    return ""
}

# ============================================================================
#  Data collection via SSH
#  Strategy: write a bash script to a temp file on the remote, execute with
#  sudo, capture output, delete temp file. This avoids all quoting issues
#  with bash -c '...' nesting.
# ============================================================================

# The bash script body -- using a literal here-string so PowerShell
# does NOT interpolate anything (no $variable expansion).
$bashScriptBody = @'
#!/bin/bash
echo "===OS_NAME==="
lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"'

echo "===KERNEL==="
uname -r

echo "===ARCH==="
uname -m

echo "===VM_HOSTNAME==="
hostname

echo "===VM_IP==="
hostname -I

echo "===MEMORY==="
free -h | awk '/Mem:/{print $2, $3, $7}'

echo "===DISK==="
df -h / | awk 'NR==2{print $2, $3, $4, $5}'

echo "===TOR_INSTALLED==="
tor --version 2>/dev/null | head -1 || echo "NOT INSTALLED"

echo "===WG_INSTALLED==="
wg --version 2>/dev/null || echo "NOT INSTALLED"

echo "===RUSTBALANCE_BIN==="
which rustbalance >/dev/null 2>&1 && rustbalance --version 2>/dev/null || echo "NOT FOUND"

echo "===CONFIG_EXISTS==="
if [ -f /etc/rustbalance/config.toml ]; then echo "YES"; else echo "NO"; fi

echo "===MASTERKEY_EXISTS==="
if [ -f /etc/rustbalance/master.key ]; then echo "YES"; else echo "NO"; fi

echo "===SERVICE_FILE==="
if systemctl list-unit-files 2>/dev/null | grep -q rustbalance; then echo "YES"; else echo "NO"; fi

echo "===SERVICE_STATUS==="
systemctl is-active rustbalance 2>/dev/null || echo "inactive"

echo "===SERVICE_ENABLED==="
systemctl is-enabled rustbalance 2>/dev/null || echo "disabled"

echo "===UPTIME==="
ps -eo etime,comm 2>/dev/null | grep rustbalance | head -1 | awk '{print $1}' || echo "not-running"

echo "===TOR_STATUS==="
systemctl is-active tor@default 2>/dev/null || systemctl is-active tor 2>/dev/null || echo "inactive"

echo "===TOR_ENABLED==="
systemctl is-enabled tor@default 2>/dev/null || systemctl is-enabled tor 2>/dev/null || echo "disabled"

echo "===NODE_ID==="
grep -oP 'id\s*=\s*"\K[^"]+' /etc/rustbalance/config.toml 2>/dev/null | head -1

echo "===NODE_PRIORITY==="
grep -oP 'priority\s*=\s*\K\d+' /etc/rustbalance/config.toml 2>/dev/null | head -1

echo "===CLUSTER_TOKEN==="
grep -oP 'cluster_token\s*=\s*"\K[^"]+' /etc/rustbalance/config.toml 2>/dev/null

echo "===TARGET_ADDR==="
grep -A2 '\[target\]' /etc/rustbalance/config.toml 2>/dev/null | grep -oP 'onion_address\s*=\s*"\K[^"]+'

echo "===TARGET_PORT==="
grep -A3 '\[target\]' /etc/rustbalance/config.toml 2>/dev/null | grep -oP 'port\s*=\s*\K\d+'

echo "===TARGET_TLS==="
grep -A4 '\[target\]' /etc/rustbalance/config.toml 2>/dev/null | grep -oP 'use_tls\s*=\s*\K\w+'

echo "===MASTER_ONION_CFG==="
grep -A2 '\[master\]' /etc/rustbalance/config.toml 2>/dev/null | grep -oP 'onion_address\s*=\s*"\K[^"]+'

echo "===NODE_HS_HOSTNAME==="
cat /var/lib/tor/rustbalance_node_hs/hostname 2>/dev/null || echo "NOT FOUND"

echo "===WG_INTERFACE==="
ip link show wg-rb 2>/dev/null | head -1 || echo "NOT FOUND"

echo "===WG_TUNNEL_IP==="
grep -oP 'tunnel_ip\s*=\s*"\K[^"]+' /etc/rustbalance/config.toml 2>/dev/null | head -1

echo "===WG_PUBKEY==="
grep 'public_key' /etc/rustbalance/config.toml 2>/dev/null | head -1 | awk -F'"' '{print $2}'

echo "===WG_ENDPOINT==="
grep -oP 'external_endpoint\s*=\s*"\K[^"]+' /etc/rustbalance/config.toml 2>/dev/null | head -1

echo "===WG_PEERS_LIVE==="
wg show wg-rb 2>/dev/null | grep -c "peer:" || echo "0"

echo "===WG_HANDSHAKE_RAW==="
wg show wg-rb latest-handshakes 2>/dev/null || echo "none"

echo "===PEER_LIFECYCLE==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -iE 'lifecycle|peer.*Healthy' | tail -3

echo "===PUBLISHER_LOG==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -iE 'Taking over as publisher|Publisher is now' | tail -3

echo "===LAST_PUBLISH==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -iE 'Successfully published merged|HSPOST.*accepted' | tail -3

echo "===PUBLISH_INTRO_MERGE==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -iE 'Publishing merged descriptor with|merging.*intro' | tail -3

echo "===MULTINODE_STATUS==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -iE 'Multi-node|auto-detect' | tail -3

echo "===OWN_INTRO_POINTS==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -iE 'Successfully decrypted descriptor with' | tail -1

echo "===ERROR_COUNT==="
journalctl -u rustbalance --no-pager -n 500 2>/dev/null | grep -ciE 'error' || echo "0"

echo "===WARN_COUNT==="
journalctl -u rustbalance --no-pager -n 500 2>/dev/null | grep -ciE 'warn' || echo "0"

echo "===RECENT_ERRORS==="
journalctl -u rustbalance --no-pager -n 500 2>/dev/null | grep -iE 'error' | tail -5

echo "===SESSION_COUNT==="
journalctl -u rustbalance --no-pager 2>/dev/null | grep -c 'Session #' || echo "0"

echo "===END==="
'@

function Collect-VMData {
    param([string]$VMHost)

    # Write bash script to a local temp file with Unix line endings (LF only).
    # CRLF line endings would break bash commands like 'hostname -I'.
    $tmpLocal = [System.IO.Path]::GetTempFileName()
    $lfBody = $bashScriptBody -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($tmpLocal, $lfBody, (New-Object System.Text.UTF8Encoding($false)))

    # SCP the script to the remote VM, then SSH to execute with sudo.
    # This avoids all quoting and command-length issues.
    $remotePath = "/tmp/_rb_collect_$([System.IO.Path]::GetRandomFileName().Replace('.',''))"
    scp -i $sshKey -o ConnectTimeout=10 -o StrictHostKeyChecking=no $tmpLocal "${VMHost}:${remotePath}" 2>$null
    $raw = ssh -i $sshKey -o ConnectTimeout=10 -o StrictHostKeyChecking=no $VMHost "chmod +x $remotePath; echo $sudoPass | sudo -S bash $remotePath 2>/dev/null; rm -f $remotePath" 2>&1

    Remove-Item $tmpLocal -Force -ErrorAction SilentlyContinue

    if ($LASTEXITCODE -ne 0 -and -not $raw) {
        return $null
    }
    return ($raw | Out-String)
}

# ============================================================================
#  Collect data from both VMs
# ============================================================================

Write-Title "RustBalance Post-Deployment Report"
Write-Host "  Generated : $reportTime" -ForegroundColor $C_DIM
Write-Host "  Master    : $masterOnion" -ForegroundColor $C_DIM

Write-Host ""
Write-Host "  Collecting data from VMs..." -ForegroundColor $C_DIM

$vm1Data = Collect-VMData -VMHost $vm1Host
$vm2Data = Collect-VMData -VMHost $vm2Host

if (-not $vm1Data -and -not $vm2Data) {
    Write-Host "  FATAL: Cannot reach either VM. Check SSH connectivity." -ForegroundColor $C_FAIL
    exit 1
}

# ============================================================================
#  Process each VM
# ============================================================================

function Process-VMReport {
    param([string]$Data, [string]$VMLabel, [string]$VMIPAddr)

    Write-Title "$VMLabel ($VMIPAddr)"

    if (-not $Data) {
        Write-Host "    UNREACHABLE - SSH connection failed" -ForegroundColor $C_FAIL
        return @{ reachable = $false }
    }

    # Extract all sections
    $osName       = Get-Section $Data "OS_NAME" "KERNEL"
    $kernel       = Get-Section $Data "KERNEL" "ARCH"
    $arch         = Get-Section $Data "ARCH" "VM_HOSTNAME"
    $vmHostname   = Get-Section $Data "VM_HOSTNAME" "VM_IP"
    $vmIp         = Get-Section $Data "VM_IP" "MEMORY"
    $memory       = Get-Section $Data "MEMORY" "DISK"
    $disk         = Get-Section $Data "DISK" "TOR_INSTALLED"
    $torInstalled = Get-Section $Data "TOR_INSTALLED" "WG_INSTALLED"
    $wgInstalled  = Get-Section $Data "WG_INSTALLED" "RUSTBALANCE_BIN"
    $rbBin        = Get-Section $Data "RUSTBALANCE_BIN" "CONFIG_EXISTS"
    $configExists = Get-Section $Data "CONFIG_EXISTS" "MASTERKEY_EXISTS"
    $masterKey    = Get-Section $Data "MASTERKEY_EXISTS" "SERVICE_FILE"
    $serviceFile  = Get-Section $Data "SERVICE_FILE" "SERVICE_STATUS"
    $svcStatus    = Get-Section $Data "SERVICE_STATUS" "SERVICE_ENABLED"
    $svcEnabled   = Get-Section $Data "SERVICE_ENABLED" "UPTIME"
    $uptime       = Get-Section $Data "UPTIME" "TOR_STATUS"
    $torStatus    = Get-Section $Data "TOR_STATUS" "TOR_ENABLED"
    $torEnabled   = Get-Section $Data "TOR_ENABLED" "NODE_ID"
    $nodeId       = Get-Section $Data "NODE_ID" "NODE_PRIORITY"
    $nodePriority = Get-Section $Data "NODE_PRIORITY" "CLUSTER_TOKEN"
    $clusterToken = Get-Section $Data "CLUSTER_TOKEN" "TARGET_ADDR"
    $targetAddr   = Get-Section $Data "TARGET_ADDR" "TARGET_PORT"
    $targetPort   = Get-Section $Data "TARGET_PORT" "TARGET_TLS"
    $targetTls    = Get-Section $Data "TARGET_TLS" "MASTER_ONION_CFG"
    $masterCfg    = Get-Section $Data "MASTER_ONION_CFG" "NODE_HS_HOSTNAME"
    $nodeHsHost   = Get-Section $Data "NODE_HS_HOSTNAME" "WG_INTERFACE"
    $wgInterface  = Get-Section $Data "WG_INTERFACE" "WG_TUNNEL_IP"
    $wgTunnelIp   = Get-Section $Data "WG_TUNNEL_IP" "WG_PUBKEY"
    $wgPubkey     = Get-Section $Data "WG_PUBKEY" "WG_ENDPOINT"
    $wgEndpoint   = Get-Section $Data "WG_ENDPOINT" "WG_PEERS_LIVE"
    $wgPeersLive  = Get-Section $Data "WG_PEERS_LIVE" "WG_HANDSHAKE_RAW"
    $wgHandshake  = Get-Section $Data "WG_HANDSHAKE_RAW" "PEER_LIFECYCLE"
    $peerLife     = Get-Section $Data "PEER_LIFECYCLE" "PUBLISHER_LOG"
    $publisherLog = Get-Section $Data "PUBLISHER_LOG" "LAST_PUBLISH"
    $lastPublish  = Get-Section $Data "LAST_PUBLISH" "PUBLISH_INTRO_MERGE"
    $introMerge   = Get-Section $Data "PUBLISH_INTRO_MERGE" "MULTINODE_STATUS"
    $multiNode    = Get-Section $Data "MULTINODE_STATUS" "OWN_INTRO_POINTS"
    $ownIntro     = Get-Section $Data "OWN_INTRO_POINTS" "ERROR_COUNT"
    $errorCount   = Get-Section $Data "ERROR_COUNT" "WARN_COUNT"
    $warnCount    = Get-Section $Data "WARN_COUNT" "RECENT_ERRORS"
    $recentErrors = Get-Section $Data "RECENT_ERRORS" "SESSION_COUNT"
    $sessionCount = Get-Section $Data "SESSION_COUNT" "END"

    # ---- 1. OS & Environment ----
    Write-Section "OS & Environment"
    Write-Item "Hostname" $vmHostname
    Write-Item "OS" $osName
    Write-Item "Kernel" $kernel
    Write-Item "Architecture" $arch
    Write-Item "IP Addresses" $vmIp
    Write-Item "Memory (total/used/avail)" $memory
    Write-Item "Disk (size/used/avail/%)" $disk

    # ---- 2. Dependencies ----
    Write-Section "Dependencies"

    $torOk = $torInstalled -and $torInstalled -notmatch "NOT INSTALLED"
    Write-Item "Tor" $torInstalled $(if ($torOk) { "pass" } else { "fail" })

    $wgOk = $wgInstalled -and $wgInstalled -notmatch "NOT INSTALLED"
    Write-Item "WireGuard" $wgInstalled $(if ($wgOk) { "pass" } else { "fail" })

    # ---- 3. Install Status ----
    Write-Section "Install Status"

    $binOk = $rbBin -and $rbBin -notmatch "NOT FOUND"
    Write-Item "RustBalance binary" $rbBin $(if ($binOk) { "pass" } else { "fail" })

    Write-Item "Config file" $(if ($configExists -eq "YES") { "/etc/rustbalance/config.toml" } else { "MISSING" }) $(if ($configExists -eq "YES") { "pass" } else { "fail" })
    Write-Item "Master key file" $(if ($masterKey -eq "YES") { "/etc/rustbalance/master.key" } else { "MISSING" }) $(if ($masterKey -eq "YES") { "pass" } else { "fail" })
    Write-Item "Systemd service file" $(if ($serviceFile -eq "YES") { "installed" } else { "MISSING" }) $(if ($serviceFile -eq "YES") { "pass" } else { "fail" })
    Write-Item "Service enabled at boot" $svcEnabled $(if ($svcEnabled -eq "enabled") { "pass" } else { "warn" })

    # ---- 4. Running Status ----
    Write-Section "Running Status"

    $svcClean = ($svcStatus -split "`n" | Select-Object -Last 1).Trim()
    Write-Item "RustBalance service" $svcClean $(if ($svcClean -eq "active") { "pass" } else { "fail" })

    $uptimeClean = ($uptime -split "`n" | Select-Object -Last 1).Trim()
    Write-Item "Process uptime" $uptimeClean $(if ($uptimeClean -and $uptimeClean -ne "not-running") { "pass" } else { "fail" })

    $torClean = ($torStatus -split "`n" | Select-Object -Last 1).Trim()
    Write-Item "Tor daemon" $torClean $(if ($torClean -eq "active") { "pass" } else { "fail" })

    Write-Item "Tor boot enabled" $torEnabled $(if ($torEnabled -match "enabled") { "pass" } else { "warn" })

    Write-Item "Node ID" $nodeId
    Write-Item "Node priority" $nodePriority

    $errNum = 0; if ($errorCount -match '(\d+)\s*$') { $errNum = [int]$Matches[1] }
    Write-Item "Errors (last 500 lines)" "$errNum" $(if ($errNum -eq 0) { "pass" } elseif ($errNum -le 5) { "warn" } else { "fail" })

    $warnNum = 0; if ($warnCount -match '(\d+)\s*$') { $warnNum = [int]$Matches[1] }
    Write-Item "Warnings (last 500 lines)" "$warnNum" $(if ($warnNum -eq 0) { "pass" } else { "warn" })

    if ($recentErrors -and $errNum -gt 0) {
        Write-Host ""
        Write-Host "    Recent errors:" -ForegroundColor $C_FAIL
        $recentErrors -split "`n" | ForEach-Object {
            $trimmed = $_.Trim()
            if ($trimmed) {
                if ($trimmed.Length -gt 120) { $trimmed = $trimmed.Substring(0, 120) + "..." }
                Write-Host "      > $trimmed" -ForegroundColor $C_DIM
            }
        }
    }

    # ---- 5. Onion Addresses ----
    Write-Section "Onion Addresses"
    Write-Item "Master (config)" $masterCfg $(if ($masterCfg -eq $masterOnion) { "pass" } else { "fail" })
    Write-Item "Node HS hostname" $nodeHsHost $(if ($nodeHsHost -eq $masterOnion) { "pass" } elseif ($nodeHsHost -match "\.onion") { "warn" } else { "fail" })
    Write-Item "Target service" "${targetAddr}:${targetPort}" $(if ($targetAddr) { "pass" } else { "fail" })
    Write-Item "Target TLS" $targetTls

    # ---- 6. Descriptors & Intro Points ----
    Write-Section "Descriptors & Intro Points"

    if ($ownIntro -match "(\d+)\s+introduction points") {
        Write-Item "Own intro points" "$($Matches[1])" "pass"
    } else {
        Write-Item "Own intro points" "unknown" "warn"
    }

    if ($introMerge) {
        $lastMerge = ($introMerge -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1).Trim()
        if ($lastMerge -match "merging\s+(\d+)\s+own\s+.*?(\d+)\s+peer") {
            Write-Item "Merged descriptor" "$($Matches[1]) own + $($Matches[2]) peer" "pass"
        } elseif ($lastMerge -match "(\d+)\s+intro") {
            Write-Item "Merged descriptor" "$($Matches[1]) intro points total" "pass"
        } else {
            Write-Item "Merged descriptor" $lastMerge
        }
    } else {
        Write-Item "Merged descriptor" "no merge log found" "warn"
    }

    # Return data for cross-VM comparison
    return @{
        reachable     = $true
        nodeId        = $nodeId
        clusterToken  = $clusterToken
        targetAddr    = $targetAddr
        targetPort    = $targetPort
        masterCfg     = $masterCfg
        wgPubkey      = $wgPubkey
        wgTunnelIp    = $wgTunnelIp
        wgEndpoint    = $wgEndpoint
        wgPeersLive   = $wgPeersLive
        wgHandshake   = $wgHandshake
        peerLife      = $peerLife
        publisherLog  = $publisherLog
        lastPublish   = $lastPublish
        multiNode     = $multiNode
        sessionCount  = $sessionCount
        svcStatus     = $svcClean
        torStatus     = $torClean
        nodeHsHost    = $nodeHsHost
    }
}

$vm1Info = Process-VMReport -Data $vm1Data -VMLabel "VM1 - hlsn1" -VMIPAddr "192.168.40.144"
$vm2Info = Process-VMReport -Data $vm2Data -VMLabel "VM2 - hlsn2" -VMIPAddr "192.168.40.145"

# ============================================================================
#  Communication Network Status
# ============================================================================

Write-Title "Communication Network"

Write-Section "WireGuard Mesh"

if ($vm1Info.reachable) {
    $vm1Peers = 0; if ($vm1Info.wgPeersLive -match '(\d+)') { $vm1Peers = [int]$Matches[1] }
    Write-Item "VM1 WG pubkey" $vm1Info.wgPubkey
    Write-Item "VM1 WG tunnel IP" $vm1Info.wgTunnelIp
    Write-Item "VM1 WG endpoint" $vm1Info.wgEndpoint
    Write-Item "VM1 live peers" "$vm1Peers" $(if ($vm1Peers -ge 1) { "pass" } else { "warn" })
}

if ($vm2Info.reachable) {
    $vm2Peers = 0; if ($vm2Info.wgPeersLive -match '(\d+)') { $vm2Peers = [int]$Matches[1] }
    Write-Item "VM2 WG pubkey" $vm2Info.wgPubkey
    Write-Item "VM2 WG tunnel IP" $vm2Info.wgTunnelIp
    Write-Item "VM2 WG endpoint" $vm2Info.wgEndpoint
    Write-Item "VM2 live peers" "$vm2Peers" $(if ($vm2Peers -ge 1) { "pass" } else { "warn" })
}

# WG Handshake freshness
Write-Section "WireGuard Handshakes"
foreach ($vm in @(@{label="VM1";info=$vm1Info}, @{label="VM2";info=$vm2Info})) {
    if ($vm.info.reachable -and $vm.info.wgHandshake -and $vm.info.wgHandshake -ne "none") {
        $lines = $vm.info.wgHandshake -split "`n" | Where-Object { $_ -match '\d' }
        foreach ($line in $lines) {
            if ($line -match '(\S+)\s+(\d+)\s*$') {
                $peerKey = $Matches[1].Substring(0, [Math]::Min(16, $Matches[1].Length)) + "..."
                $epochTime = [int64]$Matches[2]
                $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                $ageSecs = $now - $epochTime
                $ageStr = if ($ageSecs -lt 60) { "${ageSecs}s ago" }
                          elseif ($ageSecs -lt 3600) { "$([Math]::Floor($ageSecs/60))m $($ageSecs%60)s ago" }
                          else { "$([Math]::Floor($ageSecs/3600))h $([Math]::Floor(($ageSecs%3600)/60))m ago" }
                $status = if ($ageSecs -le 180) { "pass" } elseif ($ageSecs -le 600) { "warn" } else { "fail" }
                Write-Item "$($vm.label) -> $peerKey" "$ageStr" $status
            }
        }
    } elseif ($vm.info.reachable) {
        Write-Item "$($vm.label) handshake" "no data" "warn"
    }
}

# Peer health from logs
Write-Section "Peer Health"
foreach ($vm in @(@{label="VM1";info=$vm1Info}, @{label="VM2";info=$vm2Info})) {
    if ($vm.info.reachable -and $vm.info.peerLife) {
        $lastLife = ($vm.info.peerLife -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1).Trim()
        if ($lastLife -match "Healthy") {
            Write-Item "$($vm.label) sees peer" "Healthy" "pass"
        } elseif ($lastLife -match "Initializing|Joining") {
            Write-Item "$($vm.label) sees peer" "Initializing" "warn"
        } else {
            Write-Item "$($vm.label) sees peer" $lastLife "warn"
        }
    } elseif ($vm.info.reachable) {
        Write-Item "$($vm.label) sees peer" "no lifecycle log found" "warn"
    }
}

# Multi-node detection
Write-Section "Multi-Node Mode"
foreach ($vm in @(@{label="VM1";info=$vm1Info}, @{label="VM2";info=$vm2Info})) {
    if ($vm.info.reachable -and $vm.info.multiNode) {
        $last = ($vm.info.multiNode -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1).Trim()
        if ($last -match "Multi-node mode detected.*?(\d+)\s+active") {
            Write-Item "$($vm.label) mode" "Multi-node ($($Matches[1]) active peer(s))" "pass"
        } elseif ($last -match "Multi-node mode.*?merging\s+(\d+)\s+own.*?(\d+)\s+peer") {
            Write-Item "$($vm.label) mode" "Multi-node (merging $($Matches[1]) own + $($Matches[2]) peer)" "pass"
        } elseif ($last -match "Multi-node") {
            Write-Item "$($vm.label) mode" "Multi-node active" "pass"
        } elseif ($last -match "auto-detect") {
            Write-Item "$($vm.label) mode" "Auto-detect active" "pass"
        } else {
            Write-Item "$($vm.label) mode" $last
        }
    } elseif ($vm.info.reachable) {
        Write-Item "$($vm.label) mode" "no multi-node log" "warn"
    }
}

# ============================================================================
#  Config Agreement Check
# ============================================================================

Write-Title "Configuration Agreement"

if ($vm1Info.reachable -and $vm2Info.reachable) {
    # Cluster token
    $tokenMatch = $vm1Info.clusterToken -eq $vm2Info.clusterToken
    Write-Item "Cluster token" $(if ($tokenMatch) { "MATCH" } else { "MISMATCH!" }) $(if ($tokenMatch) { "pass" } else { "fail" })

    # Target address
    $targetMatch = ($vm1Info.targetAddr -eq $vm2Info.targetAddr) -and ($vm1Info.targetPort -eq $vm2Info.targetPort)
    Write-Item "Target address" $(if ($targetMatch) { "MATCH ($($vm1Info.targetAddr):$($vm1Info.targetPort))" } else { "MISMATCH!" }) $(if ($targetMatch) { "pass" } else { "fail" })

    # Master onion
    $masterMatch = $vm1Info.masterCfg -eq $vm2Info.masterCfg
    Write-Item "Master onion config" $(if ($masterMatch) { "MATCH" } else { "MISMATCH!" }) $(if ($masterMatch) { "pass" } else { "fail" })

    # Node HS hostnames should both be the master
    $hsMatch = ($vm1Info.nodeHsHost -eq $masterOnion) -and ($vm2Info.nodeHsHost -eq $masterOnion)
    Write-Item "Node HS = Master onion" $(if ($hsMatch) { "MATCH (both serve master)" } else { "MISMATCH!" }) $(if ($hsMatch) { "pass" } else { "fail" })

    # Unique node IDs
    $idsDiff = $vm1Info.nodeId -ne $vm2Info.nodeId
    Write-Item "Unique node IDs" $(if ($idsDiff) { "YES ($($vm1Info.nodeId) / $($vm2Info.nodeId))" } else { "DUPLICATE!" }) $(if ($idsDiff) { "pass" } else { "fail" })
} else {
    Write-Host "    Cannot compare - one or both VMs unreachable" -ForegroundColor $C_WARN
}

# ============================================================================
#  Publisher & Descriptor Publishing
# ============================================================================

Write-Title "Publisher & Descriptor Status"

Write-Section "Publisher Election"
$publisherNode = ""
foreach ($vm in @(@{label="VM1";info=$vm1Info}, @{label="VM2";info=$vm2Info})) {
    if ($vm.info.reachable -and $vm.info.publisherLog) {
        $lastPub = ($vm.info.publisherLog -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1).Trim()
        if ($lastPub -match "Taking over as publisher") {
            Write-Item "$($vm.label) says" "I am the publisher" "pass"
            $publisherNode = $vm.label
        } elseif ($lastPub -match "Publisher is now:\s*(\S+)") {
            Write-Item "$($vm.label) says" "Publisher is $($Matches[1])" "pass"
            $publisherNode = $Matches[1]
        } else {
            Write-Item "$($vm.label) says" $lastPub
        }
    } elseif ($vm.info.reachable) {
        Write-Item "$($vm.label) election" "no election log found" "warn"
    }
}

Write-Section "Last Descriptor Publish"
foreach ($vm in @(@{label="VM1";info=$vm1Info}, @{label="VM2";info=$vm2Info})) {
    if ($vm.info.reachable -and $vm.info.lastPublish) {
        $lines = $vm.info.lastPublish -split "`n" | Where-Object { $_.Trim() }
        $lastLine = ($lines | Select-Object -Last 1).Trim()
        if ($lastLine -match '(\d{2}:\d{2}:\d{2}).*?(HSPOST.*accepted|Successfully published)') {
            Write-Item "$($vm.label) last publish" "$($Matches[1]) UTC - $($Matches[2])" "pass"
        } else {
            Write-Item "$($vm.label) last publish" $lastLine "pass"
        }
    } elseif ($vm.info.reachable) {
        Write-Item "$($vm.label) last publish" "none found" $(if ($publisherNode -match $vm.label) { "fail" } else { "info" })
    }
}

# ============================================================================
#  Reachability
# ============================================================================

Write-Title "Reachability"

Write-Section "Backend (Target Service via Tor SOCKS)"
Write-Host "    Testing if nodes can reach the target .onion..." -ForegroundColor $C_DIM

foreach ($vm in @(@{label="VM1";host=$vm1Host}, @{label="VM2";host=$vm2Host})) {
    $reachScript = 'timeout 30 curl -s -o /dev/null -w "%{http_code}" --socks5-hostname 127.0.0.1:9050 http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion:443/ 2>/dev/null || echo "TIMEOUT"'
    $reachEnc = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($reachScript))
    $result = ssh -i $sshKey $vm.host "echo $reachEnc | base64 -d | bash" 2>&1
    $code = ($result | Out-String).Trim()
    Write-Item "$($vm.label) -> target" "HTTP $code" $(if ($code -match '^\d{3}$') { "pass" } else { "fail" })
}

Write-Section "Front Mirror (Master .onion via local Tor)"
if (-not $SkipSessions) {
    Write-Host "    Checking master .onion through Tor Browser..." -ForegroundColor $C_DIM
    try {
        $frontCheck = curl.exe --socks5-hostname $TorProxy "http://${masterOnion}/" -s -o NUL -w "%{http_code}" --max-time 60 2>&1
        if ($frontCheck -match '^\d{3}$') {
            Write-Item "Client -> master.onion" "HTTP $frontCheck" "pass"
        } else {
            Write-Item "Client -> master.onion" "$frontCheck" "fail"
        }
    } catch {
        Write-Item "Client -> master.onion" "curl failed" "fail"
    }
} else {
    Write-Host "    Skipped (run without -SkipSessions)" -ForegroundColor $C_DIM
}

# ============================================================================
#  Session Testing
# ============================================================================

if (-not $SkipSessions) {
    Write-Title "Session Distribution Test ($SessionCount requests)"

    # Auto-detect cookie file
    if ($TorCookieFile -eq "") {
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

    $sessionResults = @()
    $successCount = 0
    $failCount = 0

    Write-Host ""
    Write-Host "    Sending $SessionCount requests through Tor to master.onion..." -ForegroundColor $C_DIM
    Write-Host "    Each request uses NEWNYM + unique SOCKS identity for circuit isolation." -ForegroundColor $C_DIM
    Write-Host ""

    for ($i = 1; $i -le $SessionCount; $i++) {
        # NEWNYM for fresh circuit via control port
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect("127.0.0.1", $TorControlPort)
            $stream = $client.GetStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $writer = New-Object System.IO.StreamWriter($stream)
            $writer.AutoFlush = $true

            if ($TorCookieFile -ne "" -and (Test-Path $TorCookieFile)) {
                $cookieBytes = [System.IO.File]::ReadAllBytes($TorCookieFile)
                $cookieHex = ($cookieBytes | ForEach-Object { $_.ToString("X2") }) -join ''
                $writer.WriteLine("AUTHENTICATE $cookieHex")
            } else {
                $writer.WriteLine('AUTHENTICATE ""')
            }
            $null = $reader.ReadLine()
            $writer.WriteLine("SIGNAL NEWNYM")
            $null = $reader.ReadLine()
            $writer.WriteLine("QUIT")
            $client.Close()
        } catch {
            # Control port not available - rely on unique SOCKS username
        }

        Start-Sleep -Seconds 2

        $rnd = Get-Random -Maximum 999999
        $user = "pdtest_${i}_${rnd}"
        $ts = Get-Date -Format "HH:mm:ss"

        Write-Host "    [$ts] Request $i/$SessionCount ... " -NoNewline

        try {
            $result = curl.exe --socks5-hostname "${user}:x@${TorProxy}" `
                "http://${masterOnion}/" `
                -s -o NUL -w "%{http_code}|%{time_total}" `
                --max-time 90 2>&1

            $parts = ($result | Out-String).Trim() -split '\|'
            $httpCode = $parts[0]
            $duration = if ($parts.Count -gt 1) { try { [math]::Round([double]$parts[1], 1) } catch { "?" } } else { "?" }

            if ($httpCode -match '^\d{3}$') {
                $successCount++
                $sessionResults += @{ index = $i; code = $httpCode; time = $duration; status = "ok" }
                Write-Host "HTTP $httpCode (${duration}s)" -ForegroundColor $C_OK
            } else {
                $failCount++
                $sessionResults += @{ index = $i; code = "FAIL"; time = 0; status = "fail" }
                Write-Host "FAILED: $result" -ForegroundColor $C_FAIL
            }
        } catch {
            $failCount++
            $sessionResults += @{ index = $i; code = "ERR"; time = 0; status = "fail" }
            Write-Host "ERROR: $_" -ForegroundColor $C_FAIL
        }

        if ($i -lt $SessionCount) {
            Start-Sleep -Seconds 3
        }
    }

    # Give logs time to flush
    Start-Sleep -Seconds 3

    # Check which VM handled sessions
    Write-Section "Node Distribution"

    $vm1Sessions = ssh -i $sshKey $vm1Host "journalctl -u rustbalance --since '10 min ago' --no-pager 2>/dev/null | grep -c 'Session #'" 2>$null
    $vm2Sessions = ssh -i $sshKey $vm2Host "journalctl -u rustbalance --since '10 min ago' --no-pager 2>/dev/null | grep -c 'Session #'" 2>$null

    $vm1Count = 0; if ($vm1Sessions -match '^\d+$') { $vm1Count = [int]$vm1Sessions }
    $vm2Count = 0; if ($vm2Sessions -match '^\d+$') { $vm2Count = [int]$vm2Sessions }
    $totalHandled = $vm1Count + $vm2Count

    Write-Host ""
    Write-Host "    +--------+-----------+---------+" -ForegroundColor $C_DIM
    Write-Host "    |  Node  | Sessions  |  Share  |" -ForegroundColor $C_DIM
    Write-Host "    +--------+-----------+---------+" -ForegroundColor $C_DIM

    if ($totalHandled -gt 0) {
        $vm1Pct = [math]::Round(($vm1Count / $totalHandled) * 100, 0)
        $vm2Pct = 100 - $vm1Pct

        $vm1Color = if ($vm1Count -gt 0) { $C_OK } else { $C_WARN }
        $vm2Color = if ($vm2Count -gt 0) { $C_OK } else { $C_WARN }

        Write-Host "    |  " -ForegroundColor $C_DIM -NoNewline
        Write-Host "VM1 " -ForegroundColor $vm1Color -NoNewline
        Write-Host "  |  " -ForegroundColor $C_DIM -NoNewline
        Write-Host "$($vm1Count.ToString().PadRight(5))" -ForegroundColor $vm1Color -NoNewline
        Write-Host "    |  " -ForegroundColor $C_DIM -NoNewline
        Write-Host "$("${vm1Pct}%".PadRight(4))" -ForegroundColor $vm1Color -NoNewline
        Write-Host "   |" -ForegroundColor $C_DIM

        Write-Host "    |  " -ForegroundColor $C_DIM -NoNewline
        Write-Host "VM2 " -ForegroundColor $vm2Color -NoNewline
        Write-Host "  |  " -ForegroundColor $C_DIM -NoNewline
        Write-Host "$($vm2Count.ToString().PadRight(5))" -ForegroundColor $vm2Color -NoNewline
        Write-Host "    |  " -ForegroundColor $C_DIM -NoNewline
        Write-Host "$("${vm2Pct}%".PadRight(4))" -ForegroundColor $vm2Color -NoNewline
        Write-Host "   |" -ForegroundColor $C_DIM
    } else {
        Write-Host "    |  VM1   |  0        |  0%     |" -ForegroundColor $C_WARN
        Write-Host "    |  VM2   |  0        |  0%     |" -ForegroundColor $C_WARN
    }

    Write-Host "    +--------+-----------+---------+" -ForegroundColor $C_DIM

    # Visual distribution bar
    if ($totalHandled -gt 0) {
        Write-Host ""
        $barLen = 50
        $vm1Bar = [math]::Max(0, [math]::Round(($vm1Count / $totalHandled) * $barLen))
        $vm2Bar = $barLen - $vm1Bar

        Write-Host "    VM1 [" -NoNewline -ForegroundColor $C_DATA
        Write-Host ("#" * $vm1Bar) -NoNewline -ForegroundColor $C_OK
        Write-Host ("." * $vm2Bar) -NoNewline -ForegroundColor $C_DIM
        Write-Host "]" -ForegroundColor $C_DATA

        Write-Host "    VM2 [" -NoNewline -ForegroundColor $C_DATA
        Write-Host ("." * $vm1Bar) -NoNewline -ForegroundColor $C_DIM
        Write-Host ("#" * $vm2Bar) -NoNewline -ForegroundColor $C_OK
        Write-Host "]" -ForegroundColor $C_DATA
    }

    # Verdict
    Write-Host ""
    if ($vm1Count -gt 0 -and $vm2Count -gt 0) {
        Write-Item "Load balancing" "CONFIRMED - both nodes received traffic" "pass"
    } elseif ($totalHandled -eq 0) {
        Write-Item "Load balancing" "No sessions logged (nodes may not be proxying yet)" "warn"
    } else {
        Write-Item "Load balancing" "Only one node got traffic (try more requests)" "warn"
    }

    Write-Host ""
    Write-Item "Requests sent" "$SessionCount"
    Write-Item "Successful" "$successCount" $(if ($successCount -eq $SessionCount) { "pass" } else { "warn" })
    if ($failCount -gt 0) {
        Write-Item "Failed" "$failCount" "fail"
    }
} else {
    Write-Title "Session Distribution Test"
    Write-Host "    Skipped (-SkipSessions flag)" -ForegroundColor $C_DIM
    Write-Host "    Run without -SkipSessions to send $SessionCount test requests through Tor." -ForegroundColor $C_DIM
    Write-Host "    Requires: Tor Browser running locally (SOCKS on $TorProxy)" -ForegroundColor $C_DIM
}

# ============================================================================
#  Final Verdict
# ============================================================================

Write-Title "Overall Verdict"

$issues = @()

if ($vm1Info.reachable) {
    if ($vm1Info.svcStatus -ne "active") { $issues += "VM1 RustBalance not active" }
    if ($vm1Info.torStatus -ne "active") { $issues += "VM1 Tor not active" }
} else { $issues += "VM1 unreachable" }

if ($vm2Info.reachable) {
    if ($vm2Info.svcStatus -ne "active") { $issues += "VM2 RustBalance not active" }
    if ($vm2Info.torStatus -ne "active") { $issues += "VM2 Tor not active" }
} else { $issues += "VM2 unreachable" }

if ($vm1Info.reachable -and $vm2Info.reachable) {
    if ($vm1Info.clusterToken -ne $vm2Info.clusterToken) { $issues += "Cluster token mismatch" }
    if ($vm1Info.masterCfg -ne $vm2Info.masterCfg) { $issues += "Master onion config mismatch" }
    if ($vm1Info.targetAddr -ne $vm2Info.targetAddr) { $issues += "Target address mismatch" }
    if ($vm1Info.nodeHsHost -ne $masterOnion -or $vm2Info.nodeHsHost -ne $masterOnion) { $issues += "Node HS not serving master onion" }
}

Write-Host ""
if ($issues.Count -eq 0) {
    Write-Host "    +====================================================+" -ForegroundColor $C_OK
    Write-Host "    |     DEPLOYMENT HEALTHY - All critical checks pass   |" -ForegroundColor $C_OK
    Write-Host "    +====================================================+" -ForegroundColor $C_OK
} else {
    Write-Host "    +====================================================+" -ForegroundColor $C_FAIL
    Write-Host "    |     ISSUES DETECTED ($($issues.Count) critical)                      |" -ForegroundColor $C_FAIL
    Write-Host "    +====================================================+" -ForegroundColor $C_FAIL
    foreach ($issue in $issues) {
        Write-Host "      ! $issue" -ForegroundColor $C_FAIL
    }
}

Write-Host ""
Write-Host "  Report complete: $reportTime" -ForegroundColor $C_DIM
Write-Host "  Master address:  $masterOnion" -ForegroundColor $C_DIM
Write-Host ""
