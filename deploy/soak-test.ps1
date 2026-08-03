$ErrorActionPreference = 'Stop'

$report = 'E:\code\VeloxVPN\docs\soak-24h-windows.log'
$durationMinutes = 1440
$targetUrl = 'http://example.com/'
$ports = @(19081, 19082, 19083)
$protocols = @('vless', 'anytls', 'tuic')
$start = [DateTimeOffset]::Now
$successes = @(0, 0, 0)
$failures = @(0, 0, 0)

"start=$($start.ToString('o')) duration_minutes=$durationMinutes" | Set-Content -Encoding utf8 $report

for ($minute = 0; $minute -lt $durationMinutes; $minute++) {
    for ($index = 0; $index -lt $ports.Count; $index++) {
        & curl.exe --silent --show-error --fail --max-time 20 `
            --socks5-hostname "127.0.0.1:$($ports[$index])" $targetUrl -o NUL
        if ($LASTEXITCODE -eq 0) {
            $successes[$index]++
            $result = 'ok'
        } else {
            $failures[$index]++
            $result = 'failed'
        }

        if (($minute % 10) -eq 0 -or ($minute + 1) -eq $durationMinutes) {
            $client = Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue |
                Sort-Object StartTime -Descending | Select-Object -First 1
            $rssKib = if ($null -eq $client) { 0 } else { [math]::Round($client.WorkingSet64 / 1KB) }
            "minute=$minute protocol=$($protocols[$index]) result=$result successes=$($successes[$index]) failures=$($failures[$index]) client_rss_kib=$rssKib" |
                Add-Content -Encoding utf8 $report
        }
    }

    $next = $start.AddMinutes($minute + 1)
    $delay = $next - [DateTimeOffset]::Now
    if ($delay.TotalSeconds -lt -45) {
        "complete=0 reason=clock_gap_or_suspend minute=$minute lag_seconds=$([math]::Round(-$delay.TotalSeconds))" |
            Add-Content -Encoding utf8 $report
        exit 2
    }
    if ($delay.TotalMilliseconds -gt 0) {
        Start-Sleep -Milliseconds ([int]$delay.TotalMilliseconds)
    }
}

"complete=1 end=$([DateTimeOffset]::Now.ToString('o')) vless_successes=$($successes[0]) vless_failures=$($failures[0]) anytls_successes=$($successes[1]) anytls_failures=$($failures[1]) tuic_successes=$($successes[2]) tuic_failures=$($failures[2])" |
    Add-Content -Encoding utf8 $report
