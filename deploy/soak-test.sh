#!/usr/bin/env bash
set -u

REPORT=/opt/veloxvpn-test/reports/soak-24h.log
WARMUP_MINUTES=${WARMUP_MINUTES:-10}
DURATION_MINUTES=${DURATION_MINUTES:-$((WARMUP_MINUTES + 1440))}
TARGET_URL=https://www.cloudflare.com/cdn-cgi/trace
PROXY_PORTS=(19082 19083)
PROTOCOLS=(anytls tuic)

start_epoch=$(date +%s)
service_pid=$(systemctl show --property MainPID --value veloxvpn-test)
start_rss_kib=$(awk '/VmRSS:/ { print $2 }' "/proc/${service_pid}/status")
start_restarts=$(systemctl show --property NRestarts --value veloxvpn-test)
successes=(0 0)
failures=(0 0)
steady_rss_kib=0
steady_epoch=0

umask 077
printf 'start_epoch=%s duration_minutes=%s warmup_minutes=%s cold_start_rss_kib=%s start_restarts=%s\n' \
  "$start_epoch" "$DURATION_MINUTES" "$WARMUP_MINUTES" "$start_rss_kib" "$start_restarts" >"$REPORT"

for ((minute = 0; minute < DURATION_MINUTES; minute++)); do
  index=$((minute % 2))
  port=${PROXY_PORTS[$index]}
  protocol=${PROTOCOLS[$index]}

  if curl --silent --show-error --fail --max-time 20 \
    --socks5-hostname "127.0.0.1:${port}" "$TARGET_URL" -o /dev/null; then
    successes[$index]=$((${successes[$index]} + 1))
    result=ok
  else
    failures[$index]=$((${failures[$index]} + 1))
    result=failed
  fi

  if ((minute % 10 == 0 || minute + 1 == DURATION_MINUTES)); then
    service_pid=$(systemctl show --property MainPID --value veloxvpn-test)
    current_rss_kib=$(awk '/VmRSS:/ { print $2 }' "/proc/${service_pid}/status")
    current_restarts=$(systemctl show --property NRestarts --value veloxvpn-test)
    cloudflared_count=$(pgrep -c cloudflared || true)
    if ((minute == WARMUP_MINUTES)); then
      steady_rss_kib=$current_rss_kib
      steady_epoch=$(date +%s)
    fi
    printf 'minute=%s protocol=%s result=%s successes=%s failures=%s rss_kib=%s restarts=%s cloudflared_count=%s\n' \
      "$minute" "$protocol" "$result" "${successes[$index]}" "${failures[$index]}" \
      "$current_rss_kib" "$current_restarts" "$cloudflared_count" >>"$REPORT"
  fi

  next_epoch=$((start_epoch + (minute + 1) * 60))
  now_epoch=$(date +%s)
  if ((now_epoch > next_epoch + 45)); then
    printf 'complete=0 reason=clock_gap_or_suspend minute=%s lag_seconds=%s\n' \
      "$minute" "$((now_epoch - next_epoch))" >>"$REPORT"
    exit 2
  fi
  if ((next_epoch > now_epoch)); then
    sleep "$((next_epoch - now_epoch))"
  fi
done

service_pid=$(systemctl show --property MainPID --value veloxvpn-test)
end_rss_kib=$(awk '/VmRSS:/ { print $2 }' "/proc/${service_pid}/status")
end_restarts=$(systemctl show --property NRestarts --value veloxvpn-test)
end_epoch=$(date +%s)
growth_percent=$(awk -v start="$steady_rss_kib" -v end="$end_rss_kib" \
  'BEGIN { if (start == 0) print "nan"; else printf "%.2f", (end - start) * 100 / start }')

printf 'complete=1 steady_epoch=%s steady_rss_kib=%s end_epoch=%s anytls_successes=%s anytls_failures=%s tuic_successes=%s tuic_failures=%s end_rss_kib=%s steady_rss_growth_percent=%s end_restarts=%s\n' \
  "$steady_epoch" "$steady_rss_kib" \
  "$end_epoch" "${successes[0]}" "${failures[0]}" "${successes[1]}" "${failures[1]}" "$end_rss_kib" \
  "$growth_percent" "$end_restarts" >>"$REPORT"
