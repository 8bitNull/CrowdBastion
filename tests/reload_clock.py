"""Opt-in logical time for synchronous mocked Nginx workflow regressions.

Do not use for real commands, threads, subprocess deadlines or child cleanup:
those require the unmodified monotonic clock and real sleep.
"""


def virtual_reload_clock():
    """Share one fixture clock across Bash subshells; advance only on fake sleep."""
    return r'''
nginx_monotonic_us() {
 local now=1000000
 if [[ -f "$TRACE.reload-clock" ]]; then
  IFS= read -r now < "$TRACE.reload-clock" || return 1
 fi
 printf '%s\n' "$now"
}
sleep() {
 [[ "$#" == 1 && "$1" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]] || return 2
 local delta now
 delta=$(awk -v delay="$1" 'BEGIN {
  if (delay > 60) exit 2
  printf "%.0f\n", delay * 1000000
 }') || return 2
 now=$(nginx_monotonic_us) || return 1
 printf '%s\n' "$((now + delta))" > "$TRACE.reload-clock"
}
'''
