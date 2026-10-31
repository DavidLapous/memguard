# memguard

Lightweight macOS OOM killer.


## Kill rules

1. **RAM limit (`RAM_LIMIT`):** `max(sys_used / hw.memsize, (100 - kern.memorystatus_level) / 100)` reaches `max_ram_fraction`.
2. **Panic fallback (`PANIC_RAM`):** at `panic_ram_fraction`, if no unprotected worker `>= min_victim_gib` exists, falls back to killing the single largest soft-protected PID.
3. **Swap limit (`SWAP_LIMIT`):** `vm.swapusage` (`xsu_used`) grows by more than `max_swap_gib` above its downward-ratcheting baseline while `vm_statistics64.swapouts` increments.


## Configuration (`memguard.conf`)

[`memguard.conf`](memguard.conf) (copied to `~/.config/memguard/memguard.conf` on `just install` if not present) is loaded on startup:

```ini
# Kill largest unprotected process at this RAM fraction
max_ram_fraction = 0.95
# Fallback to largest soft-protected PID at this RAM fraction
panic_ram_fraction = 0.98
# Switch to fast polling at this RAM fraction
fast_poll_ram_fraction = 0.85
# Normal poll interval (ms)
poll_interval_ms = 1000
# High-pressure poll interval (ms)
fast_poll_interval_ms = 200
# Allowed swap growth (GiB) above baseline before killing (0.0 = any active swap)
max_swap_gib = 0.0
# Minimum swap burst (MiB/tick) required when max_swap_gib = 0.0 and RAM < 50%
swap_burst_floor_mib = 64
# Minimum process physical footprint (GiB) to qualify as a victim
min_victim_gib = 2.0
# Cooldown (s) before re-targeting the same PID
kill_cooldown_s = 15

# '!' = hard protection (case-insensitive exact or prefix* match; see race warning above)
!WindowServer
!ghostty*
!nvim
# Plain = soft-protected (spared at 95%/swap, single-PID fallback at 98% panic)
Safari*
com.apple.WebKit*
```

The requested file is the only config loaded; there is no working-directory fallback.
All numeric keys and at least one protection rule are required. Unknown or duplicate
keys, malformed values/rules, oversized lines, and invalid threshold ordering are errors.
Rules allow an optional leading `!` and trailing `*`, with a nonempty process name.
Run `memguard check` after edits; diagnostics identify the file and line where applicable.

## Usage

```bash
just check              # build and run self-tests, including an isolated child single-PID kill
just install            # install binary/config only; no new login agent or daemon
memguard --help
memguard check
memguard --dry-run      # foreground observation only; Ctrl-C to stop
just enable             # explicit LIVE opt-in: creates login agent and starts killing
memguard stop           # unload until next login or memguard start
just uninstall          # unload agent; remove binary/plist, retain config and logs
```

`memguard --dry-run` uses the same thresholds and victim selection as live mode,
but logs `WOULD_KILL` and never signals victims or sends kill notifications.
It does not stop an already running live agent. `memguard` with no arguments
(or `memguard run`) is **live** foreground mode, not observation.

`just install` does not stop or disable an agent enabled previously.
Once enabled, the agent runs at login and `KeepAlive` respawns it after exit.
Use `memguard stop` to stop it for this login, or `just uninstall` to remove it.

**Stress test: save all work and use an expendable session.** This deliberately
allocates toward 98% RAM; the live daemon can kill unrelated work, and the host
can become unresponsive. It is not needed for normal onboarding:

```bash
MEMGUARD_ALLOW_STRESS=1 just test-hog
```

Once installed, the `memguard` binary controls the LaunchAgent (`local.memguard`) through `launchctl`:

```bash
memguard status   # daemon state + pid, RAM/pressure/swap snapshot, largest processes
memguard check    # validate ~/.config/memguard/memguard.conf
memguard reload   # validate, then SIGHUP the daemon to re-read its config in place
memguard restart  # validate, then kickstart -k (picks up a newly installed binary)
memguard stop     # bootout (a plain kill would be respawned by KeepAlive); back at next login
memguard start    # load/restart an agent created by just enable; resumes LIVE killing
```

`reload` keeps the swap baseline and kill cooldowns. An invalid config is rejected by the CLI before anything is signalled, and if the daemon itself fails to parse the file it logs `RELOAD_FAILED` and keeps its previous config.

## Status

`memguard status` prints daemon state, a fresh RAM/pressure/swap snapshot,
config on disk, and the largest observed unprotected and soft-protected processes.
Eligibility is based on the disk config: below minimum, eligible at the normal
threshold, or panic only. It is not a prediction of the daemon's next victim.

The running daemon's loaded config, swap baseline, and cooldowns are not queried.
Unavailable required system data or a truncated process list makes status fail
explicitly with a nonzero exit code. Color is terminal-only; `NO_COLOR=1` disables it.
Recent kill history remains in `~/.local/state/memguard.log`, not in status output.
