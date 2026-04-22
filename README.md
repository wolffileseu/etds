# Wolffiles ETDS

**A GPL-licensed Enemy Territory dedicated server fork with modern build support and a feature parity with Pauluzz ET 3.00 0.7.4.**

Built and maintained by [Wolffiles.eu](https://wolffiles.eu) for the W:ET and RtCW community.

---

## What this is

Wolffiles ETDS (`etds`) is a dedicated server binary for Wolfenstein: Enemy Territory. It is based on id-Software's 2010 GPL source release and adds seven additional features that were previously only available in Pauluzz's closed-source `etded-pauluzz` binary (ET 3.00 - TB 0.7.4 linux-i386).

**Every one of those seven features was re-implemented from scratch** by reverse-engineering the Pauluzz binary with Ghidra and then writing clean GPL source code against id-Software's base. No code was copied — the Ghidra decompilation was used as a pseudo-specification only. The resulting source is entirely GPL-clean.

### Why this fork exists

The primary motivating feature is **dual-port protocol-inversion advertise** (`net_port_extra`). This lets a single server instance appear on the master list under **two protocol versions simultaneously**:

- Port 27960 → reports `protocol 84` (ET Legacy / 2.60b clients)
- Port 27961 → reports `protocol 82` (ET 2.40 / legacy-tail clients)

Both paths terminate at the same game world. The browser listings reach two different client populations that would otherwise never see each other.

This matters because the ET player base is fragmented across several protocol versions — ET Legacy players don't see protocol-82 servers, and vice versa. Without a dual-port server, operators have to choose which community to serve.

---

## Features

All features are reverse-engineered from the Pauluzz 0.7.4 binary.

| Feature | CVar(s) | Commit | Description |
|---------|---------|--------|-------------|
| Reflective DDoS protection | `sv_maxGetstatusCheck`, `sv_maxGetstatusPerMinute`, `sv_maxGetstatusBeforeIPTABLES` | [fae5e1a](https://github.com/wolffileseu/etds/commit/fae5e1a) | Sliding 60s window rate-limiter on getstatus queries to prevent amplification attacks |
| RCON source-IP whitelist | `sv_rconfilter`, `sv_rcon1..sv_rcon5` | [445e606](https://github.com/wolffileseu/etds/commit/445e606) | Only accepts rcon commands from configured IPs, with `A.B.C.D` or `*.*`-wildcard syntax |
| TrackBase integration | `sv_tbCommands`, `sv_tbChatRelay` | [2c4e8e5](https://github.com/wolffileseu/etds/commit/2c4e8e5) | Sends gameplay/chat events to et-tracker.trackbase.net; 22 TB_* entry points |
| GUID handling | `sv_allownoguid`, `sv_guidkickmsg` | [fc9fae9](https://github.com/wolffileseu/etds/commit/fc9fae9) | 32-char GUID validation; mod-specific fallback keys (silent→sil_guid, nitmod→n_guid) |
| Protocol version selection | `sv_protocol`, `sv_protocolcheck` | [fc9fae9](https://github.com/wolffileseu/etds/commit/fc9fae9) | Server can advertise any protocol version (83, 84); optional protocol-mismatch enforcement |
| Auth-server signaling | `sv_enableAuthServer`, `sv_authServer` | [fc9fae9](https://github.com/wolffileseu/etds/commit/fc9fae9) | Emits `gs <name>` OOB packets on player join for external auth services |
| **Dual UDP port + protocol inversion** | `net_port_extra` | [4d3ff2e](https://github.com/wolffileseu/etds/commit/4d3ff2e) | Open a second UDP socket that advertises the opposite protocol + `sv_isf` backlink |
| q3boom + Challenge-injection defence | `sv_defence`, `sv_defenceLog` | [8a50259](https://github.com/wolffileseu/etds/commit/8a50259) | Logs over-long or malformed challenge strings (q3boom 2006, info-string injection) |

Plus infrastructure work:

- [1cfb385](https://github.com/wolffileseu/etds/commit/1cfb385) — build system ported from Python 2 / SCons 1.x to Python 3 / SCons 4.x
- [a08dd31](https://github.com/wolffileseu/etds/commit/a08dd31) — GCC 12+ compatibility fix for `GetClockTicks` (rdtsc inline-asm → `__builtin_ia32_rdtsc`)
- [a923e40](https://github.com/wolffileseu/etds/commit/a923e40) — protocol-82 advertise correction (observed Pauluzz runtime behavior)

---

## Requirements

- Linux, 32-bit i386 userspace (on 64-bit systems, install `gcc-multilib` + `libc6-dev-i386`)
- GCC 12+ (tested with gcc 12.2.0 on Debian 12 Bookworm)
- Python 3.9+
- SCons 4.0+

Windows build support is [planned](https://github.com/wolffileseu/etds/issues) but not yet implemented.

---

## Install a prebuilt release

The easiest way to run ETDS is to download the prebuilt Linux binary from the [latest release](https://github.com/wolffileseu/etds/releases/latest):

```bash
cd /path/to/your/etmain
curl -L -o etded.x86 https://github.com/wolffileseu/etds/releases/latest/download/etded-v0.0.1.x86
chmod +x etded.x86

./etded.x86 +set dedicated 2 +set com_hunkMegs 128 \
    +set net_port 27960 +set sv_protocol 84 \
    +set g_gametype 4 +map oasis
```

You'll need the ET pak files (`pak0.pk3`, `pak1.pk3`, `pak2.pk3`) in the `etmain` directory. If you also want the server to run maps, put `qagame.mp.i386.so` there.

## Build from source

```bash
# System deps (Debian/Ubuntu)
sudo apt install gcc-multilib libc6-dev-i386 python3 scons git

# Clone
git clone https://github.com/wolffileseu/etds.git
cd etds
git checkout v0.0.1   # or master for bleeding edge

# Build
cd src
scons DEDICATED=1 BUILD_CLIENT=0 BUILD_SERVER=1 BUILD_BSPC=0 \
      TARGET_CORE=1 TARGET_CGAME=0 TARGET_GAME=0 TARGET_UI=0

# Output: src/etded.x86 (32-bit PIE ELF, ~2 MB)
```

The binary is statically linked against the internal game/cgame/ui VMs; it does not need any shared libraries beyond standard libc.

---

## Dual-port operation — the main event

Example `server.cfg` snippet that enables the dual-port browser listing:

```cfg
set sv_hostname "^1Wolffiles ^7Server"
set sv_protocol 84

// Main port 27960 advertises protocol 84 (ET Legacy / 2.60b)
set net_port 27960

// Extra port 27961 advertises protocol 82 (legacy tail)
// Clients see the listing twice on two different master entries
set net_port_extra 27961

set g_gametype 4
map oasis
```

The server opens both UDP sockets, responds to `getinfo` / `getstatus` queries on both, and sends heartbeats to all `sv_master1..5` entries twice — once per port. One game process, two server-browser listings, two client populations reached.

If the extra port is already in use, the server tries ports `+1..+9` as fallback, identical to how `net_port` conflict is handled. If no port binds, the server logs the failure and continues with single-port operation — extra is strictly optional.

---

## All new CVars

| CVar | Default | Notes |
|------|---------|-------|
| `net_port_extra` | `0` | Second UDP port, 0 = disabled |
| `sv_protocol` | `84` | Protocol version advertised on main port (83 or 84) |
| `sv_protocolcheck` | `0` | Reject clients with mismatched protocol |
| `sv_allownoguid` | `1` | 0 = require valid GUID for connect |
| `sv_guidkickmsg` | `"You have been kicked because don't have ETKEY"` | Shown to GUID-less clients (typo preserved for Pauluzz compat) |
| `sv_enableAuthServer` | `1` | Send player-join OOB packets to `sv_authServer` |
| `sv_authServer` | `et-auth.trackbase.net:27952` | Target address for auth-server OOB |
| `sv_tbCommands` | `1` | Allow TrackBase to issue server commands |
| `sv_tbChatRelay` | `1` | Relay in-game chat to TrackBase |
| `sv_maxGetstatusCheck` | `0` | 0 = disabled; otherwise max `getstatus` queries per minute per IP |
| `sv_maxGetstatusPerMinute` | `60` | Threshold for rate limit |
| `sv_maxGetstatusBeforeIPTABLES` | `0` | Unused in our port (Pauluzz had a shell-out here; intentionally omitted) |
| `sv_rconfilter` | `0` | 0 = rcon open to all with password; 1 = also require matching `sv_rcon1..5` |
| `sv_rcon1..sv_rcon5` | `""` | Allowed rcon source IPs; supports `*` wildcards |
| `sv_defence` | `0` | 1 = log dropped abuse events to `sv_defenceLog` |
| `sv_defenceLog` | `""` | Log file path (absolute or relative to server CWD) |

All CVars are archived (saved to server config) unless noted.

---

## Reverse-engineering methodology

The Pauluzz binary was analyzed with [Ghidra](https://ghidra-sre.org/). Functions of interest were identified by strings (`"sv_rconfilter"`, `"sv_defenceLog"`, `"heartbeat %s\n"`, etc.) and their decompiled output was read as a pseudo-specification.

No binary was disassembled verbatim into source. Each feature was understood at a behavioral level first (*what CVars does it read, what packets does it send, what side-effects does it have on `client_t`*), and then written from scratch against id-Software's GPL source using id-Software's coding style and existing idioms.

Two cases worth noting:

1. **Memory-layout-dependent hacks rejected.** Pauluzz's `Sys_SendPacket` uses `(&ip_socket)[param_8]` to index between two globals that must be placed adjacently in BSS. We replaced this with an explicit `if`/`else` — functionally equivalent, not dependent on link order.

2. **`client_t` byte-offset hacks rejected.** Pauluzz reads a magic byte at `client[0x191c7]` to determine which protocol a client connected with. We added an explicit `int protocol` field to `client_t` and updated `SV_DirectConnect` to set it. Safer, self-documenting, works across compiler versions.

The full before-and-after of every Pauluzz function we touched is available in the commit messages. Every commit is a feature on its own branch (`feat/antiflood`, `feat/trackbase`, `feat/dualport`, etc.) merged into `master` — the branches are preserved at `origin` for history.

---

## Roadmap

**Phase 1 (done).** 1:1 Pauluzz feature parity. Captured in tag `v0.0.0-pauluzz-1to1`. Released as `v0.0.1` with Wolffiles branding.

**Phase 2 (planned).** Wolffiles-specific improvements:

- Configurable TrackBase endpoint (`sv_tbHost`) — currently hardcoded to `et-tracker.trackbase.net`
- `sv_tbAllowRemoteCommand` kill-switch — currently TrackBase has unconditional server-command access
- QVM syscall round-trip for score/ready/team_id stats in `TB_Frame`
- Log rotation for `sv_defenceLog` via `FS_FOpenFileAppend` (proper `fs_homepath` integration)
- Per-IP rate limiting of defence-log writes (prevent log-flooding as its own DoS)
- GitHub Actions CI/CD for automated builds on tag push
- Windows 32-bit build support
- Consider `net_port_extra` default non-zero if operator demand exists

**Phase 3 (speculative).** Wolffiles auto-update infrastructure, extended stats reporting, CVar deprecation of the Pauluzz-1:1 naming (e.g. `sv_maxGetstatusBeforeIPTABLES` is an ugly name).

---

## License

Wolfenstein: Enemy Territory GPL Source Code is licensed under the **GNU General Public License v3**. The ETDS additions are released under the same license — see [COPYING.txt](COPYING.txt) and per-file license headers.

---

## Acknowledgments

- **id Software** for releasing the ET source code under GPL in 2010.
- **Pauluzz / TB (TrueCombat team)** whose 0.7.4 binary defined the feature surface this fork reimplements. We have no affiliation with them — this project is a clean-room third-party reimplementation.
- **ET: Legacy** for keeping the protocol-84 community alive.
- **TrackBase** for the tracking infrastructure that makes the chat/stats features useful.
- The **Wolffiles.eu community** for the motivation and the real-world test environment.

---

## Contact & support

- Website: [wolffiles.eu](https://wolffiles.eu)
- GitHub org: [wolffileseu](https://github.com/wolffileseu)
- Issues / bug reports: [Issues](https://github.com/wolffileseu/etds/issues)
- Community: Discord `@wolffileseu`, Instagram `@wolffileseu`
