# Disclosure — Project Reclaimer team

**Audience:** the Project Reclaimer developers (the community Halo 3 PC client/server that loads and
wraps the stock MCC `halo3.dll`).
**What this is:** a memory-corruption bug in the **FMOD FSB5 parser inside `halo3.dll`** that your
client reaches when it auto-downloads a server-required mod and the engine opens the mod's
`fmod/pc/sfx*.fsb` at map load. The bug is **not in your Rust code** — your transport/parsers are
memory-safe — but your delivery path is the realistic in-the-wild carrier, and **your loader is also
the best-placed layer to neutralize it today**, before any MCC/FMOD fix ships.
**Full technical detail:** [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md).

## 1. The delivery path (your client/server) — observed end-to-end

A real dedicated server + real client direct-connect was exercised on a loopback. The client joined,
your layer fetched/verified the server's required mods, the map loaded, and the engine opened a
mod-package `sfx.<name>.fsb` through FMOD — at which point `halo3.dll` faulted in the FSB5 parser.
The log below (`live-crash-ingame.log`) shows **the client connecting to the server, fetching/checking
the mods, then using (loading) the bank in question**, followed by the crash:

```
# real client + real dedicated server, direct-connect, Hugegrass map
12:05:04.655 Joining 127.0.0.1:49190 now that this game is up.
12:05:11.948 Join preparation: mods checked in 6.4 s, map prepared in 0.6 s.
12:05:41.901 Loading sound bank sfx.corvette_glassing_beam.fsb from hugeass_remastered_mcc's mod package (sfx.corvette_glassing_beam.fsb)
  [fmod-craft] ADD bank sfx.corvette_glassing_beam.fsb -> crafted .../poc_v2_numsamples_oob.fsb (map-load createStream)
12:05:42.640 Experimental startup exception 0xC0000005 in halo3.dll at RVA 0x4E93E8
12:05:42.640 Access kind 0 (0=read, 1=write, 8=execute); null target: false; low-address target: false
12:05:42.640 Access target: 300080000003
12:05:42.640 Registers: rax 7d9239db rbx 79617400 rcx 802a74eb66ba0000 rdx 7f801b97cbf0 rsi 300040de8ef8
             rdi f9c2ff4 rbp 310178940 rsp 310178800 r8 7f801b97cbe8 r9 0 r10 300080000003 r11 b0ba37
             r12 8 r13 10 r14 3000026dc628 r15 18
12:05:42.640 Unwound call chain (halo3.dll RVAs): 4E93E8 <- unmapped module <- ...
  [TerminateProcess] code=0x1
     halo3+0x4e9840          <- the FSB open, right after the call 0x4e92e0 sample-table builder
     halo3+0x462238
     ...
```

Notes on this run (full honesty): the integrity check **passed on the original bank** — the crafted
bytes were substituted only at FMOD's **map-load `createStream`** via the loader asset-redirect
(`PELOAD_FMOD_CRAFT`, gated to the engine-initiated open so your Rust integrity read still saw the
original). Every other element — join, mod fetch/verify, map load, `createStream`, FMOD parse, fault
at `0x4E93E8`, register state (`r10 = 0x300080000003` = the attacker-controlled OOB address) — is the
genuine in-game path. The register `r10` is the walk pointer `blob + Σ(size)` from the file's 24-bit
chunk sizes (see [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) §4.4).

## 2. What your layer already checks — and what it does NOT

| Reclaimer check | What it does | Effect on this bug |
|---|---|---|
| **Per-file SHA-256 vs Steam's manifest** (client + server) | Rejects a server serving bytes that differ from a subscribed Workshop item's manifest; won't host a tampered item. | **Blocks tampering a victim's *subscribed* item.** Does **not** block a *maliciously-published* Workshop item (there the crafted bank **is** the manifested content) or a **non-Workshop custom map** (`share_mods`, no Steam manifest). |
| **Shareable-file allow-filter** (ext/size/path) | `.fsb` ≤ 2 GiB; path constraints; extension allowlist. | A crafted `.fsb` **passes** — a surface filter, not a content check. |
| **Rust transport/parsers memory-safe** | QUIC/TLS/serde + `.mapinfo` (BLF) are Rust. | The bug is in **C++ FMOD** inside `halo3.dll`; a malformed `.mapinfo` is a Rust panic (DoS) at worst. |
| **No pre-open content validation of banks** | Banks go straight to FMOD `createStream`. | The crafted bank reaches the vulnerable parser unchanged. |

The SHA-256/Steam check is genuinely effective against *swapping a bank into someone else's
subscription*. It is **not** a defense against an attacker who **authors and publishes** the content,
or who runs a server sharing a non-Workshop map.

## 3. Mitigations you can ship (you wrap the game + the DLL)

You already (a) load `halo3.dll` with your own PE loader, (b) apply byte-signature code patches,
(c) own the asset redirect that resolves `fmod/pc/sfx*.fsb`, and (d) SHA-256-verify mod files. That is
enough leverage to stop this before the vulnerable parser runs. In increasing robustness:

### 3a. Secondary content check — reject the file (easiest, do this first)
In the Rust mod-acceptance / asset-redirect path (the code that already hashes mod files and returns
the `sfx.<name>.fsb` path to the engine), **validate the FSB5 header in safe Rust before it ever
reaches `createStream`** and refuse the bank (and the mod) on any failure:

* magic `FSB5`, version ∈ {0,1};
* `numSamples` capped, and **`numSamples * 4` computed in 64-bit** ≤ file size;
* `0x3C + sampleHeadersSize + nameTableSize + dataSize` consistent with the real file size;
* a Rust walk of the sample-header blob that checks **every** chunk `size` keeps the cursor within
  `sampleHeadersSize`.

This is a few dozen lines of bounds-checked Rust, version-independent, and it neutralizes **both**
defects (the integer overflow and the OOB walk) in memory-safe code. It is your "own checks that
secondarily reject the file."

### 3b. Patch the game's memory / code to prevent the trigger (you already patch halo3)
Because you load and sig-patch `halo3.dll`, you can neutralize the primitive in the engine itself:

1. **Guard-page FMOD's allocations** (`PELOAD_ALLOC_GUARD` already exists). An unmapped page after each
   FMOD allocation converts the OOB read/write into an **immediate controlled fault** (clean DoS)
   instead of silent corruption — removing both the heap-overflow path to the codec pointer and the
   silent-OOB-read.
2. **Detour the FSB `open` post-header-read** (≈`0x4e96b7`) to validate the header fields and branch to
   the codec error return (`eax = 0x13` / `FMOD_ERR_FORMAT`) on failure — a fix inside the engine's own
   flow, tied to this exact `halo3.dll` build (which you already signature-check).
3. **Software-CFG on the decode sink.** Detour `0x500e52` (`call [instance+0xa8]` in `readData`,
   `0x500e00`) to verify the target is inside halo3's `.text` before calling — a poor-man's Control
   Flow Guard for the one indirect call that yields RIP control (CFG is **off** in this build).

Caveat: 3a/3b protect **your** client only. Official Windows MCC (no Reclaimer) still needs
Microsoft/343 and Firelight to fix the bundled FMOD — see
[`DISCLOSURE-MICROSOFT-343.md`](DISCLOSURE-MICROSOFT-343.md) and [`DISCLOSURE-FMOD.md`](DISCLOSURE-FMOD.md).

## 4. Why this matters for you specifically
Your client **auto-downloads** server-required mods ("no way to turn them down" in the UI) and opens
them with no content check, so a single malicious server (or a published Workshop item) can crash — and
potentially, with heap grooming, control — every joining client. Shipping 3a alone closes the
realistic path through your distribution channel immediately. Details, register/file-byte mapping, and
the ASLR analysis (why full RCE is gated on an external info-leak that this bug does not supply) are in
[`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) §§4, 7, 12–14.

---

## P.S. — "I Can Haz Dev Helmet?" 🪖

Responsible disclosure is, of course, its own reward. But if a from-scratch FMOD loader, a confirmed
arbitrary-RIP proof in the real `halo3.dll`, a cross-version *unpatched-upstream* confirmation (through
FMOD 2.03.11), **and** a drop-in safe-Rust mitigation happen to be the sort of contribution that earns
a line in [`dev-helmets.json`](https://github.com/ProjectReclaimer/dev-player-id-list/blob/main/dev-helmets.json)
… we would wear it with great honor. 🫡

*No pressure. Mostly. (We'll also settle for the bug getting fixed.)*
