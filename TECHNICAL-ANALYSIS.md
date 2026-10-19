# FSB5 memory corruption in MCC's `halo3.dll` (statically-linked FMOD): controllable OOB from a mod-delivered sound bank

**Date:** 2026-10-19
**Target:** Halo: The Master Chief Collection — `halo3/halo3.dll`
**Binary identity:**
`sha1  fb2edf5805dd9c2adf5127f5abdd4834684b41bc`
`sha256 b209d8454b12dc77e54ccd2c9924ec8d44b8619d21cf98e36ffaf601e67efb63`
FMOD Studio low-level engine (1.10 series, ~2019), statically linked; FMOD is **not** exported (3 exports only: `CreateDataAccess`, `CreateGameEngine`, `SetLibrarySettings`), so the codec is reached by RVA.

**Companion report:** `FUZZING-SURVEY.md` (the fuzzing survey this deep-dive follows up on).

> **Status / honesty note.** This report demonstrates, in two independent execution
> environments, an **attacker-controlled out-of-bounds access** in FMOD's FSB5
> container parser, reachable from a sound-bank file with no user interaction. It
> proves (a) an integer-overflow-driven **attacker-controlled allocation size**,
> (b) an **attacker-controlled OOB read address** at a confirmed-crashing
> instruction, (c) a **remote DoS**, and (d) that the FSB **decode path
> (`readData`, `halo3+0x500e00`) dispatches through a function pointer in the codec
> instance with CFG disabled — and that corrupting that pointer yields exact,
> arbitrary instruction-pointer control**. (d) is confirmed **in MCC's real
> `halo3.dll`** (not only the emulator): driving halo3's own dispatcher with
> `instance+0xa8` set to `0x4141414141414141`, `0xdeadbeef13371337`,
> `0x0000414243444546`, … makes **`RIP` become each value exactly, every time**
> (§7.1; `rip-control-real-halo3.log`). What remains for a full weaponized RCE —
> pairing the demonstrated heap-corruption primitive (a) with this demonstrated control
> sink (d) through heap grooming, plus an ASLR leak from (b) — is argued in §7, not
> claimed as executed end-to-end.
>
> **Delivery (live test, §6.5–6.7).** A real dedicated server + real client
> direct-connect was exercised. It surfaced a genuine **mitigation**: the client *and*
> the server verify Workshop mod files' SHA-256 against **Steam's published manifest**,
> so a crafted bank **cannot** be swapped into a player's *subscribed* item (rejected on
> both ends). Pursuing the un-mitigated vector — a **server-shared non-Workshop custom
> map** — the join was accepted with no integrity block, and the real client was
> observed **opening each mod-package `sfx.<name>.fsb` through FMOD at map load**.
>
> **The live in-game crash was then demonstrated (§6.7).** In the real client, mid-match
> on the real Hugegrass map (joined via the real dedicated server, **integrity check
> passing on the original bank**), FMOD's map-load `createStream` opened a crafted ADD
> bank and the engine **faulted at `halo3+0x4E93E8`** — `0xC0000005` read access
> violation, far-OOB target `0x300080000003`, call chain `4E93E8 <- halo3+0x4E9840`
> (the FSB open, right after the `call 0x4e92e0` sample-table builder). This matches the
> from-scratch loader **and** the FMOD harness **to the instruction**. The single
> simulated element is the bank's arrival at that open: it was delivered via the loader's
> **asset-redirect** (`PELOAD_FMOD_CRAFT`, gated to FMOD's engine-initiated open so the
> integrity read still sees the original) — the same redirect a mod's `fmod/pc` override
> uses — because authoring a fully engine-*registered* mod on the macOS loader was blocked
> by the loader's own content-catalog limitations (§6.6), not by MCC. Every other element
> (client, server, UDP join, integrity pass, map load, `createStream`, FMOD parse, fault)
> is the genuine in-game path.
>
> **ASLR (§7.3).** Defeating `HIGH_ENTROPY_VA` needs an info-leak, and both candidate
> routes were investigated and came up **negative**: the client↔server protocol does not
> disclose a pointer (serde is pointer-free/bounds-checked; halo3 replicates quantized
> state + datum-handles), and the FMOD OOB-read reflection — a confirmed non-faulting leak
> *primitive* — has its pointer quantized away before any API output and is never forwarded
> to the server. So arbitrary RIP is proven, but end-to-end RCE on this build is **not**
> demonstrated; it would require an ASLR-defeat primitive from outside this parser.

---

## 1. Summary

`halo3.dll` opens mod-supplied sound banks (`halo3/fmod/pc/sfx*.fsb`) through FMOD
`System::createStream(path, CREATESTREAM|OPENONLY, exinfo=NULL)` — **no type hint**,
so FMOD selects a codec by content. For a file that is identified as an FSB
container, the **FMOD "FSB Codec" `open` callback** parses a 60-byte header plus a
per-sample header table whose sizes and counts come straight from the file. Several
of those fields are used **without validation** to:

* size heap allocations (`numSamples * 4`, `sampleHeadersSize`) — a 32-bit
  multiply that **overflows**, and
* drive a walk over the sample-header blob whose step distance is an
  attacker-controlled 24-bit field.

A crafted bank reproducibly faults **inside FMOD** at `halo3+0x4e93e8`, and the
address FMOD dereferences there is a value the attacker places in the file. The defect
is **unpatched in current FMOD** — standalone FMOD Core through 2.02.22 (May 2024)
crashes on the same input, and FMOD's public changelog shows no FSB5 fix through 2.03.15
(Sep 2026) — so it affects FMOD-based titles generally, not just MCC's older build (§3.1).

This is reachable remotely and **without any user action**: Project Reclaimer
servers push customization/sound mods to joining players (the client's own text
says players have "no way to turn them down"), and `.fsb` files up to 2 GiB are on
the client's shareable-file allowlist. See `FUZZING-SURVEY.md` §"Why this is exposed".

---

## 2. What is demonstrated (evidence at a glance)

| # | Primitive | Where | Confirmed by |
|---|---|---|---|
| V2 | `numSamples` (file +0x08) → `numSamples*4` **32-bit integer overflow** → attacker-controlled / wrapped allocation size → OOB | builder `0x4e92e0`, faults `0x4e93e8` | **real loader (SIGSEGV)** + from-scratch loader |
| V5 | 24-bit chunk **size** field → **attacker-controlled OOB read address** (`fault = buffer + size`) at the same instruction | `0x4e93e8` | from-scratch loader (byte-exact provenance) |
| V3 | huge chunk size → unbounded loop → **remote DoS (hang)** | `0x4e92e0` region | **real loader (HANG)** + from-scratch loader |
| — | `sampleHeadersSize` (file +0x0c) used directly as an allocation size (`0x7ffffff0`) | `0x4e92e0` | from-scratch loader (provenance → input@0xc) |
| **RIP** | decode `readData` does `call [instance+0xa8]` with **CFG off**; corrupt that pointer ⇒ **RIP = attacker value** | dispatcher `0x500e00` @ `0x500e52` | from-scratch loader (`RIP=0x4141414141414141`) |

"Real loader" = the project's Wine-free PE loader running `halo3.dll` under Rosetta
(x86-64), i.e. the actual production FMOD code. "From-scratch loader" = the
standalone Unicorn-based wrapper described in §5, which runs the **same real FMOD
code** but with byte-exact instrumentation.

The two environments **agree on the exact faulting instruction** (`halo3+0x4e93e8`),
which is the strongest cross-check available short of a Windows repro.

A **third, fully independent** environment corroborates it: standalone FMOD Core
`libfmod` (three versions, incl. Apple-Silicon-native arm64) crashes on the same
`poc_v2` input through the identical `createSound` path, with no `halo3.dll` and no
custom loader involved (§3.1). This confirms the defect is in **FMOD's own FSB5 logic**,
not an MCC- or loader-specific artifact, and that it is **unpatched upstream**.

---

## 3. Binary hardening posture (mitigations present on this build)

Parsed from the PE headers / load config (`harden.py`):

| Mitigation | State | Consequence for this bug class |
|---|---|---|
| **ASLR** — `DYNAMIC_BASE` + `HIGH_ENTROPY_VA`, `.reloc` present, not stripped | **ON** | Full 64-bit randomization. Absolute-address weaponization needs an info leak; the controlled OOB *read* (V5) is a genuine leak *primitive* but was **not** shown to disclose a pointer to the attacker-controlled server (§7.3), so ASLR is **not** defeated by this bug alone. |
| **DEP / NX** — `NX_COMPAT`, no RWX sections | **ON** | No shellcode-in-data; code-exec would require ROP/JOP. |
| **CFG (Control Flow Guard)** — `GUARD_CF` clear, GuardCFFunctionTable `0/0`, GuardFlags `0x100` (instrumented but table not emitted) | **OFF** | **Indirect calls through a corrupted function pointer / C++ vtable are NOT validated.** This is the realistic escalation route (§7). |
| **/GS** stack cookie — `SecurityCookie @ 0x18089b020` | **ON (partial)** | Stops naive saved-return overwrite; does **not** cover heap overflow, object/vtable corruption, or parser functions the compiler doesn't instrument. |
| SafeSEH handler table | `0/0` | Normal for x64 (table-based unwinding); no classic SEH-overwrite primitive. |
| Authenticode | Signed | Irrelevant to parsing attacker *content*. |

Net: **CFG off + /GS only partial** means a corrupted function pointer reached from
the parser/decoder is not stopped by control-flow integrity — the classic
"OOB read yields a value later used as a call target" chain is unmitigated here.

### 3.1 Upstream patch status — unpatched in every FMOD line tested

The FSB5 sample-table defect is **not an artifact of MCC shipping an old FMOD build; it
is unpatched in FMOD's current code.** This was verified against standalone FMOD Core
libraries, independent of `halo3.dll` and of either custom loader, by driving the exact
MCC load path (`createSound(path, 0x2080 /*OPENONLY|CREATESTREAM*/, NULL)`) on
`poc_v2_numsamples_oob.fsb` with a headless (`NOSOUND`) `dlopen`-based probe
(`fsb5_probe.c`):

| FMOD version | Release date | `poc_v2` via `createSound` | Source of lib |
|---|---|---|---|
| ~1.10.x (MCC's line) | 2017–2019 | **CRASH** | real `halo3.dll` (primary research: Unicorn loader + Rosetta loader + live in-game) |
| 2.01.09 | 15 Apr 2021 | **CRASH — SIGBUS** (byte-**write** translation fault) | public mirror, macOS arm64 |
| 2.02.14 | 3 May 2023 | **CRASH — SIGBUS** | public mirror, macOS arm64 |
| 2.02.22 | 8 May 2024 | **CRASH — SIGBUS** (`poc_v3` also crashes) | public mirror, macOS arm64 |
| **2.03.11** | 2025 | **CRASH — EXC_BAD_ACCESS (byte-write)** — same `str w10,[x0,x8,lsl#2]` store, `createSound → … → builder` | **GitHub LFS** (`BredaUniversityGames/xs`), macOS arm64-native; `fmod-2_03_11-regression.log` |
| 2.03.15 | 22 Sep 2026 | **no fix documented** (changelog; not runtime-tested — account-gated) | FMOD public revision history |
| 2.04.00 | 2026 | **not runtime-tested** — only Windows `fmod.dll` found on GitHub (Unreal plugins); no runnable mac/linux slice located | GitHub (header + Win64 dll) |

Two independent lines of evidence (full detail + reproduction in
`APPENDIX-UNPATCHED-SDK.md`):

* **Runtime:** four later standalone `libfmod` versions — through **2.03.11 (2025)**,
  including **Apple-Silicon-native arm64** builds, which rules out a loader/Rosetta
  artifact — crash inside `FMOD::System::createSound` on `poc_v2`. The fault is a
  **byte-write translation fault to an unmapped page** (symbolized backtrace four frames
  deep in `libfmod` under `createSound`), consistent with the `numSamples*4` 32-bit
  under-allocation being written past — a *write* primitive, which strengthens the
  corruption/exploitability story over a pure read. The 2.03.11 lib was sourced from a
  **public GitHub (Git LFS)** mirror; the same `str w10,[x0,x8,lsl#2]` store faults at
  `x0 + x8*4` exactly as on 2.02.22 (`fmod-2_03_11-regression.log`). An **exhaustive
  GitHub search** (version headers + committed `libfmod.dylib`/`.so`/`fmod.dll`) found the
  newest FMOD present to be **2.04.00**, but only as Windows `fmod.dll` inside Unreal
  plugins — no runnable mac/linux slice of 2.03.12+ or 2.04.x was locatable account-free,
  so 2.04.x remains changelog-only.
* **Changelog:** the complete public *Detailed Revision History* (1.09.07, Sep 2017 →
  2.03.15, Sep 2026; 114 point releases) contains **no** entry describing a bounds /
  overflow / out-of-bounds / crash fix in the FSB5 container or sample-header-table
  parser. FMOD *does* document malformed-input crash fixes when it makes them (corrupt
  WAV/MP3 in 2.00.01; corrupt s3m/xm/it tracker files in 2.02.35 / 2.03.14) — all in
  unrelated codecs, never FSB5 — so the 9-year absence is meaningful. No public CVE or
  FMOD advisory for an FSB/FSB5 OOB issue exists either.

A sub-format **version gate** was added at some later point (it rejects PoC variants
`v1/v4/v5` with a clean `FMOD_ERR_*`), but it does **not** cover the sample-count /
chunk-size overflow: the two real overflow vectors (`poc_v2`, `poc_v3`) still corrupt
memory on 2.02.22. So "update FMOD" is **not** a fix for MCC (see §9), and the defect
should also be reported to **Firelight Technologies (FMOD)** — it affects all current
FMOD-based titles that open untrusted FSB5 banks, not only MCC.

**Supply-chain scope.** The FSB5 container/sample-table parser is platform-independent C++
that is **statically linked into every FMOD build**, so an unpatched defect here is not a
single-product bug — it rides along in the entire FMOD install base. FMOD is one of the
most widely deployed audio middlewares in games: Wikipedia's *Games using FMOD* list
enumerates ~230 notable commercial titles and calls itself only "a partial list"
([en.wikipedia.org/wiki/FMOD#Games_using_FMOD](https://en.wikipedia.org/wiki/FMOD#Games_using_FMOD)),
spanning franchises such as *Halo*, *Dark Souls*, *BioShock*, *World of Warcraft*,
*Minecraft: Bedrock Edition*, *Roblox*, *Fall Guys*, *Celeste* and *Subnautica*, plus
official engine integrations for **Unity** and **Unreal Engine** (2.5–5) — i.e. an
effectively open-ended set of downstream products. The *realized* risk is per-title and
depends on whether a given title exposes FSB5 parsing to **attacker-controlled input**
(user/mod content, downloadable or networked banks, UGC) rather than only its own trusted,
shipped banks; MCC is **confirmed** exposed (mod-delivered `sfx*.fsb`, §1/§6), and any other
FMOD title with an untrusted-FSB5 path inherits the same OOB primitive. That is why the
right fix is **both** MCC-side input validation (§9) **and** an upstream Firelight fix that
reaches the whole ecosystem.

---

## 4. Root cause (FSB codec `open`)

Codec descriptor is built in `.data` at `0x4700f60` by the codec-registration
routine `halo3+0x4630d0`; its callbacks for the "FMOD FSB Codec":

```
open  = halo3+0x4ea490  (thunk -> 0x4e95d0, the real parser)
read  = halo3+0x4ea4b0  (-> 0x500e00, the decode path)
close = halo3+0x4ea4a0
```

### 4.1 Header fields (all attacker-controlled, read as the first 0x3c bytes)

```
+0x00  magic         "FSB5" / "FSB4"      (validated against tables @0x83f5a0 / 0x83f598)
+0x04  version       must be 1 here
+0x08  numSamples    -> loop count AND  numSamples*4 allocation size
+0x0c  sampleHdrSize -> allocation size of the sample-header blob
+0x10  nameTableSize -> read length into an allocated buffer
+0x14  dataSize
+0x18  mode          -> format dispatch (0xf enters the per-sample path)
+0x1c  (flag; ==1 required for mode 0xf)
+0x20  (flag; bit1 must be 0)
```

### 4.2 The vulnerable allocation + walk (`halo3+0x4e92e0`, called from `open` at `0x4e983b`)

Reconstructed from disassembly:

```c
// rcx = codec file, rdx = header buffer, out params = &state[+0x40], &state[+0x38]
blob      = FMOD_alloc(hdr->sampleHeadersSize);            // +0x0c, unchecked
read(file, blob, 1, hdr->sampleHeadersSize);               // fill from file
offsetTab = FMOD_alloc(hdr->numSamples * 4);               // +0x08 * 4  -> 32-bit OVERFLOW
for (i = 0; i < hdr->numSamples; i++) {                    // attacker loop count
    offsetTab[i] = (r10 - blob);                           // store current offset
    hasChunks = *r10 & 1;  r10 += 8;                       // 8-byte sample base
    while (hasChunks) {                                    // walk extra-param chunks
        dword = *r10; r10 += 4;
        size  = (dword >> 1) & 0xffffff;                   // 24-bit, attacker-controlled
        type  = dword >> 25;
        more  = dword & 1;
        ... ; r10 += size;                                 // <-- step by attacker size
        hasChunks = more;
    }
}
```

Two independent defects:

* **Integer overflow → bad allocation.** `numSamples * 4` is a 32-bit multiply.
  `numSamples = 0x7fffffff` → `0xfffffffc` (~4 GiB request: DoS / allocator
  failure). `numSamples = 0x40000000` → wraps to `0` → a zero/undersized buffer
  that the loop then writes `numSamples` entries into (**heap overflow, controlled
  count**). `sampleHeadersSize` is likewise used directly as an allocation size
  (observed value `0x7ffffff0`, provenance → input offset `0x0c`).

* **Unbounded, attacker-stepped walk.** `r10 += size` with a 24-bit attacker field
  and no check that `r10` stays within `blob[0 .. sampleHeadersSize]`. The next
  iteration dereferences `*r10`. **The dereference address is `blob + Σ(size)` —
  attacker-controlled.** This is the instruction that faults: `halo3+0x4e93e8`
  (`movzx eax, byte ptr [r10]`).

The later getter `0x4ea400` repeats the same `base + offsetTable[idx]` + chunk-walk
pattern when the per-sample path is taken, with the identical unchecked `rax += size`.

### 4.3 Abused FMOD Core API surface

Mapping the defect onto the documented FMOD Core API
([Sound reference, 2.00](https://www.fmod.com/docs/2.00/api/core-api-sound.html)):

* **Entry point — `System::createSound` / `System::createStream` (parse-time).** MCC calls
  `createStream(path, 0x2080, NULL)` = `FMOD_OPENONLY | FMOD_CREATESTREAM`, with **no**
  `FMOD_CREATESOUNDEXINFO::suggestedsoundtype` hint. With no type hint FMOD content-detects the
  container, selects its **FSB codec**, and runs that codec's `open`/parse **synchronously inside the
  create call** — so the `numSamples*4` overflow and the OOB access (§4.2) occur *there*, before any
  `Sound` method is called. `FMOD_OPENONLY` skips decoding the sample *data* but **not** the
  container-header parse, which is the vulnerable code — hence the crash lands at create time. (The
  Sound doc states it directly: *"Container for sample data… Create with `System::createSound` or
  `System::createStream`."*)
* **Corrupted abstraction — the FSB sub-sound table (`Sound::getNumSubSounds` / `Sound::getSubSound`).**
  An FSB5 is a *container of sub-sounds*; the overflowing field `numSamples` (file `+0x08`) **is** the
  sub-sound count (`getNumSubSounds`), and the per-sample header chunks are the sub-sound descriptors
  (`getSubSound`). The faulting function `0x4e92e0` is precisely the **builder of that sub-sound /
  sample-offset table** (`alloc(numSamples*4)` then the chunk walk).
* **RCE escalation sink — `Sound::readData` / `FMOD_SOUND_PCMREAD_CALLBACK`.** `readData` reads
  *"using FMOD's internal codecs"*, and `FMOD_SOUND_PCMREAD_CALLBACK` *"intercept[s] FMOD's decoder
  during a normal sound open"* — that per-codec decoder is reached through the codec-instance function
  pointer, i.e. the `call [instance+0xa8]` (§7.1) / unauthenticated `blr` (§7.5) that yields RIP once
  corrupted. Not needed for the DoS (OPENONLY stops before it); it is the control-transfer sink.
* **Info-leak read-back surface (ruled out, §7.3) — `Sound::getFormat` / `getLength` / `getDefaults`
  / `getNumSubSounds`.** These are exactly the outputs an OOB-read value would have to escape through,
  and all are quantized (format enum + channel index; frequency table; ≤32-bit length;
  `numSamples`) — which is why no full 64-bit pointer survives out of them.

In one line: **the bug is in the FSB-codec `open` invoked by `System::createSound`/`createStream`,
corrupting the sub-sound table behind `Sound::getNumSubSounds`/`getSubSound`; the RCE sink is the
internal-codec decoder dispatched by `Sound::readData`; and `Sound::getFormat`/`getLength`/
`getDefaults` are the quantized read-back that defeats the leak.**

### 4.4 The register-overwrite primitive — sent bytes → registers, with file layout

"The string that is sent" is the crafted `.fsb` bank delivered as a mod/server asset. Its header
fields and per-record `size` fields flow **directly** into the registers at the fault. There are two
corruption primitives (same function `0x4e92e0` / `libfmod b51f0`) plus one control-transfer sink:

**(P1) Integer-overflow linear heap overflow.** `offsetTab = alloc(numSamples*4)` is a **32-bit**
multiply; a large `numSamples` (file `+0x08`) wraps/under-allocates, then the loop writes
`offsetTab[i] = Σ(size)` for `i = 0 … numSamples`, walking off the short buffer.
**(P2) Attacker-stepped OOB deref.** the chunk walk does `ptr += size` with a 24-bit attacker `size`
and no bound, so the next `*ptr` lands at `blob + Σ(size)` — an attacker-chosen distance.
**(Sink)** when P1's write reaches an adjacent **codec object**, it overwrites its decoder function
pointer at `+0xa8`; the `Sound::readData` dispatch then does `call [instance+0xa8]` (x86-64, CFG off)
/ `blr` (arm64, no PAC) → **PC = the attacker-supplied pointer** (demonstrated RIP=`0x4141414141414141`,
§7.1; native-arm64 corruption §7.5).

**Register layout at the fault** — every operand traces to a sent byte:

```
 PRIMITIVE P1  (poc_v2)   store instr:   str  w10, [x0, x8, lsl #2]        // offsetTab[i] = Σsize
   register   value(run)   = sent byte(s) that control it
   ──────────────────────────────────────────────────────────────────────────────────────────
   x0  0x100579bb8   offsetTab base      = alloc(numSamples*4)   ← UNDER-sized by the +0x08 overflow
   x8  0x000fb912    loop index i        ← bounded by  numSamples  (file +0x08)   → WRITE EXTENT
   w10 0x0153af8f    value written Σsize  ← accumulated per-record 24-bit size fields → WRITE VALUE
   fault = x0 + x8*4 = 0x100968000  (first unmapped page past the under-alloc)

 PRIMITIVE P2  (poc_v3)   deref instr:   ldr/str w14, [x13]
   x13 0xb2b800000   walk pointer        = blob + Σ(size)        ← per-record 24-bit size (file)  → DEREF ADDR
   x11 0x00ffffff    the 24-bit size mask (0xffffff) applied to each chunk dword
   fault = x13 = 0xb2b800000  (attacker-magnitude address)

 CONTROL-TRANSFER SINK   dispatch:       call [instance+0xa8]  (x86-64) / blr xN (arm64)
   PC / RIP            = *(codec_obj + 0xa8)   ← bytes P1's overflow wrote into the adjacent codec object
                         (proven: plant 0x4141414141414141 → RIP=0x4141414141414141)
```
(x86-64 `halo3.dll` equivalents: the walk pointer is `r10`, faulting at `0x4e93e8`
`movzx eax,[r10]`; the sink is `0x500e52 call [instance+0xa8]`.)

**ASCII — file layout (`.fsb` "string"), records abstractly:**

```
 off     field                    size   ── attacker effect ───────────────────────────────
 ┌──────────────────────────────────────┐
 │ 0x00  magic  "FSB5"              4     │  validated
 │ 0x04  version (=1)               4     │  validated
 │ 0x08  numSamples          ◆──────4────┼─▶ loop count  &  numSamples*4 alloc  (P1: INDEX x8)
 │ 0x0c  sampleHeadersSize   ◆──────4────┼─▶ size of blob alloc = the walk arena
 │ 0x10  nameTableSize              4     │
 │ 0x14  dataSize                   4     │
 │ 0x18  mode (0xf→per-sample)      4     │  format dispatch
 │ 0x1c  flag(=1)   0x20 flag  …    …     │  (header = 0x3c bytes)
 ├──────────────────────────────────────┤  ◀── sample-header blob  (sampleHeadersSize bytes)
 │ record[0]  base dword  [.. | b0=more] │      8-byte sample base; b0 = "has chunks"
 │      └ chunk: [ type:7 | size:24 | m:1 ]  ◆─▶ ptr += size   (P2: DEREF DISTANCE x13/r10)
 │      └ chunk: [ type:7 | size:24 | m:1 ]      (repeats while m=1)
 │ record[1]  …                           │
 │   ⋮   (loop runs numSamples records — not bounded by the blob size!)
 │ record[numSamples-1]                   │
 ├──────────────────────────────────────┤  ◀── name table (nameTableSize)
 ├──────────────────────────────────────┤  ◀── sample data (dataSize)
 └──────────────────────────────────────┘
```

**ASCII — the overflow (P1), pre vs post:**

```
 numSamples = 0x40000000  →  numSamples*4 = 0x1_0000_0000  ──(32-bit truncate)──▶ 0x0000_0000
                                                            alloc(0)  → tiny/zero offsetTab

 x0 = offsetTab ─┐  (under-sized)                    adjacent heap objects
                 ▼                                   ┌───────────── codec object ─────────────┐
 [e0][e1][e2]│← in-bounds →│ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ │ … +0x80 fnptr … +0xa8 DECODER FN-PTR … │
             │              └─────────── OOB writes offsetTab[i]=Σsize, i=0…numSamples ───────▶ ▓
   str w10,[x0,x8,lsl#2]                                                 │
         ▲   ▲   ▲                                                       └─▶ overwrite [obj+0xa8]
         │   │   └ w10 = Σ(size)      (from the record size fields)         with attacker bytes
         │   └──── x8  = i → numSamples (write extent, from +0x08)
         └──────── x0  = under-alloc base
                                      then  Sound::readData → call [obj+0xa8] → PC = attacker value
         (if unmapped first:  write faults at x0+x8*4 = 0x100968000  → the observed DoS crash)
```

Net: the sent header integer (`numSamples`) chooses the **write extent / index register**, the
per-record 24-bit `size` fields choose the **written value and the deref-address register**, and the
overflow's reach into the neighbouring codec object plants the **function pointer that becomes PC** at
the `readData` dispatch.

---

## 5. The wrapper (standalone, from-scratch loader)

`rawload.py` — a self-contained loader that does **not** use Wine, the
game, or the project's harness. It:

1. maps `halo3.dll` into a Unicorn x86-64 VM at its preferred base `0x180000000`;
2. sets up a stack, a TEB (so `gs:[0x10]` stack-limit reads used by `__chkstk`
   resolve) and a **page-granular allocator with unmapped guard pages**, so an
   out-of-bounds access faults at a precise address exactly like a real heap page
   boundary;
3. stubs only the I/O + allocator boundary (`0x46b590` codec read, `0x461ff0`
   FMOD alloc, `0x4e9160` codec-cache lookup, a couple of mem ops) so that the
   **real FMOD parser code** (`0x4e95d0`, `0x4e92e0`, `0x4ea150`, `0x4ea400`,
   `0x4abde0`) executes on the attacker bytes;
4. drives the FSB `open` callback on the crafted file and, on fault, dumps the full
   x86-64 register state and runs **byte-exact provenance** — for the fault address
   and every register it reports the input-file offset the value came from; and
5. with `--decode`, drives the decode dispatcher `0x500e00` with a corrupted codec
   instance to demonstrate the CFG-off indirect-call sink (§7.1).

This is the "prove it" instrument: it shows, value by value, which bytes of the
input reach which registers / addresses.

Companion disassembly tools used to find the RVAs: `disasm.py`,
`reg_dump.py`. PoC generator: `craft.py`.

---

## 6. Reproduction

Environment used: macOS (Apple Silicon), Python 3.9, `unicorn==2.1.4`,
`pefile`, `capstone`. The harness is OS-agnostic (pure emulation); the "real
loader" cross-check used the project's `peload` under Rosetta.

```bash
# 1. set up
python3 -m venv uenv && ./uenv/bin/pip install unicorn pefile capstone

# 2. hardening report
./uenv/bin/python -I harden.py halo3.dll

# 3. (re)generate the PoC files
./uenv/bin/python -I craft.py 

# 4. drive the REAL FMOD parser on a PoC, with register + provenance dump
./uenv/bin/python -I rawload.py halo3.dll poc_v2_numsamples_oob.fsb
./uenv/bin/python -I rawload.py halo3.dll poc_v5_sizedist.fsb
```

PoC file hashes (sha256):

```
poc_v2_numsamples_oob.fsb  6b8657c0d9f78700bb7de7ea1258af5c4f7ff70c87147a5991c3c985bb5dc1b5
poc_v3_type6_bigsize.fsb   e15e8cb0a6109849cea431cdebbd82b1b278f371970b2c3200ba6eaca7117b9b
poc_v5_sizedist.fsb        ff4b1894d8225ece094c13d84b65ce38aa2c5b81850975c6da47883c040892e9
```

### 6.1 V2 — `numSamples` integer overflow → allocation + OOB (both loaders)

From-scratch loader:
```
[!] ATTACKER-CONTROLLED ALLOCATION SIZE: 0xfffffffc (memalloc(0xfffffffc))
########################## FAULT ##########################
  type        : read-unmapped
  faulting RIP: 0x00000001804e93e8  (halo3+0x4e93e8)
```

Real loader (production FMOD code under Rosetta), same instruction:
```
[CRASH] sig=11 faultaddr=0x7fc254000000 RIP=0x1804e93e8 (exe+0x4e93e8)
    ret 0x1804e9840 (exe+0x4e9840)   <- inside FSB open, right after call 0x4e92e0
    ret 0x18046afee ...
    ret 0x180525fa0 (exe+0x525fa0)
```

### 6.2 V5 — attacker controls the dereferenced address (from-scratch loader)

Input: `numSamples=2`, one chunk with 24-bit `size = 0x2a0000`.
```
########################## FAULT ##########################
  type        : read-unmapped
  fault addr  : 0x00000003002a2ffc      <-  blob_base(0x300002ffc) + 0x2a0000
  faulting RIP: 0x00000001804e93e8  (halo3+0x4e93e8)
```
`fault_addr - blob_base == 0x2a0000`, i.e. **the OOB read offset equals the 24-bit
`size` field byte-for-byte.** Changing that field moves the address FMOD reads by
the same amount (up to the 24-bit max, ±16 MiB from the buffer). In the real
process a small distance reads adjacent heap **without faulting** — i.e. an
**information-leak** read (useful against ASLR); a large/chained distance faults
as in V2.

### 6.3 V3 — remote DoS (real loader)

`poc_v3_type6_bigsize.fsb` → real loader verdict **HANG** (unbounded decode loop on
an oversized chunk). A single pushed bank wedges the client.

> Not reproduced as crashes on the real loader: `poc_v1` and `poc_v4`. The real
> loader's faithful file I/O rejects those at `open` (`FMOD_ERR_FORMAT`); they fault
> only under the harness's simplified sequential I/O and are **excluded** from the
> claims above. Reported for completeness, not as findings.

### 6.4 End-to-end: delivered as a mod, opened by the real engine

A Project Reclaimer "mod" is **not** a single packed file — it is a folder tree (a
Steam Workshop item for app 976730, or the same files a `share_mods` server hands
out). Sound banks are stored as **plain files** at `halo3/fmod/pc/sfx*.fsb` next to
`ModInfo.json` (confirmed against a real Workshop item on disk, Permafrost id
3663541185). The client verifies each delivered file's SHA-256 against the server
manifest (**integrity, not safety**) and applies only an extension / size / path
allow-filter — it **never inspects or transcodes** the `.fsb` content. Rules and
binary offsets: `shim/docs/mod-files-security.md`.

`modpack.py` packages a crafted bank as the **main** bank `sfx.fsb` (opened
unconditionally at engine init, halo3+0x172984 — no map load or user action needed)
and runs it through the documented acceptance rules:

```
=== client shareable-file acceptance ===
   path             : halo3/fmod/pc/sfx.fsb
   extension        : .fsb  (allowlisted: True)
   size             : 68 bytes  (cap for .fsb: 2147483648)
   path rules       : PASS
   bank-name redirect (type 3, exe+0xa48d90): PASS
   manifest digest  : sha256:6b8657c0d9f78700bb7de7ea1258af5c4f7ff70c87147a5991c3c985bb5dc1b5
   VERDICT: ACCEPTED by the shareable-file surface filter (extension/size/path)
   payload == source crafted FSB: True (sha256 match)
```

This covers only the **path/extension/size** surface filter. A live test (§6.5) found an
additional, important gate: for **Steam Workshop** mods the client *and* the dedicated
server verify every file's SHA-256 against **Steam's published manifest**, so a crafted
bank cannot simply be swapped into a *subscribed* item.

Opening that exact mod-delivered file through halo3's **own** `createStream` path
(`System::createStream(name, 0x2080, NULL)` at halo3+0x460b60 — the same call
halo3+0x172fc8 makes for a mod bank) crashes the real FMOD code:

```
FILE 0 .../mod-demo/halo3/fmod/pc/sfx.fsb
[CRASH] sig=11 faultaddr=0x7fed39400000 RIP=0x1804e93e8 (exe+0x4e93e8)
```

So the full chain is established with real code: **server-pushed customization mod →
`halo3/fmod/pc/sfx.fsb` delivered byte-for-byte (filter ACCEPT, SHA-256 match) →
halo3 opens it at engine init → SIGSEGV inside FMOD at `halo3+0x4e93e8`**, with no
user interaction. (Artifacts: `mod-demo/`.)

> **On reproducing `RIP=0x414141414141` in the live game.** The mod-delivered bank
> reproduces the **crash** above in the real engine. It does **not**, by itself,
> reproduce attacker-chosen `RIP` in the real process: V2 is an out-of-bounds
> *read* (faulting while dereferencing `buffer + attacker_distance`), not a call
> through attacker bytes. Attacker-chosen RIP in the real process requires steering
> the demonstrated heap-overflow write (numSamples path) onto the demonstrated
> `call [instance+0xa8]` decoder pointer (§7.1) with chosen bytes — heap grooming
> plus the ASLR leak from the controlled OOB read. That is exploit engineering on
> top of the primitives shown here; the `RIP=0x4141414141414141` result in §7.1 is
> produced in the instrumented loader by corrupting that pointer directly, to prove
> the sink is unguarded, **not** by the single file above. We flag this boundary
> explicitly rather than overstate the live-fire result.

### 6.5 Live server→client test, and the Workshop integrity mitigation

To test delivery end-to-end I stood up the **real** dedicated server
(`project-reclaimer-client-v0.9.20.exe dedicated`) hosting a Workshop map with
`share_mods = true`, and direct-connected the **real** client to it over UDP (both
under the loader). This is a genuine server↔client session, not the standalone FMOD
harness.

Replacing a bank inside a **subscribed** Workshop item was **rejected at join**:

```
Joining 127.0.0.1:49190 now that this game is up.
Join preparation: mods checked in 0.1 s, map prepared in 0.0 s.
Joining server failed: Permafrost - Beta: Steam Workshop's version differs from the
  server's (halo3/fmod/pc/sfx.building_sfx.fsb). The server and your subscription must
  use the same version.
```

and the dedicated server itself **refused to host** the tampered item:

```
Error: Workshop installation ...\Mods\Workshop\3663541185 is incomplete
  (halo3/fmod/pc/sfx.vulture_missile_detonation_lod.fsb); remove the item folder and retry
```

**Finding (a mitigation, in the client's favour):** both the client and the dedicated
server enforce **per-file SHA-256 integrity of Workshop mods against Steam's published
content manifest** (`reclaimer-workshop-version.json` carries the Steam manifest id;
`mod-digests.json` the per-file digests). A malicious server therefore **cannot** inject
a crafted bank into a player's *subscribed* Workshop item — the tamper is detected on
both ends. This is a real and effective control and should be credited as such.

**What this means for delivery.** The memory-corruption bug is unchanged; only the
*delivery path* is constrained. The vectors **not** stopped by the Workshop integrity
check are:

1. **An attacker-published Workshop item.** If the crafted bank is the item's own
   legitimate content, Steam's manifest matches it and the integrity check passes — a
   player who subscribes (or is required to, to join a server) then opens it. This is
   the most realistic at-scale vector and is **not** mitigated by the integrity check.
2. **A server-shared non-Workshop custom-map mod** (`content/Mods`, a custom `.map`
   package). These have no Steam manifest to verify against, so the client trusts the
   **server's** manifest and `auto_download_mods` fetches them. (A full live repro of
   this needs a ~2 GiB custom map hosted and downloaded; not run here.)
3. **Server-pushed customization content** ("customization mods are pushed on join …
   no way to turn them down"), to the extent it is not Steam-manifest-verified.

Honest end-to-end status: the crash is proven in the real FMOD code via the engine's
own `createStream` path (§6.1–6.3); a real server↔client join was exercised and
surfaced the Workshop integrity mitigation; a live in-engine crash requires one of the
three vectors above rather than tampering a subscribed item.

### 6.6 Non-Workshop custom-map route: reachability confirmed in the real client

Pursuing vector #2 (a server-shared non-Workshop custom map, which has no Steam
manifest to verify against), a real dedicated server hosting such a map in
`content/Mods` was accepted by both server and client over a live direct-connect join —
**no integrity block**. The decisive, real-client observation came at map load:

```
Join preparation: mods checked in 6.4 s, map prepared in 0.6 s.
Loading sound bank sfx.corvette_glassing_beam.fsb from <map>'s mod package (sfx.corvette_glassing_beam.fsb)
Loading sound bank sfx.super_mantis_landing.fsb from <map>'s mod package (sfx.super_mantis_landing.fsb)
... (one line per ADD bank the map's snd! tags name)
```

i.e. the **real client opens each mod-package `sfx.<name>.fsb` through FMOD at map
load**. Combined with §6.1–6.3 (a crafted bank of this exact kind crashes FMOD), this
closes the reachability argument: a mod-delivered crafted ADD bank is opened by the real
client's FMOD → the proven crash.

Two test-environment artifacts kept the *live* crash from firing, neither of which a
real attacker faces:

1. **Stem collision.** Reusing a map whose stem matches a client *subscription* made the
   client load its **local, original** banks (it played
   `.../workshop/content/976730/<id>/maps/<stem>.map`), not the server's crafted ones.
2. **Mac-loader map-catalog registration.** Renaming the map to a fresh stem (and
   hand-authoring its `.mapinfo` BLF — the server then hosted it fine) hit a
   `Native map catalog lookup did not resolve the selected map: expected
   halo3\maps\<stem>, got <empty>`. Per the loader project's own reverse-engineering
   notes (`shim/docs/RE-findings-menu-reentrancy.md`: `engine_catalog.rs = exe+0x1a1ce10`,
   resolve loop `exe+0x4e0abf`), this is a **known limitation of the Mac loader's
   map-catalog reimplementation** — its root cause is that the Mac loader's Forge asset
   library never builds, so catalog entries' scenario/path (`entry+0x10`) resolve to ''.
   **This is specific to the macOS loader used for this test, not to MCC or to Windows:**
   on real Windows MCC the catalog is native and maps load normally (as the *subscribed*
   map does even in this loader, §6.6 top). So the final live-crash gap is an artifact of
   the macOS test harness, **not** the vulnerability, the delivery, or Windows MCC.

So the chain is demonstrated to the point of **the real client opening mod-delivered
banks through FMOD**; the remaining gap is Blam-engine map authoring/registration, not
the vulnerability. An attacker shipping a properly-authored custom map (its own unique,
registered scenario + crafted ADD banks) has the client load the crafted banks exactly
as observed above.

A second server-delivery route was also exercised: a **customization mod**
(`halo3customization.json`), which the docs and binary confirm carries
`fmod/pc/sfx*.fsb` banks opened by a map's `snd!` tags, is **required on join** by a
server (`customization = [...]`, "no way to turn them down") and verified against the
*server's* manifest — so it needs no Steam cross-check and would reuse the already-
resolving **subscribed** map (no 2 GiB transfer, integrity-clean). The server config
field validated, but the loader only *recognises* a customization mod that contains at
least one **valid character** (a Spartan/Elite biped + armor referencing real Halo 3
tags; `src/forge_expansion/characters.rs`, "invalid armor region / variant") — a bank-
only mod is skipped. So this route, too, reduces to **authoring valid, recognised Halo 3
content** in the macOS loader.

**Conclusion on local delivery:** every server→client delivery path in this macOS test
harness terminates at the same requirement — produce **valid, engine-recognised Halo 3
content** (a catalog-registered custom map, or a customization mod with a real
character). That is exactly what the official **MCC Mod Tools** emit *by construction* on
Windows, so a real attacker never hits this wall; it is a from-scratch content-authoring
task specific to reproducing the final click **on macOS**, and it is orthogonal to the
FMOD memory-safety defect, which is fully demonstrated (§6.1–6.3) and whose in-engine
reachability is confirmed by the real client opening mod-package banks through FMOD
(§6.6). **Recommended validation**: on Windows MCC, build a trivial custom map (or
customization mod) with the Mod Tools, drop in a crafted `sfx.<name>.fsb`, and join — the
bank opens and FMOD faults at `halo3+0x4e93e8` as shown here.

### 6.7 Live in-game crash (real client + server, direct-connect)

To demonstrate the final in-engine fault without the macOS content-authoring blocker, the
crafted bank was delivered at the one point that blocker prevents — the *arrival of the
bank bytes at the engine's map-load open* — using the loader's **asset-redirect**
(`PELOAD_FMOD_CRAFT`), the same mechanism a mod's `fmod/pc` override uses. The redirect is
**gated to FMOD's engine-initiated open** (a `halo3.dll` return address on the stack), so
the client's **join-time integrity read still sees the original bank** and the join
succeeds; only the real `createStream` at map load receives the crafted bytes.

Everything else is the genuine in-game path: the real `project-reclaimer` dedicated server
hosting the subscribed **Hugegrass** map, the real client joining over UDP, the integrity
check **passing**, the real map load, and halo3's own `System::createStream`. Captured
from the client (`live-crash-ingame.log`):

```
12:05:11  Join preparation: mods checked in 6.4 s, map prepared in 0.6 s.   <- integrity PASSED
12:05:41  Loading sound bank sfx.corvette_glassing_beam.fsb from hugeass_remastered_mcc's mod package
          [fmod-craft] ADD bank sfx.corvette_glassing_beam.fsb -> crafted poc_v2_numsamples_oob.fsb (map-load createStream)
12:05:42  Experimental startup exception 0xC0000005 in halo3.dll at RVA 0x4E93E8
          Access kind 0 (read);  Access target: 300080000003   (far out-of-bounds)
          Registers: rax 7d9239db  rcx 802a74eb66ba0000  rdx 7f801b97cbf0  rsi 300040de8ef8  rbp 310178940  rsp 310178800
          Possible engine return RVAs: 0x4E9840
          Unwound call chain (halo3.dll RVAs): 4E93E8 <- halo3+0x4E9840 (FSB open, after call 0x4e92e0) <- ...
          [TerminateProcess] code=0x1   (the client's crash handler aborts)
```

The live client faults at **`halo3+0x4E93E8`** — a **read access violation** on a far
out-of-bounds address — the *identical* instruction reached by the from-scratch Unicorn
loader (§6.1) and the FMOD harness (§6.1–6.3), via the same `0x4E9840`→`0x4e92e0` FSB-open
path. This closes the chain end-to-end in the real client+server environment: a crafted
mod sound bank, opened by the real in-game FMOD at map load, crashes the engine at the
FSB5 parser. (The only non-production element is the ~15-line loader asset-redirect that
stands in for an engine-registered mod's own redirect, gated so it does not disturb the
integrity check; `shim/src/peload.c` `sfx_subst`, off unless `PELOAD_FMOD_CRAFT` is set.)

---

## 7. Exploitability

What is established: a remote, zero-interaction attacker who can get a bank opened
(server-pushed mod) controls, inside FMOD, (a) allocation sizes via a 32-bit
overflow, (b) the address of an out-of-bounds read, (c) can hang the process, and
(d) — see §7.1 — reaches a decoder **function-pointer indirect call that is not
CFG-protected**, which yields full RIP control when that pointer is corrupted.
(a) and the wrapped-to-zero allocation give a **controlled-length heap write**
primitive; (b) gives a **controlled-offset heap read** (info-leak class, exactly
what is needed to recover a module base and defeat ASLR).

### 7.1 The control sink: `readData` dispatches through `instance+0xa8` (CFG off)

The codec **read/decode** callback (`read = halo3+0x4ea4b0`, which loads the codec
instance `[codecstate+0x140]` and tail-calls the dispatcher `halo3+0x500e00`) does,
almost immediately:

```
0x500e20: mov  edx, dword ptr [rcx+0x13c]     ; rcx = codec instance, edx = format
0x500e52: call qword ptr [rcx+0xa8]           ; INDIRECT CALL through instance+0xa8
...
0x500f25 / 0x500fe8: call qword ptr [rbx+0x80]; further per-format decode dispatch
```

`instance+0xa8` and `instance+0x80` are **decoder function pointers** held in a heap
object. Driving the dispatcher with that pointer set to a tag value (as a heap
overflow / use-after-free would leave it) gives, in the from-scratch loader:

```
[*] driving decode dispatcher halo3+0x500e00
    instance+0xa8 (decode fn-ptr) = 0x4141414141414141  <-- corrupted/tagged
*** RIP CONTROL CONFIRMED ***
  readData (halo3+0x500e00) performed an INDIRECT CALL through the codec
  instance's decoder function pointer, with NO CFG check, and execution was
  redirected to the attacker value at instance+0xa8.
  RIP = 0x4141414141414141   (= the planted pointer, byte-for-byte)
```

The stack at the fault holds the return address `0x180500e58` (the instruction after
the `call`), confirming a genuine call transferred control. **Because `GUARD_CF` is
off on this binary (§3), nothing validates the target** — on a CFG-enabled build this
call would be checked and the process terminated instead.

Reproduce: `./uenv/bin/python -I rawload.py halo3.dll --decode`
(optionally `--a8 0xdeadbeefcafe0000` to plant a different value).

**Confirmed in the real halo3.dll binary (not only the emulator).** Driving halo3's
*own* `readData` dispatcher `halo3+0x500e00` under Rosetta (the loader's
`PELOAD_FMOD_RIPTEST` harness mode calls it with a codec instance whose `+0xa8` decoder
pointer is set to a chosen value — what a heap overflow / UAF of the FSB codec object
leaves there), the engine's `call [instance+0xa8]` transfers control to that value and
the process's `RIP` becomes it **exactly, every time** (`rip-control-real-halo3.log`):

```
instance+0xa8 = 0x4141414141414141   ->  [CRASH] sig=11 faultaddr=0x4141414141414141 RIP=0x4141414141414141
instance+0xa8 = 0xdeadbeef13371337   ->  [CRASH] sig=11 faultaddr=0xdeadbeef13371337 RIP=0xdeadbeef13371337
instance+0xa8 = 0x0000414243444546   ->  [CRASH] sig=11 faultaddr=0x414243444546     RIP=0x414243444546
instance+0xa8 = 0xcafebabe41414141   ->  [CRASH] sig=11 faultaddr=0xcafebabe41414141 RIP=0xcafebabe41414141
```

So in MCC's actual `halo3.dll`, **whatever value corrupts the codec instance's decoder
pointer is the next value of `RIP`** — arbitrary instruction-pointer control, with no
CFG to stop it. (lldb-on-the-live-FMOD was not usable here: a debugger's presence makes
halo3's FMOD setup take a different path — `setup=0`, the bank is rejected with a format
error rather than parsed — so the real-binary confirmation uses halo3's own dispatcher
driven directly under the loader, with the loader's crash handler reporting `RIP`.)
Reproduce: `PELOAD_FMOD_HARNESS=/dev/null PELOAD_FMOD_RIPTEST=0x4141414141414141 arch -x86_64 shim/build/peload <halo3.dll>`.

### 7.2 Chain to RCE (primitive + sink demonstrated; ASLR leak not established)

1. Defeat ASLR with an info-leak. **This is the open link.** The controlled OOB **read**
   (V5 class) is a genuine, non-faulting, attacker-offset leak *primitive* (confirmed
   dynamically, §7.3), but no examined path reflects a usable client pointer to the
   attacker-controlled server — **both** the transport/netcode protocol **and** the
   FMOD-reflection route are negative (§7.3). On this `HIGH_ENTROPY_VA` build the absolute
   address is therefore **not supplied by this bug itself**.
2. Use the integer-overflow **write** (V2 class: `numSamples=0x40000000` → `*4`
   wraps to a 0/undersized allocation → bounded write past it) to groom the heap and
   overwrite an adjacent codec instance's decoder pointer (`+0xa8`/`+0x80`) — or the
   instance field at `+0xd0` invoked via `call [instance+0xd0]` at `0x4ea5a5`.
3. Trigger `readData` (the game decodes the bank on play): the dispatcher calls the
   corrupted pointer → **RIP control (demonstrated in §7.1)**; DEP is then handled
   with ROP (large image, `.reloc` present).

The step-2 write primitive and step-3 sink are each demonstrated here, and the heap
groom + ROP assembly are engineering given those primitives. **Step 1 (the ASLR leak)
is the genuine open gap:** the OOB *read* is a real primitive, but it was **not** shown
to disclose a client pointer to the attacker across either the netcode protocol or the
FMOD-reflection path (§7.3) — so end-to-end RCE on this hardened build would require an
ASLR-defeat primitive from **outside** this parser (a second bug, a non-ASLR'd island,
or a Windows-specific info surface not present in this analysis).

Severity argument: remote + no user interaction + memory corruption in a parser on
the shareable-content path, **with an unmitigated (CFG-off) indirect-call sink that
provably yields RIP control**. Confirmed impact today is **remote DoS + local memory
corruption** (the OOB read is a local info-disclosure primitive). The demonstrated
CFG-off RIP sink makes **RCE the escalation ceiling**, but on `HIGH_ENTROPY_VA` it is
**gated on an ASLR-defeat leak this bug was not shown to supply** (§7.3). Triage
accordingly: a proven remote memory-corruption + arbitrary-RIP sink, with the
leak-dependent step honestly unmet on hardened builds.

### 7.3 ASLR and the info-leak ordering constraint

This build has full ASLR (§3), so RCE needs an absolute address — a **memory
disclosure** to recover `halo3.dll`'s (or a heap's) base. The controlled OOB **read**
(V5 class, §6.2) is an info-leak *primitive*, but note a timing constraint: **the crash
happens while the mod is being decoded, i.e. *after* the mod is accepted and loaded.** A
leak used to defeat ASLR must reach the attacker before the corrupting *write* is
committed. It need not precede mod acceptance: a **two-bank chain** fits the primitive —
bank #1 does a read-only OOB read whose bytes are reflected to the attacker-controlled
server, then bank #2 corrupts using the leaked base (banks stream over the session).

**Threat model (corrected).** The attacker **controls the dedicated server**, so it is
the **QUIC endpoint and decrypts everything the client sends**. Transport encryption
(quinn + rustls) is therefore **irrelevant** to this question — the earlier "it's
QUIC-encrypted, so no leak" framing was wrong. The real question is whether the
**plaintext application layer** the server observes after decryption, or any client
response to a server-crafted command, discloses a **client-side pointer**.

**Result of the client-side leak hunt — NO protocol-layer leak found** (full detail:
`APPENDIX-INFOLEAK-PROTOCOL.md`). The authoritative source for a *client-side*
leak is the client's own handlers, so the two application protocols a malicious server
sees were analysed by **binary RE** (the Reclaimer client ships as a **stripped release
`.exe`; there is no Rust source on the machine**, so handler names are recovered from the
`.exe` and `halo3.dll`):

* **Reclaimer transport/app layer (`serde`-derived messages).** serde serializes field
  *values*, never raw struct memory. (1) **No raw-pointer/handle/address protocol field**
  — every `addr`/`handle`/`offset` string resolves to Win32 imports, socket addressing,
  or PE-loader debug, not a wire field; the only handle-like values are **datum handles**
  (index+salt), not pointers. (2) **No server-controlled-length over-read** — a hostile
  length drives a **bounds-checked** slice → `panic` (DoS), not disclosure; **zero**
  `from_raw_parts` / `set_len` / `copy_nonoverlapping` / `MaybeUninit` / `assume_init`
  escape hatches in the wire path. (3) **`#[repr(C)]` padding send is prevented** — the
  only raw-byte casts use `bytemuck`/`zerocopy`, whose traits reject padded types at
  compile time, and their sole call site is `tiny-skia` (UI/stats pixmaps), not the
  protocol. (4) **No buffer echoed back at a server-chosen size** — the request/response
  pairs (`ContentRequest::{Manifest,Chunks,File,Range}`, `PreviewRequest`→`PreviewChunk`)
  are all **client-pull downloads**, i.e. the *server→client push* (corruption) direction,
  not a client-memory-disclosure direction.
* **halo3.dll game layer (C++ session netcode).** A **bitstream** serializer (explicit
  per-field bit widths) over the engine's **datum-handle** object model (32-bit
  index+salt). Game state is **quantized and handle-referenced, not pointer-bearing** — a
  property intrinsic to the engine, since handles must survive across machines. So the
  halo3 packets a malicious server receives carry quantized state and handles, not
  ASLR'd addresses.

Capture methods for *confirming* a candidate were also checked: **rustls key-logging is
not wired up** (`SSLKEYLOGFILE` absent; only `NoKeyLog`), so Wireshark decryption is
impossible; the AEAD backend is **`ring` with stripped asm symbols**, so there is no
hookable decrypt entry; and the loopback native-UDP **game transport uses
`WSASendMsg`/`WSARecvMsg`** — the earlier "100% QUIC" capture was dumping
`sendto`/`recvfrom`, the **wrong syscall**, which is why it saw only ciphertext. An
env-gated `PELOAD_DUMP_PLAIN` hook was added to the correct syscalls, but a verified
post-map-load join could not be reproduced on this macOS PE-loader, so **no live
post-map-load plaintext was captured** (the instrument is in place for native Windows MCC
or once the loader's join flakiness is resolved). The negative verdict therefore rests on
**serializer architecture + protocol direction + absence of any unsafe raw-copy**, which
is decisive for the protocol layer, not on the (incomplete) live capture.

**The FMOD OOB-read reflection — the one route the protocol analysis left open — was then
tested directly and is also negative** (`APPENDIX-FMOD-REFLECTION.md`). The chain
has three links; it dies at the second and third:

* **The OOB read IS a genuine, non-faulting leak primitive — confirmed dynamically.** With
  the adjacent page mapped (as the heap is at near distances), the real `halo3.dll` FSB
  parser reads a *planted* `halo3` `.text` pointer at an **attacker-chosen offset without
  faulting** (reads at `halo3+0x4e9400`/`0x4ea280`/`0x4ea440`; the offset equals the
  input's 24-bit `size` field byte-for-byte). So link 1 is real.
* **But the pointer is destroyed before any API output.** The sample-header walk consumes
  each over-read dword as **quantized chunk metadata** (24-bit size, 7-bit type) or an
  offset-table delta; the richest value it surfaces (`getLength`) is **≤32 bits**, so under
  `HIGH_ENTROPY_VA` the entropic high half of a `0x00007ff6_xxxxxxxx` pointer is lost. A
  full-pointer reflection exists only via a *different* primitive, the `readData` PCM
  memcpy (established structurally).
* **And nothing is forwarded to the server.** `readData` PCM output feeds the FMOD mixer →
  audio device (client-local playback, never serialized); `getLength`/`getFormat` configure
  local playback and are not replicated; voice chat is a separate mic-capture pipeline not
  fed by the sfx decoder. Each client decodes its own copy of the bank and sends no decode
  result back — consistent with the netcode track's pointer-free protocols.

So **neither** the transport/netcode protocol **nor** the FMOD-reflection path discloses a
client pointer to the attacker-controlled server. (One residual not exhaustively closed by
RE: a server-authored **Megalo** script reading a sound property into a *replicated*
variable — but that too would carry only the quantized/≤32-bit values above, never a full
pointer, so it cannot by itself defeat `HIGH_ENTROPY_VA`.)

**Net.** With no confirmed ASLR-defeat leak from either route, the finding stands at
**remote DoS + local memory corruption with a proven, CFG-unguarded indirect-call sink that
yields arbitrary RIP** (§7.1). On this `HIGH_ENTROPY_VA` build, **end-to-end remote RCE is
not demonstrated**: it would require an ASLR-defeat primitive from **outside** this parser
(a separate bug, a non-ASLR'd island, or a Windows-specific info surface not present here).
The controlled OOB *read* remains a real primitive, so this **bounds** the gap rather than
closing the door — but it is an honest, concrete negative, not an open "next step."

### 7.4 Delivery accessibility / attacker barrier

The un-mitigated delivery vectors are **low-barrier and broadly accessible**:

* **Published Steam Workshop item — any MCC-on-Steam owner.** MCC's official Mod Tools
  are free; publishing to Steam Workshop is **self-service and effectively immediate**,
  with **no pre-publication inspection of a mod's file contents**. The Halo 3 tools need
  a Steam license for MCC (mainstream, inexpensive, frequently discounted); the Steam
  account must have spent ≥ $5 (Valve's standard "Limited User" anti-spam threshold,
  already satisfied by owning MCC). Embedding the payload is a **one-file swap** — the
  crafted `.fsb` looks like an ordinary sound bank, and no tool inspects its internals.
  Decisively, the client+server **SHA-256 integrity check against Steam's manifest
  passes**, because the crafted bank **is** the item's legitimate published content — the
  exact mitigation that blocks tampering a victim's subscription does nothing here.
  Reclaimer clients **auto-download** server-required mods ("no way to turn them down").
* **Non-Workshop custom map — any dedicated-server operator, no Steam/account/$5/review.**
  An operator can `share_mods` a custom-map package; joining clients auto-download it with
  **no Steam cross-check** (verified against the *server's* manifest only). Zero account
  barrier; the operator requires their own map, so the "subscriber base" needed is zero.

Net attacker barrier: *own MCC on Steam + free official tools* (published-item path) or
*run a dedicated server* (custom-map path) — both mainstream — with a **trivial one-file
payload** and **no content security review** on either path. This is not a
nation-state-only capability; it is within reach of an ordinary modder or server host.

### 7.5 Native-macOS confirmation in standalone `libfmod` + arm64 hardening (usable/unusable)

The corruption primitive was reproduced **directly in Firelight's shipped `libfmod.dylib`** (FMOD
2.02.22, code-signed `TeamIdentifier=FNXNE97GV7`) — real FMOD code run **natively on Apple-Silicon
arm64** under `lldb`, with no Unicorn emulation, no Rosetta, and no `halo3.dll`. This is a second
CPU/OS confirming the same defect, and it lets the hardening question be answered against a real
process. Full detail + reproduction: `APPENDIX-LIBFMOD-REGCONTROL.md`,
`libfmod-regcontrol.log`.

**Register control, confirmed.** Driving `createSound(bank,0x2080,NULL)` on two crafted banks faults
inside FMOD's FSB5 sample-table builder with attacker-controlled register state:

* `poc_v2` → controlled **OOB write**: `str w10, [x0, x8, lsl #2]` (`x0`=under-allocated table base,
  `x8`=`0xfb912` attacker-driven index from the `numSamples*4` 32-bit overflow, `w10` the
  blob-sourced value); `x0 + x8*4 = 0x100968000` = the fault address.
* `poc_v3` → attacker-controlled **dereference address**: the walk pointer `x13 = 0xb2b800000`
  (driven by the 24-bit chunk `size`; `x11 = 0xffffff`) is the fault address.

**Hardening → usable vs unusable** (measured on the actual arm64 slice):

| Mitigation | State | Effect |
|---|---|---|
| **PAC** (pointer auth) | **ABSENT** — plain `arm64` (not `arm64e`), **0** `pac*/aut*/blraa` insns, all **1200** indirect branches are plain `blr/br xN` | **USABLE** — a corrupted function pointer transfers control through an **unauthenticated `blr`**: the arm64 analogue of Windows CFG-off (§7.1's `call [instance+0xa8]`). |
| **CFG** | N/A (Windows/PE only; none under Rosetta) | **USABLE** (same as `halo3.dll`). |
| **Stack canary** | present | **Irrelevant** — the write is heap/data, not a stack return (mirrors "/GS partial"). |
| **DEP / NX** | **ON** (no RWX) | forces **ROP/JOP** (same as Windows). |
| **ASLR / PIE** | **ON** — load base moved across runs (`0x104c04000`/`0x104be8000`/`0x104cd4000`) | **UNUSABLE without an info leak** — needs an absolute target. |
| **Hardened runtime / library validation** | ON | **No effect** on in-process data corruption. |

**Bottom line (identical to the Windows conclusion, now on a 2nd arch):** the register/memory-write
control is real and the control-transfer sink is **unauthenticated** (no PAC, no CFG) — so the
primitive is *usable* up to the **ASLR** wall; with both info-leak routes negative (§7.3), chosen-`pc`
RCE is **not** achievable without an out-of-band ASLR defeat. The one mitigation that would make even
a leaked-base hijack *unusable* is **PAC** (an `arm64e` build) / CFG — which neither this `libfmod`
nor MCC's Windows build has, which is exactly why the `blr`/indirect-call sink is open.

---

## 8. Caveats

* All dynamic results are from macOS: the from-scratch loader is a **Unicorn
  emulation** of the real `halo3.dll` code; the cross-check loader runs the real
  code under **Rosetta**, not native Windows. Heap layout and allocator behaviour
  differ. **Confirm on Windows**, ideally with PageHeap/Application Verifier, before
  final severity ranking — PageHeap will also catch the tighter sub-page OOBs the
  current page-granular guard does not.
* The two macOS environments agreeing on the faulting instruction
  (`halo3+0x4e93e8`) strongly suggests the defect is in FMOD's own logic, not an
  artifact of either loader.
* PoC `.fsb` files are tiny and benign (headers + a few tagged bytes); they are
  parser inputs, not working exploits.

---

## 9. Suggested fixes (vendor)

1. **Validate FSB5 header fields before use**: `numSamples`, `sampleHeadersSize`,
   `nameTableSize`, `dataSize` and every per-sample chunk `size` against the actual
   file size, with sane caps; reject on mismatch. (Allocation sizes must be computed
   with overflow checks — `numSamples * 4` on 64-bit math with a bound.)
2. **Restrict mod banks to FSB5** in the client: pass
   `FMOD_CREATESOUNDEXINFO::suggestedsoundtype = FMOD_SOUND_TYPE_FSB` and refuse
   anything FMOD doesn't identify as FSB — removes the tracker/MIDI/playlist/etc.
   decoders from the reachable surface (they produced the other crashes in
   `FUZZING-SURVEY.md`).
3. **Validate FSB5 banks in the client (Rust) before handing bytes to FMOD**, as the
   client already does for other mod formats.
4. **Do not rely on "update FMOD" as the fix — the defect is unpatched upstream.**
   Standalone FMOD Core crashes on the same input through at least 2.02.22 (May 2024),
   and the public changelog shows no FSB5 fix through 2.03.15 (Sep 2026) (§3.1). Updating
   FMOD does not remove this bug; the client-side mitigations (1–3) are the effective fix.
   **Report the defect to Firelight Technologies (FMOD)** so it is fixed at the source for
   all FMOD-based titles, and so a future MCC FMOD update actually helps.
5. **Decode in isolation**: decode mod audio in a low-privilege sandboxed process and
   pass PCM back.
6. **Treat server-pushed content as opt-in** (customization mods included).

---

## 10. Artifacts (repo root)

The repository is **flat** — every file in the root; the `.md` writeups cross-link each other
(index: [`README.md`](README.md)).

**Analysis & disclosure writeups (Markdown):**

* [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) — this document (root cause → exploitability → hardening).
* [`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md) — standalone-FMOD cross-version confirmation; unpatched upstream (§3.1).
* [`APPENDIX-INFOLEAK-PROTOCOL.md`](APPENDIX-INFOLEAK-PROTOCOL.md) — client-side leak hunt; no protocol leak (§7.3).
* [`APPENDIX-FMOD-REFLECTION.md`](APPENDIX-FMOD-REFLECTION.md) — FMOD OOB-read reflection; leak NOT confirmed (§7.3).
* [`APPENDIX-LIBFMOD-REGCONTROL.md`](APPENDIX-LIBFMOD-REGCONTROL.md) — native-arm64 register control + hardening (§7.5).
* [`FUZZING-SURVEY.md`](FUZZING-SURVEY.md) — the initial fuzzing survey this deep-dive follows up on.
* Disclosures: [`DISCLOSURE-FMOD.md`](DISCLOSURE-FMOD.md) · [`DISCLOSURE-RECLAIMER.md`](DISCLOSURE-RECLAIMER.md) · [`DISCLOSURE-MICROSOFT-343.md`](DISCLOSURE-MICROSOFT-343.md) · [`DISCLOSURE-DEVELOPERS.md`](DISCLOSURE-DEVELOPERS.md).

**Harness / tooling:**

* `rawload.py` — from-scratch Unicorn loader (register/provenance dump; `--decode` RIP sink; `RAWLOAD_LEAK` mode).
* `craft.py`, `craft_leak.py` — crafted `.fsb` generators.  `harden.py` — PE hardening report.
* `disasm.py`, `icall_scan.py`, `reg_dump.py` — analysis tools.  `modpack.py` — mod packaging + shareable-file filter.  `mapinfo.py` — `.mapinfo` (BLF) parser/author.
* `fsb5_probe.c`, `run_probe.sh`, `parse_rev.py` — standalone-`libfmod` `createSound` probe + changelog parser.
* `peload-fmod-poc-additions.c` — the env-gated loader blocks, **all OFF by default** (`PELOAD_FMOD_CRAFT`, `PELOAD_FMOD_RIPTEST`, `PELOAD_DUMP_UDP`, `PELOAD_DUMP_PLAIN` on `WSASendMsg`/`WSARecvMsg`).

**Samples:** `poc_v1…v6_*.fsb`, `poc_tag_414140.fsb`.  **Demo mod:** `mod-demo/` (`ModInfo.json` + `halo3/fmod/pc/sfx.fsb`).

**Evidence logs:** `rip-control-real-halo3.log`, `live-crash-ingame.log`, `poc_runs.log`, `probe_runs.log`, `backtrace_createSound.txt`, `changelog_timeline_and_keyword_hits.txt`, `fsb5_probe-*.ips`, `fmod-2_03_11-regression.log` (newest runtime-confirmed version, GitHub-sourced), `infoleak-plaintext-capture.log`, `infoleak-protocol-experiment.log`, `fmod-reflection-SQ1.log`, `libfmod-regcontrol.log`.

**Not redistributed:** `halo3.dll` (Microsoft copyright; identified by hash above) and the third-party FMOD `libfmod` binaries (`FMOD-SDK-BINARIES.txt` lists the public mirrors to re-fetch). Crashing samples and full logs can be shared privately with the vendor on request.

---

## 11. FMOD pedigree & disclosure scope

**The vulnerable FSB5 parser is not Microsoft's code — it is FMOD**, third-party audio middleware
statically linked into `halo3.dll`. This governs fix ownership and scope.

* **What it is.** The FMOD Engine exposes a low-level **Core API** (the backbone of the engine; the
  lineage of the old "FMOD Ex") and a high-level **Studio API** on top. `halo3.dll` statically links
  **FMOD 1.10.x** (~2019, the last `1.x` series before `2.00`). The **FSB / FSB5** container and its
  codecs are part of the Core API's file layer; that parser holds the defect.
* **Author / distribution.** Developed by **Firelight Technologies Pty Ltd** (Melbourne, Australia);
  the original FMOD player was written by **Brett Paterson** in the late 1990s, company **founded
  ~2002**. On **1 October 2026 Firelight was acquired by Bose**. FMOD is **closed-source,
  proprietary**, shipped as **precompiled SDK libraries** that studios link (statically here).
* **Ubiquity.** FMOD is one of the two dominant game-audio middlewares (with Audiokinetic Wwise),
  with **official Unity and Unreal integrations** (each bundles the FMOD Engine). Wikipedia's
  [*Games using FMOD*](https://en.wikipedia.org/wiki/FMOD#Games_using_FMOD) lists ~230 notable titles
  and calls itself "a partial list" (*Halo*, *Dark Souls*, *BioShock*, *World of Warcraft*,
  *Minecraft: Bedrock*, *Roblox*, *Fall Guys*, *Celeste*, *Subnautica*, …).
* **Scope implication.** The **defect is upstream FMOD**; the **reachability is MCC-specific** (MCC
  opens untrusted mod-supplied `sfx*.fsb` with no type hint). The complete fix is **both** a
  client-side input check **and** an upstream Firelight fix. See the cross-version confirmation in
  [`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md).

### 11.1 Scope — only what is factually confirmable

We do **not** claim specific third-party titles are exploitable — exposure needs *both* a vulnerable
FMOD build *and* a path that opens **untrusted** FSB, which is the exception, not the rule.

| Certainty | Claim | Basis |
|---|---|---|
| **Confirmed (binary, by us)** | **Halo: MCC `halo3.dll`** statically links **FMOD 1.10.x**; its FSB5 parser has the defect and crashes / yields RIP control | this analysis — direct binary RE + reproduced (3 environments) |
| **Confirmed (binary, by us)** | Standalone FMOD **2.01.09 / 2.02.14 / 2.02.22 / 2.03.11** crash on the same input; changelog clean through **2.03.15**; newest on GitHub is **2.04.00** (Windows-only) | [`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md) |
| **Vendor-documented** | FMOD ships official **Unity** and **Unreal** integrations bundling the engine | fmod.com docs |
| **Third-party-documented (breadth)** | Wikipedia *Games using FMOD* — ~230 titles, "a partial list"; Dolby lists "1500+ titles" | [Wikipedia](https://en.wikipedia.org/wiki/FMOD#Games_using_FMOD); Dolby partner page (secondhand) |

**Exposure caveat:** the *bug* is in FMOD; the *reachability* in MCC comes from MCC opening
**mod-supplied, untrusted** `sfx*.fsb`. Titles that parse only their own trusted banks are **not**
attacker-reachable via this bug even on a vulnerable FMOD. The reachable population is apps that open
**untrusted** FSB (mod loaders, UGC pipelines, asset front-ends on an embedded FMOD).

### 11.2 How Unreal Engine uses FMOD (and Unity) — optional plugin, not default

A common question for scope is whether Unreal titles ship FMOD by default. **They do not.**

* **Not built in / not default.** Unreal Engine's stock audio is Epic's own (the Audio Mixer and
  MetaSounds). FMOD is **not** part of a clean Unreal install, and a default Unreal project does not
  link the FMOD Engine at all. To use FMOD a developer must add the **"FMOD for Unreal"** integration —
  a separate, third-party plugin (the project plugin folder is named `FMODStudio`, with a companion
  `FMODStudioNiagara`).
* **Separate download + manual install.** The integration is **downloaded from FMOD**
  ([fmod.com/docs/unreal](https://www.fmod.com/docs/unreal)) and dropped into the project's (or
  engine's) `Plugins/` directory. It is **free to use**, but shipping a title with it requires an FMOD
  license. This is a deliberate, per-project developer action — "special intervention / third-party
  install," not a checkbox on a stock engine.
* **The plugin bundles the FMOD Engine runtime — i.e. the vulnerable parser.** GitHub-vendored Unreal
  projects show the plugin shipping the platform FMOD libraries inside it, e.g.
  `Plugins/FMODStudio/Binaries/Win64/{fmod.dll, fmodL.dll, fmodstudio.dll, fmod_haptics.dll}` and a
  macOS `libfmod.dylib`. So an Unreal game that adds FMOD carries the same FSB5 code analysed here.
* **Versions.** FMOD for Unreal officially supports Unreal **4.27** and **5.3 – 5.7**; the integration
  is free, license-gated for release. Each plugin release tracks an FMOD Engine version — GitHub-
  vendored Unreal projects carry **2.02.30, 2.02.35, and 2.04.00** plugin builds, i.e. the integration
  spans the whole vulnerable 2.0x – 2.04 range (2.04.00 is the newest FMOD seen anywhere in this
  search, and it appears specifically as an Unreal plugin).
* **Scope line.** An Unreal title is exposed by this bug **only if both** (a) the developer added the
  FMOD for Unreal plugin, **and** (b) the title opens **untrusted** FSB/bank input (mods, UGC, DLC, or
  networked banks). A title that loads only its own shipped FMOD banks is not attacker-reachable. The
  same logic applies to the official **FMOD for Unity** integration (also a separate, opt-in package
  that bundles the engine).

---

## 12. What Project Reclaimer's (Rust) layer checks — and what it does NOT

The in-the-wild distribution path is **Project Reclaimer**, a community Halo 3 PC client that drives
the stock MCC `halo3.dll`. Its client/server plumbing is **Rust** (quinn/QUIC + rustls + tokio +
serde). Its relevant defenses and their limits for *this* bug:

| Reclaimer check | What it does | Effect on this vuln |
|---|---|---|
| **Per-file SHA-256 vs Steam's published manifest** (client **and** server) | A subscribed Workshop item's files must match Steam's manifest; a server serving different bytes is rejected, and it won't host a tampered item. | **Blocks tampering a victim's *subscribed* item.** Does **not** block a *maliciously-published* item (there the crafted bank **is** the manifested content) or a **non-Workshop server custom map** (no Steam manifest). Verified live here. |
| **Shareable-file allow-filter** (ext/size/path) | `.fsb` ≤ 2 GiB; path ≤ 200 bytes, ≤ 4 `/`-parts, no traversal; extension allowlist. | A crafted `.fsb` **passes** — it is a normal-looking bank. A surface filter, not a content check. |
| **Rust transport/parsers are memory-safe** | QUIC/TLS/serde and the mod-metadata / `.mapinfo` (BLF) readers are Rust. | The bug is **not** in the Rust layer; a malformed `.mapinfo` is a Rust **panic (DoS)** at worst. The memory-corruption bug is in the **C++ FMOD** inside `halo3.dll`. |
| **No pre-open content validation of banks** | Banks go straight to FMOD `createStream`. | The crafted bank reaches the vulnerable parser unchanged. |

**Key point:** the SHA-256/Steam-manifest check genuinely stops *swapping a bank into someone else's
subscription*, but it is **not** a defense against an attacker who **authors and publishes** the
malicious content, because then the crafted bytes are the item's legitimate, manifested content.

---

## 13. Attack workflow & accessibility

### 13.1 Highest-probability workflow: a malicious Steam Workshop publisher

```
 1. Attacker owns Halo: MCC on Steam + installs the free official MCC Mod Tools.
    (Workshop submission needs a non-"Limited" account, i.e. >= $5 spent — met by owning MCC.)
 2. Build an ordinary custom map / customization mod with the tools; drop in a crafted
    sfx.<name>.fsb as one of its sound banks (one-file swap; the tools register it "by construction").
 3. PUBLISH to the Steam Workshop. NO pre-publication inspection of file contents; the item is live.
    --> the crafted bank is now the item's LEGITIMATE, Steam-manifested content, so the client+server
        SHA-256 integrity check PASSES.
 4. Run (or convince) a Reclaimer server to require that item. Joining clients AUTO-DOWNLOAD required
    mods ("no way to turn them down" per the client UI).
 5. On map load, a snd! tag opens sfx.<name>.fsb -> FMOD createStream -> the parser -> crash /
    (with grooming + an external ASLR leak) RIP control. Zero clicks beyond joining.
```

Lower-barrier variant (no Steam at all): a malicious dedicated-server operator shares a **non-Workshop
custom map** (`share_mods`); clients auto-download it with **no Steam cross-check** (verified only
against the server's own manifest).

### 13.2 Reliability of each outcome

* **DoS / crash (OOB read, `0x4E93E8`): near-certain**, mildly heap-layout-sensitive (the fault needs
  `blob + Σ(size)` to hit an unmapped page; a large/compounded size makes this overwhelmingly likely).
* **RIP control at the `call [instance+0xa8]` / `blr` sink: deterministic given a corrupted pointer**
  (no CFG / no PAC — §7.1, §7.5). The non-deterministic part is the **heap groom** landing the
  overflow on a live codec instance's `+0xa8`; the codec object and the overflowing buffers come from
  the same allocator in the same `createStream`, so they are adjacent and groomable (engineering).
* **ASLR is the real gate — and this bug does not clear it.** Both leak routes are **negative**: the
  transport/netcode protocol discloses no pointer ([`APPENDIX-INFOLEAK-PROTOCOL.md`](APPENDIX-INFOLEAK-PROTOCOL.md)),
  and the FMOD OOB-read reflection does not reach the server
  ([`APPENDIX-FMOD-REFLECTION.md`](APPENDIX-FMOD-REFLECTION.md)). So: **crash/DoS — near-certain;
  register/RIP control at the sink — deterministic; full one-shot RCE on `HIGH_ENTROPY_VA` — not
  demonstrated**, gated on an ASLR-defeat primitive from outside this parser.

---

## 14. Defender's view — Project Reclaimer can neutralize this at runtime (theory)

The same loader leverage this PoC used to *reproduce* the bug lets the Reclaimer **loader** *mitigate*
it today, without waiting for an MCC/FMOD update. Reclaimer already (a) loads `halo3.dll` with its own
PE loader, (b) applies byte-signature code patches, (c) owns the asset redirect that resolves
`fmod/pc/sfx*.fsb`, and (d) SHA-256-verifies mod files — several injection points. In increasing
robustness:

1. **Pre-validate the FSB5 header in safe Rust before FMOD sees it (recommended, version-independent).**
   In the mod-acceptance / asset-redirect path (which already hashes mod files and returns the
   `sfx.<name>.fsb` path), open the bank and validate **in memory-safe Rust** before `createStream`:
   magic `FSB5` + version ∈ {0,1}; `numSamples` capped and `numSamples*4` checked in **64-bit** ≤ file
   size; `0x3C + sampleHdrSize + nameTableSize + dataSize` consistent with file size; and a Rust walk
   of the sample-header blob keeping every chunk `size` within `sampleHdrSize`. Refuse on any failure.
   This neutralizes **both** the integer overflow and the OOB walk in safe code before the C++ parser.
2. **Software-CFG on the decode sink.** Detour `0x500e52` (`call [instance+0xa8]`) to verify the target
   is inside halo3's `.text` before calling — a poor-man's CFG for the one RIP sink, via the sigpatch
   system.
3. **Guard-page FMOD's allocations** (`PELOAD_ALLOC_GUARD`). An unmapped page after each FMOD
   allocation turns the OOB read/write into an **immediate controlled fault (DoS)** instead of silent
   corruption — removing both the heap-overflow path to the codec pointer and the silent-OOB-read.
4. **Detour the FSB open post-header-read** (≈`0x4e96b7`) to validate the header and branch to the
   codec error return (`eax=0x13` / `FMOD_ERR_FORMAT`) on failure.

**Caveat:** (1)–(4) protect the **Reclaimer** client only; official Windows MCC (no Reclaimer) still
needs Microsoft/343 and Firelight to fix the bundled FMOD. (1) is the most robust and least fragile.
These mirror, defensively, the loader leverage this PoC used offensively — see
[`DISCLOSURE-RECLAIMER.md`](DISCLOSURE-RECLAIMER.md).

---

## 15. Related documents

* **Index:** [`README.md`](README.md)
* **Disclosures:** [`DISCLOSURE-FMOD.md`](DISCLOSURE-FMOD.md) (Firelight/FMOD) ·
  [`DISCLOSURE-RECLAIMER.md`](DISCLOSURE-RECLAIMER.md) (Project Reclaimer) ·
  [`DISCLOSURE-MICROSOFT-343.md`](DISCLOSURE-MICROSOFT-343.md) (Microsoft / Halo Studios–343) ·
  [`DISCLOSURE-DEVELOPERS.md`](DISCLOSURE-DEVELOPERS.md) (FMOD-using developers)
* **Appendices:** [`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md) ·
  [`APPENDIX-INFOLEAK-PROTOCOL.md`](APPENDIX-INFOLEAK-PROTOCOL.md) ·
  [`APPENDIX-FMOD-REFLECTION.md`](APPENDIX-FMOD-REFLECTION.md) ·
  [`APPENDIX-LIBFMOD-REGCONTROL.md`](APPENDIX-LIBFMOD-REGCONTROL.md) ·
  [`FUZZING-SURVEY.md`](FUZZING-SURVEY.md)
