# FMOD FSB5 sample-table bug — "when was it fixed upstream?" — FINDINGS

**Scope:** CVP/MSRC-authorized security research.
**Date:** 2026-10-19
**Scope of this document:** determine the FMOD version + date at which the FSB5
sample-table memory-corruption bug (the one reached by MCC's `halo3.dll`) was
fixed upstream, using only publicly available SDK binaries and FMOD's public
documentation. **No fmod.com account was created** (hard constraint honored —
see *Blockers*).

---

## 1. Bottom-line conclusion

**There is no evidence that FMOD ever fixed this bug. It is present in every
FMOD release that could be obtained and tested, from MCC's 1.10.x line through
the newest lines (2.02.x / 2.03.x), and the complete public revision history
contains no entry that describes such a fix.**

Two independent lines of evidence:

1. **Runtime proof (macOS, this machine, arm64):** the exact MCC code path
   (`System::createSound(path, 0x2080 /*OPENONLY|CREATESTREAM*/)`) on the known
   crashing input `poc_v2_numsamples_oob.fsb` produces a **memory-corruption
   crash inside `FMOD::System::createSound`** in **every** standalone `libfmod`
   tested:

   | FMOD version | Release date | Result on poc_v2 |
   |---|---|---|
   | **2.01.09** | 15 Apr 2021 | **CRASH — SIGBUS (byte-write translation fault) in createSound** |
   | **2.02.14** | 3 May 2023 | **CRASH — SIGBUS in createSound** |
   | **2.02.22** | 8 May 2024 | **CRASH — SIGBUS in createSound** (poc_v3 also crashes) |

   (1.10.x — MCC's own line — is already proven vulnerable by the primary
   research against the real `halo3.dll`; see note in the table in §4.)

2. **Changelog proof:** the full public *Detailed Revision History* for the
   FMOD Engine, spanning **1.09.07 (7 Sep 2017) → 2.03.15 (22 Sep 2026)**,
   contains **no entry describing a bounds / overflow / out-of-bounds / crash
   fix in the FSB5 container or sample-header-table parser.** The only
   malformed-input crash fixes FMOD documents are in unrelated *codecs*
   (corrupt WAV/MP3 in 2.00.01; corrupt s3m/xm/it tracker files in
   2.02.35 / 2.03.14) — never the FSB5 sample-table builder. (§6)

**Implication for the MSRC report:** the report **cannot** truthfully say
"fixed upstream in FMOD x.y.z; MCC ships the vulnerable 1.10.x." The accurate
statement is:

> *This is an unpatched upstream defect in FMOD's statically-linked FSB5 parser.
> It is present in MCC's FMOD ~1.10.x and in every later FMOD line through at
> least 2.02.22 (runtime-confirmed, May 2024); FMOD's public revision history
> records no corresponding fix through the current 2.02.35 / 2.03.15
> (Sep 2026). The defect should also be reported to Firelight Technologies
> (FMOD) as it affects all current FMOD-based titles, not just MCC.*

The tightest runtime bound obtainable without an fmod.com account is now
**"vulnerable through 2.03.11 (2025)"** (see §1a); the changelog extends the
"no fix documented" evidence to **2.03.15 (22 Sep 2026)**, and the newest FMOD
present anywhere on GitHub is **2.04.00** (Windows `fmod.dll` only — not
runtime-testable here).

## 1a. Update — exhaustive GitHub search + a newer version runtime-tested (2.03.11)

An exhaustive GitHub search was run for committed FMOD libraries and version headers
newer than 2.02.22: the version macro in `fmod_common.h`
(`#define FMOD_VERSION 0x000MMmmpp`) was swept across the 2.02.2x → 2.04.x space, and
the committed library filenames (`libfmod.dylib`, `libfmod.so*`, `fmod.dll`) were
enumerated and version-checked against their sibling headers / reported runtime version.

* **Newest FMOD present on GitHub: 2.04.00** — but only as **Windows `fmod.dll`** inside
  "FMOD for Unreal" plugins (e.g. `ColinMcD05/Dissonance_Aria`, `Gyryk/advanced-games-tech`).
  2.03.15 appears only as a Windows `fmod.dll`; no runnable mac/linux slice of 2.03.12+
  or 2.04.x was locatable account-free, so those remain changelog-only.
* **2.03.11 — runtime-confirmed still vulnerable.** A macOS **universal (x86_64 + arm64)**
  `libfmod.dylib` was obtained from the public **Git LFS** store of `BredaUniversityGames/xs`
  (`external/fmod/lib/mac/libfmod.dylib`; the repo's header reads 2.03.10, the lib reports
  **0x00020311 / build 158528**). Driving the MCC path on `poc_v2` crashes identically —
  `EXC_BAD_ACCESS` (byte-write) at the same `str w10,[x0,x8,lsl#2]` store,
  `createSound → … → builder` — extending the runtime bound from 2.02.22 (May 2024) to
  **2.03.11**. Evidence: `fmod-2_03_11-regression.log`.
* **Harness note:** FMOD **2.03** changed `FMOD_System_GetVersion` to take a second
  `buildnumber` out-param; the probe (`fsb5_probe.c`) now passes both (safe for all
  versions) so the version query no longer faults before the `createSound` test.

---

## 2. The bug under test (recap)

In `halo3.dll` the FSB5 sample-table builder is at RVA `0x4e92e0` (crash at
`0x4e93e8`), called from the bank-open path `0x4e95d0`. Root cause:

- `numSamples` is read from FSB5 file offset `+0x08`; the sample-offset table is
  allocated with `numSamples * 4` evaluated as a **32-bit** value → integer
  overflow for large `numSamples`.
- The per-sample header-chunk walk trusts an attacker-controlled **24-bit size**
  field, driving an out-of-bounds access whose distance equals the attacker's
  size.

Net effect: out-of-bounds access → heap corruption. The primary PoC vector
`poc_v2_numsamples_oob.fsb` sets `numSamples = 0x7FFFFFFF` (`+0x08 = FF FF FF 7F`)
with a minimal 8-byte sample blob.

The FSB5 *container* parser is platform-independent C++ shared across all FMOD
platform builds, so exercising the same `createSound` path in a macOS `libfmod`
tests the identical logic that `halo3.dll` statically links on Windows.

---

## 3. Methodology

### 3.1 Harness (`fsb5_probe.c`)

A single, version-agnostic probe that `dlopen`s an arbitrary `libfmod.dylib`
chosen at runtime and drives the exact MCC load path with **no playback and no
audio device**:

```
FMOD_System_Create(&sys, ver)
FMOD_System_SetOutput(sys, FMOD_OUTPUTTYPE_NOSOUND)   // headless; no CoreAudio
FMOD_System_Init(sys, 32, 0, NULL)
FMOD_System_CreateSound(sys, bank, 0x2080, NULL, &sound)   // <-- FSB5 parser runs here
FMOD_Sound_Release / FMOD_System_Release
```

`dlopen`/`dlsym` (rather than link-time binding) lets one binary load any
version's dylib via `argv[1]`, and automatically selects the matching
architecture slice from a universal dylib. `0x2080` = `FMOD_OPENONLY |
FMOD_CREATESTREAM`, identical to the in-game `createStream(..., 0x2080, NULL)`.

**Outcome classification (`run_probe.sh`), by process exit status:**

| Exit | Meaning | Verdict |
|---|---|---|
| `0` + `VERDICT=CLEAN RESULT=<n> <name>` | parser returned an `FMOD_RESULT` without faulting | **CLEAN / not vulnerable** (even an *error* return like `FMOD_ERR_FORMAT` is a safe rejection) |
| `128 + signo` (138=SIGBUS, 139=SIGSEGV, 134=SIGABRT) | OS killed the process on a fault | **VULNERABLE** |
| `90–99` | harness setup problem (dlopen/create/init) | inconclusive |

The `FMOD_RESULT` enum name table is embedded in the harness (FMOD only appends
to the enum, so the low indices are identical across 1.10 → 2.03).

### 3.2 Host

`arm64`, macOS 26.5.2. Universal dylibs (x86_64 + arm64) run natively on arm64;
x86_64/i386-only dylibs are driven by a second harness build
(`fsb5_probe_x64`) under Rosetta.

---

## 4. FMOD libraries obtained (account-free) and their sources

All binaries were treated as untrusted data: each was downloaded into its own
empty directory under `downloads/`, quarantine xattr cleared, and
never used as a working directory or interpreter path. Version confirmed via the
library's own `FMOD_System_GetVersion` at runtime and/or the sibling
`fmod_common.h` `FMOD_VERSION` macro.

| FMOD ver | `FMOD_VERSION` | Arch(s) | Platform | Source repo (public GitHub mirror) | Path |
|---|---|---|---|---|---|
| 1.10.02 | `0x00011002` | x86_64 + i386 | macOS | `dotintent/pixfight` | `PLATFORM/macOS/FMOD/lib/libfmod.dylib` |
| **2.01.09** | `0x00020109` | x86_64 + **arm64** | macOS | `ZeroKill1024/FModSDK` | `Mac/api/core/lib/libfmod.dylib` |
| **2.02.14** | `0x00020214` | x86_64 + **arm64** | macOS | `ejoy/ant` | `3rd/fmod/macos/core/lib/libfmod.dylib` |
| **2.02.22** | `0x00020222` | x86_64 + **arm64** | macOS | `Laguna1989/JamTemplateCpp` | `ext/fmod/mac/api/core/lib/libfmod.dylib` |
| 2.03.14 | `0x00020314` | arm64 (+x86_64/x86/arm) | **Linux** | `mlkvs/vecxy` | `FMODEngine/api/core/lib/arm64/libfmod.so.14.14` |

Repo URLs: https://github.com/dotintent/pixfight · https://github.com/ZeroKill1024/FModSDK ·
https://github.com/ejoy/ant · https://github.com/Laguna1989/JamTemplateCpp ·
https://github.com/mlkvs/vecxy

Notes:
- **1.10.x (MCC's line)** is already proven vulnerable by the primary research
  (from-scratch Unicorn loader, the real `halo3.dll` FMOD via the peload
  harness, and a live in-game crash). The standalone 1.10.02 macOS dylib was
  obtained but is **x86_64/i386-only** (1.10 predates Apple Silicon) and hung in
  its static initializer under Rosetta in this headless sandbox, so it did not
  add a standalone datapoint. It did not contradict anything; 1.10.x
  vulnerability stands on the primary evidence.
- **2.03.14** is the newest major line; only a **Linux** arm64 build was
  obtainable account-free. It is staged in
  `downloads/fmod_2_03_14_vecxy_linux/` for one-command confirmation on any
  Linux/arm64 box (`cc fsb5_probe.c -ldl` then run) — not runnable here (no
  Docker/colima/podman/lima).
- Official repos (`fmod/fmod-for-unreal`, FMOD `UnityIntegration`) ship **no**
  binaries in-tree (stripped / Git-LFS), so they are effectively account-gated.
- 2.00.x and 2.01.00 headers were found in several repos, but those projects
  vendored only Windows libs, so no macOS 2.00.x dylib was obtainable
  account-free.

---

## 5. Full pass/fail results

### 5.1 Primary vector `poc_v2_numsamples_oob.fsb` (mode `0x2080`)

| FMOD ver | date | verdict |
|---|---|---|
| 1.10.x (MCC) | 2017–2019 | **VULNERABLE** (primary research: real halo3.dll + live in-game) |
| 2.01.09 | 15 Apr 2021 | **VULNERABLE** — SIGBUS in `createSound` |
| 2.02.14 | 3 May 2023 | **VULNERABLE** — SIGBUS in `createSound` |
| 2.02.22 | 8 May 2024 | **VULNERABLE** — SIGBUS in `createSound` |
| 2.03.15 | 22 Sep 2026 | **No fix documented** (changelog; not runtime-tested — account-gated) |

Raw transcript: `evidence/probe_runs.log`.

### 5.2 All PoC vectors against 2.02.22 (8 May 2024)

| PoC file | `createSound` result | verdict |
|---|---|---|
| `poc_v2_numsamples_oob.fsb` | — (process faulted) | **VULNERABLE — SIGBUS** |
| `poc_v3_type6_bigsize.fsb` | — (process faulted) | **VULNERABLE — SIGBUS** |
| `poc_v1_chunkwalk_oob.fsb` | `FMOD_ERR_VERSION` (69) | clean reject |
| `poc_v4_shsize_huge.fsb` | `FMOD_ERR_FORMAT` (19) | clean reject |
| `poc_v5_sizedist.fsb` | `FMOD_ERR_VERSION` (69) | clean reject |

Observation: by 2.02.22 an FSB5 sub-format **version gate** rejects some of the
malformed variants (`poc_v1/v4/v5`) with a clean error, **but the two overflow
vectors that pass that gate (`poc_v2` numSamples integer-overflow, `poc_v3`
type-6 chunk with huge size) still corrupt memory.** So the version check that
was added at some point does **not** cover the sample-count / chunk-size
overflow — the core defect is untouched. (On MCC's older 1.10.x FMOD, `poc_v5`
also crashed; the version gate is a later addition that is irrelevant to the
real bug.)

---

## 6. Crash evidence (fault is inside FMOD, via `createSound`)

macOS auto-generated crash reports for the native runs
(`evidence/fsb5_probe-2026-10-19-*.ips`). The faulting main-thread backtrace
(symbolized), saved to `evidence/backtrace_createSound.txt`:

```
Termination : Bus error: 10
ESR         : (Data Abort) byte write Translation fault
FAR (fault) : 0x1038dc000           <-- write to unmapped memory
  #0  libfmod.dylib  +0xb3d44
  #1  libfmod.dylib  +0xb405c
  #2  libfmod.dylib  +0x7f79c
  #3  libfmod.dylib  +0x805f4
  #4  libfmod.dylib  +0x682c8  FMOD::System::createSound(char const*, unsigned int, FMOD_CREATESOUNDEXINFO*, FMOD::Sound**)
  #5  fsb5_probe     +0x920    main
  #6  dyld           +0x1fe00  start
```

The fault is a **byte-write translation fault** (a write to an unmapped page)
four frames deep inside `libfmod` under `FMOD::System::createSound` — the macOS
analogue of the `halo3.dll` FSB5 sample-table crash. This is consistent with the
root cause: the `numSamples*4` 32-bit integer overflow under-allocates the
sample-offset table, and the subsequent per-sample population writes past it
into unmapped memory. (A *write* fault, if anything, strengthens the
heap-corruption / exploitability story over a pure read.)

---

## 7. Changelog evidence (public, account-free)

Source: FMOD Engine *Detailed Revision History* (public docs; the pages are a
JS SPA, rendered and text-extracted via the in-app browser). The cumulative
history is split across per-major-version pages; together they cover
**1.09.07 (7 Sep 2017) → 2.03.15 (22 Sep 2026)**, 114 point releases.

- 2.00 page (covers 1.09.07 → 2.00.22):
  https://www.fmod.com/docs/2.00/api/welcome-revision-history.html
- 2.01 page: https://www.fmod.com/docs/2.01/api/welcome-revision-history.html
- 2.02 page: https://www.fmod.com/docs/2.02/api/welcome-revision-history.html
- 2.03 page: https://www.fmod.com/docs/2.03/api/welcome-revision-history.html

**Every entry across that whole range matching `fsb|bank|overflow|out-of-bounds|
bounds|corrupt|malformed|security|parse|access violation|heap` was reviewed.**
None describes a fix to the FSB5 container / sample-header-table parser. The
closest malformed-input crash fixes are all in unrelated codecs:

| Version | Date | Entry | Relevant? |
|---|---|---|---|
| 2.00.01 | 9 May 2019 | "Fix crash trying to load corrupt WAV files with 0 length chunk size" / "Fix crash trying to load corrupt MP3 files" | **No** — WAV/MP3 codecs, not the FSB5 container |
| 2.00.17 / 2.01.09 | 15 Apr 2021 | "Fixed possible memory corruption due to race condition … audio table … unloading the bank" | **No** — threading race in Studio audio-table unload, not FSB5 parsing |
| 2.02.35 | 28 May 2026 | "Fixed crashes in s3m/xm/it codecs with corrupted files" | **No** — tracker-module codecs |
| 2.03.14 | 2 Jun 2026 | "Fixed crashes in s3m/xm/it codecs with corrupted files" | **No** — tracker-module codecs |

FMOD *does* occasionally fix malformed-input crashes and *does* describe them in
the changelog — so the absence of any FSB5 sample-table entry across 9 years is
meaningful: the specific defect was never (publicly) fixed. Independent web/CVE
search likewise found no FMOD advisory or CVE for an FSB/FSB5 out-of-bounds
issue.

The full parsed version→date timeline is in `evidence/` (reproducible via
`parse_rev.py` over the rendered pages — see §8).

---

## 8. Blockers & limitations (precise)

1. **fmod.com SDK downloads are account-gated** and no account was created
   (hard constraint). This is why the absolute-latest macOS arm64 builds
   (2.02.35 / 2.03.x) and the exact 1.10.x / 2.00.x macOS arm64 builds could not
   be obtained for runtime testing. Mitigated by: (a) third-party public mirrors
   gave 2.01.09 / 2.02.14 / 2.02.22 macOS-arm64 + 2.03.14 Linux-arm64; (b) the
   public changelog carries the "no fix" evidence all the way to 2.03.15.
2. **No Linux container runtime** on this host (no docker/colima/podman/lima), so
   the obtained **2.03.14 Linux/arm64** `libfmod.so` could not be executed here.
   It is staged for a one-command check on any Linux box.
3. **1.10.02 macOS dylib is x86_64/i386-only** and hung in static init under
   Rosetta in this headless sandbox. Not load-bearing: 1.10.x vulnerability is
   already proven against the real `halo3.dll`.
4. The FMOD revision-history pages are a JS SPA; `curl` returns only a 453-byte
   bootstrap. They were rendered with the in-app browser and text-extracted — the
   version/date/entry data in §7 is from the rendered DOM, not reconstructed.

**To close the last gap** (if desired, and if a fmod.com account or a Linux host
becomes acceptable): run `fsb5_probe` against FMOD 2.02.35 and 2.03.15 macOS
builds, or run the already-downloaded 2.03.14 Linux/arm64 `.so` in a Linux
container. Given §1–§7, the expected result is CRASH in all of them.

---

## 9. Reproduction

```bash
cd sdk-bisect
cc -O0 -g -o fsb5_probe fsb5_probe.c          # arm64 host
# one version:
fsb5_probe downloads/fmod_2_02_22_laguna/libfmod.dylib \
    ../poc_v2_numsamples_oob.fsb 0x2080 0x00020222
#   -> "Bus error: 10" during CreateSound  == VULNERABLE
# all three at once (writes evidence/probe_runs.log): see the loop in that log's header

# Linux side (2.03.14), on any Linux/arm64 host:
cc -O0 -g -o fsb5_probe fsb5_probe.c -ldl
./fsb5_probe downloads/fmod_2_03_14_vecxy_linux/libfmod.so.14.14 \
    ../poc_v2_numsamples_oob.fsb 0x2080 0x00020314
```

Exit `138` (SIGBUS) / `139` (SIGSEGV) / `134` (SIGABRT) = **VULNERABLE**.
Exit `0` with `VERDICT=CLEAN RESULT=…` = **fixed/not vulnerable** on that build.

---

## 10. Files in this directory

```

├── APPENDIX-UNPATCHED-SDK.md                      (this file)
├── 
│   ├── fsb5_probe.c                 dlopen-based probe (the deliverable harness)
│   ├── fsb5_probe                   compiled arm64
│   ├── fsb5_probe_x64               compiled x86_64 (for Rosetta / old libs)
│   ├── run_probe.sh                 exit-code -> verdict wrapper
│   └── parse_rev.py                 revision-history parser (keyword attribution)
├── downloads/                       one untrusted SDK per subdir (see §4)
│   ├── fmod_1_10_02_pixfight/       macOS x86_64+i386  (1.10.02)
│   ├── fmod_2_01_09_zerokill/       macOS x86_64+arm64 (2.01.09) + headers
│   ├── fmod_2_02_14_ejoyant/        macOS x86_64+arm64 (2.02.14)
│   ├── fmod_2_02_22_laguna/         macOS x86_64+arm64 (2.02.22)
│   └── fmod_2_03_14_vecxy_linux/    Linux arm64        (2.03.14)
└── evidence/
    ├── probe_runs.log               clean run transcript (3 native versions)
    ├── backtrace_createSound.txt    symbolized faulting backtrace
    └── fsb5_probe-2026-10-19-*.ips  raw macOS crash reports (3)
```
