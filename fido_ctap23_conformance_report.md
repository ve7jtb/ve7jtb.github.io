# FIDO CTAP 2.3 Conformance Test Report — 18 Algorithms (Including Draft NIST FIPS 206 `FN-DSA-512` & `FN-DSA-1024`), All 7 Extensions, `persistentPinUvAuthToken` (`perCredMgmtRO`), Enterprise Attestation & Post-Quantum `mtc` / `mtc-mds`

- **Log Files Analyzed**:
  1. **FIDO Conformance Debug Log**: `fido_conformance_debug.log` (`52,180` lines / `6.70 MB` in Run 18 with all 18 algorithms including `FN-DSA-512` `-60` & `FN-DSA-1024` `-61`; `48,653` lines / `6.66 MB` in Run 17; plus `223,190` lines from Runs 11–16 and `347,258` lines from Runs 1–10)
  2. **Total Phase Beagle USB Protocol Analyzer Capture**: `totalphase.csv` (`26,436` CSV rows, `68,774` USB bus records, `2.62 MB`, captured `Mon Oct 19 00:48:30` – `01:12:27 2026`, `23m 57s` total capture covering all `1,073` `CTAPHID_CBOR` exchanges of Run 17)
  3. **Fidont J-Link RTT Log**: `fidont_rtt.log` (`302,212` lines / `31.0 MB` in Run 18 with `--log=trace` DWT cycle-accurate timestamps across all 18 algorithms, `0` panics / `0` HardFaults / `0` OOMs)
- **Target Authenticator**: Fidont CTAP 2.3 (`U2F_V2`, `FIDO_2_0`, `FIDO_2_1`, `FIDO_2_3`) over USB HID (`VID: 0x1915`, `PID: 0x521f` / `0x18d1:0x0239`)
- **Related Design & Firmware Implementation**: **Compile and Install Fidont** & [pq_mtc_attestation_proposal.md](./pq_mtc_attestation_proposal.md)

## Fidont authenticator simulator platform performance numbers are for relative comparison as implemented with amateur optimization by me:)

> [!IMPORTANT]
> **Attribution & Scope of Fidont:**
> **Fidont** is an authenticator simulator designed for prototyping new specifications and testing authenticator conformance tools. It is based on the [Google OpenSK](https://github.com/google/OpenSK) Rust codebase. However, **Fidont is not suitable for production security use outside of certification, conformance testing, and prototyping new features.**

## Overview of All 18 Test Runs (`Runs 1–16` Historical + `Run 17` Total Phase USB + `Run 18` 18-Algorithm `FN-DSA` & `fidont_rtt.log` DWT Telemetry)

| Run | Line Range | Time Window | Attestation & Feature Config | Passed | Failed | Outcome & Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Run 1** | `L53–L37332` (pre-clear 1) | `15:24:18` – `15:41:24` (`17m 06s`) | `"packed"` (self-attestation, 16 algorithms) | **`211`** | **`0`** | **`100.00%` PASS** — Full CTAP 2.3 Conformance Suite (*"Testing finished. You may submit the results now."*) |
| **Run 2** | `L38483–L51656` (pre-clear 1) | `16:08:12` – `16:11:39` (`3m 27s`) | `"packed"` (all 7 CTAP 2.3 extensions) | **`68`** | **`0`** | **`100.00%` PASS** — All 7 CTAP 2.3 extensions including `hmac-secret-mc` (`26/26` passed) |
| **Run 3** | `L51657–L54978` (pre-clear 1) | `18:02:18` – `18:02:44` (`26s`) | `"packed"` (aborted early by user) | `23` | `2` | User-terminated during `Authr-MakeCred-Req-1` (`FORCED TERMINATION`) after `GetInfo` mismatch (`P-1`) |
| **Run 4** | `L54979–L94735` (pre-clear 1) | `20:03:06` – `20:10:20` (`7m 14s`) | `"packed"` (86 `MakeCred` calls) | `196` | `2` | User-terminated during `Authr-CredMgmt-1` (`FORCED TERMINATION`) after `ClientPin2` `P-5` (`CTAP2_ERR_PUAT_REQUIRED`) |
| **Run 5** | `L94736–L145398` (pre-clear 1) | `00:26:11` – `00:35:21` (`9m 10s`) | **`ML-DSA-65` (`-49`) MTC Batch Key** (`"mtc"` & `"mtc-mds"`) | `128` | `2` | **First Live Post-Quantum MTC Run** — `77` `"mtc"` + `24` `"mtc-mds"` `MakeCredential` responses; prior to patching `"mtc"`/`"mtc-mds"` verification in the tool |
| **Run 6** | `L145414–L174863` (pre-clear 1) | `01:14:20` – `01:19:57` (`5m 37s`) | **`ML-DSA-65` (`-49`) MTC Batch Key** (`"mtc"` & `"mtc-mds"`) | **`95`** | **`0`** | **`100.00%` PASS** — Verified `Authr-Generic-1` and `Authr-MakeCred-Resp-1` (`P-01`..`F-01`); restarted to remove `defaultMtcTrustAnchors` fallback |
| **Run 7** | `L174881–L232009` (pre-clear 1) | `01:42:49` – `01:53:51` (`11m 02s`) | **`ML-DSA-65` (`-49`) MTC Batch Key** (`"mtc"` + `"mtc-mds"`, strict MDS verification) | **`237`** | **`0`** | **`100.00%` PASS (`237 Passed / 45 Skipped / 0 Failed`)** — Complete CTAP 2.3 Suite + `Metadata-Stmt-1`; `79` `"mtc"` + `12` `"mtc-mds"` registrations (`caId = 0x83993f0102`) |
| **Run 8** | `L232010–L285073` (pre-clear 1) | `02:08:46` – `02:20:49` (`12m 03s`) | **`ML-DSA-44` (`-48`) MTC Batch Key** (`"mtc"` only, strict MDS verification) | **`237`** | **`0`** | **`100.00%` PASS (`237 Passed / 45 Skipped / 0 Failed`)** — Complete CTAP 2.3 Suite + `Metadata-Stmt-1`; **`92` `"mtc"` (`100%` inline `pubKey`) + `0` `"mtc-mds"`** (`caId = 0x83993f0101`) |
| **Run 9** | `L285073–L287509` (pre-clear 1) | `02:43:38` – `02:44:00` (`22s`) | **`ML-DSA-44` (`-48`) `--mtc-x5c`** (prior to reflashing firmware) | `22` | `2` | Aborted after `Authr-Generic-1` `P-1` because Oct 16 `22:35` firmware predated `0xA3` (`--mtc-x5c`) map parsing; resolved by `./flash.sh nrf52840dk` |
| **Run 10** | `L287509–L347258` (pre-clear 1) | `02:55:51` – `03:06:05` (`10m 14s`) | **`ML-DSA-44` (`-48`) `--mtc-x5c`** (**Tier 1 `"packed"` `x5c` + Tier 2 `"mtc"`**, strict MDS verification) | **`237`** | **`0`** | **`100.00%` PASS (`237 Passed / 45 Skipped / 0 Failed`)** — Complete CTAP 2.3 Suite + `Metadata-Stmt-1`; **`74` `"packed"` (`4,127 B` `x5c`) + `18` `"mtc"` (`1,322 B` inline `pubKey`)** |
| **Run 11** | `L1–L56583` (pre-clear 2) | `09:11:23` – `09:27:58` (`16m 35s`) | **`ML-DSA-87` (`-50`) MTC Batch Key** (**100% Tier 3 `"mtc-mds"`**, compact `0x02`/`0x03` cred IDs, strict MDS verification) | **`237`** | **`0`** | **`100.00%` PASS (`237 Passed / 45 Skipped / 0 Failed`)** — Complete CTAP 2.3 Suite + `Metadata-Stmt-1`; **`94` `"mtc-mds"` (`100%` MDS `batchKeys` lookup, `caId = 0x83993f0103`)** |
| **Run 12** | `L58596–L69096` (pre-clear 2) | `23:12:37` – `23:13:55` (`1m 18s`) | Dual Batch + `--enterprise` (before reloading updated MDS) | `56` | `2` | Aborted after `Authr-Generic-1` `P-1` (`options` count `12` vs `11` because `ep: false` added) and `MakeCred-Resp-1` before reloading updated metadata |
| **Run 13** | `L73661–L124119` (pre-clear 2) | `23:36:31` – `00:05:42` (`29m 11s`) | Dual Batch + `--enterprise` (with Root CA `subtrees[].signature` check, before reloading MDS) | `236` | `5` | **`Authr-MakeCred-Resp-1` (`P-01`..`P-04`) PASSED with Root CA `subtrees[].signature` check!** 5 failures due to stale MDS + unpatched `EntepriseAttestation.js` (`P-2`, `P-3`, `F-6`) |
| **Run 14** | `L124193–L126258` (pre-clear 2) | `00:23:04` – `00:23:25` (`21s`) | Dual Batch + `--enterprise` (aborted early while loading updated MDS) | `21` | `2` | User-terminated (`FORCED TERMINATION`) right before loading updated metadata with `ep: false` and `authenticatorConfigCommands: [1, 2, 3]` |
| **Run 15** | `L126339–L175678` (pre-clear 2) | `00:25:36` – `00:36:53` (`11m 17s`) | Dual Batch (`ES384` `x5c` + `ML-DSA-44` MTC) + `--enterprise` + Root CA `subtrees[].signature` Verification | `238` | `3` | **`98.76%` PASS (`238 Passed / 3 Failed`)** — `Authr-Generic-1`, `Authr-MakeCred-Resp-1` (`P-04`), `Authr-Config-1`, and `Metadata-Stmt-1` (`37/37`) passed 100%; `EntepriseAttestation.js` (`P-2`, `P-3`, `F-6`) needed MTC + serial extension support |
| **Run 16** | `L175680–L223190` (pre-clear 2) | `01:09:20` – `01:24:53` (`15m 33s`) | Dual Batch (`ES384` `x5c` + `ML-DSA-44` MTC) + `--enterprise` + Serial Number Extension (`mtcProof.extensions`) + Root CA `subtrees[].signature` Verification | **`241`** | **`0`** | **`100.00%` PASS (`241 Passed / 41 Skipped / 0 Failed`)** — Full CTAP 2.3 Suite + Security Enterprise Profile (`EntepriseAttestation.js` `6/6` PASS) + `Metadata-Stmt-1` (`37/37` PASS) |
| **Run 17** | `L1–L48653` & `totalphase.csv` | `00:48:37` – `01:01:04` (`12m 27s`) | **Full CTAP 2.3 `persistentPinUvAuthToken` (`perCredMgmtRO`, `pcmr = 0x40`, `encIdentifier = 0x19`, `encCredStoreState = 0x1E`) + Dual Batch (`ES384` `x5c` + `ML-DSA-44` MTC) + Enterprise Attestation (`--enterprise`, `serial="123456"`) + Root CA `subtrees[].signature` Verification** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 32 Skipped / 0 Failed`)** — **All `9` previously skipped `perCredMgmtRO` / `encIdentifier` / `encCredStoreState` / `pcmr (0x40)` tests executed and passed (`241` $\to$ `250` passed)! `0` USB bus errors across `68,774` records (`1,073` `CTAPHID_CBOR` exchanges, `304.4 KB` OUT / `509.9 KB` IN) in `totalphase.csv`!** |
| **Run 18 (Latest)** | `L1–L52180` & `fidont_rtt.log` (`302,212` lines) | `10:16:15` – `10:36:41` (`20m 26s`) | **All 18 Algorithms including Draft NIST FIPS 206 `FN-DSA-512` (`alg: -60`) & `FN-DSA-1024` (`alg: -61`) + `ML-DSA-87` (`-50`) MTC Batch + `ES256` Classical Batch + Enterprise Dual (`ML-DSA-44` leaf / `ML-DSA-87` Root CA) + `fidont_rtt.log` DWT Cycle-Accurate Telemetry** | **`249`** | **`1`** | **`99.60%` PASS (`249 Passed / 34 Skipped / 1 Failed`)** — **`100%` PASS across all 18 algorithms in `Authr-MakeCred-Resp-1`, `Authr-GetAssertion-Resp-1`, `EntepriseAttestation`, `Authr-CredMgmt-1`, and `Metadata-Stmt-1` (`0` panics, `0` OOMs, `0` HardFaults in `302,212` `fidont_rtt.log` lines)!** (`Authr-GetInfo-1 P-1` only noted `attestationFormats` order `["mtc-mds", "mtc", "packed"]` from `ML-DSA-87` provisioning vs `["mtc", "mtc-mds", "packed"]` in `metadata_mldsa_all_mtc.json`.) |

---

## 0.0 Run 18 Deep Dive: Adding Draft NIST FIPS 206 (`FN-DSA-512` `alg: -60` & `FN-DSA-1024` `alg: -61`) — 18-Algorithm Hardware & `fidont_rtt.log` DWT Telemetry

> [!IMPORTANT]
> **Draft NIST FIPS 206 (`FN-DSA-512` & `FN-DSA-1024`) End-to-End Hardware Conformance on Cortex-M4F (`nRF52840-DK`)**:
> Run 18 extended both the FIDO Conformance Tool (`@noble/post-quantum` pure-JS `fn_dsa512` / `fn_dsa1024` verifier, `COSE_ALG_MAP`, `ALG_DIR_TO_COSE`, `COSE_KTY_AKP = 7`) and **Fidont** (`libraries/fn-dsa` + `opensk::api::crypto::fndsa`) to test **18 COSE signature algorithms** simultaneously on the `64 MHz` Cortex-M4F (`256 KiB` SRAM).
> - **Shared `184 KiB` Stack Architecture**: Because `ML-DSA-87` signing (`152.6 KiB` stack in `raw_sign_encoded_mu::<MlDsa87>`) runs during `MakeCredential` attestation signing while `FN-DSA-1024` lattice signing (`83.8 KiB` workspace with `small_context`) runs during `GetAssertion`, placing `FN-DSA`'s `72 KiB` `tmp_flr` (`[FLR; 9 * 1024]`) workspace on the **stack** inside `#[inline(never)] sign_with_alloc` (`_rheap = 0x2002e000`: `184 KiB` stack / `72 KiB` data+heap) allows both `ML-DSA-87` and `FN-DSA-1024` to execute with `> 30 KiB` headroom on both stack and heap and **zero crashes across `302,212` lines of `fidont_rtt.log`**.

### 0.0.1 18-Algorithm Performance Comparison: `MakeCredential` & `GetAssertion` (`fido_conformance_debug.log` + `fidont_rtt.log` DWT)

| Algorithm (`COSE alg`) | Security Level | `MakeCredential` Wire Size | `MakeCredential` Host Time (`MakeCred-Resp-1`) | `MakeCredential` Host Time (`GetAssertion-Resp-1`) | `GetAssertion` Wire Size (Sig Size) | `GetAssertion` Pure CPU Sign (`fidont_rtt.log` DWT) | `GetAssertion` Host Time (`GetAssertion-Resp-1`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`FN-DSA-512` (`-60`)** | **NIST Level I** | **`6,051 B`** (`897 B` PK) | **`6,461.9 ms`** (`L7749–L7999`) | **`6,577.6 ms`** (`L22563–L22814`) | **`976 B` (`666 B`)** | **`958.0 ms`** (`61.31M` cycles, `RTT L142742`) | **`2,559.3 ms`** (`L22872–L22947`) |
| **`FN-DSA-1024` (`-61`)** | **NIST Level V** | **`6,947 B`** (`1,793 B` PK) | **`8,526.0 ms`** (`L7405–L7691`) | **`8,513.8 ms`** (`L23005–L23293`) | **`1,590 B` (`1,280 B`)** | **`2,054.9 ms`** (`131.51M` cycles, `RTT L146556`) | **`4,095.7 ms`** (`L23351–L23450`) |
| `ML-DSA-44` (`-48`) | NIST Level II | `6,466 B` (`1,312 B` PK) | `7,653.0 ms` (`L10868–L11136`) | `7,270.0 ms` (`L17363–L17629`) | `2,730 B` (`2,420 B`) | `691.3 ms` (`44.24M` cycles, `RTT L95779`) | `4,116.1 ms` (`L17687–L17827`) |
| `ML-DSA-65` (`-49`) | NIST Level III | `7,106 B` (`1,952 B` PK) | `8,474.2 ms` (`L10518–L10810`) | `7,386.0 ms` (`L17885–L18173`) | `3,619 B` (`3,309 B`) | `977.7 ms` (`62.57M` cycles, `RTT L99195`) | `4,697.2 ms` (`L18231–L18400`) |
| `ML-DSA-87` (`-50`) | NIST Level V | `7,556 B` (`2,592 B` PK) | `7,937.8 ms` (`L10155–L10460`) | `9,611.0 ms` (`L18458–L18768`) | `4,747 B` (`4,627 B`) | `898.8 ms` (`57.52M` cycles, `RTT L103614`) | `5,569.4 ms` (`L18826–L19027`) |
| `MLDSA44-ES256` (`-54`) | Hybrid Level II | `6,531 B` (`1,377 B` PK) | `7,722.6 ms` (`L9827–L10097`) | `7,257.8 ms` (`L19085–L19353`) | `2,800 B` (`2,490 B`) | `1,436.2 ms` (`RTT L108661..L110928`) | `4,468.8 ms` (`L19411–L19552`) |
| `MLDSA65-ES256` (`-55`) | Hybrid Level III | `7,171 B` (`2,017 B` PK) | `9,869.4 ms` (`L9471–L9769`) | `7,833.7 ms` (`L19610–L19901`) | `3,690 B` (`3,379 B`) | `1,248.8 ms` (`RTT L115423..L118573`) | `4,980.3 ms` (`L19959–L20130`) |
| `MLDSA87-ES384` (`-56`) | Hybrid Level V | `7,608 B` (`2,689 B` PK) | `9,078.7 ms` (`L9104–L9413`) | `10,530.3 ms` (`L20188–L20501`) | `4,804 B` (`4,723 B`) | `4,898.9 ms` (`RTT L123578–L123579`) | `9,512.9 ms` (`L20559–L20775`) |
| `MLDSA44-Ed25519` (`-57`) | Hybrid Level II | `6,498 B` (`1,344 B` PK) | `7,110.1 ms` (`L8778–L9046`) | `7,693.5 ms` (`L20833–L21103`) | `2,794 B` (`2,484 B`) | `593.2 ms` (`RTT L128521–L128522`) | `3,871.8 ms` (`L21161–L21300`) |
| `MLDSA65-Ed25519` (`-58`) | Hybrid Level III | `7,138 B` (`1,984 B` PK) | `10,023.4 ms` (`L8422–L8720`) | `7,446.2 ms` (`L21358–L21648`) | `3,683 B` (`3,373 B`) | `557.1 ms` (`RTT L132978–L132979`) | `4,533.3 ms` (`L21706–L21876`) |
| `MLDSA87-Ed448` (`-59`) | Hybrid Level V | `7,568 B` (`2,649 B` PK) | `8,474.9 ms` (`L8057–L8364`) | `8,730.2 ms` (`L21934–L22242`) | `4,815 B` (`4,741 B`) | `1,549.9 ms` (`RTT L137877–L137878`) | `6,329.6 ms` (`L22300–L22505`) |
| `ES256` (`-7`) | Classical 128-bit | `1,054 B` | `2,699.9 ms` (`L11855–L11929`) | `2,691.5 ms` (`L15896–L15970`) | `379 B` | `671.8 ms` (`RTT L74425–L74426`) | `1,658.9 ms` (`L16028–L16081`) |
| `ES384` (`-35`) | Classical 192-bit | `1,088 B` | `3,279.4 ms` (`L11720–L11797`) | `3,276.3 ms` (`L16139–L16216`) | `412 B` | `1,182.0 ms` (`RTT L73470–L73471`) | `3,488.0 ms` (`L16274–L16335`) |
| `ES512` (`-36`) | Classical 256-bit | `1,124 B` | `3,284.4 ms` (`L11583–L11662`) | `2,728.0 ms` (`L16393–L16470`) | `448 B` | `1,151.6 ms` (`RTT L72569–L72571`) | `2,352.4 ms` (`L16528–L16585`) |
| `ES256K` (`-47`) | Classical 128-bit | `1,056 B` | `2,076.0 ms` (`L11454–L11525`) | `2,060.2 ms` (`L16643–L16714`) | `380 B` | `~65 ms` | `1,191.9 ms` (`L16772–L16823`) |
| `Ed25519` (`-8`) | Classical 128-bit | `1,021 B` | `2,040.0 ms` (`L11325–L11396`) | `2,046.1 ms` (`L16881–L16953`) | `373 B` | `~18 ms` | `1,087.6 ms` (`L17011–L17062`) |
| `Ed448` (`-53`) | Classical 224-bit | `1,047 B` | `2,407.8 ms` (`L11194–L11267`) | `2,316.2 ms` (`L17120–L17192`) | `423 B` | `547.5 ms` (`RTT L90308–L90309`) | `1,759.9 ms` (`L17250–L17305`) |
| `RS256` (`-257`) | Classical 112-bit | `1,250 B` | `2,223.9 ms` (`L7267–L7347`) | `2,240.1 ms` (`L23508–L23588`) | `566 B` (`256 B`) | `4,296.8 ms` (`RTT L148584–L148585`) | `5,444.1 ms` (`L23646–L23717`) |

> [!TIP]
> **FN-DSA Wire Size & End-to-End USB HID Latency Advantage over ML-DSA**:
> - **`FN-DSA-512` (`alg: -60`)**: Produces a **`666 B` signature** (`976 B` total `GetAssertion` CBOR response vs `2,730 B` for `ML-DSA-44` — **`2.8x` smaller**). Although pure CPU lattice signing (`sign_with_alloc(9)`) is `958.0 ms` vs `691.3 ms` for `ML-DSA-44`, the `3x` reduction in USB HID packet frames makes end-to-end `GetAssertion` **`1.6x` faster overall** (`2,559.3 ms` vs `4,116.1 ms`).
> - **`FN-DSA-1024` (`alg: -61`)**: Produces a **`1,280 B` signature** (`1,590 B` total `GetAssertion` CBOR response vs `4,747 B` for `ML-DSA-87` — **`3.0x` smaller**). End-to-end `GetAssertion` completes in **`4,095.7 ms`** vs `5,569.4 ms` for `ML-DSA-87` (**`1.36x` faster**).

---

## 0. Run 17 Deep Dive: `250/250` (`100%`) Pass with `persistentPinUvAuthToken` (`perCredMgmtRO`), `encIdentifier (0x19)`, `encCredStoreState (0x1E)`, Enterprise MTC, and Total Phase USB Bus Telemetry

> [!IMPORTANT]
> **All 9 Previously Skipped `persistentPinUvAuthToken` (`perCredMgmtRO`) Conformance Tests Executed and Passed (`241` $\to$ `250` Passed, `0` Failed)**:
> Following our Fidont implementation of `perCredMgmtRO: true`, `pcmr (0x40)`, `encIdentifier (0x19)`, and `encCredStoreState (0x1E)`, the active test count increased from **`241` passed / `41` skipped** (Run 16) to **`250` passed / `32` skipped / `0` failed** (`282` total tests) in Run 17 (`L48485`: *"Testing finished. You may submit the results now."*).

### 0.1 All 9 Newly Activated CTAP 2.3 `persistentPinUvAuthToken` / `encIdentifier` / `encCredStoreState` Tests in Run 17

| # | Test Suite | Test ID | Conformance Log Lines | TotalPhase CSV Lines | Duration | What Was Verified on Hardware |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **`Authr-Generic-1`** | **`P-4`** | `L1327–L1666` | `L653–L809` | `2,425.5 ms` | **`encIdentifier (0x19)`**: Set PIN, acquired `pcmr (0x40)` token (`32 B`), called `GetInfo` twice (`L1426` `7f1ada2a...` vs `L1529` `919785d6...`), verified fresh random IV (`ct1 != ct2`) and identical `AES-128-CBC` decryption under `HKDF-SHA-256(ppuat, "encIdentifier")[..16]`, then called `Reset (0x07)` and verified `encIdentifier` rotated to a new 16-byte device identifier! |
| 2 | **`Authr-Generic-1`** | **`P-5`** | `L1677–L2019` | `L815–L971` | `3,009.6 ms` | **`encCredStoreState (0x1E)`**: Set PIN, acquired `pcmr (0x40)` token, called `GetInfo` twice (`L1777` `5baf6116...` vs `L1880` `1159ebc0...`), verified fresh IV and identical `AES-128-CBC` decryption under `HKDF-SHA-256(ppuat, "encCredStoreState")[..16]`, then called `Reset (0x07)` and verified `encCredStoreState` rotated! |
| 3 | **`Authr-ResidentKey-1`** | **`P-5`** | `L22942–L23186` | `L10949–L11076` | `2,894.3 ms` | **`encCredStoreState` Rotation on `rk: true`**: Decrypted `encCredStoreState` before (`L22986` `0dedd025...`) and after (`L23170` `687dcfa8...`) creating a discoverable credential (`MakeCredential` with `rk: true`), proving `storage::store_credential` rotated `ENC_CRED_STORE_STATE`! |
| 4 | **`Authr-ClientPin2-ChangePin`** | **`P-4`** | `L41101–L41317` | `L22646–L22726` | `2,665.5 ms` | **`persistentPinUvAuthToken` Rotation on `changePIN`**: Obtained `pcmr (0x40)` token, executed `changePIN (0x04)`, then sent `enumerateRPsBegin (0x02)` authenticated with the pre-change `pcmr` token (`CSV L22724`) — Fidont rejected it in **`7.00 ms`** with **`CTAP2_ERR_PIN_AUTH_INVALID (0x33)`**! |
| 5 | **`Authr-ClientPin2-PinUvAuthToken`** | **`P-4`** | `L42541–L42599` | `L23390–L23414` | `795.6 ms` | **`getPinUvAuthTokenUsingPinWithPermissions (0x09)` with `pcmr (0x40)`**: Verified `subCommand = 0x09` with `permissions = 0x40` returns `CTAP1_ERR_SUCCESS (0x00)` with a 48-byte (`16 B IV + 32 B CT`) encrypted `persistentPinUvAuthToken`. |
| 6 | **`Authr-CredMgmt-1` (Group 1)** | **`P-4`** | `L44827–L44912` | `L24309–L24335` | `847.8 ms` | **`getCredsMetadata (0x01)` with `pcmr (0x40)`**: Acquired `pcmr (0x40)` token (`subCommand = 0x09`), called `getCredsMetadata (0x01)` (`CID=0000001d`, `CSV L24333`), and verified response `{0x01: 2, 0x02: 148}` in **`15.00 ms`** MCU time! |
| 7 | **`Authr-CredMgmt-1` (Group 1)** | **`P-5`** | `L44920–L45003` | `L24339–L24365` | `856.6 ms` | **`enumerateRPsBegin (0x02)` with `pcmr (0x40)`**: Called `enumerateRPsBegin (0x02)` (`CID=00000020`, `CSV L24363`) authenticated with `pcmr (0x40)` token; returned first RP (`"leveleyes.ng"`, `totalRPs = 2`, `57 B`) in **`15.00 ms`** MCU time! |
| 8 | **`Authr-CredMgmt-1` (Group 1)** | **`P-6`** | `L45009–L45031` | `L24367–L24371` | `34.8 ms` | **`enumerateRPsGetNextRP (0x03)` after `pcmr (0x40)`**: Called `enumerateRPsGetNextRP (0x03)` (`CID=00000020`, `CSV L24367`); returned second RP (`"scintillatinghuckleberry.al"`, `71 B`) in **`11.00 ms`** MCU time! |
| 9 | **`Authr-CredMgmt-1` (Group 2)** | **`P-3`** | `L45469–L45564` | `L24591–L24627` | `1,179.6 ms` | **`enumerateCredentialsBegin (0x04)` with `pcmr (0x40)`**: Acquired `pcmr (0x40)` token and called `enumerateCredentialsBegin (0x04)` (`CID=0000002c`, `CSV L24615`); decrypted and returned full discoverable credential metadata (`247 B` across `5` frames) in **`339.04 ms`** MCU time! |

> [!NOTE]
> In addition to the 9 newly activated tests above, `Authr-Generic-1` `P-1` (`L1227–L1264`) and `Metadata-Stmt-1` `P-32` (`L48322–L48352`) validated `GetInfo.options.perCredMgmtRO == true`, `GetInfo.encIdentifier` (`32 B` hex), `GetInfo.encCredStoreState` (`32 B` hex), and their matching entries (`"perCredMgmtRO": true`, `"encIdentifier": ""`, `"encCredStoreState": ""`) in `metadata.authenticatorGetInfo`. Note that the standalone `Tests-CTAP2-3/PersistentPinUvAuthToken.js` file is not registered in the tool's suite runner manifest, so its assertions are executed directly through `Authr-Generic-1` (`P-4`, `P-5`), `Authr-ResidentKey-1` (`P-5`), `Authr-ClientPin2-ChangePin` (`P-4`), `Authr-ClientPin2-PinUvAuthToken` (`P-4`), and `Authr-CredMgmt-1` (`P-4`, `P-5`, `P-6`, `P-3`).

---

### 0.2 Multi-Log Telemetry Summary: `fido_conformance_debug.log`, `/tmp/totalphase.csv` & `fidont_rtt.log`

| Telemetry Metric | Value in Run 17 | Source & Details |
| :--- | :--- | :--- |
| **Conformance Suite Duration** | **`12m 26.92s`** (`00:48:37.583` – `01:01:04.501`) | `fido_conformance_debug.log` (`48,653` lines; `01:02:54` result submission check at `L48590`) |
| **Total Conformance Tests** | **`250 Passed / 32 Skipped / 0 Failed` (`100.00%`)** | All 32 skipped tests are non-applicable hardware/profile checks (`uv` internal biometric, display, consumer profile `F-1`..`F-3`, `maxPINLength`, `pinComplexityPolicy`, `longTouchForReset`, optional MDS fields) |
| **Total Phase USB Capture Window** | **`23m 57.22s`** (`00:48:30` – `01:12:27`) | `totalphase.csv` (`26,429` non-comment rows, `68,774` USB bus records) |
| **Active CTAPHID USB Bus Window** | **`12m 26.87s`** (`0:07.095.944` – `12:33.964.234`) | First `CTAPHID_INIT` at `CSV L18` (`0:07.095.944`); final `Selection (0x0B)` / `LargeBlobs (0x0C)` at `CSV L25751` (`12:33.964.234`) |
| **USB Bus Errors (`Err` Column)** | **`0` Errors** (`100%` clean USB bus) | Zero CRC, bit-stuff, framing, stall, or timeout errors across all `68,774` USB bus records |
| **Total USB `OUT txn` / `IN txn` Packets** | **`4,756` `OUT txn` (`304,352 B`) / `7,967` `IN txn` (`509,888 B`)** | Every frame is a `64 B` Full-Speed (`12 Mbps`) USB HID interrupt transaction on `Dev=01, Ep=02` |
| **CTAPHID Channel Allocations (`0x86`)** | **`1,082` `OUT` / `1,081` `IN`** | Includes 1 intentional broadcast/invalid CID test in `Transport-HID-1` |
| **Completed `CTAPHID_CBOR (0x90)` Exchanges** | **`1,073` Requests / `1,073` Responses** | `clientPin (0x06)`: `707`, `MakeCredential (0x01)`: `150`, `GetAssertion (0x02)`: `90`, `GetInfo (0x04)`: `60`, `Reset (0x07)`: `27`, `CredMgmt (0x0A)`: `16`, `Config (0x0D)`: `13`, `LargeBlobs (0x0C)`: `6`, `GetNextAssertion (0x08)`: `3`, `Selection (0x0B)`: `1` |
| **CTAP2 Response Status Codes (`0x90`)** | **`967` `0x00` (`SUCCESS`) + `106` expected error responses** | `0x11` (`INVALID_CBOR`): `36`, `0x14` (`MISSING_PARAMETER`): `16`, `0x31` (`PIN_INVALID`): `13`, `0x02` (`INVALID_PARAMETER`): `10`, `0x37` (`PIN_POLICY_VIOLATION`): `8`, `0x2e` (`NO_CREDENTIALS`): `5`, `0x2c` (`INVALID_OPTION`): `4`, `0x33` (`PIN_AUTH_INVALID`): `4`, `0x34` (`PIN_AUTH_BLOCKED`): `3`, `0x2d` (`USER_ACTION_TIMEOUT`): `2`, `0x26` (`UNSUPPORTED_ALGORITHM`): `2`, `0x32` (`PIN_BLOCKED`): `2`, `0x19` (`LIMIT_EXCEEDED`): `1` |
| **`CTAPHID_KEEPALIVE (0xBB)` Frames** | **`350` `UP_NEEDED (0x02)` / `0` `PROCESSING (0x01)`** | Emitted every `100 ms` while awaiting user presence or completing cryptographic operations |
| **USB Bus Re-Enumerations (`Set Configuration`)** | **`3` USB Reconnects** (`10:51.303`, `11:38.393`, `11:51.172`) | Triggered during `Authr-ClientPin1-PinRetries` `P-3` (`CSV L22433`) and `Authr-ClientPin2-PinRetries` `P-3`/`P-5` (`CSV L23719`, `CSV L23839`) when testing `CTAP2_ERR_PIN_AUTH_BLOCKED (0x34)` power-cycle recovery |
| **Fidont RTT Log (`fidont_rtt.log`)** | **`0 B`** (cleared at `00:47:00`) | Release firmware (`./flash.sh nrf52840dk` without `--features=debug`) omits RTT `trace` strings so all 16 algorithms + `AES-128-CBC` + MTC fit in the `500 KiB` flash image |

---

### 0.3 Six-Way Comparison: Run 10 (`-48` `--mtc-x5c`) vs. Run 8 (`-48` MTC) vs. Run 7 (`-49` MTC) vs. Run 11 (`-50` MTC) vs. Run 16 (Dual + `ep`) vs. Run 17 (Dual + `ep` + `perCredMgmtRO`)

| Metric | Run 10 (`-48` `--mtc-x5c`) | Run 8 (`-48` MTC) | Run 7 (`-49` MTC) | Run 11 (`-50` MTC) | Run 16 (Dual + `ep`) | Run 17 (Dual + `ep` + `perCredMgmtRO`) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Log Range & Duration** | `L287509–L347258` (`10m 14s`) | `L232010–L285073` (`12m 03s`) | `L174881–L232009` (`11m 02s`) | `L1–L56583` (`16m 35s`) | `L175680–L223190` (`15m 33s`) | **`L1–L48653` (`12m 27s`)** |
| **Test Results** | `237 Passed / 0 Failed` | `237 Passed / 0 Failed` | `237 Passed / 0 Failed` | `237 Passed / 0 Failed` | `241 Passed / 41 Skipped / 0 Failed` | **`250 Passed / 32 Skipped / 0 Failed (`100.00%`)`** |
| **`GetInfo` Wire Size (`BCNT`)** | `706 B` (`13` frames) | `706 B` (`13` frames) | `706 B` (`13` frames) | `706 B` (`13` frames) | `719 B` (`13` frames) | **`793 B` (`14` frames, includes `perCredMgmtRO`, `0x19`, `0x1E`)** |
| **`perCredMgmtRO` / `0x19` / `0x1E` Tests** | Skipped (`0/9`) | Skipped (`0/9`) | Skipped (`0/9`) | Skipped (`0/9`) | Skipped (`0/9`) | **`9/9 Passed (`100%`)`** |
| **Enterprise Profile (`EntepriseAttestation.js`)** | Skipped | Skipped | Skipped | Skipped | `6/6 Passed` | **`6/6 Passed (`P-1`..`P-3`, `F-4`..`F-6` at `L23738–L24973`)`** |
| **`Authr-MakeCred-Resp-1` `P-04` Verification** | `13.8 ms` | `11.1 ms` | `16.2 ms` | `7.0 ms` | `89.6 ms` | **`92.5 ms` (`L10596–L12032`)** |
| **`Metadata-Stmt-1` Verification** | `37/37` Passed | `37/37` Passed | `37/37` Passed | `37/37` Passed | `37/37` Passed | **`37/37` Passed (`P-27` at `L48273`, `P-32` at `L48322`)** |

### 0.4 `Authr-MakeCred-Resp-1` 16-Algorithm Sweep: Conformance Log vs. Total Phase Hardware USB Analyzer (`Run 17`)

| # | COSE `alg` | Algorithm Name | Run 17 `fmt` | Wire Size (`BCNT` / Frames) | Hardware MCU Compute Time (`totalphase.csv`) | USB `IN` Transfer Time (`totalphase.csv`) | Total USB Exchange Time (`totalphase.csv`) | Conformance Log Line | TotalPhase CSV Line Range |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `-257` | `RS256` | **`"packed"` (`ES384` `x5c`)** | **`1,250 B` (`22`)** | **`891.11 ms`** (`2` `KA`) | `84.01 ms` | `991.17 ms` | `L6959` | `CSV L3380–L3436` |
| 2 | `-59` | `ML-DSA-87-Ed448` | **`"mtc"` (`-48` MTC)** | **`6,689 B` (`114`)** | **`1,535.19 ms`** (`2` `KA`) | `452.06 ms` | `2,003.30 ms` | `L7188` | `CSV L3464–L3704` |
| 3 | `-58` | `ML-DSA-65-Ed25519` | **`"mtc"` (`-48` MTC)** | **`6,259 B` (`107`)** | **`1,067.13 ms`** (`2` `KA`) | `424.05 ms` | `1,507.24 ms` | `L7501` | `CSV L3732–L3958` |
| 4 | `-57` | `ML-DSA-44-Ed25519` | **`"mtc"` (`-48` MTC)** | **`5,619 B` (`96`)** | **`903.11 ms`** (`2` `KA`) | `380.05 ms` | `1,299.21 ms` | `L7795` | `CSV L3986–L4190` |
| 5 | `-56` | `ML-DSA-87-ES384` | **`"mtc"` (`-48` MTC)** | **`6,729 B` (`115`)** | **`2,275.28 ms`** (`2` `KA`) | `456.06 ms` | `2,747.39 ms` | `L8102` | `CSV L4218–L4462` |
| 6 | `-55` | `ML-DSA-65-ES256` | **`"mtc"` (`-48` MTC)** | **`6,292 B` (`107`)** | **`1,211.15 ms`** (`2` `KA`) | `424.05 ms` | `1,651.26 ms` | `L8416` | `CSV L4490–L4716` |
| 7 | `-54` | `ML-DSA-44-ES256` | **`"mtc"` (`-48` MTC)** | **`5,652 B` (`96`)** | **`1,039.13 ms`** (`2` `KA`) | `380.05 ms` | `1,435.23 ms` | `L8711` | `CSV L4744–L4948` |
| 8 | `-50` | `ML-DSA-87` | **`"mtc"` (`-48` MTC)** | **`6,677 B` (`114`)** | **`1,075.13 ms`** (`2` `KA`) | `452.06 ms` | `1,543.24 ms` | `L9013` | `CSV L4976–L5216` |
| 9 | `-49` | `ML-DSA-65` | **`"mtc"` (`-48` MTC)** | **`6,227 B` (`106`)** | **`1,731.22 ms`** (`2` `KA`) | `420.05 ms` | `2,167.32 ms` | `L9327` | `CSV L5244–L5468` |
| 10 | `-48` | `ML-DSA-44` | **`"mtc"` (`-48` MTC)** | **`5,587 B` (`95`)** | **`2,555.32 ms`** (`2` `KA`) | `376.05 ms` | `2,947.42 ms` | `L9625` | `CSV L5496–L5700` |
| 11 | `-53` | `Ed448` | **`"packed"` (`ES384` `x5c`)** | **`1,046 B` (`18`)** | **`1,211.15 ms`** (`2` `KA`) | `68.01 ms` | `1,295.21 ms` | `L9830` | `CSV L5728–L5776` |
| 12 | `-8` | `Ed25519` | **`"packed"` (`ES384` `x5c`)** | **`1,020 B` (`18`)** | **`995.12 ms`** (`2` `KA`) | `68.01 ms` | `1,079.18 ms` | `L9957` | `CSV L5804–L5852` |
| 13 | `-47` | `ES256K` | **`"packed"` (`ES384` `x5c`)** | **`1,055 B` (`18`)** | **`951.12 ms`** (`2` `KA`) | `68.01 ms` | `1,035.18 ms` | `L10084` | `CSV L5880–L5928` |
| 14 | `-36` | `ES512` | **`"packed"` (`ES384` `x5c`)** | **`1,125 B` (`20`)** | **`2,263.28 ms`** (`2` `KA`) | `76.01 ms` | `2,355.34 ms` | `L10218` | `CSV L5956–L6010` |
| 15 | `-35` | `ES384` | **`"packed"` (`ES384` `x5c`)** | **`1,089 B` (`19`)** | **`2,083.26 ms`** (`2` `KA`) | `72.01 ms` | `2,171.32 ms` | `L10352` | `CSV L6038–L6088` |
| 16 | `-7` | `ES256` | **`"packed"` (`ES384` `x5c`)** | **`1,055 B` (`18`)** | **`1,523.19 ms`** (`2` `KA`) | `68.01 ms` | `1,607.25 ms` | `L10482` | `CSV L6116–L6164` |

### 0.5 Complete Suite-by-Suite Breakdown of Run 17 (`250 Passed / 32 Skipped / 0 Failed`)

| Suite # | Test Suite | Conformance Log Lines | Time Window | Passed | Skipped | Failed | Highlights |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **`Transport-HID-1`** | `L73–L1148` | `00:48:37` – `00:48:50` | **16** | 0 | 0 | All 16 CTAPHID init, ping (`1,024 B`), wink, CBOR, cont, and error tests passed. |
| 2 | **`Authr-Generic-1`** | `L1227–L2019` | `00:48:50` – `00:48:55` | **5** | 0 | 0 | **`P-1`..`P-5` (`5/5` PASS)** — Includes newly activated **`P-4` (`encIdentifier`)** and **`P-5` (`encCredStoreState`)**! |
| 3 | **`Authr-MakeCred-Req-1`..`Req-6`** | `L2207–L6843` | `00:48:57` – `00:49:47` | **38** | 3 | 0 | All 38 applicable `MakeCredential` request tests passed (`Req-5` `P-2`, `P-3` tested `attestationFormatsPreference`). |
| 4 | **`Authr-MakeCred-Resp-1`** | `L6845–L12068` | `00:49:47` – `00:50:28` | **5** | 1 | 0 | **`P-01`..`P-04`, `F-01` (`5/5` PASS)** — Verified 7 `ES384` `x5c` chains + 9 `ML-DSA-44` MTC proofs + 9 Root CA `subtrees[0].signature` checks (`92.5 ms`). |
| 5 | **`Authr-GetAssertion-Req-1`..`Req-3`** | `L12391–L14299` | `00:50:32` – `00:50:55` | **15** | 2 | 0 | All 15 `GetAssertion` request validation tests passed. |
| 6 | **`Authr-GetAssertion-Resp-1`** | `L14310–L21198` | `00:50:55` – `00:52:25` | **5** | 0 | 0 | **`P-1`..`P-4`, `F-1` (`5/5` PASS)** — Verified assertions across all 16 algorithms (`-257`..`-7`). |
| 7 | **`Authr-MakeCred-and-GetAssertion-1`** | `L21380–L21906` | `00:52:26` – `00:52:33` | **1** | 0 | 0 | End-to-end credential registration and assertion passed. |
| 8 | **`Authr-ResidentKey-1`** | `L21987–L23476` | `00:54:42` – `00:55:08` | **5** | 1 | 0 | **`P-1`..`P-3`, `P-5`, `P-6` (`5/5` PASS)** — Includes newly activated **`P-5` (`encCredStoreState` rotation on `rk: true`)**! |
| 9 | **`EntepriseAttestation`** | `L23738–L24973` | `00:55:11` – `00:55:24` | **6** | 3 | 0 | **`P-1`..`P-3`, `F-4`..`F-6` (`6/6` PASS)** — Verified `ep: true`, Enterprise MTC (`caId = g5k_AQI`), `mtcProof.extensions` serial number (`"123456"`), and Root CA `subtrees[0].signature`! |
| 10 | **`Ext-HMAC-Secret-1` (Groups 1–4)** | `L25205–L29598` | `00:55:26` – `00:56:27` | **24** | 0 | 0 | All 24 `hmac-secret` tests across PIN Protocols 1 & 2 passed. |
| 11 | **`Ext-HMAC-Secret-MC-1` (Groups 1–4)** | `L29652–L35216` | `00:56:27` – `00:57:53` | **26** | 2 | 0 | All 26 applicable `hmac-secret-mc` tests across PIN Protocols 1 & 2 passed. |
| 12 | **`Ext-CredProtect-1` / `CredBlob` / `LargeBlobKey` / `MinPinLength` / `ThirdPartyPayment`** | `L35221–L38805` | `00:57:53` – `00:58:49` | **18** | 0 | 0 | All 18 remaining CTAP 2.3 extension tests passed (`4 + 3 + 6 + 2 + 3`). |
| 13 | **`Authr-ClientPin-1` (PIN Protocol 1)** | `L38835–L40667` | `00:58:49` – `00:59:23` | **15** | 2 | 0 | KeyAgreement (`1`), Set/Change/PinToken (`7`), PinPolicy (`4`), PinRetries (`3`, including USB replug at `CSV L22433`). |
| 14 | **`Authr-ClientPin-2` (PIN Protocol 2)** | `L40703–L44076` | `00:59:23` – `01:00:24` | **26** | 3 | 0 | KeyAgreement (`1`), ChangePin (`4`, including **`P-4` `pcmr` rotation**), PinToken (`7`), PinUvAuthToken (`5`, including **`P-4` `pcmr` token issuance**), PinPolicy (`5`), PinRetries (`4`). |
| 15 | **`Authr-CredMgmt-1`** | `L44259–L46368` | `01:00:26` – `01:00:51` | **11** | 0 | 0 | **`11/11` PASS** — Group 1 (`P-1`..`P-6`, including **`P-4`..`P-6` with `pcmr` token**), Group 2 (`P-1`..`P-3`, including **`P-3` with `pcmr` token**), Group 3 (`P-1` updateUserInfo, `P-2` deleteCredential). |
| 16 | **`Authr-Config-1` / `Selection` / `LargeBlobs-1`** | `L46551–L47920` | `01:00:53` – `01:01:04` | **9** | 2 | 0 | `Authr-Config-1` (`P-1`..`P-5`: `enableEnterpriseAttestation`, `toggleAlwaysUv`, `setMinPINLength`), `LargeBlobs-1` (`P-1`..`P-4`). |
| 17 | **`Metadata-Stmt-1`** | `L47943–L48484` | `01:01:04.42` – `01:01:04.50` | **25** | 13 | 0 | All 25 applicable MDS3 & CTAP 2.3 metadata statement checks (`P-2`..`P-37`) passed (`0` failed), including `P-27` (`29.7 ms` Root CA `subtrees[].signature` check) and `P-32` (`perCredMgmtRO`, `encIdentifier`, `encCredStoreState`). |
| **Total** | **Full CTAP 2.3 Conformance Suite (Run 17)** | `L1–L48653` | **`12m 26.92s`** | **`250`** | **`32`** | **`0`** | **`100.00%` PASS (`250 / 250` active tests, `0` failures, `0` USB bus errors)** |

---

## 1. Earlier Run 5 Analysis: Post-Quantum Merkle Tree Certificate (`mtc` & `mtc-mds`) Run (`L94736–L145398`)

### 1.1 Correlation with **Compile and Install Fidont**
Prior to Run 5 (at `00:08` in **Compile and Install Fidont**), the nRF52840 DK was flashed and provisioned with the **Post-Quantum Merkle Tree Certificate (`mtc` / `mtc-mds`)** architecture defined in [pq_mtc_attestation_proposal.md](./pq_mtc_attestation_proposal.md) and `metadata_mldsa65_mtc.json`:
- **Provisioned Batch Key**: `ML-DSA-65` (`alg: -49`, COSE `AKP` public key = `1,962 B`, signature = `3,309 B`)
- **MTC Certificate (`mtcCert`)**:
  - `caId`: `h'83993f0102'` (base64url `"g5k_AQI"`, OID `1.3.6.1.4.1.57343.1.2`)
  - `serial`: `0x0007000000000005` (`1970324836974597`, `logNumber = 7`)
  - `mtcProof`: `115 B` (`treeSize = 8`, 3-sibling SHA-256 inclusion path + `79 B` cosigner checkpoint)
  - `notBefore`: `1791847311` (`0x6acd6b8f`), `notAfter`: `2107207311` (`0x7d996e8f`)
  - **Root Hash in MDS**: `"of6RgYqR4wCmuIIEjXsX6MUT3qt7oOX9TMJXVRkpvt0"`

### 1.2 Live Verification of the 3-Tier Size-Aware Attestation Cascade (`101` `MakeCredential` Calls)
When the conformance tool sent `authenticatorMakeCredential` without `attestationFormatsPreference (0x0B)`, Fidont executed its **3-tier size-aware cascade** (`<= 7,550 B` threshold to stay within the `7,609 B` CTAPHID frame limit):
1. **Tier 1 (`"packed"` with `5,656 B` X.509 `x5c`)**: Skipped automatically because `auth_data.len() + 3309 + 5656 + 60 > 7,550 B` for all algorithms when using an `ML-DSA-65` batch certificate (`> 9,100 B`).
2. **Tier 2 (`"mtc"` — inline `pubKey` + `mtcCert`)**: Selected automatically for **10 of the 16 algorithms** (`77` total `MakeCredential` responses in Run 5), producing total CBOR responses between **`5,836 B` and `7,181 B`** (`99–122` HID frames).
3. **Tier 3 (`"mtc-mds"` — `mtcCert` only, `pubKey` resolved via MDS `mtcTrustAnchors[].batchKeys`)**: Selected automatically for the **6 `ML-DSA-65` and `ML-DSA-87` pure and composite algorithms** (`24` total `MakeCredential` responses in Run 5), where including the `1,962 B` inline batch `pubKey` alongside a `1,952–2,689 B` credential public key would have resulted in `7,761–8,498 B` (exceeding the `7,609 B` USB HID limit). With `"mtc-mds"`, all 6 algorithms fit in **`5,788 B` to `6,525 B`** (`99–111` HID frames)!

| # | COSE `alg` | Algorithm Name | Selected `fmt` | `MakeCredential` Size (`BCNT`) | HID Frames | `MakeCredential` Time | Size if `"mtc"` (Why Cascade Triggered) | Log Reference (Run 5) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `-7` | `ES256` | **`"mtc"`** | `5,871 B` | 100 | `3,182.9 ms` | `5,871 B` ($\le 7,550\text{ B}$) | `L108195` |
| 2 | `-35` | `ES384` | **`"mtc"`** | `5,904 B` | 101 | `2,679.7 ms` | `5,904 B` ($\le 7,550\text{ B}$) | `L107896` |
| 3 | `-36` | `ES512` | **`"mtc"`** | `5,940 B` | 101 | `4,750.9 ms` | `5,940 B` ($\le 7,550\text{ B}$) | `L107599` |
| 4 | `-47` | `ES256K` | **`"mtc"`** | `5,872 B` | 100 | `1,546.8 ms` | `5,872 B` ($\le 7,550\text{ B}$) | `L107297` |
| 5 | `-8` | `Ed25519` | **`"mtc"`** | `5,836 B` | 99 | `1,403.7 ms` | `5,836 B` ($\le 7,550\text{ B}$) | `L107007` |
| 6 | `-53` | `Ed448` | **`"mtc"`** | `5,862 B` | 100 | `1,643.8 ms` | `5,862 B` ($\le 7,550\text{ B}$) | `L106716` |
| 7 | `-48` | `ML-DSA-44` | **`"mtc"`** | `7,116 B` | 121 | `2,308.6 ms` | `7,116 B` ($\le 7,550\text{ B}$) | `L106382` |
| 8 | `-49` | `ML-DSA-65` | **`"mtc-mds"`** | **`5,788 B`** | 99 | `1,599.7 ms` | `7,761 B` ($> 7,609\text{ B}$ HID max) | `L106090` |
| 9 | `-50` | `ML-DSA-87` | **`"mtc-mds"`** | **`6,428 B`** | 109 | `1,376.2 ms` | `8,401 B` ($> 7,609\text{ B}$ HID max) | `L105780` |
| 10 | `-54` | `ML-DSA-44-ES256` | **`"mtc"`** | `7,181 B` | 122 | `2,842.8 ms` | `7,181 B` ($\le 7,550\text{ B}$) | `L105445` |
| 11 | `-55` | `ML-DSA-65-ES256` | **`"mtc-mds"`** | **`5,853 B`** | 100 | `2,064.2 ms` | `7,826 B` ($> 7,609\text{ B}$ HID max) | `L105149` |
| 12 | `-56` | `ML-DSA-87-ES384` | **`"mtc-mds"`** | **`6,525 B`** | 111 | `2,576.6 ms` | `8,498 B` ($> 7,609\text{ B}$ HID max) | `L104834` |
| 13 | `-57` | `ML-DSA-44-Ed25519` | **`"mtc"`** | `7,148 B` | 122 | `2,275.6 ms` | `7,148 B` ($\le 7,550\text{ B}$) | `L104495` |
| 14 | `-58` | `ML-DSA-65-Ed25519` | **`"mtc-mds"`** | **`5,820 B`** | 99 | `1,727.3 ms` | `7,793 B` ($> 7,609\text{ B}$ HID max) | `L104203` |
| 15 | `-59` | `ML-DSA-87-Ed448` | **`"mtc-mds"`** | **`6,485 B`** | 110 | `2,387.2 ms` | `8,458 B` ($> 7,609\text{ B}$ HID max) | `L103891` |
| 16 | `-257` | `RS256` | **`"mtc"`** | `6,066 B` | 103 | `1,155.5 ms` | `6,066 B` ($\le 7,550\text{ B}$) | `L103591` |

### 1.3 Root-Cause Analysis of the 2 Failures in Run 5 (`L94736–L145398`)

#### Failure 1: `Authr-Generic-1` `P-1` — `"none"` Included in `GetInfo.attestationFormats (0x16)` (`L97116–L97117`)
- **Assertion Failure**:
  ```text
  [ASSERTION FAILED] notStrictEqual {"args":["none","none","Support for 'none' attestation is implied and MUST be omitted"],"message":"Support for 'none' attestation is implied and MUST be omitted: expected 'none' to not equal 'none'"}
  ```
- **Cause**: At `00:26:28` (`L96950`), the firmware running on the board returned `0x16: ["mtc", "mtc-mds", "packed", "none"]` (`16 84 63 6d7463 67 6d74632d6d6473 66 7061636b6564 64 6e6f6e65`). Per CTAP 2.3 §6.4 (`authenticatorGetInfo`) and `Authr-Generic-1.js:391`, support for `"none"` attestation is implied and must be omitted from `attestationFormats`.
- **Status**: **Already fixed in Fidont source & MDS files at `00:31`** in **Compile and Install Fidont** (`mod.rs:647-656` and `metadata_mldsa65_mtc.json` now list `["mtc", "mtc-mds", "packed"]`). Re-flashing the updated Fidont firmware resolves this error. Note that `Authr-MakeCred-Req-5` `P-2` and `P-3` (which test `attestationFormatsPreference` set to `getInfo.attestationFormats` and `["none"]`) **passed** in Run 5 (`L102396`, `L102824`).

#### Failure 2: `Authr-MakeCred-Resp-1` `"before all" hook for "P-01"` — `"Only PACKED attestation is supported!"` (`L118207–L118215`)
- **Error Thrown**:
  ```text
  [TEST FAILED] "before all" hook for "P-01" -> Only PACKED attestation is supported!
  ```
- **Cause**: In `Authr-MakeCred-Resp-1.js:51-53` and ``P-01` (L83-85)`, the FIDO Conformance Tool hardcodes:
  ```javascript
  if(response.cborResponse[MakeCredentialsRespKeys.fmt] !== 'packed') {
      throw new Error('Only PACKED attestation is supported!');
  }
  ```
  Because Fidont returned `fmt: "mtc"` (10 algorithms) and `fmt: "mtc-mds"` (6 algorithms), the `before()` hook threw after generating all 16 credentials (and retried twice more, generating `3 × 16 = 48` credentials total before failing).
- **Important Note**: Right after `Authr-MakeCred-Resp-1`, `Authr-GetAssertion-Resp-1` also called `getMakeCredentialResponseForAllAlgorithms(rpId)` (receiving `10` `"mtc"` and `6` `"mtc-mds"` responses), extracted all 16 COSE public keys from `authData`, and **passed `5/5` tests (`P-1`..`P-4`, `F-1`) across all 16 algorithms**!
- **How to Fix in the Conformance Tool**: Patch `Authr-MakeCred-Resp-1.js` (as well as `Metadata-Stmt-1.js` and `meta.js`) to accept `'mtc'` and `'mtc-mds'` in `typesOfAttestation`, verify the Merkle tree inclusion proof (`mtcProof`) and cosigner checkpoint against `metadata.mtcTrustAnchors`, and verify the `ML-DSA` batch signature over `authData || clientDataHash` using the inline `attStmt.pubKey` (for `"mtc"`) or the MDS `mtcTrustAnchors[].batchKeys` entry matched by `(caId, serial)` (for `"mtc-mds"`).

### 1.4 Suite-by-Suite Breakdown of Run 5 (`L94736–L145398`, `128` Passed / `2` Failed)

| Suite # | Test Suite | Line Range | Passed | Failed | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **`Transport-HID-1`** | `L94800–L96853` | 16 | 0 | All 16 CTAPHID transport tests passed. |
| 2 | **`Authr-Generic-1`** | `L96860–L97207` | 2 | 1 | `P-2`, `P-3` passed; `P-1` failed on `"none"` in `0x16` (fixed in Fidont source). |
| 3 | **`Authr-MakeCred-Req-1`..`Req-6`** | `L97400–L103284` | 38 | 0 | **All 38 `MakeCredential` request tests passed** (including `Req-5` `P-2` & `P-3` testing `attestationFormatsPreference`). |
| 4 | **`Authr-MakeCred-Resp-1`** | `L103290–L118215` | 0 | 1 | Hardware generated `3 × 16 = 48` credentials (`30` `"mtc"`, `18` `"mtc-mds"`), then `before()` hook threw `"Only PACKED attestation is supported!"`. |
| 5 | **`Authr-GetAssertion-Req-1`..`Req-3`** | `L118400–L120934` | 15 | 0 | All 15 `GetAssertion` request validation tests passed. |
| 6 | **`Authr-GetAssertion-Resp-1`** | `L120935–L129134` | 5 | 0 | **All 16 algorithms (`-7`..`-257`) created credentials via `"mtc"`/`"mtc-mds"` and passed all assertion checks (`P-1`..`P-4`, `F-1`).** |
| 7 | **`Authr-MakeCred-and-GetAssertion-1`** | `L129140–L129990` | 1 | 0 | End-to-end credential creation (`"mtc"`) & assertion passed. |
| 8 | **`Authr-ResidentKey-1`** | `L130000–L133267` | 7 | 0 | All 7 discoverable credential (`rk`) tests passed with `"mtc"` responses. |
| 9 | **`Ext-HMAC-Secret-1` (PIN Proto 1 & 2)** | `L133270–L138692` | 24 | 0 | All 24 `hmac-secret` tests (4 groups) passed. |
| 10 | **`Ext-HMAC-Secret-MC-1` (Groups 1–3)** | `L138700–L144891` | 20 | 0 | All 20 `hmac-secret-mc` tests across Groups 1, 2, and 3 passed (`5,957 B` `"mtc"` responses with `hmac-secret-mc` output). |
| 11 | **`Ext-HMAC-Secret-MC-1` (Group 4)** | `L144896–L145301` | — | — | User stopped run (`L145301`) while Group 4 `P-2` was in flight. |
| **Total** | **Executed in Run 5** | **`L94736–L145398`** | **`128`** | **`2`** | **`98.46%` Pass Rate (`101` `"mtc"` / `"mtc-mds"` credentials created on hardware)** |

---

## 2. Earlier 100% Passing Runs (`Run 1` & `Run 2` with `"packed"` Self-Attestation)

### 2.1 Run 2: CTAP 2.3 Extensions Suite with `hmac-secret-mc` (`L38483–L51656`, `68` Passed / `0` Failed)

In `GetInfo (0x04)` at `L38502–L38504`, the authenticator advertised all **7** CTAP 2.3 extensions in `extensions (0x02)`:
`["hmac-secret", "hmac-secret-mc", "credProtect", "minPinLength", "credBlob", "largeBlobKey", "thirdPartyPayment"]`.

| Extension Suite | PIN Protocol & Mode | Line Range | Passed | Failed | Test IDs Verified |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Ext-HMAC-Secret-1` (Group 1)** | PIN Protocol 1 — No PIN | `L38696–L39738` | 6 | 0 | `P-1`, `P-2`, `P-3`, `F-1`, `F-2`, `F-3` |
| **`Ext-HMAC-Secret-1` (Group 2)** | PIN Protocol 1 — With PIN | `L39743–L40769` | 6 | 0 | `P-1`, `P-2`, `P-3`, `F-1`, `F-2`, `F-3` |
| **`Ext-HMAC-Secret-1` (Group 3)** | PIN Protocol 2 — No PIN | `L40864–L41924` | 6 | 0 | `P-1`, `P-2`, `P-3`, `F-1`, `F-2`, `F-3` |
| **`Ext-HMAC-Secret-1` (Group 4)** | PIN Protocol 2 — With PIN | `L41929–L42991` | 6 | 0 | `P-1`, `P-2`, `P-3`, `F-1`, `F-2`, `F-3` |
| **`Ext-HMAC-Secret-MC-1` (Group 1)** | PIN Protocol 1 — No PIN (`makeCredUvNotRqd`) | `L43041–L44502` | 7 | 0 | `P-1`, `P-2` (salt1), `P-3` (salt1+salt2), `F-1`..`F-4` |
| **`Ext-HMAC-Secret-MC-1` (Group 2)** | PIN Protocol 1 — With PIN | `L44518–L45673` | 6 | 0 | `P-2` (salt1), `P-3` (salt1+salt2), `F-1`..`F-4` |
| **`Ext-HMAC-Secret-MC-1` (Group 3)** | PIN Protocol 2 — No PIN (`makeCredUvNotRqd`) | `L45678–L47139` | 7 | 0 | `P-1`, `P-2` (salt1), `P-3` (salt1+salt2), `F-1`..`F-4` |
| **`Ext-HMAC-Secret-MC-1` (Group 4)** | PIN Protocol 2 — With PIN | `L47155–L48312` | 6 | 0 | `P-2` (salt1), `P-3` (salt1+salt2), `F-1`..`F-4` |
| **`Ext-CredProtect-1`** | PIN Protocol 1 & 2 | `L48317–L49111` | 4 | 0 | `P-1`, `P-2`, `P-3`, `P-4` |
| **`Ext-CredBlob-1`** | Discoverable `credBlob` | `L49117–L49634` | 3 | 0 | `P-1`, `P-2`, `P-3` |
| **`Ext-LargeBlobKey-1`** | `largeBlobKey` MakeCred & GetAssertion | `L49642–L50400` | 6 | 0 | `P-1`, `P-2`, `F-1`, `F-2`, `F-3`, `F-4` |
| **`Ext-MinPinLength-1`** | `minPinLength` RP ID allowlist | `L50405–L50755` | 2 | 0 | `P-1`, `F-1` |
| **`Ext-ThirdPartyPayment-1`** | Discoverable & Non-Discoverable | `L50762–L51649` | 3 | 0 | `P-1`, `P-2`, `F-1` |
| **Total (Run 2)** | **All 7 CTAP 2.3 Extensions** | **`L38483–L51656`** | **`68`** | **`0`** | **`100.00%` Pass Rate** |

### 2.2 Run 1: Full 16-Algorithm Conformance Run (`L53–L37332`, `211` Passed / `0` Failed)

| Suite # | Test Suite | Line Range | Passed | Failed | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **`Transport-HID-1`** | `L121–L1186` | 16 | 0 | All CTAPHID init, ping, wink, CBOR, cont, and error tests passed. |
| 2 | **`Authr-Generic-1`** | `L1269–L1367` | 3 | 0 | **`P-1`, `P-2`, `P-3` PASSED** (all 16 algorithms matched `Metadata.authenticatorGetInfo.algorithms`). |
| 3 | **`Authr-MakeCred-Req-1`..`Req-6`** | `L1561–L6235` | 38 | 0 | All `MakeCredential` request validation suites passed. |
| 4 | **`Authr-MakeCred-Resp-1`** | `L6235–L9058` | 5 | 0 | **All 16 algorithms** (`-257`..`-7`) created credentials & verified COSE keys and attestation signatures (`P-01`..`P-04`, `F-01`). |
| 5 | **`Authr-GetAssertion-Req-1`..`Req-3`** | `L9375–L11298` | 15 | 0 | All `GetAssertion` request validation suites passed. |
| 6 | **`Authr-GetAssertion-Resp-1`** | `L11298–L17279` | 5 | 0 | **All 16 algorithms** (`-7`..`-257`) generated and verified assertions (`P-1`..`P-4`, `F-1`). |
| 7 | **`Authr-MakeCred-and-GetAssertion-1`** | `L17454–L17976` | 1 | 0 | End-to-end credential creation & assertion flow passed. |
| 8 | **`Authr-ResidentKey-1`** | `L18053–L19949` | 7 | 0 | Discoverable credential (`rk`) creation and enumeration passed. |
| 9 | **`Ext-HMAC-Secret-1` (PIN Proto 1 & 2)** | `L20359–L24768` | 24 | 0 | All 4 `hmac-secret` suites passed. |
| 10 | **`Ext-CredProtect-1`** | `L24773–L25644` | 4 | 0 | `credProtect` levels `1`, `2`, `3` passed. |
| 11 | **`Ext-CredBlob-1`** | `L25650–L26208` | 3 | 0 | `credBlob` extension passed. |
| 12 | **`Ext-LargeBlobKey-1`** | `L26216–L27015` | 6 | 0 | `largeBlobKey` extension passed. |
| 13 | **`Ext-MinPinLength-1`** | `L27020–L27409` | 2 | 0 | `minPinLength` extension passed. |
| 14 | **`Ext-ThirdPartyPayment-1`** | `L27416–L28362` | 3 | 0 | `thirdPartyPayment` extension passed. |
| 15 | **`Authr-ClientPin-1` (PIN Protocol 1)** | `L28392–L30237` | 14 | 0 | All PIN Protocol 1 tests (including `ClientPin1-PinPolicy` `F-2`) passed. |
| 16 | **`Authr-ClientPin-2` (PIN Protocol 2)** | `L30272–L33508` | 24 | 0 | **All 24 PIN Protocol 2 tests (including `ClientPin2-PinPolicy` `F-2` at `L32293`) PASSED.** |
| 17 | **`Authr-CredMgmt-1` (PIN Protocol 1 & 2)** | `L33588–L36561` | 11 | 0 | All Credential Management enumeration, metadata, RP, and deletion tests passed. |
| 18 | **`Authr-LargeBlobs-1` / `Config` / `Selection`** | `L36566–L37332` | 30 | 0 | All remaining CTAP 2.3 suites passed. |
| **Total (Run 1)** | **All Active CTAP 2.3 Suites** | **`L121–L37332`** | **`211`** | **`0`** | **`100.00%` Pass Rate** |

---

## 3. Detailed Analysis of `Authr-ClientPin2-PinPolicy` `F-2` Test Logic

### 3.1 Specification vs. Implementation in Fidont
Per **CTAP 2.1 / 2.2 / 2.3 Section 6.5.5.5 (`Setting a new PIN`)**:
- The platform zero-pads `newPin` into a **fixed 64-byte buffer** (`newPin` must be at most 63 UTF-8 bytes so that at least one trailing `0x00` byte terminates the PIN inside the 64-byte plaintext block).
- The authenticator decrypts `newPinEnc` using `sharedSecret` to obtain `paddedPin`:
  1. If the decrypted `paddedPin` buffer length is **not 64 bytes**, the ciphertext parameter itself is malformed (`CTAP1_ERR_INVALID_PARAMETER (0x02)`).
  2. If the decrypted `paddedPin` buffer is **64 bytes** (`PIN_PADDED_LENGTH`), the authenticator strips trailing `0x00` bytes and checks the unpadded PIN length: if no `0x00` byte is present (`pin.len() == 64 > 63`) or if `pin_codepoints < minPINLength`, it returns `CTAP2_ERR_PIN_POLICY_VIOLATION (0x37)`.

Fidont implements this in `client_pin.rs:67-102`:

```rust
fn decrypt_pin<E: Env>(
    shared_secret: &SharedSecret<E>,
    new_pin_enc: Vec<u8>,
) -> CtapResult<Secret<[u8]>> {
    let decrypted_pin = shared_secret.decrypt(&new_pin_enc)?;
    if decrypted_pin.len() != PIN_PADDED_LENGTH { // PIN_PADDED_LENGTH = 64
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER); // 0x02 (2)
    }
    let len = decrypted_pin
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(decrypted_pin.len());
    let mut result = Secret::new(len);
    result.copy_from_slice(&decrypted_pin[..len]);
    Ok(result)
}
```

### 3.2 How `ClientPin1` vs. `ClientPin2` Construct `F-2` and `F-3`
1. **`Authr-ClientPin1-PinPolicy.js` (`F-2` & `F-3`)** — `Authr-ClientPin1-PinPolicy.js:112-166`:
   Both `F-2` and `F-3` generate a **64-byte** non-zero PIN inside a **64-byte** `encryptionBuffer` (`generateRandomClientPinBuffer(64)`). Because `decrypted_pin.len() == 64` with no `0x00` terminator, Fidont always returns `CTAP2_ERR_PIN_POLICY_VIOLATION (0x37)`.
2. **`Authr-ClientPin2-PinPolicy.js` (`F-2` vs `F-3`)** — `Authr-ClientPin2-PinPolicy.js:109-159`:
   - **`F-3`** (`"Try setting new pin, that is exactly 64 bytes, and check that Authenticator returns error CTAP2_ERR_PIN_POLICY_VIOLATION(0x37)"`) encrypts a **64-byte** `encryptionBuffer` (`16B IV + 64B CT = 80 bytes`) and asserts `CTAP2_ERR_PIN_POLICY_VIOLATION (0x37)`.
   - **`F-2`** (`"Try setting new pin, that is bigger than 63 bytes, and check that Authenticator returns an error"`) generates a random-length buffer `generateRandomClientPinBuffer(generateSecureRandomInt(64, 128))` and passes it to `encryptAES256CBC` (`cryptodep.js:394-405`), which calls `cipher.update(messageBuffer)` without `cipher.final()`, truncating the plaintext to $\lfloor L / 16 \rfloor \times 16$ bytes:
     - When $L \in [64, 79]$ ($24.6\%$ chance), `newPinEnc` has `64` ciphertext bytes (`80B` total with IV) $\rightarrow$ `CTAP2_ERR_PIN_POLICY_VIOLATION (0x37)`.
     - When $L \in [80, 128]$ ($75.4\%$ chance), `newPinEnc` has `80, 96, 112, or 128` ciphertext bytes (`96..144B` total with IV) $\rightarrow$ `CTAP1_ERR_INVALID_PARAMETER (0x02)` because `decrypted_pin.len() != 64`.
   - Updating `Authr-ClientPin2-PinPolicy.js:130` to `assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)` matches the `F-2` specification (`"check that Authenticator returns an error"`) and the `CTAP 2.1 module`.
