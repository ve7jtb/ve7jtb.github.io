# FIDO CTAP 2.3 Conformance Test Report — 18 Algorithms (Including Draft NIST FIPS 206 `FN-DSA-512` & `FN-DSA-1024`), All 7 Extensions, `persistentPinUvAuthToken` (`perCredMgmtRO`), Enterprise Attestation & Post-Quantum `mtc` / `mtc-mds`

- **Log Files Analyzed**:
  1. **FIDO Conformance Debug Log**: `fido_conformance_debug.log` (`66,127` lines / `8.32 MB` in Run 19 with `250 / 250` `100.00%` PASS across all 18 algorithms including `FN-DSA-512` `-60` & `FN-DSA-1024` `-61`; `52,180` lines in Run 18; `48,653` lines in Run 17; plus `282,939` lines across Runs 10–16)
  2. **Total Phase Beagle USB Protocol Analyzer Capture**: `totalphase.csv` (`28,653` CSV lines, `28,646` rows, `127,232` USB bus records, `2.91 MB`, captured `Mon Oct 19 11:49:16` – `12:20:30 2026`, `0` USB bus errors across `1,092` `CTAPHID_CBOR` exchanges in Run 19; plus `26,436` CSV rows / `68,774` USB bus records in Run 17)
  3. **Fidont J-Link RTT Log**: `fidont_rtt.log` (`304,330` lines / `32.79 MB` in Run 19 and `302,212` lines / `31.0 MB` in Run 18 with `--features=debug` `64 MHz` DWT cycle-accurate timestamps across all 18 algorithms, `0` panics / `0` HardFaults / `0` OOMs)
- **Target Authenticator**: Fidont CTAP 2.3 (`U2F_V2`, `FIDO_2_0`, `FIDO_2_1`, `FIDO_2_3`) over USB HID (`VID: 0x1915`, `PID: 0x521f` / `0x18d1:0x0239`)
- **Related Design & Firmware Implementation**: **Compile and Install Fidont** & [pq_mtc_attestation_proposal.md](./pq_mtc_attestation_proposal.md)

## Fidont authenticator simulator platform performance numbers are for relative comparison as implemented with amateur optimization by me:)

> [!IMPORTANT]
> **Attribution & Scope of Fidont:**
> **Fidont** is an authenticator simulator designed for prototyping new specifications and testing authenticator conformance tools. It is based on the [Google OpenSK](https://github.com/google/OpenSK) Rust codebase. However, **Fidont is not suitable for production security use outside of certification, conformance testing, and prototyping new features.**

## Overview of Test Runs 10–19 (`Runs 10–18` Historical + `Run 19` Latest `250 / 250` 18-Algorithm `FN-DSA`, Total Phase USB & `fidont_rtt.log` DWT Telemetry)

| Run | Line Range | Time Window | Attestation & Feature Config | Passed | Failed | Outcome & Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Run 10** | `L287509–L347258` (pre-clear 1) | `02:55:51` – `03:06:05` (`10m 14s`) | **`ML-DSA-44` (`-48`) `--mtc-x5c`** (**Tier 1 `"packed"` `x5c` + Tier 2 `"mtc"`**, strict MDS verification) | **`237`** | **`0`** | **`100.00%` PASS (`237 Passed / 45 Skipped / 0 Failed`)** — Complete CTAP 2.3 Suite + `Metadata-Stmt-1`; **`74` `"packed"` (`4,127 B` `x5c`) + `18` `"mtc"` (`1,322 B` inline `pubKey`)** |
| **Run 11** | `L1–L56583` (pre-clear 2) | `09:11:23` – `09:27:58` (`16m 35s`) | **`ML-DSA-87` (`-50`) MTC Batch Key** (**100% Tier 3 `"mtc-mds"`**, compact `0x02`/`0x03` cred IDs, strict MDS verification) | **`237`** | **`0`** | **`100.00%` PASS (`237 Passed / 45 Skipped / 0 Failed`)** — Complete CTAP 2.3 Suite + `Metadata-Stmt-1`; **`94` `"mtc-mds"` (`100%` MDS `batchKeys` lookup, `caId = 0x83993f0103`)** |
| **Run 12** | `L58596–L69096` (pre-clear 2) | `23:12:37` – `23:13:55` (`1m 18s`) | Dual Batch + `--enterprise` (before reloading updated MDS) | `56` | `2` | Aborted after `Authr-Generic-1` `P-1` (`options` count `12` vs `11` because `ep: false` added) and `MakeCred-Resp-1` before reloading updated metadata |
| **Run 13** | `L73661–L124119` (pre-clear 2) | `23:36:31` – `00:05:42` (`29m 11s`) | Dual Batch + `--enterprise` (with Root CA `subtrees[].signature` check, before reloading MDS) | `236` | `5` | **`Authr-MakeCred-Resp-1` (`P-01`..`P-04`) PASSED with Root CA `subtrees[].signature` check!** 5 failures due to stale MDS + unpatched `EntepriseAttestation.js` (`P-2`, `P-3`, `F-6`) |
| **Run 14** | `L124193–L126258` (pre-clear 2) | `00:23:04` – `00:23:25` (`21s`) | Dual Batch + `--enterprise` (aborted early while loading updated MDS) | `21` | `2` | User-terminated (`FORCED TERMINATION`) right before loading updated metadata with `ep: false` and `authenticatorConfigCommands: [1, 2, 3]` |
| **Run 15** | `L126339–L175678` (pre-clear 2) | `00:25:36` – `00:36:53` (`11m 17s`) | Dual Batch (`ES384` `x5c` + `ML-DSA-44` MTC) + `--enterprise` + Root CA `subtrees[].signature` Verification | `238` | `3` | **`98.76%` PASS (`238 Passed / 3 Failed`)** — `Authr-Generic-1`, `Authr-MakeCred-Resp-1` (`P-04`), `Authr-Config-1`, and `Metadata-Stmt-1` (`37/37`) passed 100%; `EntepriseAttestation.js` (`P-2`, `P-3`, `F-6`) needed MTC + serial extension support |
| **Run 16** | `L175680–L223190` (pre-clear 2) | `01:09:20` – `01:24:53` (`15m 33s`) | Dual Batch (`ES384` `x5c` + `ML-DSA-44` MTC) + `--enterprise` + Serial Number Extension (`mtcProof.extensions`) + Root CA `subtrees[].signature` Verification | **`241`** | **`0`** | **`100.00%` PASS (`241 Passed / 41 Skipped / 0 Failed`)** — Full CTAP 2.3 Suite + Security Enterprise Profile (`EntepriseAttestation.js` `6/6` PASS) + `Metadata-Stmt-1` (`37/37` PASS) |
| **Run 17** | `L1–L48653` (pre-clear 3) & `totalphase.csv` | `00:48:37` – `01:01:04` (`12m 27s`) | **Full CTAP 2.3 `persistentPinUvAuthToken` (`perCredMgmtRO`, `pcmr = 0x40`, `encIdentifier = 0x19`, `encCredStoreState = 0x1E`) + Dual Batch (`ES384` `x5c` + `ML-DSA-44` MTC) + Enterprise Attestation (`--enterprise`, `serial="123456"`) + Root CA `subtrees[].signature` Verification** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 32 Skipped / 0 Failed`)** — **All `9` previously skipped `perCredMgmtRO` / `encIdentifier` / `encCredStoreState` / `pcmr (0x40)` tests executed and passed (`241` $\to$ `250` passed)! `0` USB bus errors across `68,774` records (`1,073` `CTAPHID_CBOR` exchanges, `304.4 KB` OUT / `509.9 KB` IN) in `totalphase.csv`!** |
| **Run 18** | `L1–L52180` (pre-clear 4) & `fidont_rtt.log` (`302,212` lines) | `10:16:15` – `10:36:41` (`20m 26s`) | **All 18 Algorithms including Draft NIST FIPS 206 `FN-DSA-512` (`alg: -60`) & `FN-DSA-1024` (`alg: -61`) + `ML-DSA-87` (`-50`) MTC Batch + `ES256` Classical Batch + Enterprise Dual (`ML-DSA-44` leaf / `ML-DSA-87` Root CA) + `fidont_rtt.log` DWT Cycle-Accurate Telemetry** | **`249`** | **`1`** | **`99.60%` PASS (`249 Passed / 34 Skipped / 1 Failed`)** — **`100%` PASS across all 18 algorithms in `Authr-MakeCred-Resp-1`, `Authr-GetAssertion-Resp-1`, `EntepriseAttestation`, `Authr-CredMgmt-1`, and `Metadata-Stmt-1` (`0` panics, `0` OOMs, `0` HardFaults in `302,212` `fidont_rtt.log` lines)!** |
| **Run 19 (Latest)** | `L1–L66127`, `totalphase.csv` (`28,653` lines) & `fidont_rtt.log` (`304,330` lines) | `11:49:33` – `12:11:02` (`21m 28s`) | **All 18 Algorithms (`FN-DSA-512` `-60` & `FN-DSA-1024` `-61` + 16 Classical/PQ/Composite) + `perCredMgmtRO` (`0x19`, `0x1E`, `0x40`) + Dual Batch (`ML-DSA-87` MTC + `ES256` `x5c`) + Enterprise Dual (`ML-DSA-44` leaf / `ML-DSA-87` Root CA) + Simultaneous 3-Log Capture (`fido_conformance_debug.log`, `totalphase.csv` & `fidont_rtt.log`)** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 32 Skipped / 0 Failed`)** — **`250 / 250` (`100%`) pass across all 18 algorithms (`78` `"packed"`, `22` `"mtc-mds"`, `2` `"mtc"`), `0` USB bus errors across `127,232` USB records (`4,945` `OUT txn` / `8,827` `IN txn`, `1,092` `CTAPHID_CBOR` exchanges), and `0` panics/OOMs across `304,330` `fidont_rtt.log` lines!** |

---

## 0.0 Run 19 (`250 / 250` `100%` Pass) & Run 18 Deep Dive: All 18 Algorithms Including Draft NIST FIPS 206 (`FN-DSA-512` `alg: -60` & `FN-DSA-1024` `alg: -61`) Across `fido_conformance_debug.log`, `totalphase.csv` & `fidont_rtt.log`

> [!IMPORTANT]
> **`250 / 250` (`100.00%`) Pass Across All 18 Algorithms with Simultaneous 3-Log Hardware Telemetry (`fido_conformance_debug.log` + `totalphase.csv` + `fidont_rtt.log`)**:
> Runs 18 and 19 extended both the FIDO Conformance Tool (`@noble/post-quantum` pure-JS `fn_dsa512` / `fn_dsa1024` verifier, `COSE_ALG_MAP`, `ALG_DIR_TO_COSE`, `COSE_KTY_AKP = 7`) and **Fidont** (`libraries/fn-dsa` + `opensk::api::crypto::fndsa`) to test **18 COSE signature algorithms** simultaneously on the `64 MHz` Cortex-M4F (`256 KiB` SRAM).
> - **Run 19 (`11:49:33` – `12:11:02`, `21m 28.32s`)**: Achieved **`250 Passed / 32 Skipped / 0 Failed` (`100.00%` PASS)** (`L65919`: *"Testing finished. You may submit the results now."*) while simultaneously recording **`127,232` USB bus records (`0` bus errors)** on the Total Phase Beagle USB Protocol Analyzer (`totalphase.csv`, `28,653` lines) and **`304,330` lines (`32.79 MB`)** of `64 MHz` DWT cycle-accurate telemetry in `fidont_rtt.log` (`0` panics, `0` OOMs, `0` HardFaults).
> - **Shared `184 KiB` Stack Architecture**: Placing `FN-DSA`'s `72 KiB` `tmp_flr` (`[FLR; 9 * 1024]`) workspace on the **stack** inside `#[inline(never)] sign_with_alloc` (`_rheap = 0x2002e000`: `184 KiB` stack / `72 KiB` data+heap) allows both `ML-DSA-87` (`152.6 KiB` stack during `MakeCredential` attestation signing) and `FN-DSA-1024` (`83.8 KiB` stack during `GetAssertion` lattice signing) to execute with `> 30 KiB` headroom on both stack and heap.

### 0.0.1 Run 19 Three-Way Correlated `MakeCredential` Sweep (`Authr-MakeCred-Resp-1`, All 18 Algorithms)

| # | Algorithm | COSE `alg` | Attestation Format | `BCNT` (`IN` Frames) | Log Lines | TotalPhase CSV Lines (`CID`) | USB `MCU` Time (incl. RTT Debug) | USB `IN` Transfer | Total USB Time | RTT Pure Crypto Sign/Keygen (`64 MHz` DWT) |
| :-: | :--- | :---: | :---: | :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| 1 | `RS256` (RSA-2048) | `-257` | `"packed"` (`ES256` `x5c`) | `1,250 B` (`22f`) | `L7100–L7169` | `L3472–L3528` (`00000137`) | `1,659.21 ms` | `432.05 ms` | `2,191.33 ms` | `671.82 ms` (`ES256` att sig, `RTT L36718`) |
| 2 | **`FN-DSA-1024`** (Draft FIPS 206) | **`-61`** | **`"mtc-mds"` (`ML-DSA-87`)** | **`6,947 B` (`118f`)** | `L7238–L7508` | `L3556–L3808` (`0000013a`) | **`4,511.57 ms`** | **`2,492.31 ms`** | **`7,099.94 ms`** | **`583.20 ms` (`37.32M` cyc `ML-DSA-87` att sig, `RTT L37657`)** |
| 3 | **`FN-DSA-512`** (Draft FIPS 206) | **`-60`** | **`"mtc-mds"` (`ML-DSA-87`)** | **`6,051 B` (`103f`)** | `L7577–L7817` | `L3836–L4058` (`0000013d`) | **`4,331.54 ms`** | **`2,132.27 ms`** | **`6,559.87 ms`** | **`865.05 ms` (`55.36M` cyc `ML-DSA-87` att sig, `RTT L40585`)** |
| 4 | `MLDSA87-Ed448` | `-59` | `"mtc-mds"` (`ML-DSA-87`) | `7,568 B` (`129f`) | `L7886–L8185` | `L4086–L4362` (`00000140`) | `6,671.84 ms` | `2,724.34 ms` | `9,492.24 ms` | `2,479.35 ms` (`324.97 ms` keygen + `2,154.38 ms` sign, `RTT L43134..L43146`) |
| 5 | `MLDSA65-Ed25519` | `-58` | `"mtc-mds"` (`ML-DSA-87`) | `7,138 B` (`122f`) | `L8254–L8541` | `L4390–L4652` (`00000143`) | `7,215.91 ms` | `2,688.34 ms` | `10,000.31 ms` | `3,172.62 ms` (`167.02 ms` keygen + `3,005.60 ms` sign, `RTT L46339..L46343`) |
| 6 | `MLDSA44-Ed25519` | `-57` | `"mtc-mds"` (`ML-DSA-87`) | `6,498 B` (`111f`) | `L22436–L22695` | `L4848–L5086` (`00000148`) | `5,259.66 ms` | `2,400.30 ms` | `7,752.03 ms` | `1,505.47 ms` (`120.80 ms` keygen + `1,384.68 ms` sign, `RTT L50312..L50316`) |
| 7 | `MLDSA87-ES384` | `-56` | `"mtc-mds"` (`ML-DSA-87`) | `7,608 B` (`129f`) | `L22764–L23067` | `L5114–L5390` (`0000014b`) | `7,059.89 ms` | `2,788.35 ms` | `9,944.30 ms` | `2,792.99 ms` (`1,185.00 ms` keygen + `1,608.00 ms` sign, `RTT L53206..L53218`) |
| 8 | `MLDSA65-ES256` | `-55` | `"mtc-mds"` (`ML-DSA-87`) | `7,171 B` (`122f`) | `L23136–L23430` | `L5418–L5682` (`0000014e`) | `9,176.16 ms` | `2,624.33 ms` | `11,892.55 ms` | `5,118.96 ms` (`429.50 ms` keygen + `4,689.46 ms` sign, `RTT L56498..L56502`) |
| 9 | `MLDSA44-ES256` | `-54` | `"mtc-mds"` (`ML-DSA-87`) | `6,531 B` (`111f`) | `L23499–L23760` | `L5710–L5948` (`00000151`) | `6,071.77 ms` | `2,332.29 ms` | `8,496.12 ms` | `2,315.26 ms` (`383.34 ms` keygen + `1,931.92 ms` sign, `RTT L59598..L59602`) |
| 10 | `ML-DSA-87` (FIPS 204) | `-50` | `"mtc-mds"` (`ML-DSA-87`) | `7,556 B` (`129f`) | `L23829–L24124` | `L5976–L6250` (`00000154`) | `5,479.69 ms` | `2,700.34 ms` | `8,280.09 ms` | `1,301.27 ms` (`83.28M` cyc keygen + sign, `RTT L62383..L62384`) |
| 11 | `ML-DSA-65` (FIPS 204) | `-49` | `"mtc-mds"` (`ML-DSA-87`) | `7,106 B` (`121f`) | `L24193–L24474` | `L6278–L6536` (`00000157`) | `6,095.77 ms` | `2,512.32 ms` | `8,704.15 ms` | `2,096.49 ms` (`134.18M` cyc keygen + sign, `RTT L65589..L65590`) |
| 12 | `ML-DSA-44` (FIPS 204) | `-48` | `"mtc-mds"` (`ML-DSA-87`) | `6,466 B` (`110f`) | `L24543–L24800` | `L6564–L6800` (`0000015a`) | `5,455.69 ms` | `2,288.29 ms` | `7,836.04 ms` | `1,764.34 ms` (`112.92M` cyc keygen + sign, `RTT L68508..L68509`) |
| 13 | `Ed448` (RFC 8032) | `-53` | `"packed"` (`ES256` `x5c`) | `1,045 B` (`18f`) | `L24869–L24931` | `L6828–L6876` (`0000015d`) | `1,891.24 ms` | `376.05 ms` | `2,363.35 ms` | `993.73 ms` (`321.93 ms` Ed448 + `671.80 ms` `ES256` sig, `RTT L71202..L71219`) |
| 14 | `EdDSA` (Ed25519) | `-8` | `"packed"` (`ES256` `x5c`) | `1,019 B` (`18f`) | `L25000–L25061` | `L6904–L6952` (`00000160`) | `1,555.20 ms` | `336.04 ms` | `1,987.30 ms` | `723.90 ms` (`52.09 ms` Ed25519 + `671.81 ms` `ES256` sig, `RTT L72087..L72097`) |
| 15 | `ES256K` (secp256k1) | `-47` | `"packed"` (`ES256` `x5c`) | `1,057 B` (`18f`) | `L25130–L25190` | `L6980–L7028` (`00000163`) | `1,535.19 ms` | `364.05 ms` | `1,995.30 ms` | `751.40 ms` (`79.58 ms` k256 + `671.82 ms` `ES256` sig, `RTT L72930..L72947`) |
| 16 | `ES512` (P-521) | `-36` | `"packed"` (`ES256` `x5c`) | `1,123 B` (`20f`) | `L25259–L25326` | `L7056–L7110` (`00000166`) | `2,427.31 ms` | `380.05 ms` | `2,903.42 ms` | `1,555.02 ms` (`883.20 ms` P-521 + `671.82 ms` `ES256` sig, `RTT L73816..L73833`) |
| 17 | `ES384` (P-384) | `-35` | `"packed"` (`ES256` `x5c`) | `1,087 B` (`19f`) | `L25395–L25461` | `L7138–L7190` (`00000169`) | `2,723.34 ms` | `384.05 ms` | `3,203.45 ms` | `1,811.53 ms` (`1,139.71 ms` P-384 + `671.82 ms` `ES256` sig, `RTT L74703..L74720`) |
| 18 | `ES256` (P-256) | `-7` | `"packed"` (`ES256` `x5c`) | `1,055 B` (`18f`) | `L25530–L25592` | `L7218–L7266` (`0000016c`) | `2,139.27 ms` | `368.05 ms` | `2,603.38 ms` | `1,301.08 ms` (`629.26 ms` P-256 + `671.82 ms` `ES256` sig, `RTT L75601..L75634`) |

### 0.0.2 Run 19 Three-Way Correlated `GetAssertion` Sweep (`Authr-GetAssertion-Resp-1`, All 18 Algorithms)

| # | Algorithm | COSE `alg` | `BCNT` (Sig Size, `IN` Frames) | Log Lines | TotalPhase CSV Lines (`CID`) | USB `MCU` Time | USB `IN` Transfer | Total USB Time | RTT Pure CPU Sign (`64 MHz` DWT Cycles & Line) |
| :-: | :--- | :---: | :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| 1 | `ES256` (P-256) | `-7` | `379 B` (`70 B`, `7f`) | `L29703–L29745` | `L8466–L8496` (`000001b1`) | `1,431.18 ms` | `152.02 ms` | `1,687.26 ms` | **`683.31 ms`** (`43,731,904 cyc`, `RTT L89237`) |
| 2 | `ES384` (P-384) | `-35` | `412 B` (`103 B`, `8f`) | `L29949–L29999` | `L8604–L8638` (`000001b7`) | `3,139.40 ms` | `120.01 ms` | `3,407.48 ms` | **`2,422.29 ms`** (`155,026,560 cyc`, `RTT L90880`) |
| 3 | `ES512` (P-521) | `-36` | `448 B` (`139 B`, `8f`) | `L30204–L30252` | `L8746–L8780` (`000001bd`) | `2,787.35 ms` | `160.02 ms` | `3,099.44 ms` | **`2,089.04 ms`** (`133,698,688 cyc`, `RTT L92470`) |
| 4 | `ES256K` (secp256k1) | `-47` | `380 B` (`71 B`, `7f`) | `L30450–L30490` | `L8884–L8914` (`000001c3`) | `859.11 ms` | `112.01 ms` | `1,075.19 ms` | **`150.00 ms`** (`9,600,192 cyc`, `RTT L93989`) |
| 5 | `EdDSA` (Ed25519) | `-8` | `373 B` (`64 B`, `7f`) | `L30688–L30728` | `L9018–L9048` (`000001c9`) | `831.11 ms` | `156.02 ms` | `1,091.19 ms` | **`114.12 ms`** (`7,303,424 cyc`, `RTT L95550`) |
| 6 | `Ed448` (RFC 8032) | `-53` | `423 B` (`114 B`, `8f`) | `L30928–L30972` | `L9152–L9184` (`000001cf`) | `1,403.18 ms` | `160.02 ms` | `1,711.27 ms` | **`691.45 ms`** (`44,252,608 cyc`, `RTT L97083`) |
| 7 | `ML-DSA-44` (FIPS 204) | `-48` | `2,730 B` (`2,420 B`, `47f`) | `L31364–L31489` | `L9476–L9586` (`000001d5`) | `2,335.29 ms` | `976.12 ms` | `3,459.49 ms` | **`379.36 ms`** (`24,279,104 cyc`, `RTT L100529`) |
| 8 | `ML-DSA-65` (FIPS 204) | `-49` | `3,619 B` (`3,309 B`, `62f`) | `L31910–L32072` | `L9902–L10044` (`000001db`) | `4,387.55 ms` | `1,304.16 ms` | `5,795.78 ms` | **`1,987.07 ms`** (`127,172,480 cyc`, `RTT L105026`) |
| 9 | `ML-DSA-87` (FIPS 204) | `-50` | `4,747 B` (`4,627 B`, `81f`) | `L32509–L32699` | `L10376–L10548` (`000001e1`) | `3,683.46 ms` | `1,732.22 ms` | `5,459.74 ms` | **`839.92 ms`** (`53,755,072 cyc`, `RTT L109892`) |
| 10 | `MLDSA44-ES256` | `-54` | `2,801 B` (`2,491 B`, `48f`) | `L33095–L33224` | `L10842–L10956` (`000001e7`) | `2,999.38 ms` | `924.12 ms` | `4,067.56 ms` | **`1,046.65 ms`** (`66,985,536 cyc`, `RTT L115011`) |
| 11 | `MLDSA65-ES256` | `-55` | `3,690 B` (`3,379 B`, `63f`) | `L33651–L33813` | `L11274–L11418` (`000001ed`) | `3,771.47 ms` | `1,368.17 ms` | `5,239.71 ms` | **`1,408.51 ms`** (`90,144,896 cyc`, `RTT L119710`) |
| 12 | `MLDSA87-ES384` | `-56` | `4,803 B` (`4,722 B`, `82f`) | `L34251–L34452` | `L11750–L11928` (`000001f3`) | `6,343.80 ms` | `1,748.22 ms` | `8,136.08 ms` | **`3,521.04 ms`** (`225,346,560 cyc`, `RTT L124814`) |
| 13 | `MLDSA44-Ed25519` | `-57` | `2,794 B` (`2,484 B`, `48f`) | `L34847–L34974` | `L12222–L12334` (`000001f9`) | `2,327.29 ms` | `980.12 ms` | `3,411.48 ms` | **`363.16 ms`** (`23,242,368 cyc`, `RTT L129833`) |
| 14 | `MLDSA65-Ed25519` | `-58` | `3,683 B` (`3,373 B`, `63f`) | `L35392–L35552` | `L12650–L12794` (`000001ff`) | `3,399.43 ms` | `1,312.17 ms` | `4,855.66 ms` | **`1,025.27 ms`** (`65,617,408 cyc`, `RTT L134381`) |
| 15 | `MLDSA87-Ed448` | `-59` | `4,815 B` (`4,741 B`, `82f`) | `L35991–L36186` | `L13126–L13302` (`00000205`) | `4,663.59 ms` | `1,700.21 ms` | `6,407.86 ms` | **`1,812.87 ms`** (`116,023,616 cyc`, `RTT L139093`) |
| 16 | **`FN-DSA-512`** (Draft FIPS 206) | **`-60`** | **`976 B` (`666 B`, `17f`)** | `L36565–L36629` | `L13580–L13630` (`0000020b`) | **`2,031.26 ms`** | **`376.05 ms`** | **`2,555.37 ms`** | **`957.77 ms` (`61,297,536 cyc`, `RTT L143903`)** |
| 17 | **`FN-DSA-1024`** (Draft FIPS 206) | **`-61`** | **`1,590 B` (`1,280 B`, `27f`)** | `L37042–L37130` | `L13938–L14010` (`00000211`) | **`3,351.42 ms`** | **`548.07 ms`** | **`4,047.56 ms`** | **`2,049.19 ms` (`131,148,160 cyc`, `RTT L147661`)** |
| 18 | `RS256` (RSA-2048) | `-257` | `566 B` (`256 B`, `10f`) | `L37337–L37397` | `L14122–L14162` (`00000217`) | `5,127.65 ms` | `212.03 ms` | `5,491.74 ms` | **`4,296.89 ms`** (`275,001,088 cyc`, `RTT L149666`) |

> [!TIP]
> **FN-DSA Wire Size, USB Bus Transfer & Deterministic Signing Advantages over ML-DSA**:
> - **Deterministic Lattice Signing (`< 0.3%` Variance)**: Across Run 18 and Run 19, `FN-DSA-512` (`alg: -60`) pure CPU signing time was **`958.0 ms` (`61.31M` cycles)** in Run 18 and **`957.77 ms` (`61.30M` cycles)** in Run 19; `FN-DSA-1024` (`alg: -61`) was **`2,054.9 ms` (`131.51M` cycles)** in Run 18 and **`2,049.19 ms` (`131.15M` cycles)** in Run 19. By contrast, `ML-DSA`'s Fiat-Shamir with Aborts rejection sampling varies from `363 ms` to `1,987 ms` depending on rejection count.
> - **`2.6x`–`3.16x` Faster USB HID `IN` Transfer**: On `/tmp/totalphase.csv`, `FN-DSA-512` (`976 B`, `17` frames) transfers in **`376.05 ms`** vs **`976.12 ms`** for `ML-DSA-44` (`2,730 B`, `47` frames), completing end-to-end in **`2,555.37 ms`** vs `3,459.49 ms`. Similarly, `FN-DSA-1024` (`1,590 B`, `27` frames) transfers in **`548.07 ms`** vs **`1,732.22 ms`** for `ML-DSA-87` (`4,747 B`, `81` frames), completing end-to-end in **`4,047.56 ms`** vs `5,459.74 ms`!

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

### 0.3 Six-Way Comparison: Run 10 (`-48` `--mtc-x5c`) vs. Run 11 (`-50` MTC) vs. Run 16 (Dual + `ep`) vs. Run 17 (Dual + `ep` + `perCredMgmtRO`) vs. Run 18 (18 Algs + RTT) vs. Run 19 (18 Algs + USB + RTT)

| Metric | Run 10 (`-48` `--mtc-x5c`) | Run 11 (`-50` MTC) | Run 16 (Dual + `ep`) | Run 17 (16 Algs + `perCredMgmtRO`) | Run 18 (18 Algs + RTT) | Run 19 (18 Algs + USB + RTT) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Log Range & Duration** | `L287509–L347258` (`10m 14s`) | `L1–L56583` (`16m 35s`) | `L175680–L223190` (`15m 33s`) | `L1–L48653` (`12m 27s`) | `L1–L52180` (`20m 26s`) | **`L1–L66127` (`21m 28s`)** |
| **Test Results** | `237 Passed / 0 Failed` | `237 Passed / 0 Failed` | `241 Passed / 41 Skipped / 0 Failed` | `250 Passed / 32 Skipped / 0 Failed` | `249 Passed / 34 Skipped / 1 Failed` | **`250 Passed / 32 Skipped / 0 Failed (`100.00%`)`** |
| **Supported COSE Algorithms** | `16` algorithms | `16` algorithms | `16` algorithms | `16` algorithms | **`18` (`+FN-DSA-512/1024`)** | **`18` (`+FN-DSA-512/1024`)** |
| **`GetInfo` Wire Size (`BCNT`)** | `706 B` (`13` frames) | `706 B` (`13` frames) | `719 B` (`13` frames) | `793 B` (`14` frames) | `823 B` (`15` frames) | **`823 B` (`15` frames, 18 algs + `perCredMgmtRO`)** |
| **`perCredMgmtRO` / `0x19` / `0x1E` Tests** | Skipped (`0/9`) | Skipped (`0/9`) | Skipped (`0/9`) | `9/9 Passed` (`100%`) | `7/7 Passed` (`100%`) | **`9/9 Passed (`100%`)`** |
| **Enterprise Profile (`EntepriseAttestation.js`)** | Skipped | Skipped | `6/6 Passed` | `6/6 Passed` | `6/6 Passed` | **`6/6 Passed (`P-1`..`P-3`, `F-4`..`F-6`)`** |
| **`Metadata-Stmt-1` Verification** | `37/37` Passed | `37/37` Passed | `37/37` Passed | `37/37` Passed | `37/37` Passed | **`37/37` Passed (`100%`)** |

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

## 1. Detailed Analysis of `Authr-ClientPin2-PinPolicy` `F-2` Test Logic

### 1.1 Specification vs. Implementation in Fidont
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

### 1.2 How `ClientPin1` vs. `ClientPin2` Construct `F-2` and `F-3`
1. **`Authr-ClientPin1-PinPolicy.js` (`F-2` & `F-3`)** — `Authr-ClientPin1-PinPolicy.js:112-166`:
   Both `F-2` and `F-3` generate a **64-byte** non-zero PIN inside a **64-byte** `encryptionBuffer` (`generateRandomClientPinBuffer(64)`). Because `decrypted_pin.len() == 64` with no `0x00` terminator, Fidont always returns `CTAP2_ERR_PIN_POLICY_VIOLATION (0x37)`.
2. **`Authr-ClientPin2-PinPolicy.js` (`F-2` vs `F-3`)** — `Authr-ClientPin2-PinPolicy.js:109-159`:
   - **`F-3`** (`"Try setting new pin, that is exactly 64 bytes, and check that Authenticator returns error CTAP2_ERR_PIN_POLICY_VIOLATION(0x37)"`) encrypts a **64-byte** `encryptionBuffer` (`16B IV + 64B CT = 80 bytes`) and asserts `CTAP2_ERR_PIN_POLICY_VIOLATION (0x37)`.
   - **`F-2`** (`"Try setting new pin, that is bigger than 63 bytes, and check that Authenticator returns an error"`) generates a random-length buffer `generateRandomClientPinBuffer(generateSecureRandomInt(64, 128))` and passes it to `encryptAES256CBC` (`cryptodep.js:394-405`), which calls `cipher.update(messageBuffer)` without `cipher.final()`, truncating the plaintext to $\lfloor L / 16 \rfloor \times 16$ bytes:
     - When $L \in [64, 79]$ ($24.6\%$ chance), `newPinEnc` has `64` ciphertext bytes (`80B` total with IV) $\rightarrow$ `CTAP2_ERR_PIN_POLICY_VIOLATION (0x37)`.
     - When $L \in [80, 128]$ ($75.4\%$ chance), `newPinEnc` has `80, 96, 112, or 128` ciphertext bytes (`96..144B` total with IV) $\rightarrow$ `CTAP1_ERR_INVALID_PARAMETER (0x02)` because `decrypted_pin.len() != 64`.
   - Updating `Authr-ClientPin2-PinPolicy.js:130` to `assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)` matches the `F-2` specification (`"check that Authenticator returns an error"`) and the `CTAP 2.1 module`.
