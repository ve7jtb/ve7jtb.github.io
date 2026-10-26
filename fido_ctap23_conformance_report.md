# FIDO CTAP 2.3 Conformance Test Report — 18 Algorithms (Including Draft NIST FIPS 206 `FN-DSA-512` & `FN-DSA-1024`), RFC 8554 / NIST SP 800-208 HSS/LMS Certificate Hierarchy, All 8 Extensions (incl. `"mtc-debug"`), `persistentPinUvAuthToken` (`perCredMgmtRO`), Enterprise Attestation & Consolidated Post-Quantum `fmt: "mtc"`

> [!NOTE]
> **Specification Update (W3C WebAuthn Level 4 Pull Request & Authenticate 2026 CTAP2 TWG Consensus):**
> Following the W3C WebAuthn Level 4 Pull Request ([`webauthn_level4_pull_request.html`](./webauthn_level4_pull_request.html) / [`webauthn_level4_mtc_proposal.html`](./webauthn_level4_mtc_proposal.html)), the Merkle Tree Certificate attestation format has been consolidated into a single compact format identifier with an opt-in diagnostic extension:
> - **`fmt: "mtc"`** (consolidating `mtc-mds` into `mtc`): The single, compact Merkle Tree Certificate attestation statement format where `attStmt` carries only `{ alg, sig, mtcCert }` (strictly omitting inline `pubKey`, saving **`1,331 bytes`** on the wire for `ML-DSA-44` batch keys) and the verifier resolves the batch key via `mtcTrustAnchor.batchKeys` in FIDO MDS3 or an Enterprise Attestation Manifest.
> - **`"mtc-debug"` Registration Extension**: An opt-in CTAP 2.3 / WebAuthn Level 4 registration extension (`authenticatorGetInfo.extensions` includes `"mtc-debug"`) that returns `{ pubKey, deviceSerial? }` inside `authenticatorData.extensions["mtc-debug"]` for standalone conformance and diagnostic verification without pre-loaded `batchKeys`, enforcing a strict privacy gate where `deviceSerial` is emitted only when `epAtt: true`.

- **Log Files Analyzed**:
  1. **FIDO Conformance Debug Log**: `fido_conformance_debug.log` (`319,004` cumulative lines across Runs 10–24, including **`37,223` lines (`4.8 MB`) in Run 24 (`L1–L37223`, post-clear)** verifying **`250 / 250` `100.00%` PASS (`0 Failed`)** across the complete CTAP 2.3 suite with 2-field proof-less `mtcKeyRef` (`{ caId, serial }`), `batchKeys[].notBefore`/`notAfter` (`1792281600`..`253402300799`), and the expanded 7-field `"mtc-debug"` registration extension; `1,067` lines in Run 23; `34,421` lines in Run 22; `35,146` lines in Run 21; `56,117` lines in Run 20; `66,127` lines in Run 19; `52,180` lines in Run 18; `48,653` lines in Run 17; plus `282,939` lines across Runs 10–16)
  2. **Total Phase Beagle USB Protocol Analyzer Capture**: `totalphase.csv` (**`26,403` CSV lines, `122,002` USB bus records, `2.70 MB` in Run 24**, captured `Mon Oct 26 07:43:50` – `08:05:36 2026`, `0` hardware USB bus errors across `1,092` paired `CTAPHID_CBOR` exchanges, `4,956` `OUT txn` (`309.8 KB`) / `8,037` `IN txn` (`502.3 KB`); plus `28,653` CSV lines / `127,232` USB records in Run 19 and `26,436` CSV rows / `68,774` USB records in Run 17)
  3. **Fidont / OpenSK J-Link RTT Log**: `opensk_rtt.log` & `fidont_rtt.log` (`2,059,249` cumulative lines / `218.8 MB`, including **`287,281` lines (`30.9 MB`) in Run 24 (`opensk_rtt.log`)**, `11,228` lines in Run 23, `292,093` lines (`31.2 MB`) in Run 22, `304,967` lines (`31.0 MB`) in Run 21, `303,134` lines in Run 20, `304,330` lines in Run 19, and `302,212` lines in Run 18 with `--features=debug` `64 MHz` DWT cycle-accurate timestamps across all 18 algorithms, `0` panics / `0` HardFaults / `0` OOMs / `0` `[WARN]` or `[ERROR]` events)
- **Target Authenticator**: Fidont CTAP 2.3 (`U2F_V2`, `FIDO_2_0`, `FIDO_2_1`, `FIDO_2_3`) over USB HID (`VID: 0x1915`, `PID: 0x521f` / `0x18d1:0x0239`)
- **Related Design & Firmware Implementation**: **Compile and Install Fidont**, [webauthn_level4_pull_request.html](./webauthn_level4_pull_request.html), [webauthn_level4_mtc_proposal.html](./webauthn_level4_mtc_proposal.html) & [pq_mtc_attestation_proposal.md](./pq_mtc_attestation_proposal.md)

## Fidont authenticator simulator platform performance numbers are for relative comparison as implemented with amateur optimization by me:)

> [!IMPORTANT]
> **Attribution & Scope of Fidont:**
> **Fidont** is an authenticator simulator designed for prototyping new specifications and testing authenticator conformance tools. It is based on the [Google OpenSK](https://github.com/google/OpenSK) Rust codebase. However, **Fidont is not suitable for production security use outside of certification, conformance testing, and prototyping new features.**

## Overview of Test Runs 10–24 (`Runs 10–23` Historical + `Run 24` Latest Full-Suite Simultaneous 3-Log Capture with 2-Field `mtcKeyRef`, `batchKeys` `notBefore`/`notAfter` & Expanded `"mtc-debug"`)

| Run | Line Range | Time Window | Attestation & Feature Config | Passed | Failed | Outcome & Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Run 10** | `L287509–L347258` (pre-clear 1) | `02:55:51` – `03:06:05` (`10m 14s`) | **`ML-DSA-44` (`-48`) `--mtc-x5c`** (**Tier 1 `"packed"` `x5c` + Tier 2 `"mtcl"`**, strict MDS verification) | **`237`** | **`0`** | **`100.00%` PASS (`237 Passed / 45 Skipped / 0 Failed`)** — Complete CTAP 2.3 Suite + `Metadata-Stmt-1`; **`74` `"packed"` (`4,127 B` `x5c`) + `18` `"mtcl"` (`1,322 B` inline `pubKey`)** |
| **Run 11** | `L1–L56583` (pre-clear 2) | `09:11:23` – `09:27:58` (`16m 35s`) | **`ML-DSA-87` (`-50`) MTC Batch Key** (**100% Tier 3 `"mtc"`**, compact `0x02`/`0x03` cred IDs, strict MDS verification) | **`237`** | **`0`** | **`100.00%` PASS (`237 Passed / 45 Skipped / 0 Failed`)** — Complete CTAP 2.3 Suite + `Metadata-Stmt-1`; **`94` `"mtc"` (`100%` MDS `batchKeys` lookup, `caId = 0x83993f0103`)** |
| **Run 12** | `L58596–L69096` (pre-clear 2) | `23:12:37` – `23:13:55` (`1m 18s`) | Dual Batch + `--enterprise` (before reloading updated MDS) | `56` | `2` | Aborted after `Authr-Generic-1` `P-1` (`options` count `12` vs `11` because `ep: false` added) and `MakeCred-Resp-1` before reloading updated metadata |
| **Run 13** | `L73661–L124119` (pre-clear 2) | `23:36:31` – `00:05:42` (`29m 11s`) | Dual Batch + `--enterprise` (with Root CA `subtrees[].signature` check, before reloading MDS) | `236` | `5` | **`Authr-MakeCred-Resp-1` (`P-01`..`P-04`) PASSED with Root CA `subtrees[].signature` check!** 5 failures due to stale MDS + unpatched `EntepriseAttestation.js` (`P-2`, `P-3`, `F-6`) |
| **Run 14** | `L124193–L126258` (pre-clear 2) | `00:23:04` – `00:23:25` (`21s`) | Dual Batch + `--enterprise` (aborted early while loading updated MDS) | `21` | `2` | User-terminated (`FORCED TERMINATION`) right before loading updated metadata with `ep: false` and `authenticatorConfigCommands: [1, 2, 3]` |
| **Run 15** | `L126339–L175678` (pre-clear 2) | `00:25:36` – `00:36:53` (`11m 17s`) | Dual Batch (`ES384` `x5c` + `ML-DSA-44` MTC) + `--enterprise` + Root CA `subtrees[].signature` Verification | `238` | `3` | **`98.76%` PASS (`238 Passed / 3 Failed`)** — `Authr-Generic-1`, `Authr-MakeCred-Resp-1` (`P-04`), `Authr-Config-1`, and `Metadata-Stmt-1` (`37/37`) passed 100%; `EntepriseAttestation.js` (`P-2`, `P-3`, `F-6`) needed MTC + serial extension support |
| **Run 16** | `L175680–L223190` (pre-clear 2) | `01:09:20` – `01:24:53` (`15m 33s`) | Dual Batch (`ES384` `x5c` + `ML-DSA-44` MTC) + `--enterprise` + Serial Number Extension (`mtcProof.extensions`) + Root CA `subtrees[].signature` Verification | **`241`** | **`0`** | **`100.00%` PASS (`241 Passed / 41 Skipped / 0 Failed`)** — Full CTAP 2.3 Suite + Security Enterprise Profile (`EntepriseAttestation.js` `6/6` PASS) + `Metadata-Stmt-1` (`37/37` PASS) |
| **Run 17** | `L1–L48653` (pre-clear 3) & `totalphase.csv` | `00:48:37` – `01:01:04` (`12m 27s`) | **Full CTAP 2.3 `persistentPinUvAuthToken` (`perCredMgmtRO`, `pcmr = 0x40`, `encIdentifier = 0x19`, `encCredStoreState = 0x1E`) + Dual Batch (`ES384` `x5c` + `ML-DSA-44` MTC) + Enterprise Attestation (`--enterprise`, `serial="123456"`) + Root CA `subtrees[].signature` Verification** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 32 Skipped / 0 Failed`)** — **All `9` previously skipped `perCredMgmtRO` / `encIdentifier` / `encCredStoreState` / `pcmr (0x40)` tests executed and passed (`241` $\to$ `250` passed)! `0` USB bus errors across `68,774` records (`1,073` `CTAPHID_CBOR` exchanges, `304.4 KB` OUT / `509.9 KB` IN) in `totalphase.csv`!** |
| **Run 18** | `L1–L52180` (pre-clear 4) & `fidont_rtt.log` (`302,212` lines) | `10:16:15` – `10:36:41` (`20m 26s`) | **All 18 Algorithms including Draft NIST FIPS 206 `FN-DSA-512` (`alg: -60`) & `FN-DSA-1024` (`alg: -61`) + `ML-DSA-87` (`-50`) MTC Batch + `ES256` Classical Batch + Enterprise Dual (`ML-DSA-44` leaf / `ML-DSA-87` Root CA) + `fidont_rtt.log` DWT Cycle-Accurate Telemetry** | **`249`** | **`1`** | **`99.60%` PASS (`249 Passed / 34 Skipped / 1 Failed`)** — **`100%` PASS across all 18 algorithms in `Authr-MakeCred-Resp-1`, `Authr-GetAssertion-Resp-1`, `EntepriseAttestation`, `Authr-CredMgmt-1`, and `Metadata-Stmt-1` (`0` panics, `0` OOMs, `0` HardFaults in `302,212` `fidont_rtt.log` lines)!** |
| **Run 19** | `L1–L66127`, `totalphase.csv` (`28,653` lines) & `fidont_rtt.log` (`304,330` lines) | `11:49:33` – `12:11:02` (`21m 28s`) | **All 18 Algorithms (`FN-DSA-512` `-60` & `FN-DSA-1024` `-61` + 16 Classical/PQ/Composite) + `perCredMgmtRO` (`0x19`, `0x1E`, `0x40`) + Dual Batch (`ML-DSA-87` MTC + `ES256` `x5c`) + Enterprise Dual (`ML-DSA-44` leaf / `ML-DSA-87` Root CA) + Simultaneous 3-Log Capture (`fido_conformance_debug.log`, `totalphase.csv` & `fidont_rtt.log`)** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 32 Skipped / 0 Failed`)** — **`250 / 250` (`100%`) pass across all 18 algorithms (`78` `"packed"`, `22` `"mtc"`, `2` `"mtcl"`), `0` USB bus errors across `127,232` USB records (`4,945` `OUT txn` / `8,827` `IN txn`, `1,092` `CTAPHID_CBOR` exchanges), and `0` panics/OOMs across `304,330` `fidont_rtt.log` lines!** |
| **Run 20** | `L155031–L211147` (`56,117` lines) & `fidont_rtt.log` (`L860546–L1163679`, `303,134` lines) | `23:13:01` – `23:58:36` (`45m 35s` wall / `~19m 24s` active) | **RFC 8554 / NIST SP 800-208 HSS/LMS Certificate Hierarchy (`1` `Fidont LMS Root CA` + `4` Pre-Published `Fidont LMS Intermediate CA #0..#3`, OID `1.2.840.113549.1.9.16.3.17` $\to$ `ML-DSA-44` Leaf `x5c`) + HSS/LMS (`alg: -46`) Signed MTC Subtree Checkpoints (`caId: "g5k_AQE"`, `caId: "g5k_AQI"`) + All 18 Algorithms (`FN-DSA-512/1024`, `ML-DSA-44/65/87`, 6 PQ/T Composites, 7 Classical) + `perCredMgmtRO` + Enterprise Attestation + UX Metadata Statement Dialog Persistence** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 32 Skipped / 0 Failed` across all 37 CTAP 2.3 suites)** — **Verified HSS/LMS X.509 (`L=1`, `LMS_SHA256_M32_H5` / `LMOTS_SHA256_N32_W8`) + `ML-DSA-44` `"packed"` `x5c` chains (`6,693–7,173 B`), HSS/LMS `alg: -46` MTC subtree checkpoints (`1,252 B` sig) across `"mtc"` & `"mtcl"`, Enterprise Attestation (`6/6`), `Metadata-Stmt-1` (`25/25`), and `0` panics/OOMs across `303,134` `fidont_rtt.log` lines!** |
| **Run 21** | `L1–L35146` (`35,146` lines, post-clear) & `opensk_rtt.log` (`L1–L304967`, `304,967` lines) | `09:46:00` – `10:11:28` (`25m 27.56s`) | **`scripts/generate_lms_pki.py` Provisioned RFC 8554 $\cap$ NIST SP 800-208 (`LMS_SHA256_M32_H5` + `LMOTS_SHA256_N32_W8`) Root CA + 4 Pre-Published LMS Intermediate CAs (`g5k_AQE`..`g5k_AQQ`) + LMS-Signed `ML-DSA-44/65/87` Batch & Enterprise X.509 Certs (`1,296 B` sig) + Compact `fmt: "mtc"` (`alg: -46` `HSS-LMS`) Checkpoints + Single-Instance `probe-rs` RTT Capture (`opensk_rtt.log`)** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 33 Skipped / 0 Failed / 1 Retried` across all active CTAP 2.3 suites)** — **Verified automated LMS PKI provisioning (`crypto_data.rs` + `fido-mds3.json`), compact `fmt: "mtc"` (`6,067–6,728 B`) & LMS-signed `"packed"` `x5c` (`6,692–7,172 B`) across all 18 algorithms, Enterprise Attestation (`6/6`), `Metadata-Stmt-1` (`25/25`), and `0` panics / `0` `[WARN]`/`[ERROR]` lines across `304,967` `opensk_rtt.log` lines!** |
| **Run 22** | `L1–L34421` (`34,421` lines, post-clear) & `opensk_rtt.log` (`L1–L292093`, `292,093` lines) | `11:51:49` – `12:11:56` (`20m 06.79s`) | **W3C WebAuthn Level 4 PR Consolidated `fmt: "mtc"` (Omitting Inline `pubKey`, Saving `1,331 B` per Response: `4,736–5,397 B`) + `"mtc-debug"` Registration Extension + All 18 Algorithms + RFC 8554 $\cap$ NIST SP 800-208 LMS Hierarchy + Single-Instance `probe-rs` RTT Capture (`opensk_rtt.log`)** | **`247`** | **`4`*** | **`98.41%` PASS (`247 Passed / 32 Skipped / 4 Failed` across `283` unique tests)** — **`100%` PASS on consolidated `fmt: "mtc"` (`Authr-MakeCred-Resp-1` `P-01`..`P-04`, `F-01` in `0.165s`) & `Metadata-Stmt-1` (`25/25`), `0` panics / `0` `[WARN]`/`[ERROR]` lines across `292,093` `opensk_rtt.log` lines; `*4` test-harness `getGetInfoCached()` JS `TypeError`s in newly added `mtc-debug` tests fixed & repackaged in `app.asar`!** |
| **Run 23** | `L1–L1067` (`1,067` lines, post-clear) & `opensk_rtt.log` (`L1–L11228`, `11,228` lines) | `22:45:07.81` – `22:45:46.69` (`38.88s`) | **Repackaged Self-Contained `app.asar` (`getGetInfoCached()` Fix) + `CTAP2/Protocol/Options/EntepriseAttestation.js` (`P-1`..`P-3`, `F-1`..`F-6`) + LMS-Signed `ML-DSA-44` Enterprise `x5c` (`3,069 B`) + `"mtc-debug"` Privacy-Gate Verification (`deviceSerial` Emitted on `epAtt: true`, Omitted on Unauthorized RP Downgrade)** | **`6`** | **`0`** | **`100.00%` PASS (`6 Passed / 3 Skipped / 0 Failed`)** — **All 6 Enterprise Profile tests (`P-1`, `P-2`, `P-3`, `F-4`, `F-5`, `F-6`) passed `100%` across `136` CTAPHID messages (`68` exchanges), verifying both `getGetInfoCached()` harness fixes and the `"mtc-debug"` `deviceSerial` privacy gate (`0` panics / `0` errors in `11,228` `opensk_rtt.log` lines)!** |
| **Run 24 (Latest)** | `L1–L37223` (`37,223` lines), `/tmp/totalphase.csv` (`26,403` lines) & `opensk_rtt.log` (`287,281` lines) | `07:43:50` – `08:05:36` (`21m 41s` USB capture) | **Upstream-Rebased OpenSK (`google/OpenSK` PR #759) + W3C WebAuthn Level 4 PR 2-Field Proof-Less `mtcKeyRef` (`{ caId, serial }`, Saving `1,478 B` vs Pre-PR `"mtc"` & `147 B` vs `mtcEntryDesc`: `3,685–5,242 B`) + `batchKeys` `notBefore`/`notAfter` (`1792281600`..`253402300799`) + Expanded 7-Field `"mtc-debug"` Extension (`notBefore`, `notAfter`, `firmwareVersion`, `mtcProof`, `rootHash`, `pubKey`, `deviceSerial?`) + Simultaneous 3-Log Capture** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 33 Skipped / 0 Failed` across all 37 CTAP 2.3 suites)** — **Complete CTAP 2.3 suite finished with `0` failures (`"Testing finished. You may submit the results now."`), `22` proof-less `mtcKeyRef` (`{ caId, serial }`) responses (`3,685–5,242 B`), `79` `"packed"` responses, `4` `"mtc-debug"` verification exchanges (`1,374 B` & `7,492 B`), `0` hardware USB bus errors across `122,002` USB records (`1,092` `CTAPHID_CBOR` exchanges), and `0` panics/OOMs across `287,281` `opensk_rtt.log` lines!** |

---

## 0.000000 Run 24 (`07:43:50` – `08:05:36` PDT, `2026-10-26`) Full-Suite Simultaneous 3-Log Capture: Upstream-Rebased OpenSK, 2-Field Proof-Less `mtcKeyRef` (`{ caId, serial }`), `batchKeys` `notBefore`/`notAfter` & Expanded `"mtc-debug"` Extension

> [!IMPORTANT]
> **100.00% Pass (`250 Passed / 33 Skipped / 0 Failed`) Across All 37 CTAP 2.3 Suites with Proof-Less `mtcKeyRef` (`{ caId, serial }`) & Simultaneous 3-Log Telemetry**:
> In Run 24 (`2026-10-26`, `07:43:50` – `08:05:36 PDT`, `21m 41.36s` USB capture), after merging upstream `google/OpenSK` (`PR #759`), aligning the sample FIDO MDS3 metadata (`metadata_mldsa44_mtc.json`, `metadata_mldsa65_mtc.json`, `metadata_mldsa87_mtc.json`, `metadata_mldsa_all_mtc.json`, `mtc_batch_trust_anchor.json`, and `mtc_enterprise_info.json`) with `notBefore: 1792281600` (`2026-10-18T00:00:00Z`) and `notAfter: 253402300799` (`9999-12-31T23:59:59Z`) inside `mtcTrustAnchors[].batchKeys[]`, and adding 8-byte CBOR `uint64` (`additionalInfo = 27`) support to `vanillacbor.js`, we executed the complete CTAP 2.3 conformance suite while simultaneously capturing all three diagnostic layers:
> 1. **2-Field Proof-Less `mtcKeyRef` (`{ caId, serial }`) on the Wire (`22 / 22` `fmt: "mtc"` `MakeCredential` Responses)**:
>    - Every `fmt: "mtc"` `MakeCredential` response across all 11 post-quantum and PQ/T composite algorithms (`ML-DSA-44/65/87`, `MLDSA44-ES256`, `MLDSA65-ES256`, `MLDSA87-ES384`, `MLDSA44-Ed25519`, `MLDSA65-Ed25519`, `MLDSA87-Ed448`, `FN-DSA-512`, `FN-DSA-1024`) carried only the **19-byte 2-field `mtcKeyRef` map** (`{"caId": h'83993f0101', "serial": 0x0007000000000000}`), omitting both the `1,322 B` inline `pubKey` and the `147 B` inclusion proof + validity timestamps (`notBefore`, `notAfter`, `mtcProof`).
>    - Compared to Run 22 (`mtcEntryDesc`), this saves an additional **`147 bytes` (`2–3` USB HID frames)** per `MakeCredential` response, and **`1,478 bytes` (`25` USB HID frames)** total compared to pre-PR `"mtc"` (`4,100 B` vs `5,578 B` for `ML-DSA-44`!).
> 2. **Expanded 6-Field / 7-Field `"mtc-debug"` Registration Extension (`4 / 4` `100%` PASS)**:
>    - In `Authr-MakeCred-Resp-1` (`P-05`, `CID=000002e5`, `1,374 B` / `24` frames) and `EntepriseAttestation.js` (`F-6` unauthorized RP downgrade, `CID=000003eb`, `1,374 B` / `24` frames), `authenticatorData.extensions["mtc-debug"]` emitted the 6-field self-contained diagnostic map `{ pubKey (77 B), notBefore: 1792281600, notAfter: 253402300799, firmwareVersion: 256, mtcProof (115 B), rootHash (32 B) }` with `deviceSerial` strictly omitted.
>    - In `EntepriseAttestation.js` (`P-2` with `epAtt=1` on `CID=000003d7` and `P-3` with `epAtt=2` on `CID=000003da`, **`7,492 B` / `128` frames** — `117 B` under the `7,609 B` CTAPHID limit), `authenticatorData.extensions["mtc-debug"]` emitted all 7 fields including `pubKey` (`1,322 B` `ML-DSA-44`), `mtcProof` (`121 B` with `"123456"` extension), and `deviceSerial: "123456"`.
> 3. **Zero Hardware USB Bus Errors & Zero Firmware Panics**:
>    - `/tmp/totalphase.csv` recorded **`122,002` USB bus records** (`4,956` `OUT txn` = `309.8 KB`, `8,037` `IN txn` = `502.3 KB`, `1,092` paired `CTAPHID_CBOR` exchanges, `1,102` `CTAPHID_INIT` handshakes, `358` `CTAPHID_KEEPALIVE` heartbeats) with **`0` hardware packet/CRC errors**.
>    - `opensk_rtt.log` recorded **`287,281` lines (`30.9 MB`)** across **`1,040` CTAP2 command dispatches** (`101` `MakeCredential Ok`, `68` `GetAssertion Ok`, `695` `ClientPIN Ok`, `61` `GetInfo Ok`, `27` `Reset Ok`, `14` `CredentialManagement Ok`, `12` `AuthenticatorConfig Ok`, `5` `LargeBlobs Ok`, `3` `GetNextAssertion Ok`) with **`0` panics, `0` HardFaults, `0` OOMs, and `0` `[WARN]`/`[ERROR]` events**.

### 0.000000.1 Run 24 Wire Size & 64 MHz Cortex-M4 DWT Timing Across All 18 Algorithms (`Authr-MakeCred-Resp-1` & `Authr-GetAssertion-Resp-1`)

| # | Algorithm | COSE `alg` | `MakeCred` `fmt` | `attStmt` Structure | Run 24 `MakeCred` Wire Size (`mtcKeyRef`) | Run 22 `MakeCred` Size (`mtcEntryDesc`) | Pre-PR `"mtc"` Size (Inline `pubKey`) | Run 24 `MakeCred` MCU Time (`64 MHz` DWT) | Run 24 `GetAssertion` MCU Time (`64 MHz` DWT) |
| :-: | :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| 1 | **`ES256`** | `-7` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [576 B]` | **`1,054 B`** (`18f`) | `1,054 B` (`18f`) | `1,054 B` | `1,617.90 ms` (`103,545,664 cyc`) | `1,044.24 ms` (`66,831,616 cyc`) |
| 2 | **`ES384`** | `-35` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [576 B]` | **`1,089 B`** (`19f`) | `1,088 B` (`19f`) | `1,088 B` | `2,172.66 ms` (`139,050,496 cyc`) | `2,812.70 ms` (`180,012,544 cyc`) |
| 3 | **`ES512`** | `-36` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [576 B]` | **`1,124 B`** (`20f`) | `1,124 B` (`20f`) | `1,124 B` | `2,138.18 ms` (`136,843,648 cyc`) | `3,141.58 ms` (`201,061,056 cyc`) |
| 4 | **`ES256K`** | `-47` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [576 B]` | **`1,055 B`** (`18f`) | `1,055 B` (`18f`) | `1,055 B` | `1,055.17 ms` (`67,530,752 cyc`) | `499.59 ms` (`31,973,824 cyc`) |
| 5 | **`EdDSA` (`Ed25519`)** | `-8` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [576 B]` | **`1,020 B`** (`18f`) | `1,020 B` (`18f`) | `1,020 B` | `1,058.27 ms` (`67,729,216 cyc`) | `477.39 ms` (`30,552,704 cyc`) |
| 6 | **`Ed448`** | `-53` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [576 B]` | **`1,047 B`** (`18f`) | `1,047 B` (`18f`) | `1,047 B` | `1,355.20 ms` (`86,732,608 cyc`) | `1,055.69 ms` (`67,563,904 cyc`) |
| 7 | **`ML-DSA-44`** | `-48` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,100 B`** (`70f`) | `4,247 B` (`73f`) | `5,578 B` (**`-1,478 B`**) | **`679.39 ms`** (`43,481,152 cyc`) | **`619.01 ms`** (`39,616,448 cyc`) |
| 8 | **`ML-DSA-65`** | `-49` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,740 B`** (`81f`) | `4,887 B` (`83f`) | `6,218 B` (**`-1,478 B`**) | **`922.29 ms`** (`59,026,496 cyc`) | `1,446.47 ms` (`92,574,144 cyc`) |
| 9 | **`ML-DSA-87`** | `-50` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`5,190 B`** (`88f`) | `5,337 B` (`91f`) | `6,668 B` (**`-1,478 B`**) | `1,455.51 ms` (`93,152,768 cyc`) | `4,399.31 ms` (`281,556,160 cyc`) |
| 10 | **`MLDSA44-ES256`** | `-54` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,165 B`** (`71f`) | `4,312 B` (`74f`) | `5,643 B` (**`-1,478 B`**) | `1,060.58 ms` (`67,877,312 cyc`) | `1,297.08 ms` (`83,013,056 cyc`) |
| 11 | **`MLDSA65-ES256`** | `-55` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,805 B`** (`82f`) | `4,952 B` (`84f`) | `6,283 B` (**`-1,478 B`**) | `1,340.06 ms` (`85,764,096 cyc`) | `4,912.35 ms` (`314,390,656 cyc`) |
| 12 | **`MLDSA87-ES384`** | `-56` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`5,242 B`** (`89f`) | `5,389 B` (`92f`) | `6,720 B` (**`-1,478 B`**) | `1,939.67 ms` (`124,139,008 cyc`) | `3,619.71 ms` (`231,661,696 cyc`) |
| 13 | **`MLDSA44-Ed25519`** | `-57` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,132 B`** (`71f`) | `4,279 B` (`73f`) | `5,610 B` (**`-1,478 B`**) | `1,147.46 ms` (`73,437,312 cyc`) | `1,200.72 ms` (`76,846,208 cyc`) |
| 14 | **`MLDSA65-Ed25519`** | `-58` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,772 B`** (`81f`) | `4,919 B` (`84f`) | `6,250 B` (**`-1,478 B`**) | **`747.08 ms`** (`47,813,184 cyc`) | `1,391.23 ms` (`89,038,912 cyc`) |
| 15 | **`MLDSA87-Ed448`** | `-59` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`5,202 B`** (`89f`) | `5,349 B` (`91f`) | `6,680 B` (**`-1,478 B`**) | `1,324.35 ms` (`84,758,528 cyc`) | `2,133.23 ms` (`136,526,848 cyc`) |
| 16 | **`FN-DSA-512`** | `-60` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`3,685 B`** (`63f`) | `3,832 B` (`65f`) | `5,163 B` (**`-1,478 B`**) | **`731.58 ms`** (`46,821,248 cyc`) | `1,323.49 ms` (`84,703,168 cyc`) |
| 17 | **`FN-DSA-1024`** | `-61` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,581 B`** (`78f`) | `4,728 B` (`81f`) | `6,059 B` (**`-1,478 B`**) | **`581.21 ms`** (`37,197,440 cyc`) | `2,414.76 ms` (`154,544,448 cyc`) |
| 18 | **`RS256`** | `-257` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [576 B]` | **`1,250 B`** (`22f`) | `1,249 B` (`22f`) | `1,249 B` | `987.51 ms` (`63,200,512 cyc`) | `4,564.78 ms` (`292,145,728 cyc`) |

### 0.000000.2 Total Phase Beagle USB Protocol Analyzer Summary (`/tmp/totalphase.csv`, Run 24)

| Metric | Value in Run 24 (`/tmp/totalphase.csv`) | Notes |
| :--- | :--- | :--- |
| **Capture Timestamp Window** | `Mon Oct 26 07:43:50` – `08:05:36 2026` (`21m 41.36s`) | Complete start-to-finish CTAP 2.3 conformance run |
| **Total CSV Lines / USB Records** | `26,403` CSV lines / **`122,002` USB bus records** | Aggregate SOF + IN-NAK + `OUT txn` + `IN txn` records |
| **USB `OUT txn` (`64 B` reports)** | **`4,956` transactions (`317,184 B` = `309.8 KB`)** | Host-to-device (`Ep 02 OUT`) CTAPHID frames |
| **USB `IN txn` (`64 B` reports)** | **`8,037` transactions (`514,368 B` = `502.3 KB`)** | Device-to-host (`Ep 02 IN`) CTAPHID frames |
| **CTAPHID Channel Handshakes (`0x86`)** | `1,103` `OUT` / `1,102` `IN` | Fresh channel per test exchange |
| **Paired `CTAPHID_CBOR` (`0x90`) Exchanges** | **`1,092` completed pairs** (`1,094` `OUT` / `1,092` `IN`) | `154` `MakeCred`, `92` `GetAssertion`, `721` `ClientPIN`, `60` `GetInfo`, `27` `Reset`, `16` `CredMgmt`, `13` `Config`, `6` `LargeBlobs`, `3` `GetNextAssertion` |
| **`CTAPHID_KEEPALIVE` (`0xbb`) Frames** | `362` `IN` frames (`status=1` processing / `status=2` UP needed) | Emitted during multi-second PQ/RSA/ECDSA operations |
| **Intentional Protocol `CTAPHID_ERROR` (`0xbf`)** | `4` `IN` frames | Expected negative transport test responses in `HID-1` (`INVALID_CMD`, `INVALID_PAR`, `INVALID_LEN`, `INVALID_SEQ`) |
| **Hardware USB Bus / CRC Errors** | **`0`** | `100.00%` error-free physical USB bus transmission |

---

## 0.00000 Run 23 (`22:45:07.81` – `22:45:46.69` PDT) Message-Level Deep Dive: `EntepriseAttestation.js` (`6 / 6` `100.00%` PASS), LMS-Signed `ML-DSA-44` Enterprise `x5c` (`3,069 B`) & `"mtc-debug"` Privacy Gate

> [!IMPORTANT]
> **100% Pass (`6 Passed / 3 Skipped / 0 Failed`) on `EntepriseAttestation.js` & Cryptographic Verification of the `"mtc-debug"` Privacy Gate**:
> In Run 23 (`2026-10-23`, `22:45:07.813` – `22:45:46.695 PDT`, `38.88s` active execution), after repackaging `/Applications/FIDO Alliance - Certification Conformance Testing Tools (Patched).app/Contents/Resources/app.asar` (`46,624,232 B`) with the async `getGetInfoCached()` fix, we executed a clean post-clear trace of the **`CTAP2/Protocol/Options/EntepriseAttestation.js`** suite while capturing `fido_conformance_debug.log` (`1,067` lines) and `opensk_rtt.log` (`11,228` lines):
> - **All 6 Enterprise Profile Tests Passed (`P-1`, `P-2`, `P-3`, `F-4`, `F-5`, `F-6`)**: Resolved all 3 `TypeError` harness failures from Run 22 (`P-2`, `P-3`, `F-6`). The 3 Consumer Profile tests (`F-1`, `F-2`, `F-3`) were properly skipped because `GetInfo.options.ep = true`.
> - **Authorized RP Enterprise Attestation (`P-2` with `epAtt = 1`, `P-3` with `epAtt = 2`)**: When `rp.id = "enterprisetest.certinfra.fidoalliance.org"`, Fidont returns a **`7,265-byte`** (`124`-frame) `CTAPHID_CBOR` response with `fmt: "packed"`, `epAtt: true`, a `2,420 B` `ML-DSA-44` (`alg: -48`) attestation signature, a **`3,069 B` LMS-signed `ML-DSA-44` Enterprise X.509 certificate** (`Issuer: CN=Fidont LMS Intermediate CA #0`, `Subject: CN=Fidont Enterprise Attestation`, OID `1.3.6.1.4.1.45724.1.1.2 = "123456"`), and `authenticatorData.extensions["mtc-debug"]` (`1,364 B`) containing both `pubKey` (`1,322 B` `ML-DSA-44` `COSE_Key`) and **`deviceSerial: "123456"`**.
> - **Unauthorized RP Privacy-Gate Downgrade (`F-6` with `rp.id = "pinegrapefruit.gy"` & `epAtt = 1`)**: When an unauthorized RP requests `enterpriseAttestation = 1` alongside `extensions: {"mtc-debug": true}`, Fidont enforces the CTAP 2.3 RP allowlist privacy gate (`rp.id != "enterprisetest.certinfra.fidoalliance.org"`), downgrades the response to standard non-Enterprise attestation (`1,153 B` / `20` frames, `epAtt` omitted, `576 B` classical batch `x5c` without serial OID), and emits **`extensions["mtc-debug"] = { pubKey: 77 B }` with `deviceSerial` strictly omitted**, preventing hardware serial-number tracking across unauthorized origins.

### 0.00000.1 Run 23 Executive Summary & Test-by-Test Matrix

| Test ID | Profile | CTAPHID Channels | Description | Outcome | Wall Time | MCU Exec Time (`MakeCred`) | Wire Response Summary |
| :--- | :---: | :---: | :--- | :---: | :---: | :---: | :--- |
| **Suite `before()`** | Setup | `CID 0x05`..`0x0d` (`9` ch) | `GetInfo` $\to$ `Reset` $\to$ `GetInfo` $\to$ `setPIN` $\to$ `GetInfo` $\to$ `getPinUvAuthToken(acfg=0x20)` $\to$ `Config(EnableEnterpriseAttestation)` | **OK** | `6.30s` | `84.33 ms` (`Config`) | `GetInfo.options.ep` transitions `false` (`0xf4`) $\to$ `true` (`0xf5`) |
| **`P-1`** | Enterprise | `CID 0x0e`..`0x0f` (`2` ch) | Check `GetInfo.options.ep !== undefined` (`true`) | **PASSED** | `1.22s` | — | `GetInfo.options.ep === true` |
| **`P-2`** | Enterprise | `CID 0x10`..`0x12` (`3` ch) | `MakeCredential` with `rp.id = "enterprisetest.certinfra.fidoalliance.org"`, `epAtt = 1` ( vendor-facilitated), `extensions: {"mtc-debug": true}` | **PASSED** | `8.76s` | **`1,376.32 ms`** (`88,084,224 cyc`) | **`7,265 B`** (`124` frames): `fmt: "packed"`, `epAtt: true`, `alg: -48` (`ML-DSA-44`), `sig: 2,420 B`, `x5c: [3,069 B]`, `mtc-debug: {pubKey: 1,322 B, deviceSerial: "123456"}` |
| **`P-3`** | Enterprise | `CID 0x13`..`0x15` (`3` ch) | `MakeCredential` with `rp.id = "enterprisetest.certinfra.fidoalliance.org"`, `epAtt = 2` (platform-managed), `extensions: {"mtc-debug": true}` | **PASSED** | `9.29s` | **`2,076.27 ms`** (`132,881,472 cyc`) | **`7,265 B`** (`124` frames): `fmt: "packed"`, `epAtt: true`, `alg: -48` (`ML-DSA-44`), `sig: 2,420 B`, `x5c: [3,069 B]`, `mtc-debug: {pubKey: 1,322 B, deviceSerial: "123456"}` |
| **`F-1`** | Consumer | `CID 0x16`..`0x17` (`2` ch) | Consumer profile check (`options.ep === undefined`) | **SKIPPED** | `1.24s` | — | Skipped (Enterprise Profile active) |
| **`F-2`** | Consumer | `CID 0x18`..`0x19` (`2` ch) | Consumer profile `epAtt = 1` rejection | **SKIPPED** | `1.26s` | — | Skipped (Enterprise Profile active) |
| **`F-3`** | Consumer | `CID 0x1a`..`0x1b` (`2` ch) | Consumer profile `epAtt = 2` rejection | **SKIPPED** | `1.23s` | — | Skipped (Enterprise Profile active) |
| **`F-4`** | Enterprise | `CID 0x1c`..`0x1e` (`3` ch) | `MakeCredential` with `enterpriseAttestation` set to invalid CBOR boolean (`true` / `0xf5`) | **PASSED** | `1.77s` | **`< 1 ms`** (CBOR parser) | **`1 B`** (`1` frame): `CTAP2_ERR_CBOR_UNEXPECTED_TYPE` (`0x11`) |
| **`F-5`** | Enterprise | `CID 0x1f`..`0x21` (`3` ch) | `MakeCredential` with `enterpriseAttestation = 117` (`0x18 0x75`, neither `1` nor `2`) | **PASSED** | `1.92s` | **`196.93 ms`** (`12,603,776 cyc`) | **`1 B`** (`1` frame): `CTAP2_ERR_INVALID_OPTION` (`0x2C`) |
| **`F-6`** | Enterprise | `CID 0x22`..`0x26` (`5` ch) | `MakeCredential` with unauthorized `rp.id = "pinegrapefruit.gy"`, `epAtt = 1`, `extensions: {"mtc-debug": true}` | **PASSED** | `5.85s` | **`2,045.12 ms`** (`130,887,616 cyc`) | **`1,153 B`** (`20` frames): `fmt: "packed"`, **`epAtt` omitted**, `alg: -7` (`ES256`), `sig: 71 B`, `x5c: [576 B]`, **`mtc-debug: {pubKey: 77 B}` (`deviceSerial` omitted)** |

### 0.00000.2 Complete CTAPHID & RTT Message Trace (`68` Exchanges / `136` Messages Across `CID 0x00000005`..`0x00000026`)

Every test in `EntepriseAttestation.js` allocates a fresh CTAPHID channel via `CTAPHID_INIT (0x86)` on broadcast channel `0xffffffff` before transmitting `CTAPHID_CBOR (0x90)`:

| Phase / Test | CID | Timestamp (PDT) | CTAP Command & Subcommand | Req (`OUT`) | Resp (`IN`) | RTT Lines (`opensk_rtt.log`) | RTT MCU Execution (`64 MHz` DWT) | Status & Key Result |
| :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| **Setup 1** | `00000005` | `22:45:07.948` | `authenticatorGetInfo (0x04)` | `1 B` (`1f`) | `841 B` (`15f`) | `L58–L96` | `70.31 ms` | `0x00`: `ep: false`, `clientPin: true`, `exts: [..., "mtc-debug"]`, `attFmts: ["mtc", "packed"]` |
| **Setup 2** | `00000006` | `22:45:08.801` | `authenticatorReset (0x07)` | `1 B` (`1f`) | `1 B` (`1f`) | `L426–L448` | `717.54 ms` | `0x00`: Credentials & PIN cleared, persistent storage reset |
| **Setup 3** | `00000007` | `22:45:09.616` | `authenticatorGetInfo (0x04)` | `1 B` (`1f`) | `841 B` (`15f`) | `L523–L563` | `129.59 ms` | `0x00`: `ep: false`, `clientPin: false` |
| **Setup 4** | `00000008` | `22:45:10.525` | `ClientPIN (0x06)` `getKeyAgreement (0x02)` | `6 B` (`1f`) | `81 B` (`2f`) | `L901–L907` | `320.12 ms` | `0x00`: Ephemeral `P-256` `COSE_Key` (`alg: -25`) |
| **Setup 5** | `00000009` | `22:45:11.074` | `ClientPIN (0x06)` `setPIN (0x03)` (`protocol=2`) | `203 B` (`4f`) | `1 B` (`1f`) | `L1059–L1096` | `465.85 ms` | `0x00`: New PIN established |
| **Setup 6** | `0000000a` | `22:45:11.815` | `authenticatorGetInfo (0x04)` | `1 B` (`1f`) | `841 B` (`15f`) | `L1171–L1208` | `66.93 ms` | `0x00`: `ep: false`, `clientPin: true` |
| **Setup 7** | `0000000b` | `22:45:12.725` | `ClientPIN (0x06)` `getKeyAgreement (0x02)` | `6 B` (`1f`) | `81 B` (`2f`) | `L1611–L1617` | `320.12 ms` | `0x00`: Ephemeral `P-256` `COSE_Key` |
| **Setup 8** | `0000000c` | `22:45:13.307` | `ClientPIN (0x06)` `getPinUvAuthTokenUsingPinWithPermissions (0x09)` (`perms=0x20` `acfg`) | `123 B` (`3f`) | `53 B` (`1f`) | `L1735–L1765` | `416.47 ms` | `0x00`: `48 B` encrypted `pinUvAuthToken` (`acfg` permission) |
| **Setup 9** | `0000000d` | `22:45:13.976` | `authenticatorConfig (0x0D)` `enableEnterpriseAttestation (0x01)` | `41 B` (`1f`) | `1 B` (`1f`) | `L1838–L1863` | **`84.33 ms`** | `0x00`: Enterprise Attestation enabled (`options.ep = true`) |
| **`P-1`** | `0000000e`..`0f` | `22:45:14.162` | `ClientPIN` `getKeyAgreement` + `getPinUvAuthToken (perms=0x03, rpId="enterprisetest...")` | `6 B` / `166 B` | `81 B` / `53 B` | `L1927–L2071` | `320.36 ms` + `416.76 ms` | `0x00`: `P-1` verifies `GetInfo.options.ep === true` (**PASSED**) |
| **`P-2` (PUAT)** | `00000010`..`11` | `22:45:15.388` | `ClientPIN` `getKeyAgreement` + `getPinUvAuthToken (perms=0x03, rpId="enterprisetest...")` | `6 B` / `166 B` | `81 B` / `53 B` | `L2144–L2310` | `320.35 ms` + `419.00 ms` | `0x00`: PUAT scoped to `"enterprisetest.certinfra.fidoalliance.org"` |
| **`P-2` (`MakeCred`)** | `00000012` | `22:45:16.648` | `MakeCredential (0x01)` (`epAtt=1`, `exts={"mtc-debug": true}`) | **`707 B` (`13f`)** | **`7,265 B` (`124f`)** | `L2579–L2758` | **`1,376.32 ms`** | `0x00`: `fmt: "packed"`, `epAtt: true`, `ML-DSA-44` sig (`2,420 B`), LMS-signed `x5c` (`3,069 B`), `mtc-debug.deviceSerial: "123456"` (**PASSED**) |
| **`P-3` (PUAT)** | `00000013`..`14` | `22:45:24.141` | `ClientPIN` `getKeyAgreement` + `getPinUvAuthToken (perms=0x03, rpId="enterprisetest...")` | `6 B` / `166 B` | `81 B` / `53 B` | `L5295–L5450` | `320.36 ms` + `416.98 ms` | `0x00`: PUAT scoped to `"enterprisetest.certinfra.fidoalliance.org"` |
| **`P-3` (`MakeCred`)** | `00000015` | `22:45:25.454` | `MakeCredential (0x01)` (`epAtt=2`, `exts={"mtc-debug": true}`) | **`708 B` (`13f`)** | **`7,265 B` (`124f`)** | `L5702–L5884` | **`2,076.27 ms`** | `0x00`: `fmt: "packed"`, `epAtt: true`, `ML-DSA-44` sig (`2,420 B`), LMS-signed `x5c` (`3,069 B`), `mtc-debug.deviceSerial: "123456"` (**PASSED**) |
| **`F-1`..`F-3`** | `00000016`..`1b` | `22:45:33.461` | `beforeEach()` PUAT acquisition (`3` pairs) $\to$ Mocha `this.skip()` | `3×(6B+166B)` | `3×(81B+53B)` | `L8259–L8911` | `3×(~740 ms)` | Consumer-only tests skipped when Enterprise Profile is selected (**SKIPPED**) |
| **`F-4` (PUAT)** | `0000001c`..`1d` | `22:45:37.188` | `ClientPIN` `getKeyAgreement` + `getPinUvAuthToken (perms=0x03, rpId="enterprisetest...")` | `6 B` / `166 B` | `81 B` / `53 B` | `L8983–L9147` | `320.35 ms` + `452.46 ms` | `0x00`: PUAT acquired |
| **`F-4` (`MakeCred`)** | `0000001e` | `22:45:38.433` | `MakeCredential (0x01)` (`epAtt=true` `0xf5`, invalid CBOR type) | **`693 B` (`12f`)** | **`1 B` (`1f`)** | `L9418` | **`< 1 ms`** | **`0x11` (`CTAP2_ERR_CBOR_UNEXPECTED_TYPE`)** — rejected at CBOR schema decode (**PASSED**) |
| **`F-5` (PUAT)** | `0000001f`..`20` | `22:45:38.953` | `ClientPIN` `getKeyAgreement` + `getPinUvAuthToken (perms=0x03, rpId="enterprisetest...")` | `6 B` / `166 B` | `81 B` / `53 B` | `L9466–L9630` | `320.36 ms` + `459.34 ms` | `0x00`: PUAT acquired |
| **`F-5` (`MakeCred`)** | `00000021` | `22:45:40.205` | `MakeCredential (0x01)` (`epAtt=117` `0x18 0x75`, out-of-range integer) | **`679 B` (`12f`)** | **`1 B` (`1f`)** | `L9885–L9905` | **`196.93 ms`** | **`0x2C` (`CTAP2_ERR_INVALID_OPTION`)** — rejected after PIN/UV check (**PASSED**) |
| **`F-6` (PUAT)** | `00000022`..`25` | `22:45:40.882` | `beforeEach()` PUAT + `getPinToken (0x05)` unscoped token for `"pinegrapefruit.gy"` | `6B+166B+6B+120B` | `81B+53B+81B+53B` | `L9978–L10388` | `737.86 ms` + `774.26 ms` | `0x00`: Unscoped PIN token acquired for `"pinegrapefruit.gy"` |
| **`F-6` (`MakeCred`)** | `00000026` | `22:45:43.385` | `MakeCredential (0x01)` (`rp.id="pinegrapefruit.gy"`, `epAtt=1`, `exts={"mtc-debug": true}`) | **`673 B` (`12f`)** | **`1,153 B` (`20f`)** | `L10633–L10834` | **`2,045.12 ms`** | `0x00`: Downgraded to non-Enterprise `fmt: "packed"` (`epAtt` omitted, `576 B` `x5c`, **`mtc-debug.deviceSerial` omitted**) (**PASSED**) |

---

### 0.00000.3 Byte-Level CBOR & X.509 Dissection of Key Protocol Exchanges

#### 1. Enabling Enterprise Attestation via `authenticatorConfig (0x0D)` (`CID=0000000d`, `Log L185–L199`, `RTT L1838–L1863`)
- **Request (`41 B` payload, 1 CTAPHID frame)**:
  ```text
  0d                                                                 # authenticatorConfig (0x0D)
  a3                                                                 # map(3)
     01: 01                                                          # subCommand: enableEnterpriseAttestation (1)
     03: 02                                                          # pinUvAuthProtocol: 2
     04: 58 20 5d390addc9c015e92b498ecdcb45ef91                      # pinUvAuthParam (32 B): HMAC-SHA-256 over
               481f08b64d0d5bd19bfed058e9d1b795                      #   ff*32 || 0x0d || 0x01 || b""
  ```
- **Response (`1 B` payload, `84.33 ms` MCU execution)**: `00` (`CTAP1_ERR_SUCCESS`). Subsequent `authenticatorGetInfo` responses report `options.ep: true` (`0x62 0x65 0x70 0xf5`).

#### 2. Authorized Enterprise Attestation (`P-2` `epAtt=1` on `CID=00000012` & `P-3` `epAtt=2` on `CID=00000015`)
- **Request (`707 B` in `P-2` / `708 B` in `P-3`, 13 CTAPHID frames)**:
  - `req[1]` (`clientDataHash`, `32 B`): `abfd62825ac75897...` (`P-2`) / `ad133375a01eb8d5...` (`P-3`)
  - `req[2]` (`rp`): `{"id": "enterprisetest.certinfra.fidoalliance.org", "name": "The Example Corporation with fake domain!"}`
  - `req[4]` (`pubKeyCredParams`, `18` algorithms): `[-7 (ES256), -8 (EdDSA), -35 (ES384), -36 (ES512), -53 (Ed448), -48 (ML-DSA-44), -49 (ML-DSA-65), -50 (ML-DSA-87), -257 (RS256), -47 (ES256K), -54 (MLDSA44-ES256), -55 (MLDSA65-ES256), -56 (MLDSA87-ES384), -57 (MLDSA44-Ed25519), -58 (MLDSA65-Ed25519), -59 (MLDSA87-Ed448), -60 (FN-DSA-512), -61 (FN-DSA-1024)]`
  - `req[6]` (`extensions`): **`{"mtc-debug": true}`** (`a1 69 6d74632d6465627567 f5`)
  - `req[9]` (`pinUvAuthProtocol`): `2`
  - `req[10]` (`enterpriseAttestation`): **`1`** (`0x0a 0x01` in `P-2`) / **`2`** (`0x0a 0x02` in `P-3`)
- **Response (`7,265 B` = `0x1c61`, 124 CTAPHID frames — `344 B` under the `7,609 B` USB HID limit)**:
  - `status` (`1 B`): `0x00` (`CTAP1_ERR_SUCCESS`)
  - `resp[1]` (`fmt`): **`"packed"`**
  - `resp[2]` (`authData`, **`1,737 B`**):
    - `rpIdHash` (`32 B`): `4aaf81997cdb64e348a296a7ee06405b99921966ff653b9ed364df6e78306439` (`SHA-256("enterprisetest.certinfra.fidoalliance.org")`)
    - `flags` (`1 B`): `0xc5` (`UP=1`, `UV=1`, `AT=1`, `ED=1`)
    - `signCount` (`4 B`): `1` (`00000001`)
    - `aaguid` (`16 B`): `deadbeef000000000000deadbeef0000`
    - `credIdLen` (`2 B`) + `credId` (`241 B`): `0x00f1` + `014154b26666e546...` (`0x01` encrypted classical `ES256` handle)
    - `credentialPublicKey` (`77 B`): `COSE_Key` (`kty: 2 (EC2)`, `alg: -7 (ES256)`, `crv: 1 (P-256)`)
    - `extensions` (**`1,364 B`** CBOR map):
      ```text
      {
        "mtc-debug": {
          "pubKey": h'a3 01 07 03 38 2f 20 59 0520 dcd864884928fdce...' (1,322 B COSE_Key: kty=7 AKP, alg=-48 ML-DSA-44, pub=1,312 B),
          "deviceSerial": "123456"
        }
      }
      ```
  - `resp[3]` (`attStmt`, **`5,507 B`**):
    - `alg`: **`-48` (`ML-DSA-44`)**
    - `sig` (`2,420 B`): `ML-DSA-44` signature over `authData || clientDataHash` (`8df6f8064214d3d3...` in `P-2`, `8da2154917f0c360...` in `P-3`)
    - `x5c` (`[3,069 B]`): 1-element DER X.509 Enterprise batch certificate (`SHA-256 = d17af264bd4a44eb9caf2e9471019f5e486f0b7778be61d9f926d356ca051a8c`):
      - **Serial Number**: `771` (`0x0303`)
      - **Issuer**: `C=CA, O=John Bradley, OU=Authenticator Attestation, CN=Fidont LMS Intermediate CA #0`
      - **Subject**: `C=CA, O=John Bradley, OU=Authenticator Attestation, CN=Fidont Enterprise Attestation`
      - **Subject Public Key Info**: `ML-DSA-44` (`2.16.840.1.101.3.4.3.17`), `1,312 B` public key (`dcd864884928fdce...`, matching `mtc-debug.pubKey` byte-for-byte)
      - **X.509v3 Extensions**:
        - `Basic Constraints` (critical): `CA:FALSE`
        - `Key Usage` (critical): `Digital Signature`
        - `Authority Key Identifier`: `CB:02:7F:08:B2:25:5B:AB:D1:36:D2:0B:AB:81:CB:0F:03:54:39:ED` (keyIdentifier of `Fidont LMS Intermediate CA #0`)
        - `id-fido-gen-ce-aaguid` (`1.3.6.1.4.1.45724.1.1.4`): `04 10 deadbeef000000000000deadbeef0000`
        - **`id-fido-gen-ce-serial-number` (`1.3.6.1.4.1.45724.1.1.2`)**: **`04 06 31 32 33 34 35 36` (`"123456"`, matching `mtc-debug.deviceSerial`)**
      - **Signature Algorithm & Value**: `id-alg-hss-lms-hashsig` (`1.2.840.113549.1.9.16.3.17`), **`1,296 B` `LMS_SHA256_M32_H5` / `LMOTS_SHA256_N32_W8` signature** (`00000000 00000003 00000004 d500aea5...`, tree leaf index `q = 3`)
  - `resp[4]` (`epAtt`): **`true` (`0xf5`)**

#### 3. Negative Option Validation (`F-4` on `CID=0000001e` & `F-5` on `CID=00000021`)
- **`F-4` (`enterpriseAttestation = true` / `0x0a 0xf5`)**:
  - Rejected immediately by Fidont's CBOR request decoder because `enterprise_attestation` expects an unsigned integer (`u8`), returning `1 B` status **`0x11` (`CTAP2_ERR_CBOR_UNEXPECTED_TYPE`)** in `< 1 ms` (`RTT L9418`).
- **`F-5` (`enterpriseAttestation = 117` / `0x0a 0x18 0x75`)**:
  - Decodes as `Some(117)`, verifies `pinUvAuthParam`, and is rejected by the CTAP 2.3 option validator (`enterprise_attestation != 1 && enterprise_attestation != 2`), returning `1 B` status **`0x2C` (`CTAP2_ERR_INVALID_OPTION`)** in `196.93 ms` (`RTT L9885–L9905`).

#### 4. Unauthorized RP Privacy-Gate Fallback (`F-6` on `CID=00000026`, `Log L937–L1066`, `RTT L10633–L10834`)
- **Request (`673 B`, 12 CTAPHID frames)**:
  - `req[2]` (`rp`): `{"id": "pinegrapefruit.gy", "name": "The Example Corporation with fake domain!"}` (**not** on the authenticator's Enterprise RP ID allowlist)
  - `req[6]` (`extensions`): **`{"mtc-debug": true}`**
  - `req[10]` (`enterpriseAttestation`): **`1`** (`0x0a 0x01`)
- **Response (`1,153 B` = `0x0481`, 20 CTAPHID frames)**:
  - `status` (`1 B`): `0x00` (`CTAP1_ERR_SUCCESS`)
  - `resp[1]` (`fmt`): **`"packed"`**
  - `resp[2]` (`authData`, **`471 B`**):
    - `rpIdHash` (`32 B`): `64a484738a7d0600ae50147600bf74055480467703cfe0028f1d9b2c511ff4e2` (`SHA-256("pinegrapefruit.gy")`)
    - `flags` (`1 B`): `0xc5` (`UP=1`, `UV=1`, `AT=1`, `ED=1`)
    - `credId` (`241 B`) + `credentialPublicKey` (`77 B` `ES256` `COSE_Key`)
    - `extensions` (**`98 B`** CBOR map):
      ```text
      {
        "mtc-debug": {
          "pubKey": h'a5 01 02 03 26 20 01 21 58 20 071cfc02f042a7b6... 22 58 20 ecfda307ac994a6d...' (77 B ES256 COSE_Key)
          # NOTE: "deviceSerial" is STRICTLY OMITTED because epAtt was downgraded to false!
        }
      }
      ```
  - `resp[3]` (`attStmt`, **`664 B`**):
    - `alg`: **`-7` (`ES256`)**
    - `sig` (`71 B`): `30450220126a412ece48b0b36269cab5...`
    - `x5c` (`[576 B]`): Classical non-Enterprise batch certificate (`Subject: CN=Fidont Attestation`, `Issuer: CN=Fidont Enterprise Root CA ES384`, `SPKI: P-256 04071cfc02...` matching `mtc-debug.pubKey`, `1.3.6.1.4.1.45724.1.1.4` AAGUID extension only, **no `1.3.6.1.4.1.45724.1.1.2` serial number OID**)
  - `resp[4]` (`epAtt`): **Omitted (`None`)**

### 0.00000.4 Side-by-Side Comparison: Authorized Enterprise Attestation (`P-2`/`P-3`) vs. Unauthorized RP Fallback (`F-6`)

| Field / Property | Authorized Enterprise RP (`P-2` `epAtt=1` / `P-3` `epAtt=2`) | Unauthorized RP Downgrade (`F-6` `epAtt=1`) | Security & Privacy Guarantee |
| :--- | :--- | :--- | :--- |
| **Requested `rp.id`** | `"enterprisetest.certinfra.fidoalliance.org"` (Allowlisted) | `"pinegrapefruit.gy"` (Not Allowlisted) | RP allowlist enforced in firmware before attestation key selection |
| **Requested `extensions`** | `{"mtc-debug": true}` | `{"mtc-debug": true}` | Identical client extension request |
| **Response `BCNT` (Frames)** | **`7,265 B`** (`124` CTAPHID frames) | **`1,153 B`** (`20` CTAPHID frames) | Both fit comfortably within the `7,609 B` CTAPHID limit |
| **Response `epAtt` (Key `0x04`)** | **`true` (`0xf5`)** | **Omitted (`undefined`)** | Conforms to CTAP 2.3 §6.1.2 step 11 |
| **Attestation Key & `attStmt.alg`** | Enterprise `ML-DSA-44` (`alg: -48`, `sig: 2,420 B`) | Classical Batch `ES256` (`alg: -7`, `sig: 71 B`) | Enterprise key never signs for non-allowlisted RP IDs |
| **`attStmt.x5c[0]` Certificate** | **`3,069 B`** LMS-signed (`id-alg-hss-lms-hashsig`) `ML-DSA-44` Enterprise cert | **`576 B`** `ES384`-signed `P-256` Classical Batch cert | Enterprise certificate never disclosed to non-allowlisted RP IDs |
| **X.509 Serial Number OID (`1.3.6.1.4.1.45724.1.1.2`)** | **Present (`"123456"`)** | **Absent** | Hardware serial number omitted from X.509 cert on downgrade |
| **`extensions["mtc-debug"].pubKey`** | **`1,322 B`** (`ML-DSA-44` `COSE_Key`, matches `3,069 B` `x5c` SPKI) | **`77 B`** (`ES256` `COSE_Key`, matches `576 B` `x5c` SPKI) | Always reflects the actual signing key used for `attStmt.sig` |
| **`extensions["mtc-debug"].deviceSerial`** | **`"123456"`** (matches X.509 OID `1.3.6.1.4.1.45724.1.1.2`) | **Strictly Omitted (`undefined`)** | **Prevents `"mtc-debug"` from being abused to bypass the Enterprise RP allowlist** |

---

## 0.0000 Run 22 (`11:51:49` – `12:11:56` PDT) Deep Dive: W3C WebAuthn Level 4 Pull Request Consolidated `fmt: "mtc"` (`4,736–5,397 B`, Saving `1,331 B` Wire Payload), `"mtc-debug"` Extension & `opensk_rtt.log` Hardware Telemetry

> [!IMPORTANT]
> **W3C WebAuthn Level 4 PR Verification — Consolidated `fmt: "mtc"` (`1,331 B` Smaller Wire Payloads) & Opt-In `"mtc-debug"` Extension**:
> In Run 22 (`2026-10-23`, `11:51:49.597` – `12:11:56.384 PDT`, `20m 06.79s` active test execution), we updated both **Fidont / OpenSK** (`mtc.rs`, `data_formats.rs`, `mod.rs`, `configure.py`, and `fido-mds3.json`) and the **FIDO CTAP 2.3 Conformance Testing Tool** (`Authr-MakeCred-Resp-1.js`, `EntepriseAttestation.js`, `Metadata-Stmt-1.js`) to implement the W3C WebAuthn Level 4 Pull Request ([`webauthn_level4_pull_request.html`](./webauthn_level4_pull_request.html)):
> - **Consolidated `fmt: "mtc"` Omitting Inline `pubKey` (`1,331 B` Wire Reduction)**: By consolidating `mtc-mds` into `fmt: "mtc"` and omitting the inline `1,322 B` `ML-DSA-44` `COSE_Key` (`pubKey`) from `attStmt` (resolving it instead from `metadata.mtcTrustAnchors[].batchKeys` by `serial`), every 2-step PQ and composite `MakeCredential` response shrank by exactly **`1,331 bytes`** (`21` fewer 64-byte CTAPHID `IN` frames) compared to Run 21:
>   - `FN-DSA-1024 (-61)`: **`6,067 B` $\to$ `4,736 B`** (`6,778.1 ms` $\to$ `5,032.7 ms`, **`1.75s` faster** over USB HID)
>   - `ML-DSA-65 (-49)`: **`6,226 B` $\to$ `4,895 B`** (`7,387.2 ms` $\to$ `6,541.1 ms`, **`0.85s` faster**)
>   - `MLDSA65-Ed25519 (-58)`: **`6,258 B` $\to$ `4,927 B`** (`6,775.7 ms` $\to$ `6,072.3 ms`, **`0.70s` faster**)
>   - `MLDSA65-ES256 (-55)`: **`6,291 B` $\to$ `4,960 B`** (`7,953.1 ms` $\to$ `7,428.8 ms`, **`0.52s` faster**)
>   - `ML-DSA-87 (-50)`: **`6,676 B` $\to$ `5,345 B`** (`7,240.6 ms` $\to$ `5,879.8 ms`, **`1.36s` faster**)
>   - `MLDSA87-Ed448 (-59)`: **`6,688 B` $\to$ `5,357 B`** (`7,281.9 ms` $\to$ `6,870.0 ms`, **`0.41s` faster**)
>   - `MLDSA87-ES384 (-56)`: **`6,728 B` $\to$ `5,397 B`** (`9,136.6 ms` $\to$ `8,514.6 ms`, **`0.62s` faster**)
> - **100% Pass on Consolidated `fmt: "mtc"` (`Authr-MakeCred-Resp-1` `P-01`..`P-04`, `F-01`) & `Metadata-Stmt-1` (`25 / 25`)**: All 18 algorithms verified cleanly under `P-04` (`0.165s`), confirming `attStmt.pubKey === undefined`, `batchKeys` lookup by `serial`, RFC 9162 Merkle inclusion proof reduction, `HSS-LMS` (`alg: -46`) subtree checkpoint signature verification against `metadata.attestationRootCertificates`, and `ML-DSA-44` batch signature verification.
> - **Root Cause & Immediate Fix of the 4 Test-Harness `TypeError`s**: The only 4 test failures in Run 22 (`P-05` in `Authr-MakeCred-Resp-1.js`, and `P-2`, `P-3`, `F-6` in `EntepriseAttestation.js`) occurred in newly added test-harness code that referenced `window.config.test.fidoauthenticator.getInfo.extensions` synchronously (`TypeError: Cannot read properties of undefined (reading 'extensions')`) before inspecting the authenticator response. Replacing that synchronous property lookup with the conformance runner's async `getGetInfoCached()` helper in both test files and repackaging `app.asar` resolved all 4 harness errors.

### 0.0000.1 Run 22 Executive Summary (`11:51:49` – `12:11:56` PDT)

| Metric | Value in Run 22 | Source & Details |
| :--- | :--- | :--- |
| **Test Window & Duration** | **`11:51:49.597` – `12:11:56.384 PDT`** (**`20m 06.79s`** active execution) | `fido_conformance_debug.log` (`L100` first test start $\to$ `L34408` *"Testing finished."* out of `34,421` lines / `5.1 MB`, **`5m 21s` faster** than Run 21 due to `1,331 B` smaller `fmt: "mtc"` payloads and 0 power-cycle retries) |
| **Overall Test Outcome** | **`247 Passed / 32 Skipped / 4 Failed` (`98.41%` PASS across `283` unique tests)** | `100%` firmware conformance; all `4` failures were synchronous JS `TypeError`s in newly added `mtc-debug` test-harness checks (`window.config.test.fidoauthenticator.getInfo` vs `getGetInfoCached()`), now fixed and repackaged in `app.asar` |
| **W3C WebAuthn L4 `fmt: "mtc"` Wire Savings** | **`4,736 B` – `5,397 B`** (down **`1,331 B`** from `6,067 B` – `6,728 B` in Run 21) | `attStmt` omits inline `pubKey` (`1,322 B` `ML-DSA-44` `COSE_Key` + `9 B` CBOR key/header), resolving the batch key from `metadata.mtcTrustAnchors[0].batchKeys` (`serial: 4398046511104`) |
| **Supported CTAP 2.3 Extensions (`8`)** | `credProtect`, `credBlob`, `largeBlobKey`, `minPinLength`, `hmac-secret`, `hmac-secret-mc`, `thirdPartyPayment`, **`mtc-debug`** | Advertised in `authenticatorGetInfo.extensions` (`RTT L96`) and `fido-mds3.json`; verified in `Metadata-Stmt-1` (`25/25` PASS) |
| **Hardware RTT Log (`opensk_rtt.log`)** | **`292,093` lines (`31.2 MB`)** | **`0` panics, `0` HardFaults, `0` `[WARN]`/`[ERROR]` lines** across `99` `AuthenticatorMakeCredential` and `68` `AuthenticatorGetAssertion` hardware executions; `3` clean CTAP/hardware resets |

### 0.0000.2 Run 22 `Authr-MakeCred-Resp-1` (`P-01`..`F-01`): All 18 Algorithms (`Log L4521–L6676`, `RTT L36921–L70579`)

| # | Algorithm | COSE `alg` | Attestation Format | `BCNT` (vs Run 21) | Debug Log Lines | RTT Log Lines | Total USB Exchange Time | RTT MCU Command Execution (`64 MHz` DWT) |
| :-: | :--- | :---: | :---: | :---: | :--- | :--- | :---: | :--- |
| 1 | `RS256` (RSA-2048) | `-257` | `"packed"` (`ES256` `x5c`) | `1,251 B` | `L4521–L4560` | `L36921–L37086` | `2,235.6 ms` | `996.59 ms` (`63,781,888 cyc`) |
| 2 | **`FN-DSA-1024`** (Draft FIPS 206) | **`-61`** | **`"mtc"` (`g5k_AQE`, no inline `pubKey`)** | **`4,736 B` (`-1,331 B`)** | `L4597–L4695` | `L37851–L38015` | **`5,032.7 ms`** | **`693.21 ms` (`44,365,120 cyc`)** |
| 3 | **`FN-DSA-512`** (Draft FIPS 206) | **`-60`** | **`"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`)** | **`6,693 B`** | `L4732–L4863` | `L39965–L40126` | **`6,828.3 ms`** | **`1,454.76 ms` (`93,104,768 cyc`)** |
| 4 | `MLDSA87-Ed448` | `-59` | **`"mtc"` (`g5k_AQE`, no inline `pubKey`)** | **`5,357 B` (`-1,331 B`)** | `L4900–L5008` | `L42637–L42801` | `6,870.0 ms` | `1,815.95 ms` (`116,220,672 cyc`) |
| 5 | `MLDSA65-Ed25519` | `-58` | **`"mtc"` (`g5k_AQE`, no inline `pubKey`)** | **`4,927 B` (`-1,331 B`)** | `L5045–L5146` | `L44899–L45079` | `6,072.3 ms` | `1,382.01 ms` (`88,448,448 cyc`) |
| 6 | `MLDSA44-Ed25519` | `-57` | `"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`) | `7,140 B` | `L5183–L5322` | `L47171–L47328` | `6,461.2 ms` | `833.63 ms` (`53,352,640 cyc`) |
| 7 | `MLDSA87-ES384` | `-56` | **`"mtc"` (`g5k_AQE`, no inline `pubKey`)** | **`5,397 B` (`-1,331 B`)** | `L5359–L5468` | `L49978–L50144` | `8,514.6 ms` | `3,348.39 ms` (`214,296,896 cyc`) |
| 8 | `MLDSA65-ES256` | `-55` | **`"mtc"` (`g5k_AQE`, no inline `pubKey`)** | **`4,960 B` (`-1,331 B`)** | `L5505–L5607` | `L52528–L52679` | `7,428.8 ms` | `2,714.88 ms` (`173,752,064 cyc`) |
| 9 | `MLDSA44-ES256` | `-54` | `"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`) | `7,173 B` | `L5644–L5783` | `L54927–L55086` | `7,392.8 ms` | `1,431.56 ms` (`91,620,160 cyc`) |
| 10 | `ML-DSA-87` (FIPS 204) | `-50` | **`"mtc"` (`g5k_AQE`, no inline `pubKey`)** | **`5,345 B` (`-1,331 B`)** | `L5820–L5928` | `L58041–L58201` | `5,879.8 ms` | `794.50 ms` (`50,848,192 cyc`) |
| 11 | `ML-DSA-65` (FIPS 204) | `-49` | **`"mtc"` (`g5k_AQE`, no inline `pubKey`)** | **`4,895 B` (`-1,331 B`)** | `L5965–L6065` | `L60499–L60669` | `6,541.1 ms` | `1,763.47 ms` (`112,861,952 cyc`) |
| 12 | `ML-DSA-44` (FIPS 204) | `-48` | `"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`) | `7,108 B` | `L6102–L6240` | `L62890–L63062` | `6,747.3 ms` | `891.07 ms` (`57,028,288 cyc`) |
| 13 | `Ed448` (RFC 8032) | `-53` | `"packed"` (`ES256` `x5c`) | `1,046 B` | `L6277–L6312` | `L65845–L66019` | `2,343.0 ms` | `1,351.69 ms` (`86,508,032 cyc`) |
| 14 | `EdDSA` (Ed25519) | `-8` | `"packed"` (`ES256` `x5c`) | `1,021 B` | `L6349–L6384` | `L66743–L66917` | `2,102.2 ms` | `1,068.67 ms` (`68,395,008 cyc`) |
| 15 | `ES256K` (secp256k1) | `-47` | `"packed"` (`ES256` `x5c`) | `1,057 B` | `L6421–L6456` | `L67638–L67801` | `2,089.0 ms` | `1,040.93 ms` (`66,619,840 cyc`) |
| 16 | `ES512` (P-521) | `-36` | `"packed"` (`ES256` `x5c`) | `1,123 B` | `L6493–L6530` | `L68488–L68663` | `3,503.4 ms` | `2,445.26 ms` (`156,496,384 cyc`) |
| 17 | `ES384` (P-384) | `-35` | `"packed"` (`ES256` `x5c`) | `1,088 B` | `L6567–L6603` | `L69439–L69616` | `3,355.4 ms` | `2,185.43 ms` (`139,867,520 cyc`) |
| 18 | `ES256` (P-256) | `-7` | `"packed"` (`ES256` `x5c`) | `1,056 B` | `L6640–L6676` | `L70400–L70579` | `2,732.3 ms` | `1,631.25 ms` (`104,399,936 cyc`) |

### 0.0000.3 Run 22 `Authr-GetAssertion-Resp-1` (`P-1`..`P-5`): All 18 Algorithms (`Log L12889–L16645`, `RTT L83970–L140028`)

| # | Algorithm | COSE `alg` | `BCNT` (Sig Size) | Debug Log Lines | RTT Log Lines | Total USB Exchange Time | RTT MCU Command Execution (`64 MHz` DWT) |
| :-: | :--- | :---: | :---: | :--- | :--- | :---: | :--- |
| 1 | `ES256` (P-256) | `-7` | `381 B` (`70 B`) | `L12889–L12915` | `L83970–L84135` | `1,763.8 ms` | **`1,051.24 ms`** (`67,279,680 cyc`) |
| 2 | `ES384` (P-384) | `-35` | `412 B` (`103 B`) | `L13025–L13052` | `L85574–L85731` | `3,496.2 ms` | **`2,809.06 ms`** (`179,780,096 cyc`) |
| 3 | `ES512` (P-521) | `-36` | `447 B` (`138 B`) | `L13163–L13190` | `L87177–L87302` | `2,525.7 ms` | **`1,691.68 ms`** (`108,267,584 cyc`) |
| 4 | `ES256K` (secp256k1) | `-47` | `380 B` (`71 B`) | `L13299–L13325` | `L88726–L88874` | `1,243.8 ms` | **`518.08 ms`** (`33,157,120 cyc`) |
| 5 | `EdDSA` (Ed25519) | `-8` | `373 B` (`64 B`) | `L13434–L13460` | `L90310–L90463` | `1,193.9 ms` | **`489.48 ms`** (`31,326,848 cyc`) |
| 6 | `Ed448` (RFC 8032) | `-53` | `423 B` (`114 B`) | `L13569–L13596` | `L91879–L92043` | `1,787.5 ms` | **`1,054.13 ms`** (`67,464,192 cyc`) |
| 7 | `ML-DSA-44` (FIPS 204) | `-48` | `2,730 B` (`2,420 B`) | `L13808–L13874` | `L95422–L95569` | `3,409.9 ms` | **`627.16 ms`** (`40,138,496 cyc`) |
| 8 | `ML-DSA-65` (FIPS 204) | `-49` | `3,619 B` (`3,309 B`) | `L14049–L14130` | `L99124–L99280` | `5,372.7 ms` | **`1,861.87 ms`** (`119,159,808 cyc`) |
| 9 | `ML-DSA-87` (FIPS 204) | `-50` | `4,747 B` (`4,627 B`) | `L14312–L14408` | `L103061–L103210` | `6,021.0 ms` | **`1,697.02 ms`** (`108,609,152 cyc`) |
| 10 | `MLDSA44-ES256` | `-54` | `2,801 B` (`2,490 B`) | `L14621–L14688` | `L108354–L108531` | `4,439.5 ms` | **`1,433.89 ms`** (`91,769,280 cyc`) |
| 11 | `MLDSA65-ES256` | `-55` | `3,689 B` (`3,379 B`) | `L14864–L14946` | `L112402–L112564` | `6,631.4 ms` | **`2,984.70 ms`** (`191,020,800 cyc`) |
| 12 | `MLDSA87-ES384` | `-56` | `4,805 B` (`4,722 B`) | `L15129–L15226` | `L116687–L116816` | `7,989.4 ms` | **`3,607.40 ms`** (`230,873,472 cyc`) |
| 13 | `MLDSA44-Ed25519` | `-57` | `2,794 B` (`2,484 B`) | `L15439–L15506` | `L121674–L121843` | `3,583.4 ms` | **`729.78 ms`** (`46,706,112 cyc`) |
| 14 | `MLDSA65-Ed25519` | `-58` | `3,683 B` (`3,373 B`) | `L15681–L15763` | `L125388–L125541` | `4,497.4 ms` | **`852.63 ms`** (`54,568,256 cyc`) |
| 15 | `MLDSA87-Ed448` | `-59` | `4,815 B` (`4,741 B`) | `L15945–L16042` | `L129496–L129622` | `6,615.6 ms` | **`2,126.49 ms`** (`136,095,232 cyc`) |
| 16 | **`FN-DSA-512`** (Draft FIPS 206) | **`-60`** | **`976 B` (`666 B`)** | `L16248–L16284` | `L134582–L134714` | **`2,652.1 ms`** | **`1,316.62 ms` (`84,263,872 cyc`)** |
| 17 | **`FN-DSA-1024`** (Draft FIPS 206) | **`-61`** | **`1,590 B` (`1,280 B`)** | `L16456–L16502` | `L137731–L137886` | **`4,295.7 ms`** | **`2,419.90 ms` (`154,873,600 cyc`)** |
| 18 | `RS256` (RSA-2048) | `-257` | `566 B` (`256 B`) | `L16616–L16645` | `L139867–L140028` | `5,754.6 ms` | **`4,845.48 ms`** (`310,110,848 cyc`) |

### 0.0000.4 Run 22 Complete Conformance Suite Summary (`11:51:49` – `12:11:56` PDT)

| # | Category | Suite ID | Unique Tests | Passed | Skipped | Failed | Duration | Log Line Range |
| :-: | :--- | :--- | :-: | :-: | :-: | :-: | --: | :--- |
| 1 | Transports | `HID-1` | 19 | 16 | 3 | 0 | `19.62s` | `L100–L817` |
| 2 | General | `Authr-Generic-1` | 5 | 5 | 0 | 0 | `13.86s` | `L868–L1400` |
| 3 | MakeCredentialRequest | `Authr-MakeCred-Req-1`..`Req-5` | 35 | 35 | 0 | 0 | `81.75s` | `L1519–L4189` |
| 4 | MakeCredentialRequest | `Authr-MakeCred-Req-6` | 4 | 3 | 1 | 0 | `126.42s` | `L4194–L6676` |
| 5 | MakeCredentialResponse | `Authr-MakeCred-Resp-1` (Consolidated `fmt: "mtc"` & `mtc-debug`) | 7 | 5 | 1 | 1* | `0.18s` | `L6677–L11329` |
| 6 | GetAssertionReq | `Authr-GetAssertion-Req-1` | 7 | 7 | 0 | 0 | `12.27s` | `L11521–L11983` |
| 7 | GetAssertionReq | `Authr-GetAssertion-Req-2` | 3 | 2 | 1 | 0 | `6.01s` | `L12067–L12213` |
| 8 | GetAssertionReq | `Authr-GetAssertion-Req-3` | 7 | 6 | 1 | 0 | `219.74s` | `L12332–L16645` |
| 9 | GetAssertionResp | `Authr-GetAssertion-Resp-1` | 5 | 5 | 0 | 0 | `9.47s` | `L16646–L16893` |
| 10 | Reset | `Authr-Reset-1` | 1 | 1 | 0 | 0 | `13.30s` | `L17006–L17321` |
| 11 | OptionsRK | `Discoverable Credentials (Resident-Key)` | 6 | 5 | 1 | 0 | `43.24s` | `L17374–L18246` |
| 12 | OptionsEP | `Enterprise Attestation` (`mtc` `g5k_AQI` + `mtc-debug`) | 9 | 3 | 3 | 3* | `29.12s` | `L18411–L19421` |
| 13 | Extensions | `HMAC-Secret` (`hmacSecret.js` & `hmacSecret2.js`) | 24 | 24 | 0 | 0 | `110.82s` | `L19564–L22233` |
| 14 | Extensions | `HMAC-Secret MC` (`hmacSecretMC.js`) | 28 | 26 | 2 | 0 | `148.97s` | `L22267–L25742` |
| 15 | Extensions | `CredProtect` | 4 | 4 | 0 | 0 | `24.18s` | `L25747–L26277` |
| 16 | Extensions | `CredBlob` | 3 | 3 | 0 | 0 | `15.78s` | `L26283–L26619` |
| 17 | Extensions | `LargeBlob` & `LargeBlobKey` | 8 | 8 | 0 | 0 | `29.15s` | `L26627–L27368` |
| 18 | Extensions | `MinPinLength` / `PinComplexity` / `ThirdPartyPayment` / `UVM` | 3 | 3 | 0 | 0 | `26.11s` | `L27375–L27937` |
| 19 | ClientPin1 | `KeyAgreement`, `NewPin`, `Policy`, `GetRetries` | 17 | 15 | 2 | 0 | `57.49s` | `L27959–L29155` |
| 20 | ClientPin2 | `KeyAgreement`, `NewPin`, `GetPinToken`, `PinWithPermissions` | 18 | 17 | 1 | 0 | `45.07s` | `L29179–L30500` |
| 21 | ClientPin2 | `Policy` & `GetRetries` (incl. power-cycle lockout `P-5`) | 11 | 9 | 2 | 0 | `48.85s` | `L30520–L31374` |
| 22 | CredManAPI | `EnumerateRPs`, `EnumerateCredentials`, `UpdateAndDelete` | 11 | 11 | 0 | 0 | `46.19s` | `L31488–L32834` |
| 23 | AuthenticatorConfig | `Authr-AuthenticatorConfig` | 7 | 5 | 2 | 0 | `16.69s` | `L32948–L33557` |
| 24 | LargeBlobs | `Authr-LargeBlobs-1` | 4 | 4 | 0 | 0 | `2.29s` | `L33706–L33857` |
| 25 | Metadata | `Metadata-Stmt-1` (`P-1`..`P-43`, incl. `mtc` & `mtc-debug`) | 37 | 25 | 12 | 0 | `0.06s` | `L33866–L34403` |
| **Total** | | **All Active USB HID Suites** | **283** | **247** | **32** | **4*** | **`20m 06.79s`** | `L100–L34408` |

### 0.0000.5 Root-Cause Analysis & Resolution of the 4 Test-Harness `TypeError`s (`getGetInfoCached()`)

1. **Observed Symptom (`L11307`, `L18648`, `L18828`, `L19421`)**:
   - All 4 failures (`P-05` in `Authr-MakeCred-Resp-1.js`, and `P-2`, `P-3`, `F-6` in `EntepriseAttestation.js`) threw the identical JavaScript `TypeError` inside the test script before sending or inspecting the `mtc-debug` extension:
     ```text
     TypeError: Cannot read properties of undefined (reading 'extensions')
     ```
2. **Root Cause**:
   - Our initial test-harness patch checked `window.config.test.fidoauthenticator.getInfo.extensions.includes('mtc-debug')`. In the FIDO Conformance Testing Tool, `window.config.test.fidoauthenticator` does not expose a synchronous `.getInfo` property (`window.config.test.fidoauthenticator.getInfo` is `undefined`); instead, `authenticatorGetInfo` is retrieved asynchronously via `getGetInfoCached()`.
3. **Fix Applied & Repackaged (`app.asar`)**:
   - In `Authr-MakeCred-Resp-1.js` (`P-05`), wrapped the test body in `return getGetInfoCached().then((getInfo) => { if (!getInfo.extensions || !getInfo.extensions.includes('mtc-debug')) { this.skip(); return; } ... })`.
   - In `EntepriseAttestation.js`, cached `supportsMtcDebug = Boolean(getInfo.extensions && getInfo.extensions.includes('mtc-debug'))` inside the suite's `before()` hook (which already invokes `getGetInfoCached()`) and replaced the synchronous property lookup in `P-2`, `P-3`, `F-2`, `F-3`, and `F-6` with `supportsMtcDebug ? { 'mtc-debug': true } : undefined`, then repackaged `/Applications/FIDO Alliance - Certification Conformance Testing Tools (Patched).app/Contents/Resources/app.asar`.

---

## 0.000 Run 21 (`250 / 250` `100.00%` Pass) Deep Dive: Automated `generate_lms_pki.py` RFC 8554 $\cap$ NIST SP 800-208 Provisioning, Compact `fmt: "mtc"` & `opensk_rtt.log` Hardware Telemetry (`09:46:00` – `10:11:28` PDT)

> [!IMPORTANT]
> **`250 / 250` (`100.00%`) Pass with Automated LMS PKI Provisioning (`scripts/generate_lms_pki.py`), Compact `fmt: "mtc"`, and Clean Single-Instance `opensk_rtt.log`**:
> In Run 21 (`2026-10-23`, `09:46:00.569` – `10:11:28.126 PDT`, `25m 27.56s` total duration), we cleared both log files and executed a full end-to-end CTAP 2.3 conformance run following the provisioning of the authenticator and MDS3 via `scripts/generate_lms_pki.py`:
> - **RFC 8554 $\cap$ NIST SP 800-208 Parameter Intersection**: Provisioned a deterministic **LMS Root CA** and **4 Pre-Published LMS Intermediate CAs** (`caId`: `g5k_AQE` Batch #0, `g5k_AQI` Enterprise #1, `g5k_AQM` Batch #2, `g5k_AQQ` Batch #3) using `LMS_SHA256_M32_H5` (`type = 0x00000005`, 32-leaf tree) + `LMOTS_SHA256_N32_W8` (`type = 0x00000004`, `p = 34` chains), reducing each HSS/LMS signature (`L=1`) to **`1,296 bytes`** (`46%` smaller than `W=4`'s `2,420 B`) with X.509 `SubjectPublicKeyInfo` OID `1.2.840.113549.1.9.16.3.17` (`id-alg-hss-lms-hashsig`).
> - **LMS-Signed `ML-DSA` Batch & Enterprise X.509 Certificates + Compact `fmt: "mtc"`**: Provisioned 3 LMS-signed Batch X.509 certificates (`ML-DSA-44` `2,707 B`, `ML-DSA-65` `3,347 B`, `ML-DSA-87` `3,987 B`) and 3 LMS-signed Enterprise X.509 certificates (`2,740 B`, `3,380 B`, `4,020 B`) into `src/ctap/crypto_data.rs`, alongside `alg: -46` (`HSS-LMS`) signed `mtcTrustAnchors[].subtrees[]` checkpoints (`treeSize: 16`) in `fido-mds3.json`. All 2-step PQ/composite algorithms emitted compact `fmt: "mtc"` (`6,067–6,728 B`) while 1-step PQ algorithms (`FN-DSA-512`, `ML-DSA-44`, `MLDSA44-Ed25519`, `MLDSA44-ES256`) emitted LMS-signed `"packed"` `x5c` (`6,692–7,172 B`).
> - **Single-Instance `probe-rs` Hardware RTT Capture (`opensk_rtt.log`)**: Captured **`304,967` lines (`31.0 MB`)** of Wasefire/OpenSK debug telemetry (`--features=debug`) with **`0` panics, `0` HardFaults, `0` `[WARN]` or `[ERROR]` lines**, and **`5` clean hardware resets** during the `ClientPin1` and `ClientPin2` power-cycle lockout tests (`Authr-ClientPin2-Policy` `P-5` retried once automatically by Mocha after the board remained USB-powered through the J-Link port on the first prompt, then passed `100%` on retry at `L32075`).

### 0.000.1 Run 21 Executive Summary (`09:46:00` – `10:11:28` PDT)

| Metric | Value in Run 21 | Source & Details |
| :--- | :--- | :--- |
| **Test Window & Duration** | **`09:46:00.569` – `10:11:28.126 PDT`** (**`25m 27.56s`** total elapsed) | `fido_conformance_debug.log` (`L99` first test start $\to$ `L35113` *"Testing finished. You may submit the results now."* out of `35,146` lines / `5.0 MB`) |
| **Overall Test Outcome** | **`250 Passed / 33 Skipped / 0 Failed / 1 Retried` (`100.00%` PASS)** | `284` total test starts across `283` unique test cases; **`0` `[TEST FAILED]` events** |
| **Provisioned LMS Hierarchy** | `1` LMS Root CA + `4` Pre-Published LMS Intermediate CAs (`LMS_SHA256_M32_H5` + `LMOTS_SHA256_N32_W8`, `1,296 B` sig) + `3` LMS-signed `ML-DSA-44/65/87` Batch X.509 certs + `3` LMS-signed Enterprise X.509 certs + `alg: -46` (`HSS-LMS`) `mtcTrustAnchors` (`g5k_AQE`, `g5k_AQI`) | Generated deterministically by `scripts/generate_lms_pki.py` into `src/ctap/crypto_data.rs` and `fido-mds3.json` |
| **Hardware RTT Log (`opensk_rtt.log`)** | **`304,967` lines (`31.0 MB`)** | **`0` panics, `0` HardFaults, `0` `[WARN]`/`[ERROR]` lines** across `100` `AuthenticatorMakeCredential` and `69` `AuthenticatorGetAssertion` hardware executions; `5` physical board resets (`RTT L280798`, `L281602`, `L282001`, `L282840`, `L283825`) |

### 0.000.2 Run 21 `Authr-MakeCred-Resp-1` (`P-01`..`F-01`): All 18 Algorithms (`Log L4576–L6889`, `RTT L37275–L74230`)

| # | Algorithm | COSE `alg` | Attestation Format | `BCNT` | Debug Log Lines | RTT Log Lines | Total USB Exchange Time | RTT MCU Command Execution (`64 MHz` DWT) |
| :-: | :--- | :---: | :---: | :---: | :--- | :--- | :---: | :--- |
| 1 | `RS256` (RSA-2048) | `-257` | `"packed"` (`ES256` `x5c`) | `1,250 B` | `L4576–L4615` | `L37275–L37398` | `2,565.4 ms` | `1,177.47 ms` (`75,358,336 cyc`) |
| 2 | **`FN-DSA-1024`** (Draft FIPS 206) | **`-61`** | **`"mtc"` (`g5k_AQE`, LMS checkpoint)** | **`6,067 B`** | `L4652–L4772` | `L38220–L38378` | **`6,778.1 ms`** | **`1,011.13 ms` (`64,712,064 cyc`)** |
| 3 | **`FN-DSA-512`** (Draft FIPS 206) | **`-60`** | **`"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`)** | **`6,692 B`** | `L4809–L4940` | `L40981–L41153` | **`6,586.8 ms`** | **`1,168.09 ms` (`74,757,440 cyc`)** |
| 4 | `MLDSA87-Ed448` | `-59` | `"mtc"` (`g5k_AQE`, LMS checkpoint) | `6,688 B` | `L4977–L5108` | `L43816–L43988` | `7,281.9 ms` | `1,284.79 ms` (`82,226,432 cyc`) |
| 5 | `MLDSA65-Ed25519` | `-58` | `"mtc"` (`g5k_AQE`, LMS checkpoint) | `6,258 B` | `L5145–L5269` | `L46559–L46730` | `6,775.7 ms` | `946.05 ms` (`60,547,072 cyc`) |
| 6 | `MLDSA44-Ed25519` | `-57` | `"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`) | `7,139 B` | `L5306–L5445` | `L49282–L49461` | `6,721.1 ms` | `848.79 ms` (`54,322,560 cyc`) |
| 7 | `MLDSA87-ES384` | `-56` | `"mtc"` (`g5k_AQE`, LMS checkpoint) | `6,728 B` | `L5482–L5614` | `L52163–L52300` | `9,136.6 ms` | `2,518.70 ms` (`161,196,672 cyc`) |
| 8 | `MLDSA65-ES256` | `-55` | `"mtc"` (`g5k_AQE`, LMS checkpoint) | `6,291 B` | `L5651–L5775` | `L54991–L55130` | `7,953.1 ms` | `1,814.96 ms` (`116,157,568 cyc`) |
| 9 | `MLDSA44-ES256` | `-54` | `"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`) | `7,172 B` | `L5812–L5951` | `L57717–L57890` | `7,253.4 ms` | `1,101.56 ms` (`70,499,840 cyc`) |
| 10 | `ML-DSA-87` (FIPS 204) | `-50` | `"mtc"` (`g5k_AQE`, LMS checkpoint) | `6,676 B` | `L5988–L6119` | `L60791–L60957` | `7,240.6 ms` | `893.13 ms` (`57,160,448 cyc`) |
| 11 | `ML-DSA-65` (FIPS 204) | `-49` | `"mtc"` (`g5k_AQE`, LMS checkpoint) | `6,226 B` | `L6156–L6279` | `L63758–L63925` | `7,387.2 ms` | `1,366.54 ms` (`87,458,304 cyc`) |
| 12 | `ML-DSA-44` (FIPS 204) | `-48` | `"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`) | `7,107 B` | `L6316–L6454` | `L66566–L66710` | `6,879.4 ms` | `658.42 ms` (`42,138,944 cyc`) |
| 13 | `Ed448` (RFC 8032) | `-53` | `"packed"` (`ES256` `x5c`) | `1,045 B` | `L6491–L6526` | `L69673–L69830` | `2,368.2 ms` | `1,313.33 ms` (`84,052,864 cyc`) |
| 14 | `EdDSA` (Ed25519) | `-8` | `"packed"` (`ES256` `x5c`) | `1,019 B` | `L6563–L6598` | `L70572–L70745` | `2,097.6 ms` | `1,056.65 ms` (`67,625,600 cyc`) |
| 15 | `ES256K` (secp256k1) | `-47` | `"packed"` (`ES256` `x5c`) | `1,056 B` | `L6635–L6670` | `L71433–L71600` | `2,102.9 ms` | `1,056.31 ms` (`67,603,648 cyc`) |
| 16 | `ES512` (P-521) | `-36` | `"packed"` (`ES256` `x5c`) | `1,122 B` | `L6707–L6744` | `L72313–L72475` | `2,750.2 ms` | `1,674.33 ms` (`107,157,376 cyc`) |
| 17 | `ES384` (P-384) | `-35` | `"packed"` (`ES256` `x5c`) | `1,088 B` | `L6781–L6817` | `L73194–L73373` | `3,307.4 ms` | `2,225.16 ms` (`142,410,176 cyc`) |
| 18 | `ES256` (P-256) | `-7` | `"packed"` (`ES256` `x5c`) | `1,055 B` | `L6854–L6889` | `L74059–L74230` | `2,729.7 ms` | `1,624.01 ms` (`103,936,576 cyc`) |

### 0.000.3 Run 21 `Authr-GetAssertion-Resp-1` (`P-1`..`P-5`): All 18 Algorithms (`Log L13064–L16979`, `RTT L87468–L146910`)

| # | Algorithm | COSE `alg` | `BCNT` (Sig Size) | Debug Log Lines | RTT Log Lines | Total USB Exchange Time | RTT MCU Command Execution (`64 MHz` DWT) |
| :-: | :--- | :---: | :---: | :--- | :--- | :---: | :--- |
| 1 | `ES256` (P-256) | `-7` | `378 B` (`70 B`) | `L13064–L13090` | `L87468–L87623` | `1,715.0 ms` | **`1,044.32 ms`** (`66,836,736 cyc`) |
| 2 | `ES384` (P-384) | `-35` | `412 B` (`103 B`) | `L13200–L13227` | `L89049–L89189` | `3,590.3 ms` | **`2,784.06 ms`** (`178,179,904 cyc`) |
| 3 | `ES512` (P-521) | `-36` | `446 B` (`138 B`) | `L13338–L13365` | `L90655–L90818` | `2,627.2 ms` | **`1,809.96 ms`** (`115,837,312 cyc`) |
| 4 | `ES256K` (secp256k1) | `-47` | `378 B` (`71 B`) | `L13474–L13500` | `L92237–L92380` | `1,216.3 ms` | **`517.37 ms`** (`33,111,680 cyc`) |
| 5 | `EdDSA` (Ed25519) | `-8` | `372 B` (`64 B`) | `L13609–L13635` | `L93816–L93977` | `1,157.6 ms` | **`482.79 ms`** (`30,898,432 cyc`) |
| 6 | `Ed448` (RFC 8032) | `-53` | `422 B` (`114 B`) | `L13744–L13771` | `L95336–L95492` | `1,899.5 ms` | **`1,071.25 ms`** (`68,559,808 cyc`) |
| 7 | `ML-DSA-44` (FIPS 204) | `-48` | `2,729 B` (`2,420 B`) | `L13983–L14049` | `L99060–L99217` | `3,812.2 ms` | **`989.23 ms`** (`63,310,976 cyc`) |
| 8 | `ML-DSA-65` (FIPS 204) | `-49` | `3,618 B` (`3,309 B`) | `L14246–L14327` | `L103238–L103387` | `5,241.6 ms` | **`1,257.12 ms`** (`80,455,872 cyc`) |
| 9 | `ML-DSA-87` (FIPS 204) | `-50` | `4,746 B` (`4,627 B`) | `L14533–L14631` | `L107822–L107964` | `7,162.6 ms` | **`2,526.08 ms`** (`161,669,120 cyc`) |
| 10 | `MLDSA44-ES256` | `-54` | `2,799 B` (`2,490 B`) | `L14844–L14911` | `L112913–L113079` | `4,440.2 ms` | **`1,549.33 ms`** (`99,157,184 cyc`) |
| 11 | `MLDSA65-ES256` | `-55` | `3,688 B` (`3,379 B`) | `L15109–L15191` | `L117220–L117369` | `7,566.3 ms` | **`3,877.08 ms`** (`248,133,312 cyc`) |
| 12 | `MLDSA87-ES384` | `-56` | `4,802 B` (`4,722 B`) | `L15397–L15494` | `L121788–L121934` | `12,802.7 ms` | **`8,266.79 ms`** (`529,074,688 cyc`) |
| 13 | `MLDSA44-Ed25519` | `-57` | `2,793 B` (`2,484 B`) | `L15707–L15774` | `L127180–L127330` | `4,748.8 ms` | **`1,842.81 ms`** (`117,939,648 cyc`) |
| 14 | `MLDSA65-Ed25519` | `-58` | `3,682 B` (`3,373 B`) | `L15972–L16054` | `L131503–L131649` | `4,875.0 ms` | **`861.53 ms`** (`55,138,176 cyc`) |
| 15 | `MLDSA87-Ed448` | `-59` | `4,814 B` (`4,741 B`) | `L16259–L16356` | `L136274–L136428` | `6,479.3 ms` | **`1,851.21 ms`** (`118,477,248 cyc`) |
| 16 | **`FN-DSA-512`** (Draft FIPS 206) | **`-60`** | **`975 B` (`666 B`)** | `L16561–L16597` | `L141203–L141342` | **`2,601.0 ms`** | **`1,333.49 ms` (`85,343,360 cyc`)** |
| 17 | **`FN-DSA-1024`** (Draft FIPS 206) | **`-61`** | **`1,589 B` (`1,280 B`)** | `L16791–L16837` | `L144720–L144876` | **`4,196.3 ms`** | **`2,420.23 ms` (`154,894,528 cyc`)** |
| 18 | `RS256` (RSA-2048) | `-257` | `565 B` (`256 B`) | `L16950–L16979` | `L146755–L146910` | `5,527.9 ms` | **`4,654.80 ms`** (`297,907,072 cyc`) |

### 0.000.4 Run 21 Complete Conformance Suite Summary (`09:46:00` – `10:11:28` PDT)

| # | Category | Suite ID | Unique Tests | Passed | Skipped | Retried | Duration | Log Line Range |
| :-: | :--- | :--- | :-: | :-: | :-: | :-: | --: | :--- |
| 1 | Transports | `HID-1` | 19 | 16 | 3 | 0 | `19.92s` | `L99–L816` |
| 2 | General | `Authr-Generic-1` | 5 | 5 | 0 | 0 | `14.28s` | `L867–L1399` |
| 3 | MakeCredentialRequest | `Authr-MakeCred-Req-1`..`Req-5` | 36 | 36 | 0 | 0 | `86.65s` | `L1518–L4278` |
| 4 | MakeCredentialRequest | `Authr-MakeCred-Req-6` | 4 | 3 | 1 | 0 | `129.96s` | `L4283–L6899` |
| 5 | MakeCredentialResponse | `Authr-MakeCred-Resp-1` (Packed LMS `x5c` & `mtc`) | 5 | 4 | 1 | 0 | `0.27s`* | `L6908–L11502` |
| 6 | GetAssertionReq | `Authr-GetAssertion-Req-1` | 8 | 8 | 0 | 0 | `20.10s` | `L11694–L12307` |
| 7 | GetAssertionReq | `Authr-GetAssertion-Req-2` | 3 | 2 | 1 | 0 | `11.63s` | `L12312–L12575` |
| 8 | GetAssertionReq | `Authr-GetAssertion-Req-3` | 6 | 5 | 1 | 0 | `235.81s`* | `L12580–L16979` |
| 9 | GetAssertionResp | `Authr-GetAssertion-Resp-1` | 5 | 5 | 0 | 0 | `9.40s` | `L16980–L17227` |
| 10 | Reset | `Authr-Reset-1` | 1 | 1 | 0 | 0 | `13.37s` | `L17340–L17655` |
| 11 | OptionsRK | `Discoverable Credentials (Resident-Key)` | 6 | 5 | 1 | 0 | `44.24s` | `L17708–L18583` |
| 12 | OptionsEP | `Enterprise Attestation` (`mtc` `g5k_AQI` + LMS `x5c`) | 9 | 6 | 3 | 0 | `31.23s` | `L18748–L19558` |
| 13 | Extensions | `HMAC-Secret` (`hmacSecret.js` & `hmacSecret2.js`) | 24 | 24 | 0 | 0 | `115.27s` | `L19701–L22380` |
| 14 | Extensions | `HMAC-Secret MC` (`hmacSecretMC.js`) | 28 | 26 | 2 | 0 | `142.52s` | `L22414–L25765` |
| 15 | Extensions | `CredProtect` | 4 | 4 | 0 | 0 | `24.30s` | `L25770–L26299` |
| 16 | Extensions | `CredBlob` | 3 | 3 | 0 | 0 | `16.00s` | `L26305–L26641` |
| 17 | Extensions | `LargeBlob` & `LargeBlobKey` | 8 | 8 | 0 | 0 | `29.13s` | `L26649–L27388` |
| 18 | Extensions | `MinPinLength` / `PinComplexity` / `ThirdPartyPayment` / `UVM` | 3 | 3 | 0 | 0 | `25.42s` | `L27395–L27957` |
| 19 | ClientPin1 | `KeyAgreement`, `NewPin`, `Policy`, `GetRetries` | 19 | 16 | 3 | 0 | `80.31s` | `L27979–L29289` |
| 20 | ClientPin2 | `KeyAgreement`, `NewPin`, `GetPinToken`, `PinWithPermissions` | 17 | 16 | 1 | 0 | `39.20s` | `L29317–L30581` |
| 21 | ClientPin2 | `Policy` & `GetRetries` (incl. power-cycle lockout `P-5`) | 11 | 9 | 2 | 1 | `199.29s` | `L30601–L32075` |
| 22 | CredManAPI | `EnumerateRPs`, `EnumerateCredentials`, `UpdateAndDelete` | 11 | 11 | 0 | 0 | `46.53s` | `L32189–L33538` |
| 23 | AuthenticatorConfig | `Authr-AuthenticatorConfig` | 7 | 5 | 2 | 0 | `22.37s` | `L33652–L34408` |
| 24 | LargeBlobs | `Authr-LargeBlobs-1` | 4 | 4 | 0 | 0 | `2.30s` | `L34409–L34562` |
| 25 | Metadata | `Metadata-Stmt-1` (`P-1`..`P-43`, incl. `mtcTrustAnchors`) | 37 | 25 | 12 | 0 | `244.58s` | `L34571–L35146` |
| **Total** | | **All Active USB HID Suites** | **283** | **250** | **33** | **1** | **`25m 27.56s`** | `L99–L35146` |

---

## 0.00 Run 20 (`250 / 250` `100.00%` Pass) Deep Dive: RFC 8554 / NIST SP 800-208 HSS/LMS Certificate Hierarchy, Post-Quantum MTC Subtree Checkpoints (`alg: -46`) & All 18 Algorithms Across `fido_conformance_debug.log` & `fidont_rtt.log`

> [!IMPORTANT]
> **`250 / 250` (`100.00%`) Pass with RFC 8554 / NIST SP 800-208 HSS/LMS X.509 Hierarchy & HSS/LMS (`alg: -46`) MTC Subtree Checkpoints**:
> In Run 20 (`23:13:01.498` – `23:58:36.543 PDT`), we validated the complete stateful hash-based signature hierarchy (`HSS/LMS`, RFC 8554 / NIST SP 800-208, `L=1`, `LMS_SHA256_M32_H5` / `LMOTS_SHA256_N32_W8`, X.509 OID `1.2.840.113549.1.9.16.3.17`, COSE `alg: -46`, `kty: 6`) across both `"packed"` X.509 chains and `"mtc"` / `"mtcl"` Merkle Tree Certificate subtree checkpoints, achieving **`250 Passed / 32 Skipped / 0 Failed` (`100.00%` PASS)** across all 37 CTAP 2.3 suites:
> - **UX Metadata Statement Persistence**: Updated `controller.js` (`processMetadataInfo` and `buttonClearAuthenticatorInfo`) so the FIDO Conformance Testing Tool strictly persists and uses the metadata statement loaded in the UX Metadata Statement dialog (`"description": "Fidont use this key1"`).
> - **Pre-Published HSS/LMS Root & Intermediate CAs (`attestationRootCertificates`)**: Verified `1` self-signed `Fidont LMS Root CA` (`32`-leaf LMS tree) + `4` pre-published `Fidont LMS Intermediate CA #0..#3` (`32`-leaf LMS trees, `128` total leaf capacity) + `1` `Fidont Enterprise Root CA ES384`. For 1-step PQ algorithms (`ML-DSA-44` `-48`, `MLDSA44-ES256` `-54`, `MLDSA44-Ed25519` `-57`, `FN-DSA-512` `-60`), Fidont returns a single `ML-DSA-44` leaf certificate in `attStmt.x5c` (`2,854 B`, signed by `Fidont LMS Intermediate CA #0`) that chains directly to the pre-published intermediate CA in `attestationRootCertificates`, keeping the entire `"packed"` `MakeCredential` response within `6,693–7,173 B` (`\le 7,550 B` CTAPHID buffer limit).
> - **HSS/LMS (`alg: -46`) Signed MTC Subtree Checkpoints (`mtcTrustAnchors`)**: For 2-step PQ and composite algorithms (`ML-DSA-65` `-49`, `ML-DSA-87` `-50`, `MLDSA65-ES256` `-55`, `MLDSA87-ES384` `-56`, `MLDSA65-Ed25519` `-58`, `MLDSA87-Ed448` `-59`, `FN-DSA-1024` `-61`), Fidont uses the `ML-DSA-44` MTC batch key (`caId: "g5k_AQE"` standard / `"g5k_AQI"` enterprise) whose Merkle subtree checkpoint (`startIndex: 0`, `endIndex: 16`, `rootHash`) is signed with `HSS/LMS` (`alg: -46`, `1,252 B` signature) by the `Fidont LMS Root CA`.

### 0.00.1 Run 20 Executive Summary (`23:13:01` – `23:58:36` PDT)

| Metric | Value in Run 20 | Source & Details |
| :--- | :--- | :--- |
| **Test Window** | **`23:13:01.498` – `23:58:36.543 PDT`** (`45m 35s` wall-clock; `~19m 24s` active execution) | `fido_conformance_debug.log` (`lines 155,031–211,147` of `211,147` total lines; `28.31 MB`) |
| **Overall Test Outcome** | **`250 Passed / 32 Skipped / 0 Failed` (`100.00%` PASS)** | **Zero failures across all `282` CTAP 2.3 conformance tests** across all `37` test suites |
| **Configured Algorithms (`18`)** | `ES256 (-7)`, `ES384 (-35)`, `ES512 (-36)`, `ES256K (-47)`, `Ed25519 (-8)`, `Ed448 (-53)`, `ML-DSA-44 (-48)`, `ML-DSA-65 (-49)`, `ML-DSA-87 (-50)`, `MLDSA44-ES256 (-54)`, `MLDSA65-ES256 (-55)`, `MLDSA87-ES384 (-56)`, `MLDSA44-Ed25519 (-57)`, `MLDSA65-Ed25519 (-58)`, `MLDSA87-Ed448 (-59)`, **`FN-DSA-512 (-60)`**, **`FN-DSA-1024 (-61)`**, `RS256 (-257)` | All `18` algorithms verified end-to-end in `Authr-MakeCred-Resp-1.js` (`L162196–L171304`) and `Authr-GetAssertion-Resp-1.js` (`L172950–L181950`) |
| **Metadata Statement Source** | UX Metadata Statement Dialog (`"description": "Fidont use this key1"`) | Loaded via `controller.js` (`processMetadataInfo` / `saveTestConfig()`) |
| **HSS/LMS X.509 & MTC Hierarchy** | `1` Self-Signed `Fidont LMS Root CA` + `4` Pre-Published `Fidont LMS Intermediate CA #0..#3` (`LMS_SHA256_M32_H5` / `LMOTS_SHA256_N32_W8`, OID `1.2.840.113549.1.9.16.3.17`) + `1` `Fidont Enterprise Root CA ES384` + `2` HSS/LMS-signed (`alg: -46`) `mtcTrustAnchors` (`caId: "g5k_AQE"`, `caId: "g5k_AQI"`) | Verified in `Authr-MakeCred-Resp-1.js` (`P-04`, `L166786–L171268`), `EntepriseAttestation.js` (`L185357–L186970`), and `Metadata-Stmt-1.js` (`P-27`, `L210690–L210699`) |
| **Device RTT Log (`fidont_rtt.log`)** | `fidont_rtt.log` (`lines 860,546–1,163,679` of `1,163,679` lines; `124.54 MB`) | **`0` panics, `0` OOMs, `0` HardFaults** across all `111` `MakeCredential` and `75` `GetAssertion` hardware executions |

### 0.00.2 Run 20 `Authr-MakeCred-Resp-1` (`P-01`..`F-01`): All 18 Algorithms (`Log L162196–L171304`, `RTT L918000–L956650`)

| # | Algorithm | COSE `alg` | Attestation Format | `BCNT` | Debug Log Lines | RTT Log Lines | Total USB Exchange Time | RTT Pure Crypto Keygen + Attestation Sign (`64 MHz` DWT) |
| :-: | :--- | :---: | :---: | :---: | :--- | :--- | :---: | :--- |
| 1 | `RS256` (RSA-2048) | `-257` | `"packed"` (`ES256` `x5c`) | `1,250 B` | `L162196–L162276` | `L920563–L920740` | `2,201.8 ms` | `789.82 ms` (`ES256` att sig) |
| 2 | **`FN-DSA-1024`** (Draft FIPS 206) | **`-61`** | **`"mtcl"` (`ML-DSA-44` batch)** | **`6,068 B`** | `L162334–L162586` | `L923435–L923604` | **`7,250.5 ms`** | **`650.86 ms` (`41.66M` cyc `ML-DSA-44` att sig)** |
| 3 | **`FN-DSA-512`** (Draft FIPS 206) | **`-60`** | **`"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`)** | **`6,693 B`** | `L162644–L162915` | `L926206–L926360` | **`6,269.9 ms`** | **`1,163.23 ms` (`74.45M` cyc `ML-DSA-44` att sig)** |
| 4 | `MLDSA87-Ed448` | `-59` | `"mtcl"` (`ML-DSA-44` batch) | `6,689 B` | `L162973–L163247` | `L928804–L928983` | `7,119.2 ms` | `1,612.45 ms` (`Ed448` keygen + `ML-DSA-44` att sig) |
| 5 | `MLDSA65-Ed25519` | `-58` | `"mtcl"` (`ML-DSA-44` batch) | `6,259 B` | `L163305–L163563` | `L931767–L931928` | `6,460.6 ms` | `1,019.02 ms` (`Ed25519` keygen + `ML-DSA-44` att sig) |
| 6 | `MLDSA44-Ed25519` | `-57` | `"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`) | `7,140 B` | `L163621–L163908` | `L932622–L932790` | `6,447.0 ms` | `765.96 ms` (`Ed25519` keygen + `ML-DSA-44` att sig) |
| 7 | `MLDSA87-ES384` | `-56` | `"mtcl"` (`ML-DSA-44` batch) | `6,729 B` | `L163966–L164247` | `L935318–L935498` | `8,922.1 ms` | `1,879.38 ms` (`P-384` keygen + `ML-DSA-44` att sig) |
| 8 | `MLDSA65-ES256` | `-55` | `"mtcl"` (`ML-DSA-44` batch) | `6,292 B` | `L164305–L164564` | `L936223–L936408` | `6,949.4 ms` | `1,334.44 ms` (`P-256` keygen + `ML-DSA-44` att sig) |
| 9 | `MLDSA44-ES256` | `-54` | `"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`) | `7,173 B` | `L164622–L164910` | `L938429–L938613` | `6,680.9 ms` | `1,364.02 ms` (`P-256` keygen + `ML-DSA-44` att sig) |
| 10 | `ML-DSA-87` (FIPS 204) | `-50` | `"mtcl"` (`ML-DSA-44` batch) | `6,677 B` | `L164968–L165241` | `L942333–L942517` | `7,006.3 ms` | `1,334.78 ms` (`85.43M` cyc keygen + `ML-DSA-44` att sig) |
| 11 | `ML-DSA-65` (FIPS 204) | `-49` | `"mtcl"` (`ML-DSA-44` batch) | `6,227 B` | `L165299–L165557` | `L944975–L945168` | `7,037.5 ms` | `1,334.75 ms` (`85.42M` cyc keygen + `ML-DSA-44` att sig) |
| 12 | `ML-DSA-44` (FIPS 204) | `-48` | `"packed"` (`LMS` $\to$ `ML-DSA-44` `x5c`) | `7,108 B` | `L165615–L165900` | `L948707–L948888` | `6,529.8 ms` | `1,334.68 ms` (`85.42M` cyc keygen + `ML-DSA-44` att sig) |
| 13 | `Ed448` (RFC 8032) | `-53` | `"packed"` (`ES256` `x5c`) | `1,047 B` | `L165958–L166030` | `L950241–L950404` | `2,395.7 ms` | `1,019.15 ms` (`Ed448` keygen + `ES256` att sig) |
| 14 | `EdDSA` (Ed25519) | `-8` | `"packed"` (`ES256` `x5c`) | `1,020 B` | `L166088–L166159` | `L953395–L953563` | `2,039.9 ms` | `759.12 ms` (`Ed25519` keygen + `ES256` att sig) |
| 15 | `ES256K` (secp256k1) | `-47` | `"packed"` (`ES256` `x5c`) | `1,055 B` | `L166217–L166288` | `L954922–L955102` | `2,043.0 ms` | `799.29 ms` (`k256` keygen + `ES256` att sig) |
| 16 | `ES512` (P-521) | `-36` | `"packed"` (`ES256` `x5c`) | `1,123 B` | `L166346–L166424` | `L950241–L950404` | `2,835.7 ms` | `1,879.72 ms` (`P-521` keygen + `ES256` att sig) |
| 17 | `ES384` (P-384) | `-35` | `"packed"` (`ES256` `x5c`) | `1,089 B` | `L166482–L166559` | `L951817–L951979` | `3,272.4 ms` | `2,419.86 ms` (`P-384` keygen + `ES256` att sig) |
| 18 | `ES256` (P-256) | `-7` | `"packed"` (`ES256` `x5c`) | `1,054 B` | `L166617–L166691` | `L956483–L956646` | `2,672.4 ms` | `1,334.68 ms` (`P-256` keygen + `ES256` att sig) |

### 0.00.3 Run 20 `Authr-GetAssertion-Resp-1` (`P-1`..`P-5`): All 18 Algorithms (`Log L173832–L181628`, `RTT L949593–L1008688`)

| # | Algorithm | COSE `alg` | `BCNT` (Sig Size) | Debug Log Lines | RTT Log Lines | Total USB Exchange Time | RTT Pure CPU Sign (`64 MHz` DWT Cycles) |
| :-: | :--- | :---: | :---: | :--- | :--- | :---: | :--- |
| 1 | `ES256` (P-256) | `-7` | `379 B` (`70 B`) | `L173832–L173885` | `L949593–L949760` | `1,751.5 ms` | **`712.92 ms`** (`45,626,688 cyc`) |
| 2 | `ES384` (P-384) | `-35` | `412 B` (`103 B`) | `L174078–L174139` | `L951154–L951312` | `3,489.3 ms` | **`2,453.91 ms`** (`157,050,303 cyc`) |
| 3 | `ES512` (P-521) | `-36` | `447 B` (`138 B`) | `L174336–L174393` | `L952740–L952886` | `2,471.8 ms` | **`1,454.10 ms`** (`93,062,335 cyc`) |
| 4 | `ES256K` (secp256k1) | `-47` | `380 B` (`71 B`) | `L174580–L174631` | `L954270–L954425` | `1,240.1 ms` | **`181.95 ms`** (`11,644,800 cyc`) |
| 5 | `EdDSA` (Ed25519) | `-8` | `373 B` (`64 B`) | `L174819–L174870` | `L955852–L956003` | `1,144.4 ms` | **`146.13 ms`** (`9,352,448 cyc`) |
| 6 | `Ed448` (RFC 8032) | `-53` | `423 B` (`114 B`) | `L175058–L175113` | `L957317–L957484` | `1,736.5 ms` | **`723.57 ms`** (`46,308,352 cyc`) |
| 7 | `ML-DSA-44` (FIPS 204) | `-48` | `2,730 B` (`2,420 B`) | `L175515–L175650` | `L960946–L961113` | `3,279.0 ms` | **`285.68 ms`** (`18,283,455 cyc`) |
| 8 | `ML-DSA-65` (FIPS 204) | `-49` | `3,619 B` (`3,309 B`) | `L176023–L176192` | `L965149–L965304` | `4,712.8 ms` | **`947.71 ms`** (`60,653,376 cyc`) |
| 9 | `ML-DSA-87` (FIPS 204) | `-50` | `4,747 B` (`4,627 B`) | `L176585–L176787` | `L969890–L970062` | `5,877.4 ms` | **`1,156.98 ms`** (`74,046,848 cyc`) |
| 10 | `MLDSA44-ES256` | `-54` | `2,802 B` (`2,492 B`) | `L177193–L177333` | `L975080–L975250` | `4,141.0 ms` | **`964.34 ms`** (`61,718,015 cyc`) |
| 11 | `MLDSA65-ES256` | `-55` | `3,690 B` (`3,379 B`) | `L177708–L177887` | `L979373–L979530` | `7,297.4 ms` | **`3,401.39 ms`** (`217,689,215 cyc`) |
| 12 | `MLDSA87-ES384` | `-56` | `4,803 B` (`4,722 B`) | `L178281–L178491` | `L983944–L984091` | `7,713.6 ms` | **`3,031.64 ms`** (`194,025,215 cyc`) |
| 13 | `MLDSA44-Ed25519` | `-57` | `2,794 B` (`2,484 B`) | `L178894–L179032` | `L989045–L989197` | `3,601.0 ms` | **`523.13 ms`** (`33,480,063 cyc`) |
| 14 | `MLDSA65-Ed25519` | `-58` | `3,683 B` (`3,373 B`) | `L179407–L179576` | `L993208–L993353` | `4,328.3 ms` | **`522.89 ms`** (`33,465,024 cyc`) |
| 15 | `MLDSA87-Ed448` | `-59` | `4,815 B` (`4,741 B`) | `L179967–L180175` | `L997859–L998005` | `6,993.1 ms` | **`2,396.35 ms`** (`153,366,527 cyc`) |
| 16 | **`FN-DSA-512`** (Draft FIPS 206) | **`-60`** | **`976 B` (`666 B`)** | `L180560–L180635` | `L1002902–L1003067` | **`2,475.9 ms`** | **`993.71 ms` (`63,597,439 cyc`)** |
| 17 | **`FN-DSA-1024`** (Draft FIPS 206) | **`-61`** | **`1,590 B` (`1,280 B`)** | `L181003–L181102` | `L1006466–L1006619` | **`4,155.7 ms`** | **`2,087.65 ms` (`133,609,792 cyc`)** |
| 18 | `RS256` (RSA-2048) | `-257` | `566 B` (`256 B`) | `L181298–L181369` | `L1008526–L1008688` | `5,564.0 ms` | **`4,331.27 ms`** (`277,201,088 cyc`) |

### 0.00.4 Run 20 Complete 37-Suite Conformance Summary (`23:13:01` – `23:58:36` PDT)

| # | Suite | Log Line | Time Window (PDT) | Passed | Failed | Skipped | Status |
| :-: | :--- | :--- | :--- | :-: | :-: | :-: | :-: |
| 1 | `Transport-HID-1.js` | `L155175` | `23:13:01` – `23:13:20` | 16 | 0 | 3 | PASS |
| 2 | `Authr-Generic-1.js` | `L156352` | `23:13:22` – `23:13:36` | 5 | 0 | 0 | PASS |
| 3 | `Authr-MakeCred-Req-1.js` | `L157373` | `23:13:40` – `23:14:11` | 17 | 0 | 0 | PASS |
| 4 | `Authr-MakeCred-Req-2.js` | `L159266` | `23:14:11` – `23:14:27` | 8 | 0 | 0 | PASS |
| 5 | `Authr-MakeCred-Req-3.js` | `L160176` | `23:14:27` – `23:15:00` | 10 | 0 | 0 | PASS |
| 6 | `Authr-MakeCred-Req-4.js` | `L161652` | `23:15:00` – `23:15:12` | 3 | 0 | 1 | PASS |
| 7 | `Authr-MakeCred-Resp-1.js` | `L166692` | `23:15:12` – `23:17:08` | 5 | 0 | 1 | PASS |
| 8 | `Authr-GetAssertion-Req-1.js` | `L171642` | `23:17:17` – `23:17:28` | 7 | 0 | 0 | PASS |
| 9 | `Authr-GetAssertion-Req-2.js` | `L172501` | `23:17:33` – `23:17:39` | 2 | 0 | 1 | PASS |
| 10 | `Authr-GetAssertion-Req-3.js` | `L172950` | `23:17:44` – `23:17:55` | 6 | 0 | 1 | PASS |
| 11 | `Authr-GetAssertion-Resp-1.js` | `L181370` | `23:17:55` – `23:21:39` | 5 | 0 | 0 | PASS |
| 12 | `Authr-Reset-1.js` | `L181952` | `23:21:43` – `23:34:28` | 6 | 0 | 1 | PASS |
| 13 | `EntepriseAttestation.js` | `L185357` | `23:34:34` – `23:35:04` | 6 | 0 | 3 | PASS |
| 14 | `Authr-Options-rk-1.js` | `L186978` | `23:35:09` – `23:36:01` | 12 | 0 | 0 | PASS |
| 15 | `Authr-Options-up-1.js` | `L189283` | `23:36:03` – `23:36:58` | 12 | 0 | 0 | PASS |
| 16 | `Authr-Options-uv-1.js` | `L191572` | `23:36:59` – `23:39:21` | 26 | 0 | 2 | PASS |
| 17 | `Authr-Extensions-HmacSecret-1.js` | `L197282` | `23:39:21` – `23:39:44` | 4 | 0 | 0 | PASS |
| 18 | `Authr-Extensions-credBlob.js` | `L198183` | `23:39:44` – `23:39:59` | 3 | 0 | 0 | PASS |
| 19 | `Authr-Extensions-largeBlobKey.js` | `L198762` | `23:39:59` – `23:40:17` | 6 | 0 | 0 | PASS |
| 20 | `Authr-Extensions-minPinLength.js` | `L199581` | `23:40:17` – `23:40:27` | 2 | 0 | 0 | PASS |
| 21 | `Authr-Extensions-thirdPartyPayment.js` | `L199988` | `23:40:27` – `23:40:52` | 3 | 0 | 0 | PASS |
| 22 | `Authr-ClientPin1-KeyAgreement-1.js` | `L200985` | `23:40:53` – `23:40:54` | 1 | 0 | 0 | PASS |
| 23 | `Authr-ClientPin1-SetPin-1.js` | `L201062` | `23:40:55` – `23:41:12` | 7 | 0 | 0 | PASS |
| 24 | `Authr-ClientPin1-ChangePin-1.js` | `L201935` | `23:41:14` – `23:41:19` | 4 | 0 | 1 | PASS |
| 25 | `Authr-ClientPin1-PinToken-1.js` | `L202354` | `23:41:22` – `23:55:43` | 3 | 0 | 1 | PASS |
| 26 | `Authr-ClientPin2-KeyAgreement-1.js` | `L202910` | `23:55:43` – `23:55:44` | 1 | 0 | 0 | PASS |
| 27 | `Authr-ClientPin2-SetPin-1.js` | `L202987` | `23:55:45` – `23:55:57` | 4 | 0 | 0 | PASS |
| 28 | `Authr-ClientPin2-PinToken-1.js` | `L203628` | `23:55:59` – `23:56:14` | 7 | 0 | 1 | PASS |
| 29 | `Authr-ClientPin2-GetPinUvAuthTokenUsingPinWithPermissions-1.js` | `L204466` | `23:56:16` – `23:56:28` | 5 | 0 | 0 | PASS |
| 30 | `Authr-ClientPin2-ChangePin-1.js` | `L205023` | `23:56:29` – `23:56:36` | 5 | 0 | 1 | PASS |
| 31 | `Authr-ClientPin2-PinRetries-1.js` | `L205466` | `23:56:38` – `23:57:19` | 4 | 0 | 1 | PASS |
| 32 | `Authr-CredMgmt-1.js` | `L206566` | `23:57:23` – `23:57:38` | 6 | 0 | 0 | PASS |
| 33 | `Authr-CredMgmt-2.js` | `L207644` | `23:57:46` – `23:57:51` | 3 | 0 | 0 | PASS |
| 34 | `Authr-CredMgmt-3.js` | `L208052` | `23:57:55` – `23:58:08` | 2 | 0 | 0 | PASS |
| 35 | `Authr-Config-1.js` | `L208925` | `23:58:12` – `23:58:28` | 5 | 0 | 2 | PASS |
| 36 | `Authr-LargeBlobs-1.js` | `L210136` | `23:58:34` – `23:58:36` | 4 | 0 | 0 | PASS |
| 37 | `Metadata-Stmt-1.js` | `L210360` | `23:58:36` – `23:58:36` | 25 | 0 | 12 | PASS |
| **Total** | **37 Suites** | | | **250** | **0** | **32** | **100.00%** |

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
| 2 | **`FN-DSA-1024`** (Draft FIPS 206) | **`-61`** | **`"mtc"` (`ML-DSA-87`)** | **`6,947 B` (`118f`)** | `L7238–L7508` | `L3556–L3808` (`0000013a`) | **`4,511.57 ms`** | **`2,492.31 ms`** | **`7,099.94 ms`** | **`583.20 ms` (`37.32M` cyc `ML-DSA-87` att sig, `RTT L37657`)** |
| 3 | **`FN-DSA-512`** (Draft FIPS 206) | **`-60`** | **`"mtc"` (`ML-DSA-87`)** | **`6,051 B` (`103f`)** | `L7577–L7817` | `L3836–L4058` (`0000013d`) | **`4,331.54 ms`** | **`2,132.27 ms`** | **`6,559.87 ms`** | **`865.05 ms` (`55.36M` cyc `ML-DSA-87` att sig, `RTT L40585`)** |
| 4 | `MLDSA87-Ed448` | `-59` | `"mtc"` (`ML-DSA-87`) | `7,568 B` (`129f`) | `L7886–L8185` | `L4086–L4362` (`00000140`) | `6,671.84 ms` | `2,724.34 ms` | `9,492.24 ms` | `2,479.35 ms` (`324.97 ms` keygen + `2,154.38 ms` sign, `RTT L43134..L43146`) |
| 5 | `MLDSA65-Ed25519` | `-58` | `"mtc"` (`ML-DSA-87`) | `7,138 B` (`122f`) | `L8254–L8541` | `L4390–L4652` (`00000143`) | `7,215.91 ms` | `2,688.34 ms` | `10,000.31 ms` | `3,172.62 ms` (`167.02 ms` keygen + `3,005.60 ms` sign, `RTT L46339..L46343`) |
| 6 | `MLDSA44-Ed25519` | `-57` | `"mtc"` (`ML-DSA-87`) | `6,498 B` (`111f`) | `L22436–L22695` | `L4848–L5086` (`00000148`) | `5,259.66 ms` | `2,400.30 ms` | `7,752.03 ms` | `1,505.47 ms` (`120.80 ms` keygen + `1,384.68 ms` sign, `RTT L50312..L50316`) |
| 7 | `MLDSA87-ES384` | `-56` | `"mtc"` (`ML-DSA-87`) | `7,608 B` (`129f`) | `L22764–L23067` | `L5114–L5390` (`0000014b`) | `7,059.89 ms` | `2,788.35 ms` | `9,944.30 ms` | `2,792.99 ms` (`1,185.00 ms` keygen + `1,608.00 ms` sign, `RTT L53206..L53218`) |
| 8 | `MLDSA65-ES256` | `-55` | `"mtc"` (`ML-DSA-87`) | `7,171 B` (`122f`) | `L23136–L23430` | `L5418–L5682` (`0000014e`) | `9,176.16 ms` | `2,624.33 ms` | `11,892.55 ms` | `5,118.96 ms` (`429.50 ms` keygen + `4,689.46 ms` sign, `RTT L56498..L56502`) |
| 9 | `MLDSA44-ES256` | `-54` | `"mtc"` (`ML-DSA-87`) | `6,531 B` (`111f`) | `L23499–L23760` | `L5710–L5948` (`00000151`) | `6,071.77 ms` | `2,332.29 ms` | `8,496.12 ms` | `2,315.26 ms` (`383.34 ms` keygen + `1,931.92 ms` sign, `RTT L59598..L59602`) |
| 10 | `ML-DSA-87` (FIPS 204) | `-50` | `"mtc"` (`ML-DSA-87`) | `7,556 B` (`129f`) | `L23829–L24124` | `L5976–L6250` (`00000154`) | `5,479.69 ms` | `2,700.34 ms` | `8,280.09 ms` | `1,301.27 ms` (`83.28M` cyc keygen + sign, `RTT L62383..L62384`) |
| 11 | `ML-DSA-65` (FIPS 204) | `-49` | `"mtc"` (`ML-DSA-87`) | `7,106 B` (`121f`) | `L24193–L24474` | `L6278–L6536` (`00000157`) | `6,095.77 ms` | `2,512.32 ms` | `8,704.15 ms` | `2,096.49 ms` (`134.18M` cyc keygen + sign, `RTT L65589..L65590`) |
| 12 | `ML-DSA-44` (FIPS 204) | `-48` | `"mtc"` (`ML-DSA-87`) | `6,466 B` (`110f`) | `L24543–L24800` | `L6564–L6800` (`0000015a`) | `5,455.69 ms` | `2,288.29 ms` | `7,836.04 ms` | `1,764.34 ms` (`112.92M` cyc keygen + sign, `RTT L68508..L68509`) |
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

### 0.3 Seven-Way Comparison: Run 10 (`-48` `--mtc-x5c`) vs. Run 11 (`-50` MTC) vs. Run 16 (Dual + `ep`) vs. Run 17 (Dual + `ep` + `perCredMgmtRO`) vs. Run 18 (18 Algs + RTT) vs. Run 19 (18 Algs + USB + RTT) vs. Run 20 (18 Algs + HSS/LMS `x5c` & MTC Subtrees)

| Metric | Run 10 (`-48` `--mtc-x5c`) | Run 11 (`-50` MTC) | Run 16 (Dual + `ep`) | Run 17 (16 Algs + `perCredMgmtRO`) | Run 18 (18 Algs + RTT) | Run 19 (18 Algs + USB + RTT) | Run 20 (18 Algs + HSS/LMS `x5c` & MTC) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Log Range & Duration** | `L287509–L347258` (`10m 14s`) | `L1–L56583` (`16m 35s`) | `L175680–L223190` (`15m 33s`) | `L1–L48653` (`12m 27s`) | `L1–L52180` (`20m 26s`) | `L1–L66127` (`21m 28s`) | **`L155031–L211147` (`45m 35s` wall / `~19m 24s` active)** |
| **Test Results** | `237 Passed / 0 Failed` | `237 Passed / 0 Failed` | `241 Passed / 41 Skipped / 0 Failed` | `250 Passed / 32 Skipped / 0 Failed` | `249 Passed / 34 Skipped / 1 Failed` | `250 Passed / 32 Skipped / 0 Failed` | **`250 Passed / 32 Skipped / 0 Failed (`100.00%`)`** |
| **Supported COSE Algorithms** | `16` algorithms | `16` algorithms | `16` algorithms | `16` algorithms | **`18` (`+FN-DSA-512/1024`)** | **`18` (`+FN-DSA-512/1024`)** | **`18` (`+FN-DSA-512/1024`)** |
| **Root & Intermediate CAs / MTC Anchor** | `ML-DSA-44` `x5c` + MTC | `ML-DSA-87` MTC | `ES384` `x5c` + `ML-DSA-44` MTC | `ES384` `x5c` + `ML-DSA-44` MTC | `ML-DSA-87` Root CA & MTC | `ML-DSA-87` Root CA & MTC | **`HSS/LMS` Root & `4` Intermediates (`1.2.840.113549.1.9.16.3.17`) + `HSS/LMS` (`alg: -46`) MTC Subtrees** |
| **`GetInfo` Wire Size (`BCNT`)** | `706 B` (`13` frames) | `706 B` (`13` frames) | `719 B` (`13` frames) | `793 B` (`14` frames) | `823 B` (`15` frames) | `823 B` (`15` frames) | **`823 B` (`15` frames, 18 algs + `perCredMgmtRO`)** |
| **`perCredMgmtRO` / `0x19` / `0x1E` Tests** | Skipped (`0/9`) | Skipped (`0/9`) | Skipped (`0/9`) | `9/9 Passed` (`100%`) | `7/7 Passed` (`100%`) | `9/9 Passed` (`100%`) | **`9/9 Passed (`100%`)`** |
| **Enterprise Profile (`EntepriseAttestation.js`)** | Skipped | Skipped | `6/6 Passed` | `6/6 Passed` | `6/6 Passed` | `6/6 Passed` | **`6/6 Passed (`P-1`..`P-3`, `F-4`..`F-6`)`** |
| **`Metadata-Stmt-1` Verification** | `37/37` Passed | `37/37` Passed | `37/37` Passed | `37/37` Passed | `37/37` Passed | `37/37` Passed | **`25/25` Applicable (`37/37`) Passed (`100%`)** |

### 0.4 `Authr-MakeCred-Resp-1` 16-Algorithm Sweep: Conformance Log vs. Total Phase Hardware USB Analyzer (`Run 17`)

| # | COSE `alg` | Algorithm Name | Run 17 `fmt` | Wire Size (`BCNT` / Frames) | Hardware MCU Compute Time (`totalphase.csv`) | USB `IN` Transfer Time (`totalphase.csv`) | Total USB Exchange Time (`totalphase.csv`) | Conformance Log Line | TotalPhase CSV Line Range |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `-257` | `RS256` | **`"packed"` (`ES384` `x5c`)** | **`1,250 B` (`22`)** | **`891.11 ms`** (`2` `KA`) | `84.01 ms` | `991.17 ms` | `L6959` | `CSV L3380–L3436` |
| 2 | `-59` | `ML-DSA-87-Ed448` | **`"mtcl"` (`-48` MTC)** | **`6,689 B` (`114`)** | **`1,535.19 ms`** (`2` `KA`) | `452.06 ms` | `2,003.30 ms` | `L7188` | `CSV L3464–L3704` |
| 3 | `-58` | `ML-DSA-65-Ed25519` | **`"mtcl"` (`-48` MTC)** | **`6,259 B` (`107`)** | **`1,067.13 ms`** (`2` `KA`) | `424.05 ms` | `1,507.24 ms` | `L7501` | `CSV L3732–L3958` |
| 4 | `-57` | `ML-DSA-44-Ed25519` | **`"mtcl"` (`-48` MTC)** | **`5,619 B` (`96`)** | **`903.11 ms`** (`2` `KA`) | `380.05 ms` | `1,299.21 ms` | `L7795` | `CSV L3986–L4190` |
| 5 | `-56` | `ML-DSA-87-ES384` | **`"mtcl"` (`-48` MTC)** | **`6,729 B` (`115`)** | **`2,275.28 ms`** (`2` `KA`) | `456.06 ms` | `2,747.39 ms` | `L8102` | `CSV L4218–L4462` |
| 6 | `-55` | `ML-DSA-65-ES256` | **`"mtcl"` (`-48` MTC)** | **`6,292 B` (`107`)** | **`1,211.15 ms`** (`2` `KA`) | `424.05 ms` | `1,651.26 ms` | `L8416` | `CSV L4490–L4716` |
| 7 | `-54` | `ML-DSA-44-ES256` | **`"mtcl"` (`-48` MTC)** | **`5,652 B` (`96`)** | **`1,039.13 ms`** (`2` `KA`) | `380.05 ms` | `1,435.23 ms` | `L8711` | `CSV L4744–L4948` |
| 8 | `-50` | `ML-DSA-87` | **`"mtcl"` (`-48` MTC)** | **`6,677 B` (`114`)** | **`1,075.13 ms`** (`2` `KA`) | `452.06 ms` | `1,543.24 ms` | `L9013` | `CSV L4976–L5216` |
| 9 | `-49` | `ML-DSA-65` | **`"mtcl"` (`-48` MTC)** | **`6,227 B` (`106`)** | **`1,731.22 ms`** (`2` `KA`) | `420.05 ms` | `2,167.32 ms` | `L9327` | `CSV L5244–L5468` |
| 10 | `-48` | `ML-DSA-44` | **`"mtcl"` (`-48` MTC)** | **`5,587 B` (`95`)** | **`2,555.32 ms`** (`2` `KA`) | `376.05 ms` | `2,947.42 ms` | `L9625` | `CSV L5496–L5700` |
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
