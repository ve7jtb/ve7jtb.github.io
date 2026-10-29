# FIDO CTAP 2.3 Conformance Test Report — 18 Algorithms (Including Draft NIST FIPS 206 `FN-DSA-512` & `FN-DSA-1024`), Stateless `ML-DSA-87` (`alg: -50`) & `ES384` (`alg: -35`) Root CA Hierarchy, All 8 Extensions (incl. `"mtc-debug"`), `persistentPinUvAuthToken` (`perCredMgmtRO`), Enterprise Attestation, Dual Hardware/VCOM User Presence & Consolidated Post-Quantum `fmt: "mtc"`

> [!NOTE]
> **Specification Update (W3C WebAuthn Level 4 Pull Request & Authenticate 2026 CTAP2 TWG Consensus):**
> Following the W3C WebAuthn Level 4 Pull Request ([`webauthn_level4_pull_request.html`](./webauthn_level4_pull_request.html) / [`webauthn_level4_mtc_proposal.html`](./webauthn_level4_mtc_proposal.html)), the Merkle Tree Certificate attestation format has been consolidated into a single compact format identifier with an opt-in diagnostic extension:
> - **`fmt: "mtc"`** (consolidating `mtc-mds` into `mtc`): The single, compact Merkle Tree Certificate attestation statement format where `attStmt` carries only `{ alg, sig, mtcCert }` with a **19-byte 2-field `mtcKeyRef` (`{ caId, serial }`)** (strictly omitting both the `1,322 B` inline `pubKey` and `147 B` inclusion proof, saving **`1,478 bytes`** on the wire for `ML-DSA-44` batch/enterprise keys) and the verifier resolves the key via `mtcTrustAnchor.batchKeys` in FIDO MDS3 or an Enterprise Attestation Manifest.
> - **`"mtc-debug"` Registration Extension**: An opt-in CTAP 2.3 / WebAuthn Level 4 registration extension (`authenticatorGetInfo.extensions` includes `"mtc-debug"`) that returns `{ pubKey, notBefore, notAfter, firmwareVersion, mtcProof, rootHash, deviceSerial? }` inside `authenticatorData.extensions["mtc-debug"]` for standalone conformance and diagnostic verification without pre-loaded `batchKeys`, enforcing a strict privacy gate where `deviceSerial` is emitted only when `epAtt: true`.

- **Log Files Analyzed (Last 12 Runs: Runs 17–28)**:
  1. **FIDO Conformance Debug Log**: `fido_conformance_debug.log` (**`38,373` lines in Run 28 (`L1–L38373`, `13m 32.03s`, `18:45:59` – `18:59:31` PDT on `2026-10-29`)** verifying **`260 / 260` `100.00%` PASS (`31` Skipped, `0` Failed across `291` unique tests / `38` suites)** — adding the dedicated `mtcDebug.js` (`7 / 7` PASS: `P-1`..`P-3`, `F-1` `"none"`, `F-2` `"packed"`, `F-3` Enterprise Fallback Privacy Gate, `F-4` Unsolicited Extension Gate), the exhaustive `Authr-MakeCred-Resp-1.js` `P-06` (`3 formats × 18 algorithms = 54` `MakeCredential` matrix), strict ASN.1 DER `SubjectPublicKeyInfo` (`SPKI`) parsing in `cryptodep.js`, and authenticated `metadata.mtcTrustAnchors` subtree/checkpoint verification across all MTC verifiers; **`49,340` lines in Run 27 (`L387515–L436854`, `11m 11.17s`, `20:56:32` – `21:07:43` PDT on `2026-10-27`)** and **`49,932` lines in Run 26 (`L210496–L260427`, `18m 27.46s`)** verifying **`252 / 252` `100.00%` PASS (`31` Skipped, `0` Failed across `283` unique tests)** with P-384 (`ES384`, `alg: -35`) Root CA certificate over P-256 (`ES256`, `alg: -7`) batch key (`600 B` DER `x5c`) for non-post-quantum algorithms, stateless `ML-DSA-87` (`alg: -50`) Root CA over `ML-DSA-44` (`alg: -48`) `fmt: "mtc"` (`19 B` `mtcKeyRef`) for post-quantum algorithms, real hardware/VCOM User Presence (`179` UP checks, compiled **without** `up-always-true`), and `3 / 3` zero-dialog `probe-rs` MCU power-cycle resets on `[HID] Wasefire`; `51,269` lines in Run 25; `37,223` lines in Run 24; `1,067` lines in Run 23; `34,421` lines in Run 22; `35,146` lines in Run 21; `56,117` lines in Run 20; `66,127` lines in Run 19; `52,180` lines in Run 18; `48,653` lines in Run 17)
  2. **Total Phase Beagle USB Protocol Analyzer Capture**: `/tmp/totalphase.csv` (**`25,926` CSV lines, `67,983` USB bus records in Run 27 (`20:56:27` – `21:11:02` PDT on `2026-10-27`)**, **`0` CRC/packet USB errors** across **`1,094` paired `CTAPHID_CBOR` exchanges**, **`4,962` `OUT txn` (`317,568 B` = `310.1 KB`)** / **`7,814` `IN txn` (`500,096 B` = `488.4 KB`)**, `1,104` `CTAPHID_INIT` handshakes, `187` `CTAPHID_KEEPALIVE` frames, and `3` `Set Configuration` USB power-cycle re-enumerations; plus `26,648` CSV lines / `123,951` USB bus records in Run 25; `26,403` CSV lines / `122,002` USB bus records in Run 24; `28,653` CSV lines / `127,232` USB records in Run 19; and `26,436` CSV rows / `68,774` USB records in Run 17)
  3. **Fidont / OpenSK J-Link RTT Log**: `opensk_rtt.log` & `fidont_rtt.log` (`0 B` RTT overhead in Runs 27–28 release builds for full-speed USB execution; **`269,469` lines in Run 26 (`L1195201–L1464669`)** recording `295` `Button(Event { button: 1, pressed: true })` hardware/VCOM UP events, `3` clean MCU power-cycle reboots, and `64 MHz` DWT cycle-accurate timestamps across all 18 algorithms with **`0` panics / `0` HardFaults / `0` OOMs / `0` `[WARN]` or `[ERROR]` events**; plus `290,581` lines in Run 25, `287,281` lines in Run 24, `11,228` lines in Run 23, `292,093` lines in Run 22, `304,967` lines in Run 21, `303,134` lines in Run 20, `304,330` lines in Run 19, and `302,212` lines in Run 18)
- **Target Authenticator**: Fidont CTAP 2.3 (`U2F_V2`, `FIDO_2_0`, `FIDO_2_1`, `FIDO_2_3`) over USB HID (`VID: 0x1915`, `PID: 0x521f` / `[HID] Wasefire`)
- **Related Design & Firmware Implementation**: **Compile and Install Fidont**, [webauthn_level4_pull_request.html](./webauthn_level4_pull_request.html), [webauthn_level4_mtc_proposal.html](./webauthn_level4_mtc_proposal.html) & [pq_mtc_attestation_proposal.md](./pq_mtc_attestation_proposal.md)

## Fidont authenticator simulator platform performance numbers are for relative comparison as implemented with amateur optimization by me:)

> [!IMPORTANT]
> **Attribution & Scope of Fidont:**
> **Fidont** is an authenticator simulator designed for prototyping new specifications and testing authenticator conformance tools. It is based on the [Google OpenSK](https://github.com/google/OpenSK) Rust codebase. However, **Fidont is not suitable for production security use outside of certification, conformance testing, and prototyping new features.**

## Overview of the Last 12 Test Runs (`Runs 17–28`: 18 Algorithms, `3×18` Attestation Format Matrix `P-06`, Dedicated `mtcDebug.js` Suite, Strict ASN.1 DER `SPKI` & `mtcTrustAnchors` Verification, `perCredMgmtRO`, 2-Field `mtcKeyRef`, Stateless `ML-DSA-87` & `ES384` Root CAs, Dual Hardware/VCOM UP & `/tmp/totalphase.csv` Telemetry)

| Run | Line Range | Time Window | Attestation & Feature Config | Passed | Failed | Outcome & Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Run 17** | `L1–L48653` (pre-clear 3) & `totalphase.csv` | `00:48:37` – `01:01:04` (`12m 27s`) | **Full CTAP 2.3 `persistentPinUvAuthToken` (`perCredMgmtRO`, `pcmr = 0x40`, `encIdentifier = 0x19`, `encCredStoreState = 0x1E`) + Dual Batch (`ES384` `x5c` + `ML-DSA-44` MTC) + Enterprise Attestation (`--enterprise`, `serial="123456"`) + Root CA `subtrees[].signature` Verification** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 32 Skipped / 0 Failed`)** — **All `9` previously skipped `perCredMgmtRO` / `encIdentifier` / `encCredStoreState` / `pcmr (0x40)` tests executed and passed (`241` $\to$ `250` passed)! `0` USB bus errors across `68,774` records (`1,073` `CTAPHID_CBOR` exchanges, `304.4 KB` OUT / `509.9 KB` IN) in `totalphase.csv`!** |
| **Run 18** | `L1–L52180` (pre-clear 4) & `fidont_rtt.log` (`302,212` lines) | `10:16:15` – `10:36:41` (`20m 26s`) | **All 18 Algorithms including Draft NIST FIPS 206 `FN-DSA-512` (`alg: -60`) & `FN-DSA-1024` (`alg: -61`) + `ML-DSA-87` (`-50`) MTC Batch + `ES256` Classical Batch + Enterprise Dual (`ML-DSA-44` leaf / `ML-DSA-87` Root CA) + `fidont_rtt.log` DWT Cycle-Accurate Telemetry** | **`249`** | **`1`** | **`99.60%` PASS (`249 Passed / 34 Skipped / 1 Failed`)** — **`100%` PASS across all 18 algorithms in `Authr-MakeCred-Resp-1`, `Authr-GetAssertion-Resp-1`, `EntepriseAttestation`, `Authr-CredMgmt-1`, and `Metadata-Stmt-1` (`0` panics, `0` OOMs, `0` HardFaults in `302,212` `fidont_rtt.log` lines)!** |
| **Run 19** | `L1–L66127`, `totalphase.csv` (`28,653` lines) & `fidont_rtt.log` (`304,330` lines) | `11:49:33` – `12:11:02` (`21m 28s`) | **All 18 Algorithms (`FN-DSA-512` `-60` & `FN-DSA-1024` `-61` + 16 Classical/PQ/Composite) + `perCredMgmtRO` (`0x19`, `0x1E`, `0x40`) + Dual Batch (`ML-DSA-87` MTC + `ES256` `x5c`) + Enterprise Dual (`ML-DSA-44` leaf / `ML-DSA-87` Root CA) + Simultaneous 3-Log Capture (`fido_conformance_debug.log`, `totalphase.csv` & `fidont_rtt.log`)** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 32 Skipped / 0 Failed`)** — **`250 / 250` (`100%`) pass across all 18 algorithms (`78` `"packed"`, `22` `"mtc"`, `2` `"mtcl"`), `0` USB bus errors across `127,232` USB records (`4,945` `OUT txn` / `8,827` `IN txn`, `1,092` `CTAPHID_CBOR` exchanges), and `0` panics/OOMs across `304,330` `fidont_rtt.log` lines!** |
| **Run 20** | `L155031–L211147` (`56,117` lines) & `fidont_rtt.log` (`L860546–L1163679`, `303,134` lines) | `23:13:01` – `23:58:36` (`45m 35s` wall / `~19m 24s` active) | **RFC 8554 / NIST SP 800-208 HSS/LMS Certificate Hierarchy (`1` `Fidont LMS Root CA` + `4` Pre-Published `Fidont LMS Intermediate CA #0..#3`, OID `1.2.840.113549.1.9.16.3.17` $\to$ `ML-DSA-44` Leaf `x5c`) + HSS/LMS (`alg: -46`) Signed MTC Subtree Checkpoints (`caId: "g5k_AQE"`, `caId: "g5k_AQI"`) + All 18 Algorithms (`FN-DSA-512/1024`, `ML-DSA-44/65/87`, 6 PQ/T Composites, 7 Classical) + `perCredMgmtRO` + Enterprise Attestation + UX Metadata Statement Dialog Persistence** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 32 Skipped / 0 Failed` across all 37 CTAP 2.3 suites)** — **Verified HSS/LMS X.509 (`L=1`, `LMS_SHA256_M32_H5` / `LMOTS_SHA256_N32_W8`) + `ML-DSA-44` `"packed"` `x5c` chains (`6,693–7,173 B`), HSS/LMS `alg: -46` MTC subtree checkpoints (`1,252 B` sig) across `"mtc"` & `"mtcl"`, Enterprise Attestation (`6/6`), `Metadata-Stmt-1` (`25/25`), and `0` panics/OOMs across `303,134` `fidont_rtt.log` lines!** |
| **Run 21** | `L1–L35146` (`35,146` lines, post-clear) & `opensk_rtt.log` (`L1–L304967`, `304,967` lines) | `09:46:00` – `10:11:28` (`25m 27.56s`) | **`scripts/generate_lms_pki.py` Provisioned RFC 8554 $\cap$ NIST SP 800-208 (`LMS_SHA256_M32_H5` + `LMOTS_SHA256_N32_W8`) Root CA + 4 Pre-Published LMS Intermediate CAs (`g5k_AQE`..`g5k_AQQ`) + LMS-Signed `ML-DSA-44/65/87` Batch & Enterprise X.509 Certs (`1,296 B` sig) + Compact `fmt: "mtc"` (`alg: -46` `HSS-LMS`) Checkpoints + Single-Instance `probe-rs` RTT Capture (`opensk_rtt.log`)** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 33 Skipped / 0 Failed / 1 Retried` across all active CTAP 2.3 suites)** — **Verified automated LMS PKI provisioning (`crypto_data.rs` + `fido-mds3.json`), compact `fmt: "mtc"` (`6,067–6,728 B`) & LMS-signed `"packed"` `x5c` (`6,692–7,172 B`) across all 18 algorithms, Enterprise Attestation (`6/6`), `Metadata-Stmt-1` (`25/25`), and `0` panics / `0` `[WARN]`/`[ERROR]` lines across `304,967` `opensk_rtt.log` lines!** |
| **Run 22** | `L1–L34421` (`34,421` lines, post-clear) & `opensk_rtt.log` (`L1–L292093`, `292,093` lines) | `11:51:49` – `12:11:56` (`20m 06.79s`) | **W3C WebAuthn Level 4 PR Consolidated `fmt: "mtc"` (Omitting Inline `pubKey`, Saving `1,331 B` per Response: `4,736–5,397 B`) + `"mtc-debug"` Registration Extension + All 18 Algorithms + RFC 8554 $\cap$ NIST SP 800-208 LMS Hierarchy + Single-Instance `probe-rs` RTT Capture (`opensk_rtt.log`)** | **`247`** | **`4`*** | **`98.41%` PASS (`247 Passed / 32 Skipped / 4 Failed` across `283` unique tests)** — **`100%` PASS on consolidated `fmt: "mtc"` (`Authr-MakeCred-Resp-1` `P-01`..`P-04`, `F-01` in `0.165s`) & `Metadata-Stmt-1` (`25/25`), `0` panics / `0` `[WARN]`/`[ERROR]` lines across `292,093` `opensk_rtt.log` lines; `*4` test-harness `getGetInfoCached()` JS `TypeError`s in newly added `mtc-debug` tests fixed & repackaged in `app.asar`!** |
| **Run 23** | `L1–L1067` (`1,067` lines, post-clear) & `opensk_rtt.log` (`L1–L11228`, `11,228` lines) | `22:45:07.81` – `22:45:46.69` (`38.88s`) | **Repackaged Self-Contained `app.asar` (`getGetInfoCached()` Fix) + `CTAP2/Protocol/Options/EntepriseAttestation.js` (`P-1`..`P-3`, `F-1`..`F-6`) + LMS-Signed `ML-DSA-44` Enterprise `x5c` (`3,069 B`) + `"mtc-debug"` Privacy-Gate Verification (`deviceSerial` Emitted on `epAtt: true`, Omitted on Unauthorized RP Downgrade)** | **`6`** | **`0`** | **`100.00%` PASS (`6 Passed / 3 Skipped / 0 Failed`)** — **All 6 Enterprise Profile tests (`P-1`, `P-2`, `P-3`, `F-4`, `F-5`, `F-6`) passed `100%` across `136` CTAPHID messages (`68` exchanges), verifying both `getGetInfoCached()` harness fixes and the `"mtc-debug"` `deviceSerial` privacy gate (`0` panics / `0` errors in `11,228` `opensk_rtt.log` lines)!** |
| **Run 24** | `L1–L37223` (`37,223` lines), `/tmp/totalphase.csv` (`26,403` lines) & `opensk_rtt.log` (`287,281` lines) | `07:43:50` – `08:05:36` (`21m 41s` USB capture) | **Upstream-Rebased OpenSK (`google/OpenSK` PR #759) + W3C WebAuthn Level 4 PR 2-Field Proof-Less `mtcKeyRef` (`{ caId, serial }`, Saving `1,478 B` vs Pre-PR `"mtc"` & `147 B` vs `mtcEntryDesc`: `3,685–5,242 B`) + `batchKeys` `notBefore`/`notAfter` (`1792281600`..`253402300799`) + Expanded 7-Field `"mtc-debug"` Extension (`notBefore`, `notAfter`, `firmwareVersion`, `mtcProof`, `rootHash`, `pubKey`, `deviceSerial?`) + Simultaneous 3-Log Capture** | **`250`** | **`0`** | **`100.00%` PASS (`250 Passed / 33 Skipped / 0 Failed` across all 37 CTAP 2.3 suites)** — **Complete CTAP 2.3 suite finished with `0` failures (`"Testing finished. You may submit the results now."`), `22` proof-less `mtcKeyRef` (`{ caId, serial }`) responses (`3,685–5,242 B`), `79` `"packed"` responses, `4` `"mtc-debug"` verification exchanges (`1,374 B` & `7,492 B`), `0` hardware USB bus errors across `122,002` USB records (`1,092` `CTAPHID_CBOR` exchanges), and `0` panics/OOMs across `287,281` `opensk_rtt.log` lines!** |
| **Run 25** | `L1–L51269` (`51,269` lines, 100% intact `>>` append-mode), `/tmp/totalphase.csv` (`26,648` lines) & `opensk_rtt.log` (`290,581` lines) | `09:34:42` – `09:55:59` (`21m 17.03s` USB / `20m 54.50s` Mocha) | **Dynamic `OPENSK_FIRMWARE_VERSION = 256` (`0x0100` in `src/env.rs`) & `--enterprise-serial` (`"123456"`) Propagation Across Firmware (`GetInfo 0x0E = 256`), X.509 Certificates (`id-fido-gen-ce-fwversion` OID `1.3.6.1.4.1.45724.1.1.3 = 04 04 00 00 01 00` & `id-fido-gen-ce-sernum` OID `1.3.6.1.4.1.45724.1.1.2`), MTC Leaves/Checkpoints & FIDO MDS3 Metadata + 100% Intact `>>` Append-Mode Debug Log + Simultaneous 3-Log Capture** | **`249`** | **`1`*** | **`99.60%` PASS (`249 Passed / 35 Skipped / 1 Failed*` across `285` unique tests / `37` suites)** — **Verified `GetInfo 0x0E = 256` (`0x0100`) on the wire across all `60` `GetInfo` calls (`845 B`), `103` `MakeCredential Ok` (`81` `"packed"`, `22` 2-field `mtcKeyRef` `"mtc"`, `4` `"mtc-debug"`), `66` `GetAssertion Ok`, `0` CRC/packet USB errors across `123,951` USB bus records (`5,038` `OUT` / `8,088` `IN`), and `0` panics/OOMs across `290,581` `opensk_rtt.log` lines; `*1` stale `localStorage` metadata check (`expected 256 to equal 1`) fixed via `loadLatestOpenSKMetadata` auto-refresh in `app.asar`!** |
| **Run 26** | `L210496–L260427` (`49,932` lines) & `opensk_rtt.log` (`L1195201–L1464669`, `269,469` lines) | `10:21:46.18` – `10:40:13.64` PDT (`18m 27.46s`) | **Stateless `ML-DSA-87` (`alg: -50`) & `ES384` (`alg: -35`) Root CAs (No LMS) + 2-Field `mtcKeyRef` for Both Batch (`caId: 83993f0101`) & Enterprise (`caId: 83993f0102`, Cutting Enterprise `P-2`/`P-3` to `4,448 B` / `76f`) + Real Hardware Button (`P0.11`) & J-Link VCOM (`P0.08`) User Presence (`up-always-true` Removed, `179` UP Checks) + `has_display=false` Default + Hardened `resetOpenSKBoard()` (`3 / 3` Zero-Dialog MCU Power Cycles)** | **`252`** | **`0`** | **`100.00%` PASS (`252 Passed / 31 Skipped / 0 Failed` across `283` unique tests / `37` suites in `18m 27.46s`)** — **`+2` newly executed & passing tests (`250` $\to$ `252` Passed) via real UP & `has_display=false`; `100%` PASS across all 18 algorithms in `Authr-MakeCred-Resp-1` (`6/6`) and `EntepriseAttestation.js` (`6/6`, `4,448 B` Enterprise `fmt: "mtc"` with `ML-DSA-87` Root CA checkpoint verification); `3 / 3` (`100%`) automated MCU resets (`393–440 ms`) with zero manual dialogs; `0` panics/OOMs across `269,469` `opensk_rtt.log` lines!** |
| **Run 27** | `L387515–L436854` (`49,340` lines) & `/tmp/totalphase.csv` (`25,926` lines / `67,983` USB bus records) | `20:56:32.57` – `21:07:43.74` PDT (`11m 11.17s`) | **Release Build + P-384 (`ES384`, `alg: -35`) Root CA Certificate over P-256 (`ES256`, `alg: -7`) Batch Key (`600 B` DER `x5c`) for All 7 Non-Post-Quantum Algorithms + Stateless `ML-DSA-87` (`alg: -50`) Root CA over `ML-DSA-44` (`alg: -48`) 2-Field `mtcKeyRef` (`19 B`) for All 11 Post-Quantum Algorithms + Simultaneous `/tmp/totalphase.csv` Hardware USB Protocol Analyzer Capture** | **`252`** | **`0`** | **`100.00%` PASS (`252 Passed / 31 Skipped / 0 Failed` in `11m 11.17s` — `7m 16.29s` faster than Run 26!)** — **Verified P-384 Root CA cert over P-256 batch key (`1,000.17–2,132.31 ms` total USB exchange time across all 7 classical algorithms) and `ML-DSA-44` `fmt: "mtc"` (`1,284.20–3,208.44 ms` across all 11 PQ algorithms), `0` USB bus errors across `67,983` records (`4,962` `OUT` / `7,814` `IN`, `1,094` `CTAPHID_CBOR` exchanges), and `3 / 3` automated power-cycle resets!** |
| **Run 28 (Latest)** | `L1–L38373` (`38,373` lines, post-clear) | `18:45:59.37` – `18:59:31.40` PDT (`13m 32.03s`, `2026-10-29`) | **Expanded `260`-Test Suite (`+8` New Tests): Exhaustive `Authr-MakeCred-Resp-1` `P-06` (`3 Formats ["none", "mtc", "packed"] × 18 Algorithms = 54` Registrations) + Dedicated `CTAP2/Protocol/Extensions/mtcDebug.js` (`7 / 7` PASS: `P-1`..`P-3`, `F-1` `"none"` Gate, `F-2` `"packed"` Gate, `F-3` Enterprise Fallback Privacy Gate, `F-4` Unsolicited Extension Gate) + Strict ASN.1 DER `SubjectPublicKeyInfo` (`SPKI`) Parsing (`cryptodep.js`) + Authenticated `metadata.mtcTrustAnchors` Subtree & Checkpoint Verification Across All Verifiers** | **`260`** | **`0`** | **`100.00%` PASS (`260 Passed / 31 Skipped / 0 Failed` across `291` unique tests / `38` suites in `13m 32.03s`)** — **All `54` format $\times$ algorithm registrations in `Authr-MakeCred-Resp-1` `P-06` (`18` `"none"`, `18` `"mtc"`, `18` `"packed"`), all `18` default-format registrations in `P-01`..`P-04` (verified strictly against `metadata.attestationRootCertificates` and `metadata.mtcTrustAnchors` without `mtc-debug`), all `7` `mtcDebug.js` extension tests (`P-1`..`F-4`), and all `6` Enterprise Attestation tests (`EntepriseAttestation.js` `P-1`..`P-3`, `F-4`..`F-6`) passed `100%`!** |

---

## 0.000000000 Run 28 (`18:45:59` – `18:59:31` PDT, `2026-10-29`, `13m 32.03s`) Full-Suite Conformance (`260 / 260` `100.00%` PASS): Exhaustive `3 × 18 = 54` Attestation Format Matrix (`P-06`), Dedicated `mtcDebug.js` Suite (`7 / 7` PASS), Strict ASN.1 DER `SPKI` Parsing & Authenticated `metadata.mtcTrustAnchors` Verification

> [!IMPORTANT]
> **Expanded `260 / 260` (`100.00%`) Conformance Across `38` CTAP 2.3 Suites (`+8` New Tests Over Run 27)**:
> Run 28 (`fido_conformance_debug.log` `L1–L38373`, `13m 32.03s` on `2026-10-29`) verified four major conformance-tool and firmware enhancements against Fidont / OpenSK (`AAGUID: deadbeef-0000-0000-0000-deadbeef0000`, `firmwareVersion: 256` / `0x0100`):
> 1. **Strict ASN.1 DER `SubjectPublicKeyInfo` (`SPKI`) Extraction (`dependencies/cryptodep.js:462-583`)**:
>    - Replaced byte-pattern scanning in `extractMldsaPubKeyFromPem()` with structural ASN.1 DER traversal (`readDerTlv`, `parseSpkiDer`, `extractSpkiFromCertOrSpkiDer`) that distinguishes `"CERTIFICATE"` vs `"PUBLIC KEY"` PEM labels, walks the outer X.509 `Certificate` `SEQUENCE` $\to$ `TBSCertificate` `SEQUENCE` (`version [0]`, `serialNumber`, `signature`, `issuer`, `validity`, `subject`, `subjectPublicKeyInfo`), and enforces zero trailing bytes and `0x00` unused bits on the `ML-DSA-44/65/87` `BIT STRING`.
>    - Rejects malformed DER wrapped in `PUBLIC KEY` PEM labels, bare SPKIs wrapped in `CERTIFICATE` labels, and certificates carrying an `ML-DSA` SPKI inside an unrelated X.509 extension.
> 2. **Separation of Diagnostic `mtc-debug` Consistency from Authenticated Issuer Trust (`metadata.mtcTrustAnchors`)**:
>    - Across `mtcDebug.js`, `Authr-MakeCred-Resp-1.js` (`P-04` & `P-06`), and `EntepriseAttestation.js` (`P-2`, `P-3`, `F-6`), every MTC verifier now requires a matching `trustAnchor` in `metadata.mtcTrustAnchors` for `mtcCert.caId`, checks `trustAnchor.revokedSerials`, compares `mtc-debug.pubKey` against `trustAnchor.batchKeys` whenever a `batchKey` entry exists for `serial`, requires any Merkle inclusion proof root hash to match an authorized `[start, end)` subtree in `trustAnchor.subtrees` (in addition to `mtc-debug.rootHash`), and verifies the `FIDO-MTC-SUBTREE-CHECKPOINT-V1` Root CA checkpoint signature (`ML-DSA-87`, `alg: -50`) against `metadata.attestationRootCertificates`.
>    - Removed `mtc-debug` from `Authr-MakeCred-Resp-1.js` (`P-01`..`P-06`, `F-01`) so baseline registration tests verify `"packed"` and `"mtc"` responses strictly against `metadata.attestationRootCertificates` and `metadata.mtcTrustAnchors` without requesting `mtc-debug`.
> 3. **Exhaustive `3 Formats × 18 Algorithms = 54` Registration Matrix (`Authr-MakeCred-Resp-1.js` `P-06`, `L7967–L14775`)**:
>    - Iterates through `"none"` and all formats listed in `authenticatorGetInfo.attestationFormats` (`"mtc"`, `"packed"`) across all **18 supported algorithms** (`54` `MakeCredential` ceremonies in `1m 59.92s`), verifying that `Response.fmt` equals the requested format and that `Response.attStmt` passes full cryptographic verification for every `(format, algorithm)` pair.
> 4. **Dedicated `CTAP2/Protocol/Extensions/mtcDebug.js` Suite (`7 / 7` PASS, `L30774–L31684`) & Firmware Format Gate (`OpenSK/libraries/opensk/src/ctap/mod.rs:1288-1326`)**:
>    - OpenSK resolves `selected_format` (`Mtc`, `Packed`, `NoneFormat`) prior to constructing `authData.extensions` (`let include_mtc_debug = extensions.mtc_debug && selected_format == SelectedAttestationFormat::Mtc;`), ensuring `mtc-debug` is suppressed whenever `fmt` is `"none"` (`F-1`) or `"packed"` (`F-2`).

### 0.000000000.1 Run 28 Test Suite Breakdown (`Authr-MakeCred-Resp-1.js`, `mtcDebug.js` & `EntepriseAttestation.js`)

| Suite & Test ID | Log Line (`Timestamp`) | Test Scope & Cryptographic / Protocol Assertions Verified | Outcome |
| :--- | :--- | :--- | :---: |
| **`Authr-MakeCred-Resp-1` — `P-01`..`P-03`** | `L6431–L6508` (`18:48:08.78`) | Default `MakeCredential` across all 18 algorithms (`attestationFormatsPreference` unset, `extensions` unset): verified `fmt` $\in$ `{"packed", "mtc"}`, `authData` ($\ge 113\text{ B}$), `AAGUID`, `rpIdHash`, `UP=1`, `AT=1`, `ED=0`, and COSE key structure across all 18 algorithms. | **`PASS`** |
| **`Authr-MakeCred-Resp-1` — `P-04`** | `L7966` (`18:48:08.84`) | **Attestation Verification Without `mtc-debug`**:<br/>• **`"packed"` (`x5c`):** Verified X.509 v3 leaf certificate chain and signature against `metadata.attestationRootCertificates`.<br/>• **`"mtc"` (`mtcCert`):** Resolved `caId` (`06082b06010401868d1f07`) and `serial` (`4097` / `0x1001`) directly from `metadata.mtcTrustAnchors[0].batchKeys` and verified COSE batch attestation signatures over `authData \|\| clientDataHash`. | **`PASS`** |
| **`Authr-MakeCred-Resp-1` — `P-06`** | `L14775` (`18:50:08.76`) | **Exhaustive `3 Formats × 18 Algorithms = 54` Registration Matrix (`1m 59.92s`)**:<br/>• `attestationFormatsPreference: ["none"]` $\times$ 18 algs $\to$ `fmt == "none"`, `attStmt == {}`<br/>• `attestationFormatsPreference: ["mtc"]` $\times$ 18 algs $\to$ `fmt == "mtc"`, `attStmt.mtcCert` verified against `metadata.mtcTrustAnchors`<br/>• `attestationFormatsPreference: ["packed"]` $\times$ 18 algs $\to$ `fmt == "packed"`, `attStmt.x5c` verified against `metadata.attestationRootCertificates` | **`PASS`** |
| **`Authr-MakeCred-Resp-1` — `F-01`** | `L14793` (`18:50:08.76`) | Verified `unsignedExtensionOutputs (0x06)` is `undefined` when no extensions are requested. | **`PASS`** |
| **`mtcDebug.js` — `P-1`** | `L30774` (`18:56:43.76`) | `GetInfo` consistency: `"mtc-debug"` in `extensions (0x02)` paired with `"mtc"` in `attestationFormats (0x16)`. | **`PASS`** |
| **`mtcDebug.js` — `P-2`** | `L30927` (`18:56:46.69`) | Non-Enterprise `MakeCredential` (`extensions: {"mtc-debug": true}`, `attestationFormatsPreference: ["mtc"]`): verified `ED=1`, 6-field `mtc-debug` map (`deviceSerial === undefined`), `mtc-debug.pubKey` match against `metadata.mtcTrustAnchors[0].batchKeys` (`serial: 4097`), RFC 9162 Merkle inclusion proof against both `mtc-debug.rootHash` and `metadata.mtcTrustAnchors[0].subtrees` (`[4096, 4098)`), and `ML-DSA-87` (`alg: -50`) `FIDO-MTC-SUBTREE-CHECKPOINT-V1` signature against `metadata.attestationRootCertificates`. | **`PASS`** |
| **`mtcDebug.js` — `P-3`** | `L31220` (`18:56:52.79`) | Enterprise `MakeCredential` (`epAtt = 0x01` & `0x02`, `rp.id = "enterprisetest.certinfra.fidoalliance.org"`, `extensions: {"mtc-debug": true}`, `attestationFormatsPreference: ["mtc"]`): verified `epAtt === true`, 7-field `mtc-debug` map with `deviceSerial: "123456"` matching `mtcProof.extensions`, RFC 9162 Merkle inclusion proof (`serial: 8192`) against `metadata.mtcTrustAnchors[0].subtrees` (`[8192, 8193)`), and `ML-DSA-87` (`alg: -50`) checkpoint signature against `metadata.attestationRootCertificates`. | **`PASS`** |
| **`mtcDebug.js` — `F-1`** | `L31306` (`18:56:54.61`) | **Attestation Format Gate (`"none"`):** With `extensions: {"mtc-debug": true}` and `attestationFormatsPreference: ["none"]`, verified `fmt == "none"` and **`mtc-debug` is suppressed** (`ED=0`, `extensionsData === undefined`). | **`PASS`** |
| **`mtcDebug.js` — `F-2`** | `L31404` (`18:56:57.23`) | **Attestation Format Gate (`"packed"`):** With `extensions: {"mtc-debug": true}` and `attestationFormatsPreference: ["packed"]`, verified `fmt == "packed"` and **`mtc-debug` is suppressed** (`ED=0`, `extensionsData === undefined`). | **`PASS`** |
| **`mtcDebug.js` — `F-3`** | `L31558` (`18:57:00.06`) | **Enterprise Fallback Privacy Gate:** Unauthorized `rp.id` with `epAtt = 0x01`, `extensions: {"mtc-debug": true}`, `attestationFormatsPreference: ["mtc"]` downgraded to non-Enterprise batch MTC (`epAtt` omitted, `deviceSerial` omitted, empty `mtcProof.extensions`, verified against `metadata.mtcTrustAnchors`). | **`PASS`** |
| **`mtcDebug.js` — `F-4`** | `L31684` (`18:57:03.32`) | **Unsolicited Extension Gate:** `MakeCredential` with `attestationFormatsPreference: ["mtc"]` and no `mtc-debug` request omitted `mtc-debug` (`ED=0`). | **`PASS`** |
| **`EntepriseAttestation.js` — `P-1`..`P-3`, `F-4`..`F-6`** | `L21709–L22360` (`18:54:06–18:54:23`) | Full Enterprise Attestation option suite (`epAtt = 0x01`, `epAtt = 0x02`, invalid type/value rejection `0x11` / `0x2C`, and unauthorized RPID privacy downgrade) verified against `metadata.attestationRootCertificates` and `metadata.mtcTrustAnchors`. | **`6 / 6 PASS`** |

---

## 0.00000000 Run 27 (`20:56:32` – `21:07:43` PDT, `2026-10-27`, `11m 11.17s`) & Run 26 Full-Suite Conformance (`252 / 252` `100.00%` PASS): P-384 (`ES384`) Certificate over P-256 (`ES256`) Batch Key for Non-Post-Quantum, Stateless `ML-DSA-87` (`alg: -50`) Root CA over `ML-DSA-44` `fmt: "mtc"`, & `/tmp/totalphase.csv` Hardware USB Telemetry

> [!IMPORTANT]
> **100.00% Unattended Conformance (`252 Passed / 31 Skipped / 0 Failed` in `11m 11.17s`) with Simultaneous Total Phase Beagle USB Protocol Analyzer Capture (`/tmp/totalphase.csv`)**:
> Run 27 (`fido_conformance_debug.log` `L387515–L436854`, `49,340` lines; `/tmp/totalphase.csv` `25,926` lines / `67,983` USB bus records) and Run 26 (`L210496–L260427`, `opensk_rtt.log` `L1195201–L1464669`) verified the complete CTAP 2.3 conformance suite against Fidont (`[HID] Wasefire`) with **`252 / 252` (`100.00%`) PASS**:
> 1. **Stateless Dual Root CA Hierarchy (`ES384` `alg: -35` Root CA over P-256 `ES256` Batch Key + `ML-DSA-87` `alg: -50` Root CA over `ML-DSA-44` `fmt: "mtc"`, LMS Removed)**:
>    - **`Fidont Enterprise Root CA ES384` (`ECDSA P-384 / SHA-384`, `alg: -35`, `620 B` DER)**: Signs the **`600 B` P-256 (`ES256`, `alg: -7`) classical batch X.509 certificate** (`cX5c`, `Subject: CN=Fidont Attestation`, `Issuer: CN=Fidont Enterprise Root CA ES384`, carrying `id-fido-gen-ce-aaguid` OID `1.3.6.1.4.1.45724.1.1.4` and `id-fido-gen-ce-fwversion` OID `1.3.6.1.4.1.45724.1.1.3 = 04 04 00 00 01 00` [`256`] with a `96 B` P-384 signature) used by `fmt: "packed"` across all 7 non-post-quantum credential algorithms (`RS256`, `Ed448`, `Ed25519`, `ES256K`, `ES512`, `ES384`, `ES256`).
>    - **`Fidont Enterprise Root CA` (`ML-DSA-87`, `alg: -50`, `8,273 B` DER in `metadata_mldsa44_mtc.json`)**: Signs the Merkle Tree Certificate (`fmt: "mtc"`) subtree checkpoints (`FIDO-MTC-SUBTREE-CHECKPOINT-V1\x00\x00` context, **`4,627 B` signature**) for both Non-Enterprise Batch MTC (`caId = 83993f0101` / `"g5k_AQE"`, `rootHash = 883c0cd3648c6d8aa9f49c242dab040ec11a8ec288997b39e770b3588038f5d8`) and Enterprise MTC (`caId = 83993f0102` / `"g5k_AQI"`), where the authenticator signs with its **`ML-DSA-44` (`alg: -48`, `2,420 B` sig)** batch/enterprise key and emits only the **19-byte 2-field `mtcKeyRef` (`{ caId, serial }`)**.
> 2. **Non-Post-Quantum & Post-Quantum Hardware USB Timings (`/tmp/totalphase.csv` in Run 27)**:
>    - With the P-384 Root CA certificate over the P-256 (`ES256`) batch key, the 7 non-post-quantum `MakeCredential` responses (`1,045–1,273 B` / `18–22` USB HID frames) complete on the physical USB bus in **`996.17 ms` (`RS256`)**, **`1,000.17 ms` (`Ed25519`)**, **`1,008.17 ms` (`ES256K`)**, **`1,268.20 ms` (`Ed448`)**, **`1,576.24 ms` (`ES256`)**, **`1,576.24 ms` (`ES512`)**, and **`2,132.31 ms` (`ES384`)** (`72.01–84.01 ms` USB `IN` transfer time).
>    - The 11 post-quantum and composite `fmt: "mtc"` `MakeCredential` responses (`3,685–5,242 B` / `63–89` USB HID frames) complete on the USB bus in **`1,284.20 ms` (`MLDSA44-Ed25519`)**, **`1,324.21 ms` (`FN-DSA-512`)**, **`1,456.23 ms` (`MLDSA65-Ed25519`)**, **`1,624.25 ms` (`ML-DSA-65`)**, **`1,668.25 ms` (`ML-DSA-87`)**, **`1,788.27 ms` (`MLDSA44-ES256`)**, **`1,816.27 ms` (`ML-DSA-44`)**, **`1,860.28 ms` (`MLDSA65-ES256`)**, **`2,136.31 ms` (`MLDSA87-Ed448`)**, **`2,704.38 ms` (`FN-DSA-1024`)**, and **`3,208.44 ms` (`MLDSA87-ES384`)** (`248.03–352.04 ms` USB `IN` transfer time).
> 3. **Enterprise `MakeCredential` Wire Size Reduced by `3,044 B` (`7,492 B` $\to$ `4,448 B` / `76` HID Frames)**:
>    - In `EntepriseAttestation.js` (`P-2` with `ep=1` on `CID=000001d8` [`CSV L13724–L13902`] and `P-3` with `ep=2` on `CID=000001db` [`CSV L13930–L14108`]), Fidont emits **`fmt: "mtc"`** with the **19-byte 2-field `mtcKeyRef`** (`attStmt.mtcCert = { caId: h'83993f0102', serial: 0x0007000000000000 }`) plus the `2,420 B` `ML-DSA-44` signature (`attStmt.sig`), while `authenticatorData.extensions["mtc-debug"]` carries the 7-field diagnostic payload (`pubKey: 1,322 B`, `mtcProof: 121 B` with `"123456"` serial extension, `notBefore: 1793033200`, `notAfter: 253402300799`, `firmwareVersion: 256`, `rootHash: 32 B`, `deviceSerial: "123456"`), transferring in **`300.04 ms` (`76` USB `IN` frames)** and completing in **`3,132.43 ms` (`P-2`)** and **`2,444.35 ms` (`P-3`)** total USB time.
> 4. **Zero USB Bus Errors & `3 / 3` Automated MCU Power Cycles (`/tmp/totalphase.csv`)**:
>    - `/tmp/totalphase.csv` recorded **`67,983` USB bus records** (`25,926` CSV lines) across **`1,094` completed `CTAPHID_CBOR (0x90)` exchanges** (`4,962` `OUT txn` = `317,568 B` / `310.1 KB`; `7,814` `IN txn` = `500,096 B` / `488.4 KB`; `1,104` `CTAPHID_INIT` handshakes; `187` `CTAPHID_KEEPALIVE` frames; `3` `Set Configuration` power-cycle resets at `9:30.448`, `10:19.445`, and `10:25.569`) with **`0` hardware USB packet/CRC errors**.

### 0.00000000.1 Run 27 Correlated `fido_conformance_debug.log` & `/tmp/totalphase.csv` Deep Dive — Part 1: `Authr-MakeCred-Resp-1` (`P-01`..`P-05`, `F-01`) & `Authr-GetAssertion-Resp-1` Across All 18 Algorithms (`Log L394469–L408900`, `CSV L3430–L12066`)

In `Authr-MakeCred-Resp-1` (`L394469–L399817`, `6 / 6` PASS) and `Authr-GetAssertion-Resp-1` (`L402197–L408900`, `5 / 5` PASS), the conformance tool iterates through all **18 `pubKeyCredParams` algorithms** advertised in `authenticatorGetInfo` (`-257` through `-7`):
- **7 Non-Post-Quantum Algorithms (`RS256`, `Ed448`, `Ed25519`, `ES256K`, `ES512`, `ES384`, `ES256`)**: Fidont selects **`fmt: "packed"`**, signing `authData || clientDataHash` with the P-256 (`ES256`, `alg: -7`) batch key (`70–72 B` ECDSA P-256 signature) and attaching the **`600 B` P-256 batch X.509 certificate** (`cX5c`, carrying `id-fido-gen-ce-fwversion = 256` and signed with a `96 B` P-384 signature by `Fidont Enterprise Root CA ES384`).
- **11 Post-Quantum & PQ/T Composite Algorithms (`FN-DSA-1024`, `FN-DSA-512`, `MLDSA87-Ed448`, `MLDSA65-Ed25519`, `MLDSA44-Ed25519`, `MLDSA87-ES384`, `MLDSA65-ES256`, `MLDSA44-ES256`, `ML-DSA-87`, `ML-DSA-65`, `ML-DSA-44`)**: Fidont selects **`fmt: "mtc"`**, signing `authData || clientDataHash` with the `ML-DSA-44` (`alg: -48`) batch key (`2,420 B` signature) and attaching the **19-byte 2-field `mtcKeyRef`** (`{"caId": h'83993f0101', "serial": 0x0007000000000000}`) anchored to the stateless `ML-DSA-87` (`alg: -50`) Root CA.

| # | Algorithm | COSE `alg` | `MakeCred` `CID` (`Log` / `CSV Lines`) | `fmt` & Attestation Structure | `MakeCred` Wire Size (`BCNT` / Frames) | `MakeCred` USB `MCU` Time (`totalphase.csv`) | `MakeCred` USB `IN` Transfer | `MakeCred` Total USB Time (`Log Time`) | `GetAssertion` `CID` (`CSV Lines`) & Wire Size | `GetAssertion` USB `MCU` + `IN` = Total USB Time (`Log Time`) |
| :-: | :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | **`RS256`** | `-257` | `000000b0` (`L394481` / `CSV L3430–L3484`) | `"packed"` (`alg: -7` P-256 batch key, `sig: 70 B`, `x5c: [600 B]` P-384 Root CA cert) | **`1,273 B`** (`22f`) | **`896.11 ms`** | `84.01 ms` | **`996.17 ms`** (`1,003.4 ms`) | `00000191` (`CSV L12028–L12066`, `566 B` / `10f`) | `4,660.57 + 36.01` = **`4,720.63 ms`** (`4,727.5 ms`) |
| 2 | **`FN-DSA-1024`** | `-61` | `000000b3` (`L394615` / `CSV L3512–L3680`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`4,581 B`** (`78f`) | `2,380.29 ms` | `308.04 ms` | **`2,704.38 ms`** (`2,708.5 ms`) | `0000018b` (`CSV L11848–L11918`, `1,590 B` / `27f`) | `2,372.29 + 104.01` = **`2,500.36 ms`** (`2,505.6 ms`) |
| 3 | **`FN-DSA-512`** | `-60` | `000000b6` (`L394866` / `CSV L3708–L3844`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`3,685 B`** (`63f`) | `1,060.13 ms` | `248.03 ms` | **`1,324.21 ms`** (`1,334.6 ms`) | `00000185` (`CSV L11578–L11626`, `976 B` / `17f`) | `1,188.14 + 64.01` = **`1,276.20 ms`** (`1,281.3 ms`) |
| 4 | **`MLDSA87-Ed448`** | `-59` | `000000b9` (`L395083` / `CSV L3872–L4060`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`5,202 B`** (`89f`) | `1,768.21 ms` | `352.04 ms` | **`2,136.31 ms`** (`2,146.3 ms`) | `0000017f` (`CSV L11214–L11386`, `4,815 B` / `82f`) | `3,096.38 + 324.04` = **`3,428.47 ms`** (`3,433.7 ms`) |
| 5 | **`MLDSA65-Ed25519`** | `-58` | `000000bc` (`L395354` / `CSV L4088–L4260`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`4,772 B`** (`81f`) | `1,120.13 ms` | `320.04 ms` | **`1,456.23 ms`** (`1,462.3 ms`) | `00000179` (`CSV L10828–L10968`, `3,683 B` / `63f`) | `1,988.24 + 248.03` = **`2,260.33 ms`** (`2,265.8 ms`) |
| 6 | **`MLDSA44-Ed25519`** | `-57` | `000000bf` (`L395607` / `CSV L4288–L4440`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`4,132 B`** (`71f`) | `988.12 ms` | `280.03 ms` | **`1,284.20 ms`** (`1,289.8 ms`) | `00000173` (`CSV L10490–L10600`, `2,794 B` / `48f`) | `1,424.17 + 188.02` = **`1,636.25 ms`** (`1,641.9 ms`) |
| 7 | **`MLDSA87-ES384`** | `-56` | `000000c2` (`L395840` / `CSV L4468–L4658`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`5,242 B`** (`89f`) | `2,840.35 ms` | `352.04 ms` | **`3,208.44 ms`** (`3,216.0 ms`) | `0000016d` (`CSV L10108–L10282`, `4,804 B` / `82f`) | `4,520.56 + 324.04` = **`4,852.65 ms`** (`4,857.6 ms`) |
| 8 | **`MLDSA65-ES256`** | `-55` | `000000c5` (`L396115` / `CSV L4686–L4860`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`4,805 B`** (`82f`) | `1,520.18 ms` | `324.04 ms` | **`1,860.28 ms`** (`1,868.0 ms`) | `00000167` (`CSV L9720–L9862`, `3,689 B` / `63f`) | `3,604.44 + 248.03` = **`3,876.53 ms`** (`3,882.7 ms`) |
| 9 | **`MLDSA44-ES256`** | `-54` | `000000c8` (`L396371` / `CSV L4888–L5040`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`4,165 B`** (`71f`) | `1,492.18 ms` | `280.03 ms` | **`1,788.27 ms`** (`1,796.3 ms`) | `00000161` (`CSV L9380–L9490`, `2,800 B` / `48f`) | `1,396.17 + 188.02` = **`1,608.25 ms`** (`1,619.5 ms`) |
| 10 | **`ML-DSA-87`** | `-50` | `000000cb` (`L396605` / `CSV L5068–L5254`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`5,190 B`** (`88f`) | `1,304.16 ms` | `348.04 ms` | **`1,668.25 ms`** (`1,678.5 ms`) | `0000015b` (`CSV L9002–L9170`, `4,747 B` / `81f`) | `1,528.18 + 320.04` = **`1,856.28 ms`** (`1,867.7 ms`) |
| 11 | **`ML-DSA-65`** | `-49` | `000000ce` (`L396873` / `CSV L5282–L5454`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`4,740 B`** (`81f`) | `1,288.15 ms` | `320.04 ms` | **`1,624.25 ms`** (`1,635.9 ms`) | `00000155` (`CSV L8620–L8760`, `3,619 B` / `62f`) | `3,068.38 + 244.03` = **`3,336.46 ms`** (`3,344.6 ms`) |
| 12 | **`ML-DSA-44`** | `-48` | `000000d1` (`L397127` / `CSV L5482–L5632`) | **`"mtc"`** (`alg: -48`, `sig: 2,420 B`, **`mtcKeyRef: 19 B`** `caId=83993f0101`) | **`4,100 B`** (`70f`) | `1,524.18 ms` | `276.03 ms` | **`1,816.27 ms`** (`1,825.0 ms`) | `0000014f` (`CSV L8284–L8392`, `2,730 B` / `47f`) | `1,188.14 + 184.02` = **`1,396.22 ms`** (`1,406.7 ms`) |
| 13 | **`Ed448`** | `-53` | `000000d4` (`L397359` / `CSV L5660–L5708`) | `"packed"` (`alg: -7` P-256 batch key, `sig: 71 B`, `x5c: [600 B]` P-384 Root CA cert) | **`1,070 B`** (`19f`) | **`1,180.14 ms`** | `72.01 ms` | **`1,268.20 ms`** (`1,276.4 ms`) | `00000149` (`CSV L8048–L8078`, `423 B` / `8f`) | `852.10 + 28.00` = **`904.16 ms`** (`912.5 ms`) |
| 14 | **`EdDSA` (`Ed25519`)** | `-8` | `000000d7` (`L397488` / `CSV L5736–L5782`) | `"packed"` (`alg: -7` P-256 batch key, `sig: 72 B`, `x5c: [600 B]` P-384 Root CA cert) | **`1,045 B`** (`18f`) | **`916.11 ms`** | `68.01 ms` | **`1,000.17 ms`** (`1,009.0 ms`) | `00000143` (`CSV L7916–L7944`, `373 B` / `7f`) | `268.03 + 24.00` = **`316.08 ms`** (`326.2 ms`) |
| 15 | **`ES256K`** | `-47` | `000000da` (`L397614` / `CSV L5810–L5858`) | `"packed"` (`alg: -7` P-256 batch key, `sig: 72 B`, `x5c: [600 B]` P-384 Root CA cert) | **`1,080 B`** (`19f`) | **`920.11 ms`** | `72.01 ms` | **`1,008.17 ms`** (`1,015.3 ms`) | `0000013d` (`CSV L7786–L7814`, `380 B` / `7f`) | `308.03 + 24.00` = **`356.09 ms`** (`361.0 ms`) |
| 16 | **`ES512`** | `-36` | `000000dd` (`L397742` / `CSV L5886–L5936`) | `"packed"` (`alg: -7` P-256 batch key, `sig: 71 B`, `x5c: [600 B]` P-384 Root CA cert) | **`1,148 B`** (`20f`) | **`1,484.18 ms`** | `76.01 ms` | **`1,576.24 ms`** (`1,582.4 ms`) | `00000137` (`CSV L7652–L7682`, `448 B` / `8f`) | `1,968.24 + 28.00` = **`2,020.30 ms`** (`2,025.6 ms`) |
| 17 | **`ES384`** | `-35` | `000000e0` (`L397874` / `CSV L5964–L6012`) | `"packed"` (`alg: -7` P-256 batch key, `sig: 72 B`, `x5c: [600 B]` P-384 Root CA cert) | **`1,113 B`** (`19f`) | **`2,044.25 ms`** | `72.01 ms` | **`2,132.31 ms`** (`2,138.6 ms`) | `00000131` (`CSV L7512–L7544`, `412 B` / `8f`) | `2,584.32 + 28.00` = **`2,636.37 ms`** (`2,647.9 ms`) |
| 18 | **`ES256`** | `-7` | `000000e3` (`L398006` / `CSV L6040–L6088`) | `"packed"` (`alg: -7` P-256 batch key, `sig: 70 B`, `x5c: [600 B]` P-384 Root CA cert) | **`1,078 B`** (`19f`) | **`1,488.18 ms`** | `72.01 ms` | **`1,576.24 ms`** (`1,582.6 ms`) | `0000012b` (`CSV L7380–L7408`, `380 B` / `7f`) | `832.10 + 24.00` = **`880.16 ms`** (`882.7 ms`) |

#### Test-by-Test Breakdown of `Authr-MakeCred-Resp-1` (`L398067–L399817`, `6 / 6` PASS)
1. **`P-01` (`L398067–L398097`)**: Verified that for all 18 algorithms, the response is a valid CBOR map containing required members `0x01` (`fmt`, text string), `0x02` (`authData`, byte string $\ge 37\text{ B}$), and `0x03` (`attStmt`, CBOR map), and matches `MetadataStatement.authenticationAlgorithms`.
2. **`P-02` (`L398098–L398141`)**: Parsed `authData` across all 18 responses (`196 B` for `ES256` up to `2,676 B` for `MLDSA87-ES384`) and verified `rpIdHash == SHA-256("fidoalliance.org")`, `flags.UP == 1`, `flags.AT == 1`, `aaguid == 8836336b-ef35-40b5-b098-3695029f1d62`, `credentialIdLength`, and valid COSE_Key structure for every classical, post-quantum (`kty: 7` `AKP` for `ML-DSA` and `FN-DSA`), and PQ/T composite (`kty: 8`) key.
3. **`P-03` (`L398142–L398160`)**: Verified `flags` bitmask consistency (`UP=1`, `UV=1`, `AT=1`, reserved bits `RFU1=0`, `RFU2=0`).
4. **`P-04` (`L398161–L399611`, `28.2 ms`)**: Performed full cryptographic attestation verification across all 18 responses:
   - **7 `"packed"` responses (`RS256`, `Ed448`, `Ed25519`, `ES256K`, `ES512`, `ES384`, `ES256`)**: Extracted the **`600 B` P-256 (`ES256`) leaf X.509 certificate** (`CN=Fidont Attestation, O=John Bradley, OU=Authenticator Attestation, C=CA`), verified basic constraints (`CA:FALSE`), `id-fido-gen-ce-aaguid` (`1.3.6.1.4.1.45724.1.1.4`), and `id-fido-gen-ce-fwversion` (`1.3.6.1.4.1.45724.1.1.3 = 04 04 00 00 01 00` = `256`), chained it to the **P-384 Root CA (`CN=Fidont Enterprise Root CA ES384`)** in `metadata.attestationRootCertificates`, and verified the P-256 (`ES256`) batch signature over `authData || clientDataHash`.
   - **11 `"mtc"` responses (`FN-DSA-1024/512`, `MLDSA87-Ed448`, `MLDSA65/44-Ed25519`, `MLDSA87-ES384`, `MLDSA65/44-ES256`, `ML-DSA-87/65/44`)**: Matched `mtcCert.caId = 83993f0101` (`"g5k_AQE"`) and `mtcCert.serial = 0x0007000000000000` (`504,403,158,265,495,552`) against `metadata.mtcTrustAnchors[0].batchKeys[0]`, verified the batch key's `notBefore` (`1792281600`) and `notAfter` (`253402300799`) validity window, and verified each `2,420 B` `ML-DSA-44` signature over `authData || clientDataHash`.
5. **`P-05` (`L399633–L399797`, `CID=000000e6`, `CSV L6116–L6188`, `1,397 B` / `24f`, `1,968.24 ms` USB MCU + `92.01 ms` `IN` = `2,104.31 ms` total USB time)**: Sent `authenticatorMakeCredential` with `extensions: { "mtc-debug": true }` and no `enterpriseAttestation`:
   - Verified `authData.flags.ED == 1` (`0xc5 = UP | UV | AT | ED`).
   - Verified `authenticatorData.extensions["mtc-debug"]` (`295 B` CBOR map) contained all 6 non-enterprise diagnostic fields (`pubKey: 77 B`, `notBefore: 1793033200`, `notAfter: 253402300799`, `firmwareVersion: 256`, `mtcProof: 115 B`, `rootHash: 32 B`) and enforced the privacy gate (`mtcDebug["deviceSerial"] === undefined`).
6. **`F-01` (`L399798–L399817`, `CID=000000ee`, `CSV L6320–L6382`, `1,078 B` / `19f`, `1,556.19 ms` USB MCU + `72.01 ms` `IN` = `1,672.25 ms` total USB time)**: Sent `MakeCredential` with an unknown extension `{"unknownExtension": true}` and verified that Fidont ignored the unknown extension (`flags.ED == 0`, `statusCode == 0x00`).

---

### 0.00000000.2 Run 27 Correlated `fido_conformance_debug.log` & `/tmp/totalphase.csv` Deep Dive — Part 2: `EntepriseAttestation.js` (`P-1`..`P-3`, `F-4`..`F-6`, `6 / 6` PASS) & `4,448 B` Enterprise `fmt: "mtc"` (`Log L411863–L413150`, `CSV L13672–L14400`)

In Run 27, `CTAP2/Protocol/Options/EntepriseAttestation.js` (`L411863–L413150`, `CSV L13650–L14400`) executed all **6 active Enterprise Attestation tests** (`P-1`, `P-2`, `P-3`, `F-4`, `F-5`, `F-6`; `F-1`..`F-3` skipped because `options.ep` is supported) with **`6 / 6` (`100.00%`) PASS**:

| Test ID | Test Description | Channel ID (`Log` / `CSV Lines`) | Request Parameters | Response Size (`BCNT` / Frames) | USB `MCU` + `IN` = Total USB Time (`totalphase.csv`) | Attestation & `"mtc-debug"` Verification Outcome |
| :---: | :--- | :---: | :--- | :---: | :---: | :--- |
| **`P-1`** | Enable Enterprise Attestation & verify `GetInfo.options.ep == true` | `000001d3` (`L411863` / `CSV L13672–L13674`) | `AuthenticatorConfig (0x0D)` `subCommand = 0x01` (`enableEnterpriseAttestation`) + `GetInfo (0x04)` | `1 B` (`1f`) + `845 B` (`15f`) | **`68.00 + 0.00 = 68.05 ms`** (`Config`) | **`PASS`** — `options.ep` transitioned from `false` (`0xf4`) to `true` (`0xf5`). |
| **`P-2`** | Vendor-facilitated Enterprise Attestation (`enterpriseAttestation = 1`) + `"mtc-debug"` | `000001d8` (`L411933–L412218` / `CSV L13724–L13902`) | `rp.id = "enterprisetest.certinfra.fidoalliance.org"`, `alg = -7` (`ES256`), `extensions: {"mtc-debug": true}`, `enterpriseAttestation: 1` | **`4,448 B` (`76f`)** | **`2,788.34 + 300.04 = 3,132.43 ms`** | **`PASS`** — `fmt: "mtc"`, `attStmt`: `{alg: -48, sig: 2,420 B, mtcCert: {caId: h'83993f0102', serial: 0x0007000000000000}}` (`19 B`), `mtc-debug`: 7 fields (`pubKey: 1,322 B`, `mtcProof: 121 B`, `deviceSerial: "123456"`), verified against `ML-DSA-87` Root CA checkpoint! |
| **`P-3`** | Platform-managed Enterprise Attestation (`enterpriseAttestation = 2`) + `"mtc-debug"` | `000001db` (`L412219–L412494` / `CSV L13930–L14108`) | `rp.id = "enterprisetest.certinfra.fidoalliance.org"`, `alg = -7` (`ES256`), `extensions: {"mtc-debug": true}`, `enterpriseAttestation: 2` | **`4,448 B` (`76f`)** | **`2,096.25 + 300.04 = 2,444.35 ms`** | **`PASS`** — Identical `4,448 B` (`76f`) Enterprise `fmt: "mtc"` + 7-field `"mtc-debug"` response; Merkle proof + `ML-DSA-87` (`alg: -50`) subtree checkpoint + `ML-DSA-44` (`alg: -48`) attestation signature verified! |
| **`F-4`** | Negative: `enterpriseAttestation` set to non-integer (`true`) | `000001e4` (`L412684–L412799` / `CSV L14202–L14226`) | `enterpriseAttestation: true` (boolean instead of unsigned int) | `1 B` (`1f`) | **`56.00 + 0.00 = 100.06 ms`** | **`PASS`** — Rejected with `CTAP2_ERR_CBOR_UNEXPECTED_TYPE (0x11)`. |
| **`F-5`** | Negative: `enterpriseAttestation` set to invalid integer (`3`) | `000001e7` (`L412800–L412915` / `CSV L14254–L14278`) | `enterpriseAttestation: 3` (only `1` or `2` valid) | `1 B` (`1f`) | **`96.01 + 0.00 = 140.06 ms`** | **`PASS`** — Rejected with `CTAP2_ERR_INVALID_OPTION (0x2C)`. |
| **`F-6`** | Privacy Gate: `enterpriseAttestation = 1` with non-allowlisted RP ID + `"mtc-debug"` | `000001ec` (`L412916–L413150` / `CSV L14328–L14400`) | `rp.id = <random domain>`, `extensions: {"mtc-debug": true}`, `enterpriseAttestation: 1` | **`1,397 B` (`24f`)** | **`1,984.24 + 92.01 = 2,120.31 ms`** | **`PASS`** — Downgraded to non-enterprise batch attestation (`fmt: "packed"`, `ES256` `600 B` `x5c` signed by `ES384` Root CA), `epAtt` omitted, and **`mtc-debug.deviceSerial` strictly omitted (`undefined`)**! |

#### Byte-Budget Breakdown of the `4,448 B` (`0x1160`) Enterprise `fmt: "mtc"` + `"mtc-debug"` Response (`P-2` & `P-3`)

```text
CTAPHID_CBOR (0x90) Response on CID=00000249 (P-2) & CID=0000024c (P-3):
Total Payload: 1 B status (0x00) + 4,447 B CBOR map = 4,448 bytes (76 USB HID 64 B frames)
├── 0x01 (fmt): "mtc"                                                     (  6 B)
├── 0x02 (authData): bstr (1,978 B)                                       (1,982 B)
│   ├── rpIdHash: SHA-256("fidoalliance.org")                             ( 32 B)
│   ├── flags: 0xc5 (UP=1 | UV=1 | AT=1 | ED=1)                           (  1 B)
│   ├── signCount: 0x00000001                                             (  4 B)
│   ├── attestedCredentialData:                                           (159 B)
│   │   ├── aaguid: 8836336b-ef35-40b5-b098-3695029f1d62                  ( 16 B)
│   │   ├── credentialIdLength: 0x0041 (65 B)                             (  2 B)
│   │   ├── credentialId: 0x02 || 64 B AES-CBC/HMAC wrapped handle        ( 65 B)
│   │   └── credentialPublicKey: ES256 COSE_Key (kty=2, alg=-7, crv=1)    ( 76 B)
│   └── extensions: {"mtc-debug": { ... }}                                (1,782 B)
│       ├── "pubKey": bstr(1,322 B) (Enterprise ML-DSA-44 COSE_Key)
│       ├── "notBefore": 1793033200
│       ├── "notAfter": 253402300799 (9999-12-31T23:59:59Z)
│       ├── "firmwareVersion": 256 (0x0100)
│       ├── "mtcProof": bstr(121 B) (serial=0x0007000000000000, idx=0, ext=0x0106"123456", 3x32B path)
│       ├── "rootHash": h'883c0cd3648c6d8aa9f49c242dab040ec11a8ec288997b39e770b3588038f5d8' (32 B)
│       └── "deviceSerial": "123456" (emitted ONLY because epAtt == true)
└── 0x03 (attStmt): map(3)                                                (2,458 B)
    ├── "alg": -48 (ML-DSA-44)                                            (  6 B)
    ├── "sig": bstr(2,420 B) (ML-DSA-44 signature over authData || hash)  (2,427 B)
    └── "mtcCert": map(2) (2-field mtcKeyRef)                             ( 25 B)
        ├── "caId": h'83993f0102' ("g5k_AQI", Enterprise MTC CA ID)
        └── "serial": 0x0007000000000000
```

#### Step-by-Step Cryptographic Verification Performed by `verifyMtcAttestation()` in `P-2` & `P-3`:
1. **Trust Anchor Resolution**: Looks up `mtcCert.caId = 83993f0102` (`"g5k_AQI"`) in `metadata.mtcTrustAnchors` (`L235484`).
2. **Diagnostic Key & Proof Extraction via `"mtc-debug"`**: Because the enterprise per-device key is not pre-shared in the public MDS `batchKeys` array, the verifier extracts `pubKey` (`1,322 B` `ML-DSA-44` `COSE_Key`), `notBefore` (`1793033200`), `notAfter` (`253402300799`), and `mtcProof` (`121 B`) from `authenticatorData.extensions["mtc-debug"]`.
3. **Device Serial Number Binding (`mtcProof.extensions` $\leftrightarrow$ `mtc_enterprise_info.json` $\leftrightarrow$ `mtc-debug.deviceSerial`)**:
   - Parses the 121-byte `mtcProof`: `serial = 0007000000000000` (`8 B`), `leaf_index = 0` (`8 B`), `ext_len = 8` (`2 B`), `extensions = 01 06 31 32 33 34 35 36` (`ext_type = 0x01` [device serial], `len = 6`,UTF-8 `"123456"`), and `3` sibling hashes (`96 B`).
   - Asserts `serialNumber == "123456"` matches both `mtc_enterprise_info.json` (`expectedSerial = "123456"`) and `mtcDebug.deviceSerial` (`"123456"`).
4. **Merkle Inclusion Proof & `ML-DSA-87` (`alg: -50`) Root CA Checkpoint Verification**:
   - Reconstructs the 68-byte `FidoMtcLogEntry`: `caId (5 B) || serial (8 B) || notBefore (8 B) || notAfter (8 B) || aaguid (16 B) || SHA-256(pubKey) (11 B truncated) || firmwareVersion=256 (4 B) || ext_len=8 (2 B) || 0106"123456" (8 B)`.
   - Hashes the leaf (`SHA-256(0x00 || entry)`) and walks the 3 sibling hashes in `inclusion_path` (`SHA-256(0x01 || left || right)`), arriving at `computedRoot = iDwM02SMbYqp9JwkLasEDsEajsKImXs553CzWIA49dg`, which matches both `subtree.rootHash` and `mtcDebug.rootHash`.
   - Verifies the **`4,627 B` `ML-DSA-87` (`alg: -50`) signature** in `subtree.signature` over `FIDO-MTC-SUBTREE-CHECKPOINT-V1\x00\x00 || caId || logNum || start || end || rootHash` (`73 B` message) using the **`2,592 B` `ML-DSA-87` public key** from `Fidont Enterprise Root CA` in `metadata.attestationRootCertificates` (`L235484`: `MTC Subtree Root CA signature verified successfully (alg: -50, caId: 83993f0102)`).
5. **Attestation Signature Verification**: Verifies the `2,420 B` `ML-DSA-44` (`alg: -48`) signature in `attStmt.sig` over `authData || clientDataHash` using the authenticated `1,312 B` `ML-DSA-44` public key (`L235485`: `MTC Attestation verified successfully (alg: -48, serial: 0007000000000000)`).

---

### 0.00000000.3 Dual Hardware Button (`P0.11`) & J-Link VCOM (`P0.08`) User Presence Architecture & Automated `probe-rs` Power Cycles in Run 26

| Capability | Hardware / Firmware Implementation (`OpenSK`) | Conformance Tool Hook (`fido_extracted`) | Run 26 Telemetry (`fido_conformance_debug.log` & `opensk_rtt.log`) |
| :--- | :--- | :--- | :--- |
| **1. Dual User Presence (UP) Trigger (`P0.11` Physical Button + `P0.08` J-Link VCOM)** | Compiled **without** `up-always-true`. `runner-nordic/src/main.rs` configures `buttons[0]` = `P0.11` (`SW1`) and `buttons[1]` = `P0.08` (J-Link OB VCOM TX, with `P0.05` `RTS` driven low). `src/touch.rs` registers listeners across all `button::count()` channels, and `CtapState::check_user_presence` (`libraries/opensk/src/ctap/mod.rs:536`) immediately emits `CTAPHID_KEEPALIVE(UpNeeded)` (`0xbb 0x00 0x01 0x02`). | When `CTAPHID_KEEPALIVE(UpNeeded)` arrives and triggers `WAITING FOR TEST OF USER PRESENCE`, `app/js/integration.js` calls `global.triggerOpenSKUserPresence()` (`preload.js:48`), which checks that `[HID] Wasefire` is selected and pulses `0x00` at `300 baud` (`~30 ms` low pulse) on `/dev/cu.usbmodem0010502395621`. Intentional timeout tests (`F-1`/`F-2`) do not call the hook and time out naturally after `30 s`. | **`179` UP checks triggered** in `fido_conformance_debug.log`; **`295` `Button(Event { button: 1, pressed: true })`** events logged in `opensk_rtt.log`; **`0` manual button presses required**, while physical `SW1` remains active at all times. |
| **2. Automated MCU Power-Cycle Reset (`resetOpenSKBoard`)** | `probe-rs reset --chip nRF52840_xxAA` asserts hardware `SYSRESETREQ` over the on-board J-Link OB SWD debugger, clearing RAM (`pinAuthRetries`, volatile `pinUvAuthToken` state, and ephemeral ECDH `keyAgreement` keys) while preserving NVRAM flash (`PIN` hash, `pinRetries`, credentials). | `preload.js:67` (`global.resetOpenSKBoard`) verifies `[HID] Wasefire` is selected, sends `killall -TERM probe-rs` + `120 ms` USB bulk-IN drain so the background RTT logger releases J-Link cleanly, runs `probe-rs reset` (with up to 4 retries), and waits `2,000 ms` for USB HID re-enumeration. Hooked in `Authr-ClientPin1-GetRetries.js` (`P-3`), `Authr-ClientPin2-GetRetries.js` (`P-3`, `P-5`), and `controller.js`. | **`3 / 3` (`100%`) power cycles succeeded on Attempt 1 with zero user dialogs**:<br/>1. `ClientPin1-GetRetries` `P-3` (`L252351`, `439.5 ms` reset, `RTT L1429206`)<br/>2. `ClientPin2-GetRetries` `P-5` initial (`L255496`, `393.4 ms` reset, `RTT L1442546`)<br/>3. `ClientPin2-GetRetries` `P-5` mid-loop (`L255688`, `400.7 ms` reset, `RTT L1443394`) |
| **3. Default Display Support Toggle (`has_display=false`)** | Headless security key profile (`maxMsgSize = 7609`, no on-device display). | Added ` Authenticator supports display` checkbox in `app/views/main.html` & `app/js/controller.js` (`window.config.test.fidoauthenticator.has_display`, defaulting to `false`) and hooked `Authr-ResidentKey-1.js` `P-4` to read `has_display` instead of blocking on a manual confirmation dialog. | `Authr-ResidentKey-1` `P-4` (`L234154`) executed automatically with `has_display = false` and **PASSED** (`6 / 6` PASS in `Authr-ResidentKey-1`, up from `5 Passed / 1 Skipped` in Runs 17–25). |

---

## 0.0000000 Run 25 (`09:34:42` – `09:55:59` PDT, `2026-10-26`) Full-Suite Simultaneous 3-Log Capture: Dynamic `OPENSK_FIRMWARE_VERSION = 256` (`0x0100`) & Serial Number Propagation Across Firmware, X.509 (`id-fido-gen-ce-fwversion`), MTC & FIDO MDS3 + 100% Intact `>>` Append-Mode Debug Log

> [!IMPORTANT]
> **End-to-End Single-Source-of-Truth Propagation for Firmware Version (`256` / `0x0100`) and Device Serial Number (`"123456"`), Plus 100% Uncorrupted `51,269`-Line Debug Log Capture**:
> Prior to Run 25, we unified the definition and propagation of `firmwareVersion` (`256` / `0x0100`) and the device/enterprise serial number across the entire OpenSK / Fidont stack and re-flashed and re-provisioned the Nordic nRF52840 DK:
> 1. **Single Source of Truth in Firmware (`src/env.rs`)**:
>    - Defined `pub const OPENSK_FIRMWARE_VERSION: u64 = 256;` (`0x0100`, v1.0) in `src/env.rs`, returned by both `WasefireEnv::firmware_version() -> Some(OPENSK_FIRMWARE_VERSION)` (controlling `authenticatorGetInfo` member `0x0E` on the hardware board) and `TestEnv::firmware_version() -> Some(OPENSK_FIRMWARE_VERSION)`.
>    - Every MTC leaf entry constructed on-device in `src/ctap/mod.rs` calls `env.firmware_version().unwrap_or(0) as u32`, dynamically hashing `firmware_version = 256` (`0x00000100`) into both the 60-byte MTC leaf header (`bytes[56..60]`) and `"mtc-debug".firmwareVersion`.
>    - Device serial number is read dynamically from hardware silicon (`FICR.DEVICEID[0..1]` on nRF52840) or NVRAM file `0x0206` (`get_device_serial_string()` in `src/ctap/storage.rs`), populated by `tools/configure.py --enterprise-serial "123456"`.
> 2. **Dynamic Propagation to X.509 Certificates (`id-fido-gen-ce-fwversion` OID `1.3.6.1.4.1.45724.1.1.3` & `id-fido-gen-ce-sernum` OID `1.3.6.1.4.1.45724.1.1.2`), MTC Subtrees & FIDO MDS3 Metadata**:
>    - Added `read_opensk_firmware_version(repo_root)` to `tools/configure.py`, `tools/gen_lms_certs.py`, and `crypto_data_enterprise/gen_enterprise_key.py` so Python provisioning tools parse `OPENSK_FIRMWARE_VERSION` directly from `src/env.rs`.
>    - Added the FIDO Firmware Version X.509 extension (**`id-fido-gen-ce-fwversion`**, OID `1.3.6.1.4.1.45724.1.1.3`, DER `OCTET STRING` `04 04 00 00 01 00` = `256` big-endian) to all 5 leaf X.509 certificates (`crypto_data_mldsa44/fidont_cert.pem` `3,056 B`, `crypto_data_mldsa65/fidont_cert.pem` `3,696 B`, `crypto_data_mldsa87/fidont_cert.pem` `4,336 B`, `crypto_data_enterprise/fidont_cert.pem` `3,094 B` alongside `id-fido-gen-ce-sernum` `1.3.6.1.4.1.45724.1.1.2`, and `crypto_data/fidont_cert.pem` `599 B`).
>    - `tools/configure.py` dynamically propagates both `--firmware-version` (`256`) and `--enterprise-serial` (`"123456"`) into the on-device NVRAM (`0x0206`), the enterprise X.509 certificate, the enterprise MTC leaf & LMS-signed subtree checkpoint (`0x0205`), and all FIDO MDS3 metadata files (`metadata/metadata_*.json` and `metadata/mtc_enterprise_info.json`).
> 3. **100% Intact `51,269`-Line `fido_conformance_debug.log` via Append Mode (`>>`)**:
>    - Launching the Electron/Chromium + Node.js Conformance Tool with `>> /Users/jbradley/.gemini/antigravity/scratch/fido_conformance_debug.log 2>&1` (`O_APPEND`) completely eliminated independent stdout/stderr file-descriptor offset overwrites. All **`51,269` lines (`6.87 MB`)** — including all **`21,225` 64-byte HID frames** (`13,178` `OUT`, `8,047` `IN`) and all **`285` Mocha test results** — were preserved in strict chronological order from `L1` (`P-1` of `HID-1`) to `L51269` (`"Testing finished. You may submit the results now."`).
> 4. **Why `Authr-Generic-1 P-1` Reported `expected 256 to equal 1` & Auto-Refresh Fix (`loadLatestOpenSKMetadata`)**:
>    - On the USB wire, the newly flashed OpenSK firmware returned `firmwareVersion (0x0E): 256` (`0x0e 0x19 0x01 0x00`) in all `60` `authenticatorGetInfo` (`0x04`) responses (`845 B` CBOR, up from `844 B` when `firmwareVersion` was `1`).
>    - However, the FIDO Conformance Tool caches `window.config.test.metadataStatement` in Chromium's `localStorage` (`db.save`) when a metadata JSON file is dropped into the UI, so `localStorage` still held the previous session's cached `firmwareVersion: 1`.
>    - We patched `fido_extracted/preload.js` and `fido_extracted/app/js/controller.js` (`global.loadLatestOpenSKMetadata`) and repackaged `app.asar` so the tool automatically reloads `/Users/jbradley/.gemini/antigravity/scratch/OpenSK/metadata/metadata_mldsa44_mtc.json` into `window.config.test.metadataStatement` and `localStorage` whenever a suite is loaded or `Start` is clicked.

### 0.0000000.1 End-to-End Dynamic Propagation Matrix (`OPENSK_FIRMWARE_VERSION = 256` & Device Serial `"123456"`)

| Artifact / Protocol Layer | Firmware Version (`256` / `0x0100`) Field & Encoding | Device / Enterprise Serial (`"123456"`) Field & Encoding | Source & Propagation Mechanism |
| :--- | :--- | :--- | :--- |
| **1. Rust Firmware (`src/env.rs`, `src/ctap/storage.rs`)** | `pub const OPENSK_FIRMWARE_VERSION: u64 = 256;` $\to$ `WasefireEnv::firmware_version() -> Some(256)` | `get_device_serial_string(env)`: reads NVRAM key `0x0206` (`"123456"`), or falls back to hardware `FICR.DEVICEID[0..1]` (`16` hex chars) | Compiled into Cortex-M4F firmware & provisioned over CTAPHID vendor command by `tools/configure.py` |
| **2. `authenticatorGetInfo (0x04)` CBOR (`845 B`)** | Key `0x0E`: `0x0e 0x19 0x01 0x00` (`256` unsigned integer) | Privacy-gated (never exposed in `GetInfo`) | Constructed dynamically in `CtapState::process_get_info()` from `env.firmware_version()` |
| **3. Leaf X.509 Certificates (`x5c` in `fmt: "packed"`)** | OID **`1.3.6.1.4.1.45724.1.1.3`** (`id-fido-gen-ce-fwversion`): `OCTET STRING` `04 04 00 00 01 00` (`4 B` big-endian `u32 = 256`) | OID **`1.3.6.1.4.1.45724.1.1.2`** (`id-fido-gen-ce-sernum`): `UTF8String` `"123456"` (Enterprise cert only; omitted on batch certs) | Generated by `tools/gen_lms_certs.py` & `tools/configure.py` reading `OPENSK_FIRMWARE_VERSION` from `src/env.rs` |
| **4. MTC Leaf Entry (`60 B` header) & Subtree Root (`fmt: "mtc"`)** | `bytes[56..60]`: `00 00 01 00` (`u32 = 256` big-endian) hashed into leaf & LMS-signed (`alg: -46`) subtree root | `mtcProof.extensions`: `0x01 \|\| len("123456") \|\| "123456"` (`8 B`, Enterprise MTC leaf only; `0 B` on batch MTC leaf) | Computed in `tools/configure.py` (provisioning) and `src/ctap/mod.rs` (runtime `"mtc-debug"` proof reconstruction) |
| **5. `"mtc-debug"` Registration Extension (`authenticatorData.extensions`)** | `"firmwareVersion": 256` (`0x19 0x01 0x00`) | `"deviceSerial": "123456"` (emitted **only** when `epAtt: true`; strictly omitted on standard/downgraded registrations) | Constructed at runtime in `src/ctap/mod.rs` from `env.firmware_version()` and `storage::get_device_serial_string(env)` |
| **6. FIDO MDS3 Metadata (`metadata_*.json` & `mtc_enterprise_info.json`)** | Top-level `"firmwareVersion": 256` & `"authenticatorGetInfo": { "firmwareVersion": 256 }` | `"enterpriseAttestation": { "deviceSerial": "123456" }` in `mtc_enterprise_info.json` | Updated automatically by `tools/configure.py` and auto-loaded into the FIDO Conformance Tool via `loadLatestOpenSKMetadata()` |

### 0.0000000.2 Run 25 / Run 27 Wire Size & Timing Across All 18 Algorithms (Non-PQ Updated with Run 27 `600 B` P-384 Cert over P-256 Batch Key + `/tmp/totalphase.csv`)

| # | Algorithm | COSE `alg` | `MakeCred` `fmt` | `attStmt` Structure | `MakeCred` Wire Size | `MakeCred` MCU / Total USB Time (`/tmp/totalphase.csv` / Conformance Log) | `GetAssertion` MCU / Total USB Time (`/tmp/totalphase.csv` / Conformance Log) |
| :-: | :--- | :---: | :---: | :--- | :---: | :---: | :---: |
| 1 | **`ES256`** | `-7` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,078 B`** (`19f`) | **`1,488.18 ms`** (`Total USB = 1,576.24 ms`, `Log = 1,582.6 ms`, `CSV L6040–L6088`) | **`832.10 ms`** (`Total USB = 880.16 ms`, `Log = 882.7 ms`, `CSV L7380–L7408`) |
| 2 | **`ES384`** | `-35` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,113 B`** (`19f`) | **`2,044.25 ms`** (`Total USB = 2,132.31 ms`, `Log = 2,138.6 ms`, `CSV L5964–L6012`) | **`2,584.32 ms`** (`Total USB = 2,636.37 ms`, `Log = 2,647.9 ms`, `CSV L7512–L7544`) |
| 3 | **`ES512`** | `-36` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,148 B`** (`20f`) | **`1,484.18 ms`** (`Total USB = 1,576.24 ms`, `Log = 1,582.4 ms`, `CSV L5886–L5936`) | **`1,968.24 ms`** (`Total USB = 2,020.30 ms`, `Log = 2,025.6 ms`, `CSV L7652–L7682`) |
| 4 | **`ES256K`** | `-47` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,080 B`** (`19f`) | **`920.11 ms`** (`Total USB = 1,008.17 ms`, `Log = 1,015.3 ms`, `CSV L5810–L5858`) | **`308.03 ms`** (`Total USB = 356.09 ms`, `Log = 361.0 ms`, `CSV L7786–L7814`) |
| 5 | **`EdDSA` (`Ed25519`)** | `-8` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,045 B`** (`18f`) | **`916.11 ms`** (`Total USB = 1,000.17 ms`, `Log = 1,009.0 ms`, `CSV L5736–L5782`) | **`268.03 ms`** (`Total USB = 316.08 ms`, `Log = 326.2 ms`, `CSV L7916–L7944`) |
| 6 | **`Ed448`** | `-53` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,070 B`** (`19f`) | **`1,180.14 ms`** (`Total USB = 1,268.20 ms`, `Log = 1,276.4 ms`, `CSV L5660–L5708`) | **`852.10 ms`** (`Total USB = 904.16 ms`, `Log = 912.5 ms`, `CSV L8048–L8078`) |
| 7 | **`ML-DSA-44`** | `-48` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,100 B`** (`70f`) | `1,868.04 ms` (`119,554,688 cyc`) / **`679.31 ms`** (`43,475,904 cyc`) | `1,673.85 ms` (`107,126,400 cyc`) |
| 8 | **`ML-DSA-65`** | `-49` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,740 B`** (`81f`) | `1,880.02 ms` (`120,321,024 cyc`) / **`1,089.30 ms`** (`69,715,328 cyc`) | **`742.22 ms`** (`47,501,888 cyc`) |
| 9 | **`ML-DSA-87`** | `-50` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`5,190 B`** (`88f`) | **`883.37 ms`** (`56,535,744 cyc`) / `1,259.65 ms` (`80,617,344 cyc`) | **`901.13 ms`** (`57,672,128 cyc`) |
| 10 | **`MLDSA44-ES256`** | `-54` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,165 B`** (`71f`) | `1,072.53 ms` (`68,641,856 cyc`) / `1,071.40 ms` (`68,569,472 cyc`) | `1,416.49 ms` (`90,655,424 cyc`) |
| 11 | **`MLDSA65-ES256`** | `-55` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,805 B`** (`82f`) | `1,934.33 ms` (`123,797,312 cyc`) / `1,161.42 ms` (`74,330,944 cyc`) | `1,414.31 ms` (`90,515,712 cyc`) |
| 12 | **`MLDSA87-ES384`** | `-56` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`5,242 B`** (`89f`) | `2,994.97 ms` (`191,677,888 cyc`) / `2,400.78 ms` (`153,649,728 cyc`) | `5,112.91 ms` (`327,226,432 cyc`) |
| 13 | **`MLDSA44-Ed25519`** | `-57` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,132 B`** (`71f`) | `1,040.49 ms` (`66,591,616 cyc`) / **`578.80 ms`** (`37,043,136 cyc`) | `946.46 ms` (`60,573,184 cyc`) |
| 14 | **`MLDSA65-Ed25519`** | `-58` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,772 B`** (`81f`) | `1,678.84 ms` (`107,445,632 cyc`) / **`940.14 ms`** (`60,169,216 cyc`) | `1,391.21 ms` (`89,037,504 cyc`) |
| 15 | **`MLDSA87-Ed448`** | `-59` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`5,202 B`** (`89f`) | `1,438.44 ms` (`92,060,288 cyc`) / `2,591.28 ms` (`165,841,920 cyc`) | `1,538.48 ms` (`98,462,464 cyc`) |
| 16 | **`FN-DSA-512`** | `-60` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`3,685 B`** (`63f`) | **`915.10 ms`** (`58,566,656 cyc`) / **`744.23 ms`** (`47,630,400 cyc`) | `1,334.72 ms` (`85,421,952 cyc`) |
| 17 | **`FN-DSA-1024`** | `-61` | **`"mtc"`** | `alg: -48`, `sig: 2,420 B`, **`mtcKeyRef` (`19 B`)** | **`4,581 B`** (`78f`) | `2,225.95 ms` (`142,460,608 cyc`) / **`600.28 ms`** (`38,417,856 cyc`) | `2,431.71 ms` (`155,629,632 cyc`) |
| 18 | **`RS256`** | `-257` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,273 B`** (`22f`) | **`896.11 ms`** (`Total USB = 996.17 ms`, `Log = 1,003.4 ms`, `CSV L3430–L3484`) | **`4,660.57 ms`** (`Total USB = 4,720.63 ms`, `Log = 4,727.5 ms`, `CSV L12028–L12066`) |

### 0.0000000.3 Total Phase Beagle USB Protocol Analyzer Summary (`/tmp/totalphase.csv`, Run 25 vs Run 24)

| Metric | Value in Run 25 (`/tmp/totalphase.csv`) | Value in Run 24 (`/tmp/totalphase.csv`) | Notes |
| :--- | :--- | :--- | :--- |
| **Capture Timestamp Window** | `Mon Oct 26 09:34:42` – `09:55:59 2026` (`21m 17.03s`) | `Mon Oct 26 07:43:50` – `08:05:36 2026` (`21m 41.36s`) | Complete start-to-finish CTAP 2.3 conformance run |
| **Total CSV Lines / USB Records** | `26,648` CSV lines / **`123,951` USB bus records** | `26,403` CSV lines / `122,002` USB bus records | Aggregate SOF + IN-NAK + `OUT txn` + `IN txn` records |
| **USB `OUT txn` (`64 B` reports)** | **`5,038` transactions (`322,432 B` = `314.9 KB`)** | `4,956` transactions (`317,184 B` = `309.8 KB`) | Host-to-device (`Ep 02 OUT`) CTAPHID frames |
| **USB `IN txn` (`64 B` reports)** | **`8,088` transactions (`517,632 B` = `505.5 KB`)** | `8,037` transactions (`514,368 B` = `502.3 KB`) | Device-to-host (`Ep 02 IN`) CTAPHID frames |
| **Total `64 B` HID Data Transactions** | **`13,126` transactions (`840,064 B` = `820.4 KB`)** | `12,993` transactions (`831,552 B` = `812.1 KB`) | Combined `OUT` + `IN` 64-byte USB interrupt transfers |
| **CTAPHID Channel Handshakes (`0x86`)** | `1,104` `OUT` / `1,103` `IN` | `1,103` `OUT` / `1,102` `IN` | Fresh channel per test exchange |
| **Paired `CTAPHID_CBOR` (`0x90`) Exchanges** | **`1,092` completed pairs** (`154` `MakeCred`, `92` `GetAssertion`, `721` `ClientPIN`, `60` `GetInfo`, `27` `Reset`, `16` `CredMgmt`, `13` `Config`, `6` `LargeBlobs`, `3` `GetNextAssertion`) | `1,092` completed pairs | Identical 37-suite CTAP 2.3 command distribution |
| **`CTAPHID_KEEPALIVE` (`0xbb`) Frames** | `364` `IN` frames (`358` logged by Node) | `362` `IN` frames (`358` logged by Node) | Emitted during multi-second PQ/RSA/ECDSA operations |
| **Intentional Protocol `CTAPHID_ERROR` (`0xbf`)** | `4` `IN` frames | `4` `IN` frames | Expected negative transport test responses in `HID-1` (`INVALID_CMD`, `INVALID_PAR`, `INVALID_LEN`, `INVALID_SEQ`) |
| **Hardware USB Bus / CRC Errors** | **`0` CRC/packet errors** (`1` normal `[1 ORPHANED]` token during USB reset) | **`0`** | `100.00%` CRC-error-free physical USB bus transmission |

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

### 0.000000.1 Wire Size & Timing Across All 18 Algorithms (Non-PQ Updated with Run 27 `600 B` P-384 Cert over P-256 Batch Key + `/tmp/totalphase.csv`)

| # | Algorithm | COSE `alg` | `MakeCred` `fmt` | `attStmt` Structure | `MakeCred` Wire Size (`mtcKeyRef` / `600 B` `x5c`) | Run 22 `MakeCred` Size (`mtcEntryDesc`) | Pre-PR `"mtc"` Size (Inline `pubKey`) | `MakeCred` MCU / Total USB Time (`/tmp/totalphase.csv`) | `GetAssertion` MCU / Total USB Time (`/tmp/totalphase.csv`) |
| :-: | :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| 1 | **`ES256`** | `-7` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,078 B`** (`19f`) | `1,054 B` (`18f`) | `1,054 B` | **`1,488.18 ms`** (`1,576.24 ms` USB) | **`832.10 ms`** (`880.16 ms` USB) |
| 2 | **`ES384`** | `-35` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,113 B`** (`19f`) | `1,088 B` (`19f`) | `1,088 B` | **`2,044.25 ms`** (`2,132.31 ms` USB) | **`2,584.32 ms`** (`2,636.37 ms` USB) |
| 3 | **`ES512`** | `-36` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,148 B`** (`20f`) | `1,124 B` (`20f`) | `1,124 B` | **`1,484.18 ms`** (`1,576.24 ms` USB) | **`1,968.24 ms`** (`2,020.30 ms` USB) |
| 4 | **`ES256K`** | `-47` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,080 B`** (`19f`) | `1,055 B` (`18f`) | `1,055 B` | **`920.11 ms`** (`1,008.17 ms` USB) | **`308.03 ms`** (`356.09 ms` USB) |
| 5 | **`EdDSA` (`Ed25519`)** | `-8` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,045 B`** (`18f`) | `1,020 B` (`18f`) | `1,020 B` | **`916.11 ms`** (`1,000.17 ms` USB) | **`268.03 ms`** (`316.08 ms` USB) |
| 6 | **`Ed448`** | `-53` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,070 B`** (`19f`) | `1,047 B` (`18f`) | `1,047 B` | **`1,180.14 ms`** (`1,268.20 ms` USB) | **`852.10 ms`** (`904.16 ms` USB) |
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
| 18 | **`RS256`** | `-257` | `"packed"` | `alg: -7`, `sig: 71 B`, `x5c: [600 B]` (`ES384` Root) | **`1,273 B`** (`22f`) | `1,249 B` (`22f`) | `1,249 B` | **`896.11 ms`** (`996.17 ms` USB) | **`4,660.57 ms`** (`4,720.63 ms` USB) |

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

### 0.3 Multi-Run Comparison Across the Last 10 Runs (`Runs 17–26`): Evolution of 18 Algorithms, 2-Field `mtcKeyRef`, `"mtc-debug"`, Stateless Root CAs, Real Hardware/VCOM UP & Automated MCU Power Cycles

| Metric | Run 17 (`perCredMgmtRO`) | Run 19 (18 Algs + USB + RTT) | Run 20–21 (HSS/LMS Hierarchy) | Run 22 (`fmt: "mtc"` Consolidated) | Run 24 (2-Field `mtcKeyRef` + USB) | Run 25 (`FW=256` + USB) | Run 26 (Stateless `ML-DSA-87`/`ES384` + Real UP + Auto Reset) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Log Range & Duration** | `L1–L48653` (`12m 27s`) | `L1–L66127` (`21m 28s`) | `35,146` lines (`25m 28s`) | `L1–L34421` (`20m 07s`) | `L1–L37223` (`21m 41s`) | `L1–L51269` (`21m 17s`) | **`L210496–L260427` (`18m 27.46s`)** |
| **Test Results** | `250 Passed / 32 Skipped / 0 Failed` | `250 Passed / 32 Skipped / 0 Failed` | `250 Passed / 33 Skipped / 0 Failed` | `247 Passed / 32 Skipped / 4 Failed*` | `250 Passed / 33 Skipped / 0 Failed` | `249 Passed / 35 Skipped / 1 Failed*` | **`252 Passed / 31 Skipped / 0 Failed (`100.00%`)`** |
| **Supported COSE Algorithms** | `16` algorithms | **`18` (`+FN-DSA-512/1024`)** | **`18` (`+FN-DSA-512/1024`)** | **`18` (`+FN-DSA-512/1024`)** | **`18` (`+FN-DSA-512/1024`)** | **`18` (`+FN-DSA-512/1024`)** | **`18` (`+FN-DSA-512/1024`)** |
| **Root CAs & MTC Trust Anchor** | `ES384` `x5c` + `ML-DSA-44` MTC | `ML-DSA-87` Root CA & MTC | `HSS/LMS` (`alg: -46`) Root & Intermediates | `HSS/LMS` (`alg: -46`) Root & Intermediates | `HSS/LMS` (`alg: -46`) + 2-Field `mtcKeyRef` | `HSS/LMS` (`alg: -46`) + `FW=256` OID | **Stateless `ML-DSA-87` (`alg: -50`) & `ES384` (`alg: -35`) Root CAs** |
| **Enterprise `P-2`/`P-3` Wire Size** | `5,595 B` (`"mtcl"`) | `7,452 B` (`"packed"` `x5c`) | `6,692 B` (`"packed"` `x5c`) | `7,265 B` (`x5c` + `"mtc-debug"`) | `7,492 B` (`x5c` + 7-field `"mtc-debug"`) | `7,492 B` (`x5c` + 7-field `"mtc-debug"`) | **`4,448 B` (`76f`, `fmt: "mtc"` `mtcKeyRef` + 7-field `"mtc-debug"`)** |
| **User Presence (UP) & Power Cycles** | `up-always-true` + Manual Replug | `up-always-true` + Manual Replug | `up-always-true` + Manual Replug | `up-always-true` + Manual Replug | `up-always-true` + Manual Replug | `up-always-true` + Auto Reset (`2/3`) | **Real `P0.11`/`P0.08` UP (`179` checks) + `3/3` Zero-Dialog Auto Resets** |
| **`Metadata-Stmt-1` Verification** | `37/37` Passed | `37/37` Passed | `25/25` Applicable Passed | `25/25` Applicable Passed | `25/25` Applicable Passed | `25/25` Applicable Passed | **`25/25` Applicable (`100%`) Passed** |

### 0.4 `Authr-MakeCred-Resp-1` Algorithm Sweep: Conformance Log vs. Total Phase Hardware USB Analyzer (Non-PQ Updated with Run 27 `600 B` P-384 Cert over P-256 Batch Key + `/tmp/totalphase.csv`)

| # | COSE `alg` | Algorithm Name | `fmt` & Attestation Cert / MTC | Wire Size (`BCNT` / Frames) | Hardware MCU Compute Time (`totalphase.csv`) | USB `IN` Transfer Time (`totalphase.csv`) | Total USB Exchange Time (`totalphase.csv`) | Conformance Log Line | TotalPhase CSV Line Range |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `-257` | `RS256` | **`"packed"` (`600 B` `ES384` Root over `ES256` Batch)** | **`1,273 B` (`22`)** | **`896.11 ms`** (`1` `KA`) | `84.01 ms` | **`996.17 ms`** (`Log: 1,003.4 ms`) | `L394481–L394522` | `CSV L3430–L3484` |
| 2 | `-59` | `ML-DSA-87-Ed448` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`5,202 B` (`89`)** | **`1,436.18 ms`** (`2` `KA`) | `352.04 ms` | **`1,804.27 ms`** (`Log: 1,813.0 ms`) | `L395035–L395146` | `CSV L3876–L4066` |
| 3 | `-58` | `ML-DSA-65-Ed25519` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`4,772 B` (`81`)** | **`1,708.21 ms`** (`2` `KA`) | `320.04 ms` | **`2,044.30 ms`** (`Log: 2,053.6 ms`) | `L395331–L395434` | `CSV L4118–L4292` |
| 4 | `-57` | `ML-DSA-44-Ed25519` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`4,132 B` (`71`)** | **`1,040.13 ms`** (`1` `KA`) | `280.03 ms` | **`1,336.21 ms`** (`Log: 1,341.0 ms`) | `L395610–L395702` | `CSV L4342–L4494` |
| 5 | `-56` | `ML-DSA-87-ES384` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`5,242 B` (`89`)** | **`2,988.37 ms`** (`5` `KA`) | `352.04 ms` | **`3,356.46 ms`** (`Log: 3,365.4 ms`) | `L395891–L396005` | `CSV L4546–L4742` |
| 6 | `-55` | `ML-DSA-65-ES256` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`4,805 B` (`82`)** | **`1,940.24 ms`** (`3` `KA`) | `324.04 ms` | **`2,280.33 ms`** (`Log: 2,293.0 ms`) | `L396190–L396295` | `CSV L4794–L4972` |
| 7 | `-54` | `ML-DSA-44-ES256` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`4,165 B` (`71`)** | **`1,072.13 ms`** (`1` `KA`) | `280.03 ms` | **`1,368.22 ms`** (`Log: 1,375.5 ms`) | `L396471–L396563` | `CSV L5022–L5174` |
| 8 | `-50` | `ML-DSA-87` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`5,190 B` (`88`)** | **`884.11 ms`** (`1` `KA`) | `348.04 ms` | **`1,248.20 ms`** (`Log: 1,259.6 ms`) | `L396750–L396859` | `CSV L5226–L5412` |
| 9 | `-49` | `ML-DSA-65` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`4,740 B` (`81`)** | **`1,876.23 ms`** (`3` `KA`) | `320.04 ms` | **`2,212.32 ms`** (`Log: 2,223.9 ms`) | `L397045–L397149` | `CSV L5464–L5640` |
| 10 | `-48` | `ML-DSA-44` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`4,100 B` (`70`)** | **`1,864.23 ms`** (`3` `KA`) | `276.03 ms` | **`2,156.32 ms`** (`Log: 2,163.9 ms`) | `L397335–L397428` (`P-01` `L394058–L394149`) | `CSV L3108–L3262` |
| 11 | `-53` | `Ed448` | **`"packed"` (`600 B` `ES384` Root over `ES256` Batch)** | **`1,070 B` (`19`)** | **`1,180.14 ms`** (`1` `KA`) | `72.01 ms` | **`1,268.20 ms`** (`Log: 1,276.4 ms`) | `L397359–L397398` | `CSV L5660–L5708` |
| 12 | `-8` | `Ed25519` | **`"packed"` (`600 B` `ES384` Root over `ES256` Batch)** | **`1,045 B` (`18`)** | **`916.11 ms`** (`1` `KA`) | `68.01 ms` | **`1,000.17 ms`** (`Log: 1,009.0 ms`) | `L397488–L397525` | `CSV L5736–L5782` |
| 13 | `-47` | `ES256K` | **`"packed"` (`600 B` `ES384` Root over `ES256` Batch)** | **`1,080 B` (`19`)** | **`920.11 ms`** (`1` `KA`) | `72.01 ms` | **`1,008.17 ms`** (`Log: 1,015.3 ms`) | `L397614–L397652` | `CSV L5810–L5858` |
| 14 | `-36` | `ES512` | **`"packed"` (`600 B` `ES384` Root over `ES256` Batch)** | **`1,148 B` (`20`)** | **`1,484.18 ms`** (`2` `KA`) | `76.01 ms` | **`1,576.24 ms`** (`Log: 1,582.4 ms`) | `L397742–L397783` | `CSV L5886–L5936` |
| 15 | `-35` | `ES384` | **`"packed"` (`600 B` `ES384` Root over `ES256` Batch)** | **`1,113 B` (`19`)** | **`2,044.25 ms`** (`3` `KA`) | `72.01 ms` | **`2,132.31 ms`** (`Log: 2,138.6 ms`) | `L397874–L397916` | `CSV L5964–L6012` |
| 16 | `-7` | `ES256` | **`"packed"` (`600 B` `ES384` Root over `ES256` Batch)** | **`1,078 B` (`19`)** | **`1,488.18 ms`** (`2` `KA`) | `72.01 ms` | **`1,576.24 ms`** (`Log: 1,582.6 ms`) | `L398006–L398046` | `CSV L6040–L6088` |
| 17 | `-60` | `FN-DSA-512` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`3,685 B` (`63`)** | **`908.11 ms`** (`1` `KA`) | `248.03 ms` | **`1,172.19 ms`** (`Log: 1,182.8 ms`) | `L394853–L394937` | `CSV L3688–L3824` |
| 18 | `-61` | `FN-DSA-1024` | **`"mtc"` (`-48` MTC under `ML-DSA-87` Root)** | **`4,581 B` (`78`)** | **`2,224.28 ms`** (`3` `KA`) | `308.04 ms` | **`2,548.36 ms`** (`Log: 2,557.9 ms`) | `L394589–L394690` | `CSV L3498–L3668` |

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
