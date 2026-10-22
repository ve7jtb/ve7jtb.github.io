# Multi-Batch Post-Quantum FIDO Attestation via LM-OTS & Google Longfellow (`longfellow-lmots-zk` and Direct Enterprise LMS)

> [!IMPORTANT]
> **Notice:** This document is an early architectural proposal for discussion only. It is aligned with the **FIDO Client to Authenticator Protocol (CTAP) v2.3 Proposed Standard (`2026-02-26`)** and **W3C Web Authentication (WebAuthn) Level 3**, and has not yet been adopted by the FIDO Alliance or W3C WebAuthn Working Group.

This specification defines a post-quantum, multi-batch FIDO2/WebAuthn attestation architecture combining **RFC 8554 LM-OTS (Leighton-Micali One-Time Signatures)** on resource-constrained hardware security keys with **Google Longfellow** (a zero-knowledge prover using GKR layered sumcheck + Ligero over binary extension fields $\text{GF}(2^k)$) on participating host platforms, alongside a **zero-ZK Direct Enterprise Attestation profile**:

1. **[Section 1 — Hardware Layer: 128-Byte Core State & Black-Box Manufacturer Profiles](#1-hardware-layer-128-byte-core-state--black-box-manufacturer-profiles)**
2. **[Section 2 — Component Pipeline, `authenticatorGetInfo` Signaling & Witness Sourcing (CTAP 2.3 & WebAuthn Level 3)](#2-component-pipeline-authenticatorgetinfo-signaling--witness-sourcing-ctap-23--webauthn-level-3)**
3. **[Section 3 — Multi-Batch AAGUID Routing & WebAuthn Level 3 Public Input Structure](#3-multi-batch-aaguid-routing--webauthn-level-3-public-input-structure)**
4. **[Section 4 — Circuit Optimization for Google Longfellow (GKR SIMD + $\text{GF}(2^k)$)](#4-circuit-optimization-for-google-longfellow-gkr-simd--gf2k)**
5. **[Section 5 — Overhead & Performance Summary (Consumer Anonymous ZK Profile — 31-Level Tree)](#5-overhead--performance-summary-consumer-anonymous-zk-profile--31-level-tree)**
6. **[Section 6 — Enterprise Direct Attestation Profile (No Host ZK — 25-Level Self-Contained Tree)](#6-enterprise-direct-attestation-profile-no-host-zk--25-level-self-contained-tree)**

---

## 1. Hardware Layer: 128-Byte Core State & Black-Box Manufacturer Profiles

To enable seamless post-quantum attestation on resource-constrained Secure Element microcontrollers without storing multi-megabyte hash trees or executing heavy post-quantum group signature schemes on-chip, the authenticator maintains a **128-byte core persistent state** in Non-Volatile Memory (NVM) and derives its one-time signing keys and local subtree path nodes on the fly.

### 1.1 Core Persistent State Layout (128 Bytes Total: 112 B Read-Only + 16 B Mutable)

| Component Group | Field Name | Size | NVM Type | Architectural Role |
| :--- | :--- | :---: | :---: | :--- |
| **Master Secret Core (96 B)** | `Master Seed` | 32 B | Read-Only (Provisioned) | High-entropy random root for dynamic, on-the-fly LM-OTS private key derivation via `HMAC-SHA-256` / `HKDF`. |
| | `Key Identifier (I)` | 32 B | Read-Only (Provisioned) | Internal RFC 8554 tree/leaf domain-separation binding string. |
| | `Batch Root ID` | 32 B | Read-Only (Provisioned) | SHA-256 hash of the Batch Master Root Public Key; emitted in CTAP 2.3 responses to anchor the token to its manufacturing batch root. |
| **Stateful Monotonic Bounds (32 B)** | `Global Leaf Index Counter (q)` | 8 B | **Mutable (Monotonic)** | Monotonic counter tracking the next available unique, non-reusable registration (`makeCredential`) index. |
| | `Subtree Offset ID` | 8 B | Read-Only (Provisioned) | Identifies the $2^{14}$ ($16,384$-leaf) block boundary assigned to this specific device within the $2^{17}$ ($131,072$-device) batch. |
| | `Subtree Range Limit` | 8 B | Read-Only (Provisioned) | Upper bound parameter enforcing the $16,384$ `makeCredential` registration limit per key. |
| | `Reservation Milestone Guard` | 8 B | **Mutable (Every $\Delta$ signs)** | Manages state reservation blocks of size $\Delta$ in NVM to minimize flash write wear. On power-up or reset, the active RAM counter initializes directly to the Milestone Guard and advances NVM by $+\Delta$ before signing, guaranteeing **zero index reuse** across unexpected USB unplugging or power loss. |
| **Total Core State** | **Core Allocation** | **128 B** | **112 B RO + 16 B Mutable** | *(Or **112 B** if using 32-bit `uint32` counters; budgeted under 250 B for core applet headers.)* |

---

### 1.2 Black-Box Manufacturer Implementation Choices for the 14-Level Device Subtree

In the **31-level Consumer Anonymous configuration** ($17\text{ batch levels} + 14\text{ device levels} = 31\text{ levels}$), each authenticator is assigned a **14-level ($2^{14} = 16,384$-leaf) device subtree**.

Because the authenticator outputs the **exact same 14 sibling hashes (448 bytes)** of its $16,384$-leaf subtree regardless of how they are computed internally, **the on-key traversal mechanism is a complete black box** to the CTAP 2.3 wire protocol, the Host Longfellow Prover, and the Relying Party Verifier. Authenticator manufacturers can select between two implementation profiles based on their Secure Element's NVM/flash characteristics:

| Manufacturer Profile | Persistent NVM / Flash Footprint | Peak Volatile RAM | On-Key Path Compute (`makeCredential`) | Operational Mechanism |
| :--- | :--- | :---: | :---: | :--- |
| **Profile 1: Latency-Optimized**<br/>*(Incremental BDS State in NVM)* | **~1,568 B Total**<br/>*(128 B core + 1,440 B mutable 45-node BDS buffer)* | **~512 B** | **~6.2 ms**<br/>*(6 leaf evaluations = 6,234 SHA-256 blocks worst-case)* | Maintains a rolling 45-node Buchmann–Dahmen–Szydlo (BDS) fractal traversal state in NVM so incremental state persists across power cycles. |
| **Profile 2: Flash-Wear-Optimized**<br/>*(Read-Only Top-7 Subtree Cache)* | **4,224 B Total**<br/>*(128 B core [only 16 B mutable!] + 4,096 B Read-Only factory flash)* | **~320 B**<br/>*(8-node stack)* | **~130 ms**<br/>*(127 leaves = 131,953 SHA-256 blocks statelessly in RAM)* | Splits the 14 device levels into **Top 7 levels** ($2^7 = 128$ roots cached in read-only factory flash = $4,096\text{ B}$) + **Bottom 7 levels** ($2^7 = 128$ leaves per sub-subtree). Computes the active 128-leaf sub-subtree 100% statelessly in volatile RAM and folds the 128 read-only roots in `<0.1 ms`—achieving **zero flash wear** from tree updates. |
| **Optional: Self-Contained On-Key Batch Path** | **+544 B Read-Only Flash**<br/>*(17 $\times$ 32 B static batch ancestor hashes)* | **+0 B** | **+0 ms** | Stores the 17 static batch ancestor hashes in read-only flash on the key and returns all 31 Merkle path nodes (992 B) over CTAP 2.3, eliminating the host Subtree Token entirely for 100% self-contained roaming across any host PC/phone. |

---

## 2. Component Pipeline, `authenticatorGetInfo` Signaling & Witness Sourcing (CTAP 2.3 & WebAuthn Level 3)

Before credential registration, an authenticator supporting this scheme advertises its capability in the **CTAP 2.3 `authenticatorGetInfo` (`0x04`)** response (via `attestationFormats` `0x16` / `extensions`), signaling to a participating host platform that it can emit a structured LM-OTS witness for host-side Longfellow proof generation.

```mermaid
sequenceDiagram
    participant RP as Relying Party (WebAuthn L3)
    participant P as Participating Host Platform (Longfellow ZK Prover)
    participant A as Security Key (CTAP 2.3 / ML-DSA-65 + LM-OTS)

    P->>A: authenticatorGetInfo (0x04)
    A-->>P: versions: ["FIDO_2_3"], algorithms: [{alg: -49 (ML-DSA-65)}],<br/>attestationFormats: ["lmots-batch-witness", "longfellow-lmots-zk"], maxMsgSize: 7609

    RP->>P: navigator.credentials.create(PublicKeyCredentialCreationOptions)
    P->>A: authenticatorMakeCredential (0x01: clientDataHash, rp, user, pubKeyCredParams: [-49])

    Note over A: 1. Generates ML-DSA-65 credential keypair (1,952 B PK)<br/>2. Constructs canonical authData (rpIdHash, flags, signCount, aaguid, 32B credId, COSE_Key)<br/>3. Signs authData || clientDataHash (~2,053 B = 33 SHA-256 blocks) with derived LM-OTS key (q)<br/>4. Computes 14 device-subtree sibling nodes (448 B) on the fly (Profile 1: ~6.2 ms / Profile 2: ~130 ms)

    A-->>P: CTAP 2.3 MakeCredential Response (~4.66 KB, single USB CTAPHID frame):<br/>0x01 fmt: "lmots-batch-witness", 0x02 authData, 0x03 attStmt: {lmotsSig (2,180B), devicePath (448B), C, q, I, batchRootId}

    Note over P: Host Blinding Operation (Local Zero-Roundtrip Anonymization CA):<br/>1. Pairs 14 on-the-fly device nodes (448 B) with 17 static batch nodes (544 B) -> 31-node path (992 B)<br/>2. Packs (31-node path, lmotsSig, C, I, q) into Longfellow private witness<br/>3. Runs 47-layer GKR SIMD SHA-256 prover (~785-1,470 ms)<br/>4. Rewrites fmt -> "longfellow-lmots-zk" and replaces attStmt with {batchRootId, zkProof (310-345 KB)}

    P-->>RP: WebAuthn AttestationObject {fmt: "longfellow-lmots-zk", authData (unmodified), attStmt: {batchRootId, zkProof}}
    Note over RP: 1. Extracts AAGUID from authData + batchRootId from attStmt -> Resolves Batch Master Root in FIDO MDS<br/>2. Verifies Longfellow ZK proof against (authData, clientDataHash, batchRootId) in ~480 ms
```

### 2.1 The Edge Operation (Security Key — On-the-Fly Signing & Subtree Path Derivation)

1. **Post-Quantum Credential Generation:** The key generates a new post-quantum credential key pair (**`ML-DSA-65`**, COSE `alg: -49`, raw public key footprint of `1,952 bytes`) and constructs the canonical CTAP 2.3 `authData` byte string (`rpIdHash` 32 B, `flags` 1 B, `signCount` 4 B, `aaguid` 16 B, fixed 32-byte `credentialId`, and canonical `COSE_Key` map).
2. **CTAP 2.3 Compliant LM-OTS Signing:** Per CTAP 2.3 Section 6.1 and WebAuthn Level 3, the key reads its internal leaf index $q$, derives the corresponding one-time LM-OTS private key ($w = 4, p = 67$ chains) from its 32-byte `Master Seed`, and signs the constant-length concatenation:
   $$\text{SignedPayload} = \texttt{authData} \parallel \texttt{clientDataHash} \quad (\sim 2,053\text{ bytes} = 33\text{ SHA-256 blocks})$$
   using native hardware SHA-256 in `<8 ms`.
3. **On-the-Fly Device Subtree Path Generation:** Using either **Manufacturer Profile 1** (incremental BDS traversal in `~6.2 ms`) or **Manufacturer Profile 2** (stateless bottom-7 RAM derivation + read-only top-7 flash cache in `~130 ms`), the key produces the **14 dynamic sibling nodes (`448 bytes`)** of its $16,384$-leaf ($2^{14}$) device subtree on the fly for leaf $q$.
4. **CTAP 2.3 Response Framing:** The key returns a standard CTAP 2.3 response (**`~4.66 KB` total**, or **`~5.20 KB`** if the 544-byte static batch path is also stored on-key—both fitting comfortably inside a single `7,609-byte` USB CTAPHID frame, or fragmented over BLE/NFC):
   * `0x01` (`fmt`): Initial authenticator attestation format (e.g., `"batch"` / `"lmots-batch-witness"`).
   * `0x02` (`authData`): Canonical Authenticator Data containing the `ML-DSA-65` public key.
   * `0x03` (`attStmt`) / `0x06` (`unsignedExtensionOutputs`): Carries the `2,180-byte` LM-OTS signature ($4\text{ B type} + 32\text{ B } C + 67 \times 32\text{ B chains}$), the 14 on-the-fly device-subtree path nodes (`448 bytes`), leaf index $q$, Key Identifier $I$, and `batchRootId`.

---

### 2.2 The Blinding Operation (Host Client Prover — Platform Format Rewriting)

1. **Witness Extraction (Zero Host Database Required):** Having detected the authenticator's capability via `authenticatorGetInfo`, a participating host platform intercepts the `makeCredential` response, parses the LM-OTS signature and the 14 on-the-fly dynamic path nodes from the authenticator's raw/batch attestation statement, and keeps `authData` untouched. Because the security key generates its 14 device-subtree path nodes on the fly, **the host requires no local SQLite/RocksDB leaf database**.
2. **Full 31-Node Path Assembly:** The host pairs the **14 dynamic path nodes (`448 bytes`)** received from the key with the **17 static batch ancestor hashes (`544 bytes`)** (either from its cached Subtree Token or emitted directly by the key), forming a complete **31-node (`992-byte`) Merkle authentication path** to the Batch Master Root.
3. **Longfellow Private Witness Packing:** The 31-node Merkle path, the raw LM-OTS signature ($67 \times 32\text{ B}$ chain values + 32-byte randomizer $C$), Key Identifier $I$, and 31-bit leaf index $q$ (whose binary bits control left/right child ordering at each of the 31 Merkle levels) are packed into the private witness of the Google Longfellow circuit.
4. **Platform Format Transition (`fmt` Rewriting):** Acting as a **local, zero-roundtrip WebAuthn Level 3 Anonymization CA** (for `"indirect"` and `"direct"` `AttestationConveyancePreference`), the participating platform rewrites the attestation format (`fmt`) in the `makeCredential` output from the authenticator's native batch format to the new ZK attestation format string (**`"longfellow-lmots-zk"`**) and replaces `attStmt` with the generated proof and `batchRootId`.

---

## 3. Multi-Batch AAGUID Routing & WebAuthn Level 3 Public Input Structure

To support production models where a single 16-byte `AAGUID` spans multiple distinct manufacturing batches—each tied to an isolated Master Root—the attestation output provides a dynamic routing anchor without compromising user anonymity or mutating `authData`:

```cddl
; WebAuthn Level 3 AttestationObject emitted by a Participating Platform
LongfellowZkAttestationObject = {
    "fmt": "longfellow-lmots-zk",
    "authData": bstr,                  ; Unmodified from Authenticator (includes AAGUID & ML-DSA-65 COSE_Key)
    "attStmt": {
        "batchRootId": bstr .size 32,  ; SHA-256 hash of the Batch Master Root Public Key
        "zkProof": bstr                ; 310-345 KB Google Longfellow GKR+Ligero ZK Proof
    }
}
```

* **Standard WebAuthn Level 3 Encapsulation:** Because WebAuthn Level 3 forbids host modification of `authData` while explicitly permitting platform replacement of `fmt` and `attStmt`, encapsulating `batchRootId` and `zkProof` inside `attStmt` ensures **100% compatibility with existing WebAuthn Level 3 browser APIs** (`getAuthenticatorData()`, `getPublicKey()`, `getPublicKeyAlgorithm()`) with zero Web IDL changes.
* **Relying Party Resolution (WebAuthn Level 3 Section 7.1):** During credential registration verification (`Verify(attStmt, authData, clientDataHash)`), the RP extracts the 16-byte `aaguid` from `authData.attestedCredentialData.aaguid` and pairs it with `attStmt.batchRootId` to query its FIDO Metadata Service (MDS) catalog, resolving the exact public Master Root anchor for the target manufacturing batch (e.g., *"Titan Batch 2026-B"*).
* **Privacy Isolation ($>100,000$ Keys / $>2.14\text{B}$ Signatures per Batch):** Because each Master Root encompasses an entire production batch of up to **$131,072$ ($2^{17}$) authenticators**—each supporting **$16,384$ ($2^{14}$) `makeCredential` registrations** for over **$2.14\text{ billion}$ ($2^{31}$) total leaf signatures per batch**—revealing `batchRootId` identifies only the manufacturing batch while eliminating individual token tracking or cross-site correlation.

---

## 4. Circuit Optimization for Google Longfellow (GKR SIMD + $\text{GF}(2^k)$)

Google Longfellow (combining a **GKR layered sumcheck** with **Ligero** over binary extension fields $\text{GF}(2^k)$) is uniquely suited to LM-OTS + Merkle attestation by exploiting fixed-bound structural constraints and **SIMD data-parallelism** across Winternitz chains:

```mermaid
flowchart LR
    subgraph L1["Layer Group 1: Message Digest (Public + Private Prefix)"]
        M["authData || clientDataHash (~2,053 B)<br/>+ Private (I, q, D_MESG, C)<br/>33 SHA-256 Blocks"] --> D["256-Bit Randomized Digest Q<br/>+ 3-Nibble Checksum (67 Nibbles)"]
    end

    subgraph L2["Layer Group 2: GKR SIMD Winternitz Evaluation (15 Layers x Width 67)"]
        D --> W["67 Parallel Winternitz Chains (w=4)<br/>15 Conditional SHA-256 + MUX Steps Each<br/>(1,005 SHA-256 Blocks in 15 Sequential Layers)"]
    end

    subgraph L3["Layer Group 3: Leaf & 31-Level Merkle Path (32 Sequential Layers)"]
        W --> K["LM-OTS Public Key Compression<br/>(34 SHA-256 Blocks / 1 Logical Layer)"]
        K --> P["31-Level Merkle Path Verification<br/>Controlled by 31 Bits of Secret Index q<br/>(31 Sequential SHA-256 Layers)"]
        P --> R[" Public Output:<br/>batchRootId (32 B)"]
    end
```

1. **Fixed-Bound SHA-256 Pre-Padding:**
   Because the `credentialId` (fixed 32 bytes), canonical COSE-encoded `ML-DSA-65` public key (`1,952 bytes` + fixed CBOR header), `authData` header, and `clientDataHash` (32 bytes) have a known compile-time constant length (**`~2,053 bytes = 33 SHA-256 blocks`**), all SHA-256 bit-padding logic and message block boundaries are hardcoded into Longfellow's circuit configuration, eliminating dynamic length-validation overhead.
2. **Bit-Sliced Winternitz Multiplexing & Checksum in $\text{GF}(2^k)$:**
   Longfellow extracts the $w = 4$ Winternitz nibbles ($a_0, \dots, a_{63}$) directly from bit-sliced SHA-256 output wires, computes the 3-nibble Winternitz checksum $C_{\text{sum}} = \sum_{i=0}^{63}(15 - a_i)$ ($a_{64}, a_{65}, a_{66}$), and evaluates conditional step-count multiplexers (selecting between applying SHA-256 for steps $j \ge a_i$ and bypassing for steps $j < a_i$ across all 15 steps) natively in $\text{GF}(2^k)$ without the bit-decomposition/re-packing overhead required by prime-field provers.
3. **GKR SIMD Data-Parallelism & Trace Uniformity (1,100 Blocks in 47 Sequential Layers):**
   Full in-circuit verification evaluates **`~1,100 SHA-256 compression blocks`**:
   * `33 blocks` for `I || q || D_MESG || C || authData || clientDataHash`
   * `67 × 15 = 1,005 blocks` for the 67 Winternitz chains ($w = 4$)
   * `34 blocks` to compress the 67 chain endpoints ($2,144\text{ B} + \text{prefix}$) into the LM-OTS leaf hash
   * `31–62 blocks` for the 31-level Merkle authentication path
   Crucially, because all **67 Winternitz chains execute identical 15-step SHA-256 subcircuits in parallel**, Longfellow's GKR sumcheck evaluates all 67 chains simultaneously as a **single SIMD-batched subcircuit of depth 15** (adding only $\lceil\log_2(67)\rceil = 7$ sumcheck variables per layer), compressing the entire execution trace into just **47 sequential SHA-256 circuit layers**.

---

## 5. Overhead & Performance Summary (Consumer Anonymous ZK Profile — 31-Level Tree)

| Metric | Consumer Anonymous ZK Profile (`longfellow-lmots-zk`) |
| :--- | :--- |
| **Tree Topology & Capacity** | **31-Level Merkle Tree:** 17 Batch Levels ($2^{17} = \mathbf{131,072\text{ keys/batch}}$) + 14 Device Levels ($2^{14} = \mathbf{16,384\text{ registrations/key}}$; $2.14\text{B}$ total batch leaves) |
| **On-Key Persistent Storage** | **128 B Core State** + Black-Box Choice: **Profile 1:** `1,440 B` mutable BDS state (`~1.57 KB` total) **OR Profile 2:** `4,096 B` Read-Only Top-7 flash cache (`0 B` mutable tree state!) *(Optional `+544 B` RO flash for self-contained batch path)* |
| **On-Key `makeCredential` Latency** | **~15 ms** (Profile 1: LM-OTS sign + 6 BDS leaves) **OR ~138 ms** (Profile 2: LM-OTS sign + 127 stateless RAM leaves) |
| **CTAP 2.3 Hardware Wire Payload** | **~4.66 KB** (`~5.20 KB` with on-key batch path) — fits in a **single 7,609 B USB CTAPHID frame** |
| **Circuit Depth & Total SHA-256 Work** | **`~1,100 SHA-256 blocks`** compressed via GKR SIMD batching into **47 sequential SHA-256 layers** (15 SIMD Winternitz layers of width 67 + 1 leaf compression layer + 31 Merkle layers) |
| **Host Longfellow Prover Latency** | **~785–1,470 ms** on a standard consumer CPU (with **zero local SQLite/RocksDB database**) |
| **WebAuthn Public Inputs** | `(authData, clientDataHash, attStmt.batchRootId)` |
| **WebAuthn Network Payload (`zkProof`)** | **310–345 KB** inside `attStmt.zkProof` (pure symmetric/hash-based post-quantum security) |
| **Relying Party Verification Time** | **~480 ms** |

---

## 6. Enterprise Direct Attestation Profile (No Host ZK — 25-Level Self-Contained Tree)

When deployed for **Enterprise Attestation (`AttestationConveyancePreference: "enterprise"`)** where zero-knowledge blinding is not required, where **$\ge 1,000$ `makeCredential` registrations per device** ($2^{10} = 1,024, h_{\text{device}} = 10$) is sufficient, and where manufacturing batches are up to **$\ge 20,000$ keys** ($2^{15} = 32,768, h_{\text{batch}} = 15$), the architecture simplifies into a **25-level hierarchical LMS/LM-OTS Merkle tree** that operates **100% self-contained on the security key** with zero host software or storage.

### 6.1 Self-Contained On-Authenticator Storage (~1.6 KB Total Persistent Storage)

Because the 15 static batch ancestor hashes occupy only **$15 \times 32\text{ B} = \mathbf{480\text{ bytes}}$**, they are stored directly in read-only flash on the authenticator, eliminating the host Subtree Token completely. Splitting the 10-level ($1,024$-leaf) device subtree into **Top 5 levels ($2^5 = 32$ roots)** cached in read-only factory flash + **Bottom 5 levels ($2^5 = 32$ leaves)** computed statelessly in RAM yields:

| On-Key Storage Component | Size | Memory Type | Purpose |
| :--- | :---: | :---: | :--- |
| **Core Secret & Bounds** | **112 B** | Read-Only Flash | 32 B `Master Seed` + 32 B `Key ID (I)` + 32 B `Batch Root ID` + 16 B subtree bounds |
| **Monotonic Counter State** | **16 B** | **Mutable NVM** | 8 B `Global Leaf Index (q)` + 8 B `Reservation Milestone Guard` *(only mutable bytes written)* |
| **15 Batch Ancestor Hashes** | **480 B** | Read-Only Flash | Static upper Merkle path for the $2^{15}$ ($32,768$-key) manufacturing batch |
| **Top-5 Device Subtree Cache** | **1,024 B** | Read-Only Flash | The 32 roots ($32 \times 32\text{ B}$) of the bottom 5-level ($32$-leaf) sub-subtrees |
| **Total Persistent Storage** | **1,632 B (~1.6 KB)** | **1,616 B RO + 16 B Mutable** | **100% self-contained on-key; zero flash wear from tree state updates** |
| **Peak Volatile RAM** | **~192 B** | Volatile SRAM | 6-node stack during stateless 32-leaf bottom sub-subtree evaluation |

*(Note: If a manufacturer omits the 1,024 B Read-Only Top-5 cache, total persistent storage drops to just **608 bytes**—128 B core + 480 B batch path—and computing all $1,023$ sibling leaves statelessly from scratch takes `~1.0 s` on a hardware SHA-256 engine.)*

---

### 6.2 End-to-End Comparison: Consumer Anonymous ZK Mode vs. Enterprise Direct Mode

| Metric | Consumer Anonymous Mode (With Longfellow ZK)<br/>*(17-Batch + 14-Device = 31 Levels)* | Enterprise Direct Mode (No Host ZK)<br/>*(15-Batch + 10-Device = 25 Levels)* |
| :--- | :--- | :--- |
| **Batch Capacity / Registrations per Key** | **131,072 keys** ($2^{17}$) / **16,384 registrations** ($2^{14}$) | **32,768 keys** ($2^{15}$) / **1,024 registrations** ($2^{10}$) |
| **Authenticator Total Flash / NVM** | `128 B` core + `1.44 KB` BDS *(or `4.1 KB` RO cache; `+544 B` batch path)* | **`16 B` mutable + `1,616 B` Read-Only (`~1.6 KB` total, 100% self-contained)** |
| **Authenticator Peak Volatile RAM** | `~320–512 B` | **`~192 B`** |
| **Authenticator `makeCredential` Latency** | `~15 ms` (Profile 1 BDS) or `~138 ms` (Profile 2 RO Cache) | **`~40 ms`** (`~8 ms` sign + `~32 ms` for 31 stateless leaves / `32,209` SHA-256 blocks) |
| **Host Storage & Prover Latency** | `544 B` Subtree Token (if not on-key) + **`~785–1,470 ms` Longfellow ZK prover** | **`0 Bytes` + `0 ms` (pure CTAP 2.3 passthrough)** |
| **WebAuthn `attStmt` Payload Size** | **310–345 KB** (`zkProof` + `batchRootId`) | **`3,048 B (~2.98 KB)`** (`2,180 B` LM-OTS sig + `800 B` 25-node path + `68 B` IDs — **$>100\times$ smaller**) |
| **Total CTAP 2.3 / WebAuthn Frame Size** | `~4.66–5.20 KB` on USB bus $\to$ `~312–347 KB` to RP | **`~4,051–5,746 B (~3.96–5.61 KB)` end-to-end** including the signed `"fido-mtc-ent"` `deviceSerial` extension (`5,106 B` for `ML-DSA-65`; fits in a single `7,609 B` USB CTAPHID message for all 5 PQ credential algorithms — see §6.3) |
| **Relying Party Verification Time** | **`~480 ms`** (Longfellow GKR+Ligero verifier) | **`~0.08 ms (80 µs)`** (`~600–1,120` SHA-256 blocks — **`~6,000×` faster**) |
| **Hardware Auditability & Trust Anchor** | **Zero-Knowledge Anonymity:** Unlinkable across RPs; RP trusts single 32 B `Batch Root ID` in FIDO MDS | **Built-In Subtree Auditability:** Upper 15 bits of $q$ ($\lfloor q / 1024 \rfloor$) = exact Device ID; lower 10 bits ($q \bmod 1024$) = exact registration count; RP trusts single 32 B `Batch Root ID` with zero X.509 `x5c` chains |
| **Dual-Mode Hardware Compatibility** | Native `"longfellow-lmots-zk"` (with optional `"enterprise"` passthrough) | **Dual-Mode Ready:** The exact same `1.6 KB` key can pass the `3.0 KB` `attStmt` directly for `"enterprise"` RPs **or** let a participating platform wrap the 25-node witness in a 41-layer Longfellow ZK proof for `"indirect"` / `"direct"` consumer anonymity |

---

### 6.3 Enterprise Wire-Size Comparison with Device Serial Number: Direct `LM-OTS` vs. `fmt: "mtc"` + `"fido-mtc-ent"`

This section compares **only the two Enterprise Attestation designs** (`enterpriseAttestation` `0x0A = 1` or `2`). Both carry the **same signed device serial number**:
- **Direct Enterprise `LM-OTS`**: this section's 25-level self-contained tree.
- **Enterprise MTC (`fmt: "mtc"` + `"fido-mtc-ent"`)**: from [pq_mtc_attestation_proposal.md §8.1–§8.3](file:///Users/jbradley/.gemini/antigravity/scratch/GitHub/ve7jtb.github.io/pq_mtc_attestation_proposal.md). It uses a stateless single-device `ML-DSA`/`FN-DSA` key per device, an inline `pubKey`, and a 17-hash `mtcCert`.

Non-enterprise batch formats (`mtc-mds`, batch `mtc`) are left out on purpose. They need a shared batch key across at least 100,000 devices, so they cannot carry a per-device serial.

#### 6.3.1 Carrying the Device Serial Number in Both Designs

Both designs set the `ED` flag (`0x80`) and add the **same signed `authenticatorData.extensions` entry** from `pq_mtc_attestation_proposal.md` §8.3:

```cddl
"fido-mtc-ent": { "deviceSerial": tstr / uint }   ; e.g. { "deviceSerial": "123456" }
```

The CBOR encoding is `A1` + `"fido-mtc-ent"` (13 B) + `A1` + `"deviceSerial"` (13 B) + `"123456"` (7 B) = `35 B`. This section budgets **`36 B`** so there is room for longer serials. The extension is inside `authenticatorData`, so the attestation signature covers it in both designs.

The table below shows how each design gets a **CA-committed** serial on top of the **device-signed** one:

| Binding Layer | Enterprise MTC (`fmt: "mtc"` + `"fido-mtc-ent"`) | Direct Enterprise `LM-OTS` |
| :--- | :--- | :--- |
| **Device-signed serial** | `"fido-mtc-ent".deviceSerial` in `authData`, signed by the single-device `ML-DSA` key (`attStmt.sig`) | `"fido-mtc-ent".deviceSerial` in `authData`, signed by the one-time `LM-OTS` leaf key (`lmotsSig`) |
| **CA-committed serial (leaf binding)** | `deviceSerial` goes in `MtcProof.extensions`, which is hashed into the `FidoMtcLogEntry` leaf. This adds **`~10 B`** to `mtcCert` (`2 B` type + `2 B` length + `6 B` serial), so `563 B` becomes **`573 B`** | The factory binds the serial at the batch/device boundary of the tree. Device $d$'s level-15 batch leaf is $H(\texttt{0x83} \parallel \text{deviceSubtreeRoot}_d \parallel \text{SHA-256}(\text{deviceSerial}))$. The RP rebuilds it from the `deviceSerial` already in `authData`, so it costs **`0 B` on the wire** and one extra `SHA-256` call |
| **Index ↔ serial cross-check** | `mtcCert.serial & 0xFFFFFFFFFFFF` = leaf index $k$ | $\lfloor q / 1024 \rfloor$ = Device ID, and $q \bmod 1024$ = registration count. Both are authenticated by the 25-node path |
| **Result** | The serial is attested by the CA (leaf hash) and signed by the device | The serial is attested by the factory (batch-level leaf hash) and signed by the device. This gives parity with X.509 `id-fido-gen-ce-sernum` (`1.3.6.1.4.1.45724.1.1.2`) |

#### 6.3.2 Fixed `attStmt` Components

All totals use the same `authData` baseline as §2.1 and §6.2: `PK_len + 70 B` with a 16-byte `credentialId`, **plus `36 B` for `"fido-mtc-ent"`**, giving `authData = PK_len + 106 B`. A 32-byte `credentialId` plus full top-level CTAP CBOR framing adds `+52 B` to every column, so the deltas do not change. CBOR map-key framing inside `attStmt` (`~30–40 B` in both designs) is left out of both sides.

- **Direct `LM-OTS` (`w = 4`, `LMOTS_SHA256_N32_W4`, dual-mode ZK-compatible):** `2,180 B` sig + `800 B` 25-node path + `68 B` IDs = **`3,048 B`**, the same for every credential algorithm.
- **Direct `LM-OTS` (`w = 8`, `LMOTS_SHA256_N32_W8`, enterprise-only):** `1,124 B` sig + `800 B` path + `68 B` IDs = **`1,992 B`**, the same for every credential algorithm.
- **Enterprise MTC `attStmt` = `sig` + `pubKey` (`COSE_Key`, `PK + 10 B`) + `573 B` `mtcCert` (17-hash proof including the serial extension):**

| Enterprise MTC Attestation Key | `sig` | `pubKey` (`COSE_Key`) | `mtcCert` | **Enterprise MTC `attStmt`** | vs. `LM-OTS` `w = 4` (`3,048 B`) | vs. `LM-OTS` `w = 8` (`1,992 B`) |
| :--- | ---: | ---: | ---: | ---: | :---: | :---: |
| `FN-DSA-512` (`-60`) | `666 B` | `907 B` | `573 B` | **`2,146 B`** | MTC is `902 B` smaller | MTC is `154 B` larger |
| **`ML-DSA-44` (`-48`)** *(the proposal's provisioned Enterprise key)* | `2,420 B` | `1,322 B` | `573 B` | **`4,315 B`** | `LM-OTS` is `1,267 B` smaller | `LM-OTS` is `2,323 B` smaller |
| `FN-DSA-1024` (`-61`) | `1,280 B` | `1,803 B` | `573 B` | **`3,656 B`** | `LM-OTS` is `608 B` smaller | `LM-OTS` is `1,664 B` smaller |
| `ML-DSA-65` (`-49`) | `3,309 B` | `1,962 B` | `573 B` | **`5,844 B`** | `LM-OTS` is `2,796 B` smaller | `LM-OTS` is `3,852 B` smaller |
| `ML-DSA-87` (`-50`) | `4,627 B` | `2,602 B` | `573 B` | **`7,802 B`** | `LM-OTS` is `4,754 B` smaller | `LM-OTS` is `5,810 B` smaller |

#### 6.3.3 End-to-End `MakeCredential` Wire Size: All 3 `ML-DSA` and Both `FN-DSA` Credential Algorithms

The `7,609 B` USB CTAPHID single-message limit is 1 init packet (`57 B`) plus 128 continuation packets (`59 B` each). Entries over the limit are marked ⚠️, and their size is still calculated.

| User Credential (`COSE alg`) | NIST Level / `PK_len` | `authData` incl. `"fido-mtc-ent"` (`PK + 106 B`) | **Direct `LM-OTS` `w = 4`** (`authData` + `3,048 B`) | **Direct `LM-OTS` `w = 8`** (`authData` + `1,992 B`) | **Enterprise MTC: Fixed `ML-DSA-44` Key** (`authData` + `4,315 B`) | **Enterprise MTC: Level-Matched Key** (`Att Key == Cred Key`) | **`LM-OTS` `w = 4` Saving vs. MTC** (Fixed / Matched) |
| :--- | :---: | ---: | :---: | :---: | :---: | :---: | :---: |
| **`FN-DSA-512` (`-60`)** | I / `897 B` | `1,003 B` | **`4,051 B`** (`69` fr) ✅ | **`2,995 B`** (`51` fr) ✅ | `5,318 B` (`91` fr) ✅ | `3,149 B` (`54` fr) ✅ *(`-60` key)* | `-1,267 B` / **`+902 B`** *(MTC smaller)* |
| **`ML-DSA-44` (`-48`)** | II / `1,312 B` | `1,418 B` | **`4,466 B`** (`76` fr) ✅ | **`3,410 B`** (`58` fr) ✅ | `5,733 B` (`98` fr) ✅ | `5,733 B` (`98` fr) ✅ *(same `-48` key)* | `-1,267 B` / `-1,267 B` |
| **`FN-DSA-1024` (`-61`)** | V / `1,793 B` | `1,899 B` | **`4,947 B`** (`84` fr) ✅ | **`3,891 B`** (`66` fr) ✅ | `6,214 B` (`106` fr) ✅ | `5,555 B` (`95` fr) ✅ *(`-61` key)* | `-1,267 B` / `-608 B` |
| **`ML-DSA-65` (`-49`)** | III / `1,952 B` | `2,058 B` | **`5,106 B`** (`87` fr) ✅ | **`4,050 B`** (`69` fr) ✅ | `6,373 B` (`109` fr) ✅ | **`7,902 B`** (`134` fr) ⚠️ **OVER HID LIMIT (`+293 B`)** *(`-49` key)* | `-1,267 B` / `-2,796 B` |
| **`ML-DSA-87` (`-50`)** | V / `2,592 B` | `2,698 B` | **`5,746 B`** (`98` fr) ✅ | **`4,690 B`** (`80` fr) ✅ | `7,013 B` (`119` fr) ✅ *(`596 B` margin)* | **`10,500 B`** (`178` fr) ⚠️ **OVER HID LIMIT (`+2,891 B`)** *(`-50` key)* | `-1,267 B` / `-4,754 B` |

> [!NOTE]
> **Normalization:** `pq_mtc_attestation_proposal.md` §8.1.1 quotes `5,931 B`, `6,571 B`, and `7,211 B` for Enterprise `fmt: "mtc"` with a fixed `ML-DSA-44` key. Those figures use that document's larger `authData` estimate (`~198 B` more). The numbers above recompute both designs on the same §6.2 `authData` baseline, so every byte of difference comes from `attStmt`. The `573 B` `mtcCert` assumes the proposal's `100k`-device `2^17` Enterprise subtree. Sizing the MTC subtree to this section's `2^15` (`32,768`-device) batch would make it `509 B` (`-64 B`).

#### 6.3.4 Key Takeaways (Enterprise Only, With Serial Number in Both)

1. **The serial number costs the same `36 B` in both designs.** MTC spends another `~10 B` committing it in `MtcProof.extensions`. `LM-OTS` binds it into the batch-level leaf hash at no wire cost, because the RP reads `deviceSerial` from `authData`.
2. **Against the proposal's provisioned `ML-DSA-44` Enterprise key, `LM-OTS` is a constant `1,267 B` smaller (`w = 4`) or `2,323 B` smaller (`w = 8`) for every credential algorithm.** The reason is that `LM-OTS` sends no attestation public key, while MTC sends `1,322 B`.
3. **With level-matched Enterprise keys, the gap widens for `ML-DSA`.** Enterprise MTC goes over the `7,609 B` limit for `ML-DSA-65` (`7,902 B`) and `ML-DSA-87` (`10,500 B`). Direct `LM-OTS` stays at `5,106 B` and `5,746 B` (`w = 4`), or `4,050 B` and `4,690 B` (`w = 8`). The `LM-OTS` attestation is NIST Category 5 (`SHA-256`, `N32`) in every row.
4. **`FN-DSA-512` is the one case where MTC is smaller.** A level-matched `FN-DSA-512` Enterprise key gives `3,149 B` total, which is `902 B` smaller than `LM-OTS` `w = 4` but `154 B` larger than `LM-OTS` `w = 8`. That MTC configuration only gives Level I attestation, and it requires constant-time `FN-DSA` floating-point signing on the authenticator.
5. **Operational tradeoff:** Enterprise MTC keys are **stateless** (unlimited registrations). Direct `LM-OTS` is **bounded to `1,024` registrations per device** and needs a `16 B` monotonic counter. In exchange, `LM-OTS` gets smaller wire size, `~40 ms` hardware `SHA-256` attestation signing (vs. `~700–1,400 ms` software `ML-DSA` on Cortex-M4), and no `pubKey` or `batchKeys` in MDS (a single `32 B` `Batch Root ID`).
