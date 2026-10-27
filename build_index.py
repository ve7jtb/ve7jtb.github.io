#!/usr/bin/env python3
"""Build index.html for ve7jtb.github.io.

Generates a modern, responsive showcase index of all technical specifications,
architecture reports, conformance results, pull requests, RFC proposals, and bug analyses.
"""
import os
import re

REPO = os.path.dirname(os.path.abspath(__file__))

def build_index():
    index_path = os.path.join(REPO, "index.html")

    html = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ve7jtb.github.io — Technical Specifications &amp; Cryptographic Architecture Reports</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --background: #f8fafc;
      --foreground: #0f172a;
      --card: #ffffff;
      --content: #f1f5f9;
      --border: #e2e8f0;
      --muted-foreground: #475569;
      --primary: #2563eb;
      --primary-foreground: #ffffff;
      --secondary: #e2e8f0;
      --secondary-foreground: #1e293b;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --background: #0b0f19;
        --foreground: #f1f5f9;
        --card: #111827;
        --content: #1e293b;
        --border: #334155;
        --muted-foreground: #94a3b8;
        --primary: #3b82f6;
        --primary-foreground: #ffffff;
        --secondary: #1e293b;
        --secondary-foreground: #e2e8f0;
      }
    }
    code, pre {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
    html {
      scroll-behavior: smooth;
    }
  </style>
</head>
<body class="bg-[var(--background)] text-[var(--foreground)] antialiased min-h-screen p-6 md:p-12 leading-relaxed">

  <div class="max-w-5xl mx-auto space-y-10">

    <!-- Top Masthead -->
    <header class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-10 shadow-sm">
      <div class="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div class="text-xs font-bold uppercase tracking-widest text-[var(--primary)] mb-1">
            ve7jtb.github.io
          </div>
          <h1 class="text-2xl md:text-4xl font-bold tracking-tight text-[var(--foreground)]">
            John Bradley — Technical Specifications &amp; Architecture Reports
          </h1>
          <p class="text-sm md:text-base text-[var(--muted-foreground)] mt-2 max-w-3xl">
            Working drafts, cryptographic analyses, and protocol proposals across FIDO2 / CTAP, W3C WebAuthn, IETF CFRG / JOSE / COSE, Post-Quantum Cryptography, and Decentralized / Verifiable Digital Identity.
          </p>
        </div>
        <div class="flex items-center gap-3">
          <a href="https://github.com/ve7jtb" target="_blank" rel="noopener noreferrer"
             class="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
            <span>GitHub (@ve7jtb)</span>
            <span>&rarr;</span>
          </a>
        </div>
      </div>

      <!-- Quick Navigation Directory -->
      <div class="mt-8 pt-6 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-4">
          Quick Specification &amp; Report Directory
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
          <!-- Item 1 -->
          <a href="#sec-mtc-dummies" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-[var(--primary)]">Architecture Primer</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">MTC for Dummies</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">Merkle Tree COSE (fmt: "mtc") explainer, chainsawing X.509, append-only trees &amp; revocation.</p>
            </div>
          </a>

          <!-- Item 2 -->
          <a href="#sec-fido-conformance" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">100% PASS Telemetry</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">FIDO CTAP 2.3 Conformance (Run 26)</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">252/252 PASS across 18 algorithms (ML-DSA, FN-DSA), stateless Root CAs &amp; hardware UP.</p>
            </div>
          </a>

          <!-- Item 3 -->
          <a href="#sec-webauthn-l4" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-violet-600 dark:text-violet-400">W3C Specification</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">WebAuthn Level 4 Spec Review</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">Full Bikeshed HTML copy, fmt: "mtc" normative statement, mtcDebug extension &amp; W3C PR.</p>
            </div>
          </a>

          <!-- Item 4 -->
          <a href="#sec-lmots-longfellow" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-[var(--primary)]">PQ Attestation</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">LM-OTS &amp; Google Longfellow</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">128B core state LM-OTS on SEs, 47-layer GKR SIMD circuit &amp; Direct RFC 8554 LMS.</p>
            </div>
          </a>

          <!-- Item 5 -->
          <a href="#sec-pq-mtc" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-[var(--primary)]">PQ Specification</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">PQ WebAuthn MTC (mtc &amp; mtcl)</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">draft-ietf-plants-merkle-tree-certs, 7,609B USB HID ceiling &amp; Enterprise manifest lookup.</p>
            </div>
          </a>

          <!-- Item 6 -->
          <a href="#sec-enterprise-comparison" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-[var(--primary)]">Architectural Report</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">Enterprise MTC vs. Direct LM-OTS</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">Comparison across 7,609B HID budget, manifest distribution, and RP verification complexity.</p>
            </div>
          </a>

          <!-- Item 7 -->
          <a href="#sec-chromium-pr" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-blue-600 dark:text-blue-400">Chromium PR</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">Chromium HEAD mtcDebug PR</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">MtcDebugExtensionOutput, Base64URL toJSON(), and dual-layer EP 1/2 privacy gate.</p>
            </div>
          </a>

          <!-- Item 8 -->
          <a href="#sec-chromium-virtual-authenticator" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-blue-600 dark:text-blue-400">Chromium &amp; MDS3</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">Chromium Virtual Authenticator</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">ML-DSA -48/-49/-50, W3C L4 MTC attestation, exact key reuse &amp; FIDO MDS3 exporter.</p>
            </div>
          </a>

          <!-- Item 9 -->
          <a href="#sec-chromium-pqc-rfc" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-amber-600 dark:text-amber-400">Design Proposal</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">PQC Virtual Authenticator RFC</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">Design for pure-signature EVP_DigestSignInit, net/cert/x509_util, and test coverage.</p>
            </div>
          </a>

          <!-- Item 10 -->
          <a href="#sec-chromium-crash-fix" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-rose-600 dark:text-rose-400">Crash Triage &amp; Fix</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">Credential Management Crash Fix</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">Disassembly of SIGABRT CHECK_EQ, WebUI debounce guard, and C++ handler re-entrancy fix.</p>
            </div>
          </a>

          <!-- Item 11 -->
          <a href="#sec-java-webauthn" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-[var(--primary)]">Relying Party Engine</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">java-webauthn-server MTC Proposal</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">Consolidated fmt: "mtc" &amp; mtc-debug, resolving batch keys via MDS3 and enterprise manifests.</p>
            </div>
          </a>

          <!-- Item 12 -->
          <a href="#sec-ctap23-pin-protocol" class="p-3 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition flex flex-col justify-between">
            <div>
              <span class="text-[10px] font-bold uppercase tracking-wider text-[var(--primary)]">CTAP 2.3+ Protocol</span>
              <div class="font-semibold text-sm text-[var(--foreground)] mt-1">Post-Quantum PIN Protocols 3 &amp; 4</div>
              <p class="text-[var(--muted-foreground)] text-[11px] mt-1 line-clamp-2">RFC 9180 HPKE, Hierarchical PPUAT derivation, downgrade integrity &amp; encrypted extensions.</p>
            </div>
          </a>
        </div>
      </div>
    </header>

    <!-- Section 1: MTC (Merkle Tree COSE) for Dummies -->
    <section id="sec-mtc-dummies" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-[var(--primary)] text-[var(--primary-foreground)]">
            New Explainer &amp; Architecture Primer
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Merkle Tree COSE (fmt: "mtc")
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            CTAP 2.3 &amp; W3C WebAuthn
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Append-Only &amp; Sparse Merkle Trees
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./mtc_for_dummies.html" class="hover:underline">
            MTC (Merkle Tree COSE) for Dummies by a Bigger Dummy
          </a>
        </h2>
        <div class="text-sm font-medium italic text-[var(--muted-foreground)]">
          How I failed to explain this to Dirk (and why I don't want to have to explain it again to 2<sup>8</sup> people — a Merkle joke I hope you'll get by the end)
        </div>
        <p class="text-sm text-[var(--muted-foreground)]">
          Why we retronymed <strong>MTC</strong> from <em>Merkle Tree Certificates</em> to <strong>Merkle Tree COSE</strong>, how taking a chainsaw to X.509 overhead in <code>MakeCredential</code> cuts nearly 2/3 of the Post-Quantum (<code>ML-DSA-87</code>) wire response by reconstructing the pre-image via the FIDO MDS, how append-only Merkle trees and checkpoints save product managers from themselves without breaking existing Enterprise Attestation manifests, and how Sparse Merkle Trees answer <em>"Where's the revocation?!"</em>
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./mtc_for_dummies.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-95 shadow-sm transition">
          <span>Read Full HTML Guide</span>
          <span>&rarr;</span>
        </a>
        <a href="./mtc_for_dummies.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          Guide Sections &amp; Direct Deep Links
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <a href="./mtc_for_dummies.html#section-1"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 1–2</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              PQ Wire Bloat &amp; Taking the Chainsaw to <code>MakeCredential</code>
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Why 2 <code>ML-DSA-87</code> keys + 2 signatures blow up NFC/HID, stripping duplicate AAGUIDs, and reconstructing the pre-image from the FIDO MDS without sending the X.509 certificate.
            </p>
          </a>

          <a href="./mtc_for_dummies.html#section-3"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 3–4</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Why Merkle Trees in MDS, Append-Only Trees &amp; Checkpoints
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Scaling Enterprise Attestation (batch size = 1) without blowing up the FIDO MDS, immutable left-to-right leaf indexing, and doubling tree depth on the right via checkpoints.
            </p>
          </a>

          <a href="./mtc_for_dummies.html#section-5"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 5</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              &quot;Where's the Revocation?!&quot; &amp; Attestation Selection
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Sparse Merkle Trees for compact non-membership revocation proofs, when RPs should choose <code>none</code> vs. <code>packed</code> vs. <code>mtc</code>, and shared batch keys on authenticators.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 2: Conformance & Telemetry Report -->
    <section id="sec-fido-conformance" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-600 text-white">
            Conformance &amp; Hardware Telemetry Report
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Run 26: 252 / 252 (100.00% PASS)
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            18 Algorithms (incl. FN-DSA-512 &amp; FN-DSA-1024)
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Stateless ML-DSA-87 &amp; ES384 Root CAs
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./fido_ctap23_conformance_report.html" class="hover:underline">
            FIDO CTAP 2.3 Conformance Test Report — 18 Algorithms (Including Draft NIST FIPS 206 <code>FN-DSA-512</code> &amp; <code>FN-DSA-1024</code>), Stateless <code>ML-DSA-87</code> (<code>alg: -50</code>) &amp; <code>ES384</code> (<code>alg: -35</code>) Root CA Hierarchy, All 8 Extensions (incl. <code>"mtc-debug"</code>), <code>persistentPinUvAuthToken</code> (<code>perCredMgmtRO</code>), Enterprise Attestation, Dual Hardware/VCOM User Presence &amp; Consolidated Post-Quantum <code>fmt: "mtc"</code>
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          Multi-log hardware conformance and bus-level telemetry report for the <strong>Fidont</strong> CTAP 2.3 authenticator simulator on the Nordic nRF52840 DK across the last 10 test runs (Runs 17–26), highlighted by <strong>Run 26 (<code>252 / 252</code> <code>100.00%</code> PASS, <code>31</code> Skipped, <code>0</code> Failed in <code>18m 27.46s</code>)</strong> with stateless <code>ML-DSA-87</code> (<code>alg: -50</code>) &amp; <code>ES384</code> (<code>alg: -35</code>) Root CAs, 2-field proof-less <code>mtcKeyRef</code> (<code>{ caId, serial }</code>, cutting Enterprise <code>MakeCredential</code> with <code>"mtc-debug"</code> to <code>4,448 B</code> / <code>76</code> HID frames — <code>3,161 B</code> below the <code>7,609 B</code> CTAPHID limit), real Hardware Button (<code>P0.11</code>) &amp; J-Link VCOM (<code>P0.08</code>) User Presence (compiled without <code>up-always-true</code>, <code>179</code> UP checks), and <code>3 / 3</code> zero-dialog automated <code>probe-rs</code> MCU power cycles.
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./fido_ctap23_conformance_report.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-95 shadow-sm transition">
          <span>Read Full HTML Report</span>
          <span>&rarr;</span>
        </a>
        <a href="./fido_ctap23_conformance_report.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          Report Sections &amp; Direct Deep Links
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <a href="./fido_ctap23_conformance_report.html#section-0-00000000"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition md:col-span-2">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 0.00000000 (Latest — Run 26: 252 / 252 100.00% PASS)</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Run 26 (<code>252 / 252</code> <code>100.00%</code> PASS in <code>18m 27.46s</code>): Attestation Deep Dive (<code>Authr-MakeCred-Resp-1</code> &amp; <code>4,448 B</code> Enterprise <code>fmt: "mtc"</code>), Dual <code>P0.11</code>/<code>P0.08</code> UP &amp; <code>3 / 3</code> Zero-Dialog MCU Resets
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Detailed wire trace analysis of Test 108 (<code>Authr-MakeCred-Resp-1</code>), zero-dialog MCU reboot cycles via <code>probe-rs reset</code>, and hardware verification of all 18 credential key algorithms.
            </p>
          </a>

          <a href="./fido_ctap23_conformance_report.html#section-0-0000000"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 0.0000000 (Run 25)</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Run 25: 18 Algorithms &amp; Draft NIST FIPS 206 FN-DSA
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              First hardware verification of draft NIST FIPS 206 <code>FN-DSA-512</code> and <code>FN-DSA-1024</code> on an embedded Cortex-M4 microcontroller.
            </p>
          </a>

          <a href="./fido_ctap23_conformance_report.html#section-0-00000"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 0.00000 (Run 23)</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Run 23: Enterprise Attestation (6/6 PASS) &amp; <code>mtc-debug</code> Gate
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Verification of Enterprise Attestation (EP 1 and 2) privacy gates and strict <code>deviceSerial</code> elision on standard makeCredential.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 3: W3C WebAuthn Level 4 Proposal, PR & Full Review -->
    <section id="sec-webauthn-l4" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-[var(--primary)] text-[var(--primary-foreground)]">
            W3C WebAuthn Level 4 Proposal
          </span>
          <a href="./webauthn_level4_review.html" class="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-600 text-white hover:bg-emerald-500 transition">
            ★ Full Level 4 Review Copy (HTML)
          </a>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            fmt: "mtc"
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            mtcDebug Extension (§10.x)
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            IETF PLANTS &amp; FIDO CTAP 2.3
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./webauthn_level4_mtc_proposal.html" class="hover:underline">
            Proposed Changes to W3C WebAuthn Level 4: Merkle Tree Certificate Attestation Format (<code>mtc</code>) and the <code>mtcDebug</code> Extension
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          Targeting the <strong>W3C WebAuthentication Working Group</strong> (Level 4 Editor's Draft). Formally proposes adding the compact <strong><code>mtc</code></strong> statement format to WebAuthn §8, standardizing the <strong><code>mtcDebug</code></strong> registration extension in §10 for automated test fixtures and diagnostic verification, and aligning with the <strong>Authenticate 2026 CTAP2 Technical Working Group consensus</strong>. Includes the complete compiled <strong><a href="./webauthn_level4_review.html" class="text-[var(--primary)] hover:underline font-semibold">WebAuthn Level 4 Spec Review Copy (HTML)</a></strong> and companion pull request.
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./webauthn_level4_review.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-emerald-600 text-white hover:bg-emerald-500 transition shadow-sm">
          <span>Read Full Level 4 Review Copy (HTML)</span>
          <span>&rarr;</span>
        </a>
        <a href="./webauthn_level4_pull_request.html"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] hover:opacity-90 transition shadow-sm">
          <span>View W3C Pull Request (HEAD 0c50bd0)</span>
          <span>&rarr;</span>
        </a>
        <a href="./webauthn_level4_pull_request.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>W3C PR (<code>.md</code>)</span>
        </a>
        <a href="./webauthn_level4_mtc_proposal.html"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
          <span>Read Proposal Analysis</span>
        </a>
        <a href="./webauthn_level4_mtc_proposal.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
          <span>Markdown Source</span>
        </a>
      </div>

      <!-- Highlights Grid -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          Proposal Sections &amp; Core Additions
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
          <a href="./webauthn_level4_mtc_proposal.html#section-1"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 1</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Post-Quantum USB HID Ceiling (7,609 B)
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Why classical X.509 <code>packed</code> attestation with ML-DSA CAs (7.9–22.9 KB) exceeds the USB HID single-message ceiling, and how MTC solves post-quantum scaling.
            </p>
          </a>

          <a href="./webauthn_level4_review.html#sctn-mtc-attestation"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Spec §8.10</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Defined Format: <code>mtc</code>
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              View rendered Bikeshed normative text, CDDL syntax, and RP verification algorithm in the Level 4 review copy.
            </p>
          </a>

          <a href="./webauthn_level4_review.html#sctn-mtc-debug-extension"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Spec §10.2.1</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Extension: <code>mtcDebug</code>
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              View rendered WebIDL dictionaries, authenticator CDDL, and client processing algorithms in the Level 4 review copy.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 4: LM-OTS + Google Longfellow Specification -->
    <section id="sec-lmots-longfellow" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-[var(--primary)] text-[var(--primary-foreground)]">
            Featured Specification Report
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            FIDO2 CTAP 2.3 &amp; W3C WebAuthn L3
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            fmt: "longfellow-lmots-zk"
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            RFC 8554 LM-OTS &amp; Google Longfellow (GF(2^k))
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./lmots_longfellow_attestation_proposal.html" class="hover:underline">
            Multi-Batch Post-Quantum FIDO Attestation via LM-OTS &amp; Google Longfellow (<code>longfellow-lmots-zk</code> and Direct Enterprise LMS)
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          Defines a post-quantum FIDO2/WebAuthn attestation architecture combining a <strong>128-byte core state RFC 8554 LM-OTS</strong> engine on resource-constrained Secure Elements with <strong>Google Longfellow</strong> (GKR layered sumcheck + Ligero over binary extension fields <code>GF(2^k)</code>) on participating host platforms. Covers black-box manufacturer subtree profiles (incremental BDS vs. read-only top-7 flash cache), <code>authenticatorGetInfo</code> capability signaling, platform-side <code>fmt</code> rewriting, multi-batch AAGUID routing, 47-layer GKR SIMD circuit optimization, and a <strong>Standard RFC 8554 HSS/LMS Enterprise Direct Attestation profile</strong> (<code>LMS_SHA256_M32_H25</code>, <code>L=1</code>, 60 B public key, <code>3,008 B</code> <code>W=4</code> / <code>1,952 B</code> <code>W=8</code> <code>attStmt</code>, <code>80 &mu;s</code> RP verification, and Section 6.3 comparison against Enterprise MTC across ML-DSA and FN-DSA).
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./lmots_longfellow_attestation_proposal.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-95 shadow-sm transition">
          <span>Read Full HTML Report</span>
          <span>&rarr;</span>
        </a>
        <a href="./lmots_longfellow_attestation_proposal.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          Report Sections &amp; Direct Deep Links
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <a href="./lmots_longfellow_attestation_proposal.html#section-1"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 1–2</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              128-Byte Core State, Black-Box Manufacturer Profiles &amp; CTAP 2.3 Pipeline
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              On-key NVM layout, black-box manufacturer subtree profiles (Profile 1 BDS in ~6.2 ms vs. Profile 2 Read-Only Top-7 cache with zero mutable tree flash wear), <code>authenticatorGetInfo</code> signaling, on-the-fly path derivation, and platform <code>fmt</code> rewriting.
            </p>
          </a>

          <a href="./lmots_longfellow_attestation_proposal.html#section-3"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 3–5</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Multi-Batch AAGUID Routing &amp; 47-Layer GKR SIMD Longfellow Circuit
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              WebAuthn Level 3 <code>attStmt.batchRootId</code> FIDO MDS resolution (131,072 keys/batch), 33-block SHA-256 pre-padding, and 67-wide GKR SIMD batching compressing ~1,100 SHA-256 blocks into 47 sequential layers (310–345 KB proof).
            </p>
          </a>

          <a href="./lmots_longfellow_attestation_proposal.html#section-6"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition md:col-span-2">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 6</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Standard RFC 8554 HSS/LMS Enterprise Direct Profile &amp; Wire Comparison vs. Enterprise MTC
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Fully compliant RFC 8554 single-tree profile (<code>LMS_SHA256_M32_H25</code>, <code>L=1</code>, standard 16 B tree ID <code>I</code>, 60 B public key) supporting 33.5M signatures per batch with 3,008 B (W=4) or 1,952 B (W=8) <code>attStmt</code> and 80 &mu;s RP verification.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 5: PQ MTC Attestation (mtc & mtcl) -->
    <section id="sec-pq-mtc" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-[var(--primary)] text-[var(--primary-foreground)]">
            Featured Specification Report
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            W3C WebAuthn &amp; FIDO2 CTAP 2.3+
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            fmt: "mtc" &amp; "mtcl"
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Merkle Tree Certificates &amp; ML-DSA
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./pq_mtc_attestation_proposal.html" class="hover:underline">
            Post-Quantum WebAuthn Attestation Using Merkle Tree Certificates (<code>mtc</code> and <code>mtcl</code>)
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          Defines two complementary Post-Quantum WebAuthn attestation statement formats—<strong><code>mtc</code></strong> (compact MDS/Log-assisted public key lookup) and <strong><code>mtcl</code></strong> (inline <code>COSE_Key</code> + <code>MTCProof</code>, MTC Large)—based on <strong><code>draft-ietf-plants-merkle-tree-certs</code></strong>, enabling <code>ML-DSA-44</code>, <code>ML-DSA-65</code>, and <code>ML-DSA-87</code> hardware authenticator attestations (including Enterprise Attestation <code>0x0A</code>) to fit within a single 7,609-byte USB HID CTAP2 frame. Includes WebAuthn Level 3 AAGUID preservation analysis, Section 7.5 legacy client detection and fallback attestation defaults, Section 8.6 unified <code>(caId, serial)</code> Enterprise manifest lookup, C509 comparisons, and Section 11 multi-level HSS/LMS intermediate hierarchy trade-offs.
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./pq_mtc_attestation_proposal.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-95 shadow-sm transition">
          <span>Read Full HTML Report</span>
          <span>&rarr;</span>
        </a>
        <a href="./pq_mtc_attestation_proposal.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          Report Sections &amp; Direct Deep Links
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <a href="./pq_mtc_attestation_proposal.html#section-1"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 1–5</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Normative <code>mtc</code> &amp; <code>mtcl</code> Formats, Leaf Structure &amp; RP Verification
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Why classical X.509 <code>packed</code> attestation with <code>ML-DSA</code> exceeds the 7,609-byte USB HID frame limit, CDDL definitions for <code>mtcStmtFormat</code> and <code>mtclStmtFormat</code>, deterministic <code>FidoMtcLogEntry</code> serialization, and unified RP verification.
            </p>
          </a>

          <a href="./pq_mtc_attestation_proposal.html#section-6"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 6–7</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              FIDO MDS3 <code>mtcTrustAnchors</code>, 3-Tier Cascade &amp; Legacy Client Detection
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              WebIDL extensions for FIDO Metadata Statements, shared vs. separate <code>caId</code> models, <code>authenticatorGetInfo</code> <code>attestationFormats</code>, and Section 7.5 legacy client detection with backwards-compatible defaults.
            </p>
          </a>

          <a href="./pq_mtc_attestation_proposal.html#section-8"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition md:col-span-2">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 8</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Enterprise Attestation (<code>0x0A</code>), Manifest-Assisted <code>mtc</code>, 100k–5M Scaling &amp; WebAuthn L4 <code>mtc-debug</code>
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Dual-key provisioning (<code>AttestationId::Batch</code> vs. individual <code>AttestationId::Enterprise</code>), Root CA subtree checkpoints, leaf-committed and manifest device serial number binding, and Section 8.6 unified <code>(caId, serial)</code> key lookup via manufacturer manifests.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 6: Enterprise Attestation MTC vs LM-OTS Comparison -->
    <section id="sec-enterprise-comparison" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-[var(--primary)] text-[var(--primary-foreground)]">
            Architectural Comparison Report
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Enterprise Attestation (0x0A)
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            MTC vs. RFC 8554 LM-OTS
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            7,609 B Wire Analysis
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./enterprise_attestation_mtc_vs_lmots_comparison.html" class="hover:underline">
            Post-Quantum Enterprise Attestation: Compact MTC vs. Direct LM-OTS (RFC 8554) Comparison Report
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          Comprehensive technical comparison between MDS/Manifest-Assisted Merkle Tree Certificates (<code>fmt: "mtc"</code>) and Standard RFC 8554 Leighton-Micali One-Time Signatures (Direct Enterprise HSS/LMS) across wire payload budgets, manifest distribution logistics, and Relying Party verification complexity.
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./enterprise_attestation_mtc_vs_lmots_comparison.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-95 shadow-sm transition">
          <span>Read Full Comparison Report</span>
          <span>&rarr;</span>
        </a>
        <a href="./enterprise_attestation_mtc_vs_lmots_comparison.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          Report Sections &amp; Direct Deep Links
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <a href="./enterprise_attestation_mtc_vs_lmots_comparison.html#section-1"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 1–2</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Protocol Mechanics &amp; Wire Payload Analysis
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Wire size breakdown of Enterprise <code>mtc</code> (3,832–7,319 B) vs. Direct LMS (1,952–3,008 B), both comfortably fitting within the 7,609 B USB HID budget.
            </p>
          </a>

          <a href="./enterprise_attestation_mtc_vs_lmots_comparison.html#section-3"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 3–5</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              RP Validation Complexity &amp; Decision Matrix
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              5 branching validation paths and out-of-band manifest desync risks in <code>mtc</code> vs. single, deterministic, 80-microsecond stateless RFC 8554 hash verification requiring only a 60-byte root key.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 7: Chromium HEAD mtcDebug Pull Request -->
    <section id="sec-chromium-pr" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-[var(--primary)] text-[var(--primary-foreground)]">
            Chromium Pull Request / CL
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Base: HEAD (4f9f0d6afb)
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Branch: feat/webauthn-l4-mtc-debug
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            EP 1/2 Privacy Gate for deviceSerial
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./chromium_mtc_debug_pull_request.html" class="hover:underline">
            Chromium Pull Request: WebAuthn Level 4 <code>mtcDebug</code> (<code>mtc-debug</code>) Extension &amp; Enterprise Attestation (<code>EP</code> 1/2) Privacy Gate
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          Full implementation against <strong>Chromium <code>HEAD</code> (<code>4f9f0d6afb</code>)</strong> on branch <code>feat/webauthn-l4-mtc-debug</code> (<code>27 files changed, +474 / -5 lines</code>). Implements the WebAuthn Level 4 §10.2.1 <strong><code>mtcDebug</code></strong> registration extension across Blink WebIDL (<code>MtcDebugExtensionOutput</code> &amp; <code>MtcDebugExtensionOutputJSON</code>), <code>PublicKeyCredential.toJSON()</code> Base64URL serialization, Mojo IPC (<code>authenticator.mojom</code>), <code>content/browser/webauth</code>, and <code>device/fido</code> CTAP2 CBOR parsing—including dual-layer <strong>Enterprise Attestation (<code>EP 1</code> or <code>2</code>) privacy enforcement</strong> that cancels the ceremony with <code>NotAllowedError</code> if an authenticator returns <code>deviceSerial</code> when Enterprise Attestation was not requested.
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./chromium_mtc_debug_pull_request.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-95 shadow-sm transition">
          <span>Read Full Chromium PR &amp; Unified Diff (HTML)</span>
          <span>&rarr;</span>
        </a>
        <a href="./chromium_mtc_debug_pull_request.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
        <a href="./webauthn_level4_pull_request.html"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>Companion W3C Spec PR</span>
          <span>&rarr;</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          PR Sections &amp; Direct Deep Links
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <a href="./chromium_mtc_debug_pull_request.html#section-2"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 1–2</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              End-to-End Chromium Pipeline &amp; Build Verification
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Request/response flow across Blink, Mojo IPC, <code>AuthenticatorCommonImpl</code>, and <code>device/fido</code>, verified with zero warnings across <code>out/Default</code>.
            </p>
          </a>

          <a href="./chromium_mtc_debug_pull_request.html#section-3"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 3</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Dual-Layer EP 1/2 Privacy Gate Architecture
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Defense-in-depth privacy validation in both device layer (<code>device/fido</code>) and browser coordinator (<code>AuthenticatorCommonImpl</code>), aborting illicit serial leakages.
            </p>
          </a>

          <a href="./chromium_mtc_debug_pull_request.html#section-4"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 4</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Complete Unified Git Diff (27 Files)
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Full syntax-highlighted git diff covering WebIDL definitions, toJSON() serializers, Mojo bindings, FIDO parsers, and browser unit tests.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 8: Chromium Virtual Authenticator (PQC & MTC) -->
    <section id="sec-chromium-virtual-authenticator" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-[var(--primary)] text-[var(--primary-foreground)]">
            Chromium Architecture &amp; Guide
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            ML-DSA-44, 65, 87 (-48, -49, -50)
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            W3C WebAuthn L4 fmt: "mtc"
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            FIDO MDS3 &amp; Yubico RP Integration
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./chromium_pqc_mtc_virtual_authenticator.html" class="hover:underline">
            Chromium Virtual Authenticator: Post-Quantum ML-DSA (<code>-48</code>, <code>-49</code>, <code>-50</code>) &amp; WebAuthn Level 4 MTC Attestation with FIDO MDS Export
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          Comprehensive specification and implementation guide for <code>VirtualCtap2Device</code> on branch <code>feat/pqc-mtc-attestation</code>. Combines pure Post-Quantum ML-DSA batch attestation certificates with WebAuthn Level 4 Merkle Tree Certificate (<code>fmt: "mtc"</code>) statements, <code>mtcDebug</code> diagnostic extension emission, exact public key reuse across formats, and automated <strong>FIDO Metadata Service (MDS3)</strong> export for test Relying Party servers like Yubico's <code>java-webauthn-server</code>.
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./chromium_pqc_mtc_virtual_authenticator.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-95 shadow-sm transition">
          <span>Read Full HTML Report</span>
          <span>&rarr;</span>
        </a>
        <a href="./chromium_pqc_mtc_virtual_authenticator.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
        <a href="./pqc_virtual_authenticator_proposal.html"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>PQC Batch RFC (Branch 2)</span>
          <span>&rarr;</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          Key Architecture &amp; Integration Sections
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <a href="./chromium_pqc_mtc_virtual_authenticator.html#section-2"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 2</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Public Key Reuse Architecture
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Guaranteed cryptographic key identity across X.509 certs, MTC log entries, <code>mtc-debug</code>, and FIDO MDS3 statements.
            </p>
          </a>

          <a href="./chromium_pqc_mtc_virtual_authenticator.html#section-4"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 4</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              FIDO MDS3 Format &amp; Exporter
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              FIDO MDS3 schema, AAGUID <code>01020304-...</code> metadata, PEM certificates, and <code>MtcTrustAnchor</code> table exports.
            </p>
          </a>

          <a href="./chromium_pqc_mtc_virtual_authenticator.html#section-5"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 5</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Yubico <code>java-webauthn-server</code> Guide
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Step-by-step Java code configuring <code>InMemoryMetadataService</code> and Bouncy Castle PQC for ML-DSA attestation validation.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 9: PQC Virtual Authenticator RFC / Design Proposal -->
    <section id="sec-chromium-pqc-rfc" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-amber-600 text-white">
            Chromium Design RFC
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            feat/pqc-virtual-authenticator
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            COSE -48, -49, -50 (ML-DSA)
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Pure-Signature EVP_DigestSignInit
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./pqc_virtual_authenticator_proposal.html" class="hover:underline">
            RFC / Design Proposal: Post-Quantum Cryptography (PQC) Updates to Chromium Virtual Authenticator
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          RFC and technical design proposal specifying support for COSE algorithms <code>-48</code> (<code>ML-DSA-44</code>), <code>-49</code> (<code>ML-DSA-65</code>), and <code>-50</code> (<code>ML-DSA-87</code>) in Chromium's test authenticator framework (<code>VirtualCtap2Device</code> / <code>VirtualFidoDevice</code>), pure-signature <code>EVP_DigestSignInit</code> integration (omitting hash functions per FIPS 204), and self-signed X.509 batch attestation certificate generation in <code>net/cert/x509_util.cc</code>.
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./pqc_virtual_authenticator_proposal.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-95 shadow-sm transition">
          <span>Read Full Design RFC (HTML)</span>
          <span>&rarr;</span>
        </a>
        <a href="./pqc_virtual_authenticator_proposal.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
        <a href="./chromium_pqc_mtc_virtual_authenticator.html"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>Virtual Authenticator Architecture Guide</span>
          <span>&rarr;</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          RFC Sections &amp; Direct Deep Links
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <a href="./pqc_virtual_authenticator_proposal.html#section-2"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 2</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Problem Statement &amp; PQC Attestation Gaps
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Identifies lack of ML-DSA batch attestation support in <code>VirtualFidoDevice</code> and BoringSSL signature requirements.
            </p>
          </a>

          <a href="./pqc_virtual_authenticator_proposal.html#section-3"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 3</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Pure-Signature EVP Architecture
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Transitioning <code>net/cert/x509_util.cc</code> to pass <code>nullptr</code> for digest type to <code>EVP_DigestSignInit</code> for pure ML-DSA.
            </p>
          </a>

          <a href="./pqc_virtual_authenticator_proposal.html#section-4"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 4</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Detailed Implementation Changes
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Code diffs across <code>virtual_ctap2_device.cc</code>, <code>virtual_fido_device.cc</code>, WebIDL dictionaries, and unit test coverage.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 10: Chromium Credential Management Crash Bug Report & Fix -->
    <section id="sec-chromium-crash-fix" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-rose-600 text-white">
            Chromium Bug Report &amp; Fix
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            SIGABRT / CHECK_EQ
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            SecurityKeysCredentialHandler
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            chrome://settings/securityKeys
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./chromium_credential_management_crash_analysis.html" class="hover:underline">
            Chromium Security Keys Credential Management: SIGABRT Crash Analysis and Re-Entrancy Fix
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          Root-cause diagnostic analysis, stack trace disassembly, and two-layer fix (WebUI debounce + C++ re-entrancy protection) for a fatal <code>SIGABRT</code> crash in <code>SecurityKeysCredentialHandler::HandleDelete</code> during FIDO credential management deletion in Chromium's Settings page (<code>chrome://settings/securityKeys</code>).
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./chromium_credential_management_crash_analysis.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-rose-600 text-white hover:bg-rose-500 shadow-sm transition">
          <span>Read Full Crash Analysis &amp; Fix (HTML)</span>
          <span>&rarr;</span>
        </a>
        <a href="./chromium_credential_management_crash_analysis.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          Analysis Sections &amp; Direct Deep Links
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <a href="./chromium_credential_management_crash_analysis.html#section-2"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 2</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Crash Diagnostics &amp; Disassembly
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Disassembly of <code>SecurityKeysCredentialHandler::HandleDelete</code> at offset +1332 showing fatal <code>CHECK_EQ(State::kReady, state_)</code> abort.
            </p>
          </a>

          <a href="./chromium_credential_management_crash_analysis.html#section-3"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 3</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Root Cause Analysis
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              WebUI confirmation button failed to debounce during in-flight deletion, causing duplicate IPC while <code>state_ == State::kDeletingCredentials</code>.
            </p>
          </a>

          <a href="./chromium_credential_management_crash_analysis.html#section-4"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 4–5</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Two-Layer Fix &amp; Implementation
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              TypeScript <code>confirmButtonDisabled_</code> debouncing in the WebUI dialog and C++ early-return state guards in <code>settings_security_key_handler.cc</code>.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 11: Yubico java-webauthn-server MTC Proposal -->
    <section id="sec-java-webauthn" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-[var(--primary)] text-[var(--primary-foreground)]">
            Relying Party Engine Proposal
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Yubico java-webauthn-server
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            fmt: "mtc" (No Inline pubKey)
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            MDS3 &amp; Vendor Manifests
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./mtc_attestation_proposal.html" class="hover:underline">
            Proposal: Consolidated <code>fmt: "mtc"</code> &amp; <code>mtc-debug</code> Support in <code>java-webauthn-server</code>
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          Architecture and implementation proposal for adding consolidated Merkle Tree Certificate attestation (<code>fmt: "mtc"</code>) and the <code>mtc-debug</code> registration extension to Yubico <code>java-webauthn-server</code>, resolving batch keys from FIDO MDS3 and enterprise keys from vendor manifests or <code>mtc-debug</code> authenticated against the MDS subtree <code>rootHash</code>.
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./mtc_attestation_proposal.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-95 shadow-sm transition">
          <span>Read Full Java RP Proposal (HTML)</span>
          <span>&rarr;</span>
        </a>
        <a href="./mtc_attestation_proposal.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          Proposal Sections &amp; Direct Deep Links
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <a href="./mtc_attestation_proposal.html#section-1"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 1</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Key &amp; Trust Resolution Architecture
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Unified resolution for batch attestation (MDS3 lookup by AAGUID) and enterprise attestation (vendor manifest &amp; rootHash validation).
            </p>
          </a>

          <a href="./mtc_attestation_proposal.html#section-2"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Sections 2–3</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Server Core &amp; Attestation Modules
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              <code>MtcAttestationStatementSupport</code> class, Jackson CBOR mapping, and Bouncy Castle <code>ML-DSA</code> signature verification.
            </p>
          </a>

          <a href="./mtc_attestation_proposal.html#section-5"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 5</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              End-to-End Test Suite
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              JUnit 5 test fixtures verifying ML-DSA-44, 65, and 87 test vectors from Chromium's VirtualCtap2Device.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Section 12: CTAP 2.3+ Post-Quantum PIN/UV Protocol 3 & 4 -->
    <section id="sec-ctap23-pin-protocol" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-[var(--primary)] text-[var(--primary-foreground)]">
            Featured Specification Report
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            FIDO2 CTAP 2.3+
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            pinUvAuthProtocol = 3 &amp; 4
          </span>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-[var(--secondary)] text-[var(--secondary-foreground)]">
            Post-Quantum HPKE &amp; ARKG
          </span>
        </div>
        <span class="text-xs text-[var(--muted-foreground)] font-mono">October 2026</span>
      </div>

      <div class="space-y-3">
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)]">
          <a href="./ctap23_hierarchical_ppuat_spec.html" class="hover:underline">
            CTAP 2.3+ Post-Quantum PIN/UV Auth Protocol 3: Architecture, Downgrade Integrity, Hierarchical PPUAT, and Encrypted Extensions
          </a>
        </h2>
        <p class="text-sm text-[var(--muted-foreground)]">
          Defines a Post-Quantum <strong>PIN/UV Auth Protocol 3 (<code>pinUvAuthProtocol = 3</code>)</strong> for FIDO2 CTAP 2.3+ based on <strong>RFC 9180 HPKE</strong> (<code>X-Wing</code>, <code>MLKEM768-P256</code>, and <code>ML-KEM-1024</code>), addressing Harvest-Now-Decrypt-Later (HNDL) quantum threats and active bus MITM attacks while maintaining strict Relying Party unlinkability, zero extra Authenticator NVRAM, and 0-RTT key agreement caching. Includes companion proposals for <strong>HPKE Stateful AEAD (<code>0x0002</code>)</strong> and <strong>HPKE Export-Only (<code>0xFFFF</code>)</strong>.
        </p>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 pt-1">
        <a href="./ctap23_hierarchical_ppuat_spec.html"
           class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-95 shadow-sm transition">
          <span>Read Full Architecture Spec (HTML)</span>
          <span>&rarr;</span>
        </a>
        <a href="./ctap23_hierarchical_ppuat_spec.md"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--content)] text-[var(--foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>View Markdown Source (<code>.md</code>)</span>
        </a>
        <a href="./ctap23_pin_protocol_3_hpke_stateful_aead_proposal.html"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>Protocol 3 Proposal (AEAD 0x0002)</span>
          <span>&rarr;</span>
        </a>
        <a href="./ctap23_pin_protocol_4_hpke_export_only_proposal.html"
           class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] hover:opacity-90 transition">
          <span>Protocol 4 Proposal (Export-Only 0xFFFF)</span>
          <span>&rarr;</span>
        </a>
      </div>

      <!-- Deep Links -->
      <div class="pt-4 border-t border-[var(--border)]">
        <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
          Report Sections &amp; Direct Deep Links
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <a href="./ctap23_hierarchical_ppuat_spec.html#section-1"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 1</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Core PIN Protocol Issues &amp; Post-Quantum HPKE Architecture
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              HNDL and active MITM vulnerabilities in CTAP 2.0–2.3 Protocols 1 &amp; 2, mapping §6.5.4 to RFC 9180 HPKE with KEM agility, and 0-RTT caching of <code>pk_batch</code> against <code>PPUAT_v3</code>.
            </p>
          </a>

          <a href="./ctap23_hierarchical_ppuat_spec.html#section-2"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 2</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Downgrade Issues &amp; <code>authenticatorGetInfo</code> Integrity
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Defending against KEM stripping, UV-to-PIN modality downgrades, and back-to-back protocol-translating relay MITMs without leaking fingerprinting bits into <code>authenticatorData</code>.
            </p>
          </a>

          <a href="./ctap23_hierarchical_ppuat_spec.html#section-3"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 3</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              PPUAT Domain Separation Between Protocols 2 and 3
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              One-way hierarchical derivation tree (<code>PPUAT_v3 &rarr; PPUAT_v2 &rarr; K_id, K_css</code>) requiring only a single 32-byte NVRAM root secret while creating a 2<sup>128</sup> quantum preimage firewall.
            </p>
          </a>

          <a href="./ctap23_hierarchical_ppuat_spec.html#section-4"
             class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
            <div class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section 4</div>
            <h3 class="text-base font-semibold text-[var(--foreground)] mt-0.5">
              Extensions Using Encryption (<code>hmac-secret</code>, <code>largeBlobKey</code>, <code>credBlob</code>, &amp; <code>sign</code>)
            </h3>
            <p class="text-xs text-[var(--muted-foreground)] mt-1.5">
              Token-bound <code>1: keyAgreement</code> elision in <code>hmac-secret</code> (saving 1.1–1.5 KB), encrypting <code>largeBlobKey</code>, and securing the WebAuthn <code>sign</code> extension + ARKG.
            </p>
          </a>
        </div>
      </div>
    </section>

    <!-- Related Specifications & Normative References -->
    <section class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-4">
      <h2 class="text-lg font-bold text-[var(--foreground)]">
        Related Specifications &amp; Normative References
      </h2>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/" target="_blank" rel="noopener noreferrer"
           class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
          <div class="font-bold text-[var(--primary)] uppercase tracking-wider">IETF PLANTS Internet-Draft</div>
          <div class="font-semibold text-sm text-[var(--foreground)] mt-1">
            Merkle Tree Certificates (MTC)
          </div>
          <div class="text-[var(--muted-foreground)] mt-1">
            <code>draft-ietf-plants-merkle-tree-certs</code> — D. Benjamin, D. Stebila, B. Westerbaan
          </div>
        </a>

        <a href="https://datatracker.ietf.org/doc/draft-bradleylundberg-cfrg-arkg/" target="_blank" rel="noopener noreferrer"
           class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
          <div class="font-bold text-[var(--primary)] uppercase tracking-wider">IETF CFRG Internet-Draft</div>
          <div class="font-semibold text-sm text-[var(--foreground)] mt-1">
            The Asynchronous Remote Key Generation (ARKG) Algorithm
          </div>
          <div class="text-[var(--muted-foreground)] mt-1">
            <code>draft-bradleylundberg-cfrg-arkg</code> — E. Lundberg, J. Bradley
          </div>
        </a>

        <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html" target="_blank" rel="noopener noreferrer"
           class="block p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] hover:border-[var(--primary)] transition">
          <div class="font-bold text-[var(--primary)] uppercase tracking-wider">FIDO Alliance Specification</div>
          <div class="font-semibold text-sm text-[var(--foreground)] mt-1">
            Client to Authenticator Protocol (CTAP) v2.3
          </div>
          <div class="text-[var(--muted-foreground)] mt-1">
            Proposed Standard (February 2026) — PIN/UV Auth Protocols, PPUAT &amp; Attestation Formats
          </div>
        </a>
      </div>
    </section>

  </div>

  <footer class="max-w-5xl mx-auto mt-12 mb-8 text-center text-xs text-[var(--muted-foreground)]">
    &copy; 2026 John Bradley (ve7jtb). Hosted on <a href="https://github.com/ve7jtb/ve7jtb.github.io" target="_blank" rel="noopener noreferrer" class="text-[var(--primary)] hover:underline">GitHub Pages</a>.
  </footer>

</body>
</html>
'''

    with open(index_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Generated {index_path} ({len(html)} bytes)")

if __name__ == "__main__":
    build_index()
