#!/usr/bin/env python3
"""Unified Markdown -> HTML converter for all documents in ve7jtb.github.io.

Usage:
    ./build_all_html.py              # Build all 6 documents
    ./build_all_html.py pq_mtc       # Build a specific document

Applies modern Tailwind styling, KaTeX math auto-rendering, Mermaid diagram rendering,
GFM tables with alignment, GitHub alerts, responsive navigation grid, and detailed TOC.
"""
import html
import os
import re
import sys

REPO = os.path.dirname(os.path.abspath(__file__))
LINK = 'class="text-[var(--primary)] hover:underline"'

# ---------------------------------------------------------------- inline ----
def map_url(url):
    m = re.match(r"file://(/[^#]*?)(#.*)?$", url)
    if m:
        path, frag = m.group(1), m.group(2) or ""
        name = path.rsplit("/", 1)[-1]
        if name.endswith(".md"):
            name = name[:-3] + ".html"
            frag = ""
        return "./" + name + frag, False
    return url, url.startswith("http")


def inline(text):
    toks = []

    def stash(s):
        toks.append(s)
        return f"\x00{len(toks) - 1}\x00"

    # escaped dollars -> literal, ignored by KaTeX
    text = text.replace("\\$", stash('<span class="nokatex">$</span>'))
    # code spans
    text = re.sub(r"(`+)(.+?)\1",
                  lambda m: stash("<code>" + html.escape(m.group(2).strip(), quote=False) + "</code>"),
                  text)
    # display + inline math (kept verbatim for KaTeX auto-render)
    text = re.sub(r"\$\$(.+?)\$\$", lambda m: stash("$$" + html.escape(m.group(1), quote=False) + "$$"), text)
    text = re.sub(r"(?<![\w$])\$(?!\s)([^$\n]+?)(?<!\s)\$(?!\w)",
                  lambda m: stash("$" + html.escape(m.group(1), quote=False) + "$"), text)
    # <br/> passthrough
    text = re.sub(r"<br\s*/?>", lambda m: stash("<br/>"), text)

    def link(m):
        label, url = m.group(1), m.group(2)
        href, external = map_url(url)
        tgt = ' target="_blank" rel="noopener noreferrer"' if external else ""
        return stash(f'<a href="{html.escape(href)}"{tgt} {LINK}>') + label + stash("</a>")

    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, text)
    text = html.escape(text, quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", text)
    # restore (nested tokens possible)
    for _ in range(4):
        text = re.sub(r"\x00(\d+)\x00", lambda m: toks[int(m.group(1))], text)
    return text


def slug(s):
    """GitHub-style heading anchor."""
    s = re.sub(r"<[^>]+>", "", s).strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"\s+", "-", s)


# ---------------------------------------------------------------- blocks ----
LIST_RE = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")
ALERTS = {
    "NOTE": ("Note", "border-blue-500/40 bg-blue-500/5", "text-blue-700 dark:text-blue-300"),
    "TIP": ("Tip", "border-emerald-500/40 bg-emerald-500/5", "text-emerald-700 dark:text-emerald-300"),
    "IMPORTANT": ("Important", "border-violet-500/40 bg-violet-500/5", "text-violet-700 dark:text-violet-300"),
    "WARNING": ("Warning", "border-amber-500/40 bg-amber-500/5", "text-amber-700 dark:text-amber-300"),
    "CAUTION": ("Caution", "border-red-500/40 bg-red-500/5", "text-red-700 dark:text-red-300"),
}


def split_row(line):
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|") and not line.endswith("\\|"):
        line = line[:-1]
    cells, cur, tick = [], "", False
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            cur += "|"
            i += 2
            continue
        if c == "`":
            tick = not tick
        if c == "|" and not tick:
            cells.append(cur.strip())
            cur = ""
        else:
            cur += c
        i += 1
    cells.append(cur.strip())
    return cells


def render_table(rows):
    head = split_row(rows[0])
    aligns = []
    for spec in split_row(rows[1]):
        spec = spec.strip()
        if spec.startswith(":") and spec.endswith(":"):
            aligns.append("text-center")
        elif spec.endswith(":"):
            aligns.append("text-right")
        else:
            aligns.append("text-left")
    out = ['<div class="overflow-x-auto rounded-xl border border-[var(--border)] my-3 shadow-sm">',
           '<table class="w-full border-collapse text-xs">',
           '<thead><tr class="bg-[var(--content)] border-b border-[var(--border)]">']
    for i, h in enumerate(head):
        a = aligns[i] if i < len(aligns) else "text-left"
        out.append(f'<th class="p-3 font-semibold align-bottom {a}">{inline(h)}</th>')
    out.append('</tr></thead><tbody class="divide-y divide-[var(--border)]">')
    for r in rows[2:]:
        cells = split_row(r)
        out.append("<tr>")
        for i, c in enumerate(cells):
            a = aligns[i] if i < len(aligns) else "text-left"
            out.append(f'<td class="p-3 align-top {a}">{inline(c)}</td>')
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "\n".join(out)


def indent_of(s):
    return len(s) - len(s.lstrip(" "))


def dedent(lines, n):
    return [l[n:] if l[:n].strip() == "" else l.lstrip() for l in lines]


def parse_blocks(lines):
    out = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        s = line.strip()
        if not s or s == "---":
            i += 1
            continue
        # fenced code
        if s.startswith("```"):
            lang = s[3:].strip()
            ind = indent_of(line)
            body = []
            i += 1
            while i < n and not lines[i].strip().startswith("```"):
                body.append(lines[i][ind:] if lines[i][:ind].strip() == "" else lines[i])
                i += 1
            i += 1
            code = html.escape("\n".join(body), quote=False)
            if lang == "mermaid":
                out.append(f'<div class="rounded-xl border border-[var(--border)] bg-white dark:bg-[var(--content)] p-4 overflow-x-auto my-3"><pre class="mermaid">{code}</pre></div>')
            else:
                label = f'<div class="text-[10px] uppercase tracking-wider text-[var(--muted-foreground)] mb-2">{html.escape(lang)}</div>' if lang else ""
                out.append(f'<div class="rounded-xl bg-[var(--content)] border border-[var(--border)] p-4 overflow-x-auto my-3">{label}<pre class="text-xs leading-relaxed"><code>{code}</code></pre></div>')
            continue
        # headings
        m = re.match(r"^(#{3,6})\s+(.*)$", s)
        if m:
            lvl = len(m.group(1))
            txt = inline(m.group(2))
            cls = {3: "text-lg font-semibold pt-4 border-t border-[var(--border)]",
                   4: "text-base font-semibold"}.get(lvl, "text-sm font-semibold")
            out.append(f'<h{lvl} id="{slug(m.group(2))}" class="{cls} text-[var(--foreground)]">{txt}</h{lvl}>')
            i += 1
            continue
        # blockquote / alert
        if s.startswith(">"):
            ind = indent_of(line)
            body = []
            while i < n and lines[i].strip().startswith(">"):
                body.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            am = re.match(r"^\[!(\w+)\]\s*$", body[0].strip()) if body else None
            if am and am.group(1).upper() in ALERTS:
                title, box, tc = ALERTS[am.group(1).upper()]
                inner = parse_blocks(body[1:])
                out.append(f'<div class="rounded-xl border {box} p-4 text-sm space-y-2 my-3"><div class="text-xs font-bold uppercase tracking-wider {tc}">{title}</div>{inner}</div>')
            else:
                inner = parse_blocks(body)
                out.append(f'<blockquote class="border-l-4 border-[var(--border)] pl-4 text-sm text-[var(--muted-foreground)] italic space-y-2 my-3">{inner}</blockquote>')
            continue
        # table
        if s.startswith("|") and i + 1 < n and re.match(r"^\s*\|?\s*:?-{2,}", lines[i + 1]):
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append(lines[i])
                i += 1
            out.append(render_table(rows))
            continue
        # display math block on its own line
        if s.startswith("$$") and s.endswith("$$") and len(s) > 4:
            out.append(f'<div class="overflow-x-auto py-1 text-sm my-2">$${html.escape(s[2:-2], quote=False)}$$</div>')
            i += 1
            continue
        # list
        lm = LIST_RE.match(line)
        if lm:
            base = indent_of(line)
            ordered = lm.group(2)[0].isdigit()
            items = []
            while i < n:
                lm = LIST_RE.match(lines[i])
                if not (lm and indent_of(lines[i]) == base and (lm.group(2)[0].isdigit()) == ordered):
                    break
                content_ind = base + len(lm.group(2)) + 1
                item = [lm.group(3)]
                i += 1
                while i < n:
                    l = lines[i]
                    if not l.strip():
                        j = i + 1
                        while j < n and not lines[j].strip():
                            j += 1
                        if j < n and indent_of(lines[j]) > base:
                            item.append("")
                            i += 1
                            continue
                        break
                    if indent_of(l) > base:
                        item.append(l)
                        i += 1
                        continue
                    break
                items.append((item[0], dedent(item[1:], content_ind)))
                j = i
                while j < n and not lines[j].strip():
                    j += 1
                nm = LIST_RE.match(lines[j]) if j < n else None
                if nm and indent_of(lines[j]) == base and (nm.group(2)[0].isdigit()) == ordered:
                    i = j
            tag = "ol" if ordered else "ul"
            cls = "list-decimal" if ordered else "list-disc"
            parts = [f'<{tag} class="{cls} pl-6 space-y-2 text-sm my-2">']
            for first, rest in items:
                lead = [first]
                k = 0
                while k < len(rest) and rest[k].strip() and not re.match(r"^\s*([-*]|\d+\.)\s+|^\s*(```|>|\||\$\$)", rest[k]):
                    lead.append(rest[k].strip())
                    k += 1
                body = parse_blocks(rest[k:]) if k < len(rest) else ""
                parts.append(f'<li>{inline(" ".join(lead))}{body}</li>')
            parts.append(f"</{tag}>")
            out.append("\n".join(parts))
            continue
        # paragraph
        para = []
        while i < n:
            l = lines[i]
            st = l.strip()
            if (not st or st.startswith(("```", ">", "#", "|")) or st == "---"
                    or (para and LIST_RE.match(l)) or (st.startswith("$$") and st.endswith("$$") and len(st) > 4)):
                break
            para.append(st)
            i += 1
        if para:
            out.append(f'<p class="text-sm my-2">{inline(" ".join(para))}</p>')
        else:
            i += 1
    return "\n".join(out)


# ---------------------------------------------------------------- page specs -
DOCUMENT_CONFIGS = {
    "pq_mtc_attestation_proposal": {
        "title": "Post-Quantum WebAuthn Attestation Using Merkle Tree Certificates (mtc and mtcl)",
        "badges": [
            ("W3C WebAuthn & CTAP 2.3+", "bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold"),
            ("fmt: \"mtc\" & \"mtcl\"", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("IETF PLANTS Merkle Tree Certs", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("ML-DSA & OpenID Federation 1.1", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
        ],
        "desc": "Based on draft-ietf-plants-merkle-tree-certs, W3C WebAuthn Level 3/4 §8, FIDO CTAP 2.3, and FIDO Metadata Statement (MDS3).",
        "attribution": "Fidont is an authenticator simulator designed for prototyping new specifications and testing authenticator conformance tools. It is based on the Google OpenSK Rust codebase. Fidont is not suitable for production security use outside of certification, conformance testing, and prototyping new features.",
        "section_id_fn": lambda num, title: f"section-{num}" if num else slug(title),
    },
    "lmots_longfellow_attestation_proposal": {
        "title": "Multi-Batch Post-Quantum FIDO Attestation via LM-OTS & Google Longfellow (longfellow-lmots-zk and Direct Enterprise LMS)",
        "badges": [
            ("FIDO2 CTAP 2.3 & WebAuthn L3", "bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold"),
            ("fmt: \"longfellow-lmots-zk\"", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("RFC 8554 LM-OTS + ML-DSA-65", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("Google Longfellow (GKR + Ligero GF(2^k))", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
        ],
        "notice": "This document is an early architectural proposal for discussion only. It is aligned with the FIDO Client to Authenticator Protocol (CTAP) v2.3 Proposed Standard (2026-02-26) and W3C WebAuthn Level 3, and has not yet been adopted by the FIDO Alliance or W3C WebAuthn Working Group.",
        "desc": "A post-quantum FIDO2/WebAuthn attestation architecture combining 128-byte core state RFC 8554 LM-OTS on resource-constrained Secure Elements with Google Longfellow (GKR layered sumcheck + Ligero over binary extension fields GF(2^k)) on participating host platforms. Covers on-the-fly device subtree derivation, authenticatorGetInfo capability signaling, platform-side fmt rewriting, multi-batch AAGUID routing, 47-layer GKR SIMD circuit optimization, and a 1.6 KB self-contained Enterprise Direct Attestation profile verifying in 80 µs.",
        "section_id_fn": lambda num, title: f"section-{num}" if num else slug(title),
    },
    "ctap23_hierarchical_ppuat_spec": {
        "title": "CTAP 2.3+ Post-Quantum PIN/UV Auth Protocol 3: Architecture, Downgrade Integrity, Hierarchical PPUAT, and Encrypted Extensions",
        "badges": [
            ("FIDO2 CTAP 2.3+", "bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold"),
            ("pinUvAuthProtocol = 3", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("Post-Quantum HPKE & ARKG", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("Hierarchical PPUAT", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
        ],
        "desc": "Defines a Post-Quantum PIN/UV Auth Protocol 3 (pinUvAuthProtocol = 3) for FIDO2 CTAP 2.3+ based on RFC 9180 HPKE (X-Wing, MLKEM768-P256, and ML-KEM-1024), addressing Harvest-Now-Decrypt-Later (HNDL) quantum threats and active bus MITM attacks while maintaining strict Relying Party unlinkability, zero extra Authenticator NVRAM, and 0-RTT key agreement caching.",
        "section_id_fn": lambda num, title: f"section-{num}" if num else slug(title),
    },
    "ctap23_pin_protocol_3_hpke_stateful_aead_proposal": {
        "title": "FIDO2 CTAP 2.3+ Proposal: Post-Quantum PIN/UV Auth Protocol 3 Using RFC 9180 HPKE Stateful AEAD (AES-256-GCM)",
        "badges": [
            ("FIDO2 CTAP 2.3+", "bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold"),
            ("pinUvAuthProtocol = 3", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("HPKE Stateful AEAD", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("Mode B1 SymPSK (0-RTT)", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
        ],
        "desc": "Defines the normative core protocol, multi-tier trust hierarchy, 0-RTT symmetric PSK caching, encrypted extension AEAD contexts, and end-to-end Python reference implementation for PIN Protocol 3.",
        "section_id_fn": lambda num, title: f"section-{num}" if num else ("abstract" if "abstract" in title.lower() else slug(title)),
    },
    "ctap23_pin_protocol_4_hpke_export_only_proposal": {
        "title": "FIDO2 CTAP 2.3+ Proposal: Post-Quantum PIN/UV Auth Protocol 4 Using RFC 9180 HPKE Export-Only (aead_id = 0xFFFF)",
        "badges": [
            ("FIDO2 CTAP 2.3+", "bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold"),
            ("pinUvAuthProtocol = 4", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("HPKE Export-Only (0xFFFF)", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("Zero AEAD State Overhead", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
        ],
        "desc": "Defines an alternative PIN Protocol 4 operating entirely through RFC 9180 Secret Exporter (export-only mode), retaining zero authenticator-side AEAD context state while matching Protocol 3 downgrade protection.",
        "section_id_fn": lambda num, title: f"section-{num}" if num else ("abstract" if "abstract" in title.lower() else slug(title)),
    },
    "fido_ctap23_conformance_report": {
        "title": "FIDO CTAP 2.3 Conformance Test Report — 18 Algorithms (Including Draft NIST FIPS 206 FN-DSA-512 & FN-DSA-1024), RFC 8554 / NIST SP 800-208 HSS/LMS Certificate Hierarchy, All 7 Extensions, persistentPinUvAuthToken (perCredMgmtRO), Enterprise Attestation & Post-Quantum mtc / mtcl",
        "badges": [
            ("FIDO2 CTAP 2.3 Conformance Report", "bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold"),
            ("250 / 250 Passed (100%)", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("18 Algorithms (incl. FN-DSA-512 & 1024)", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("HSS/LMS Hierarchy & PQ MTC", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("perCredMgmtRO & Enterprise Attestation", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
        ],
        "desc": "Multi-log hardware verification on the Nordic nRF52840 DK running Fidont across the FIDO Conformance Debug Log (211,147 lines, 250 / 250 100.00% PASS), Total Phase Beagle USB Protocol Analyzer (127,232 USB bus records, 0 bus errors), and J-Link RTT DWT cycle-accurate telemetry (1,163,679 lines, 0 panics/OOMs).",
        "attribution": "Fidont is an authenticator simulator designed for prototyping new specifications and testing authenticator conformance tools. It is based on the Google OpenSK Rust codebase. Fidont is not suitable for production security use outside of certification, conformance testing, and prototyping new features.",
        "section_id_fn": lambda num, title: (
            "section-0-00" if "0.00" in title else
            ("section-0-0" if "0.0 " in title else
            ("section-0" if title.strip().startswith("0.") else
            ("overview" if "overview" in title.lower() else
            (f"section-{num}" if num else slug(title)))))
        ),
    },
    "enterprise_attestation_mtc_vs_lmots_comparison": {
        "title": "Post-Quantum Enterprise Attestation: Compact MTC vs. Direct LM-OTS (RFC 8554) Comparison Report",
        "badges": [
            ("Enterprise Attestation (0x0A)", "bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold"),
            ("MTC vs. RFC 8554 LM-OTS", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("7,609 B USB HID Wire Analysis", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("RP Validation Complexity", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
        ],
        "desc": "Comprehensive technical comparison between MDS/Manifest-Assisted Merkle Tree Certificates (fmt: 'mtc') and Standard RFC 8554 Leighton-Micali One-Time Signatures (Direct Enterprise HSS/LMS) across wire payload budgets, manifest distribution logistics, and Relying Party verification complexity.",
        "section_id_fn": lambda num, title: f"section-{num}" if num else slug(title),
    },
    "webauthn_level4_mtc_proposal": {
        "title": "Proposed Changes to W3C WebAuthn Level 4: Merkle Tree Certificate Attestation Format (mtc) and the mtcDebug Extension",
        "badges": [
            ("W3C WebAuthn Level 4 Proposal", "bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold"),
            ("fmt: \"mtc\"", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("mtcDebug Extension (§10.x)", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
            ("IETF PLANTS & FIDO CTAP 2.3", "bg-[var(--secondary)] text-[var(--secondary-foreground)]"),
        ],
        "desc": "Formal specification changes targeting the W3C WebAuthentication Working Group to define the compact mtc statement format in §8, the mtcDebug registration extension in §10, and size-aware attestation selection.",
        "section_id_fn": lambda num, title: f"section-{num}" if num else slug(title),
    }
}


def build_page(doc_name):
    cfg = DOCUMENT_CONFIGS[doc_name]
    md_path = f"{REPO}/{doc_name}.md"
    out_path = f"{REPO}/{doc_name}.html"

    md_text = open(md_path, encoding="utf-8").read().replace("\r\n", "\n")
    md_lines = md_text.split("\n")

    # Split markdown into sections by "## " (ignoring "## " inside fenced code)
    sections = []
    lead_lines = []
    cur_sec = None
    in_fence = False

    for line in md_lines:
        s = line.strip()
        if s.startswith("```"):
            in_fence = not in_fence

        if not in_fence and line.startswith("## "):
            raw_title = line[3:].strip()
            # check if title starts with number e.g. "1. Title" or "0.00 Run 20..."
            m_num = re.match(r"^(\d+(?:\.\d+)?)\.?\s*(.*)$", raw_title)
            if m_num:
                num = m_num.group(1)
                title = m_num.group(2) if m_num.group(2) else raw_title
            else:
                num = None
                title = raw_title

            sec_id = cfg["section_id_fn"](num, raw_title)
            cur_sec = {"num": num, "title": title, "raw_title": raw_title, "id": sec_id, "lines": []}
            sections.append(cur_sec)
        elif cur_sec is not None:
            cur_sec["lines"].append(line)
        else:
            lead_lines.append(line)

    # Build Navigation Cards
    nav_cards = []
    toc_items = []

    for s in sections:
        # Build TOC item
        sec_num_label = f"Section {s['num']}" if s['num'] else ""
        card_label = sec_num_label if sec_num_label else "Overview"
        clean_title = re.sub(r"[`*_]", "", s['title']).strip()
        short_title = clean_title[:45] + ("..." if len(clean_title) > 45 else "")

        nav_cards.append(f'''        <a href="#{s['id']}" class="block p-2.5 rounded-xl bg-[var(--content)] hover:border-[var(--primary)] border border-[var(--border)] transition">
          <div class="font-bold text-[var(--primary)]">{card_label}</div>
          <div class="font-semibold text-[var(--foreground)] mt-0.5 truncate">{inline(s['title'])}</div>
        </a>''')

        # Find subheadings inside section lines for TOC
        subheadings = []
        in_code = False
        for l in s["lines"]:
            if l.strip().startswith("```"):
                in_code = not in_code
            if not in_code:
                sm = re.match(r"^###\s+(.+)$", l.strip())
                if sm:
                    sub_title = sm.group(1).strip()
                    sub_slug = slug(sub_title)
                    subheadings.append((sub_title, sub_slug))

        sub_html = ""
        if subheadings:
            sub_links = "\n".join([f'            <div><a href="#{sub_id}" class="hover:underline">&sect;{inline(sub_t)}</a></div>' for sub_t, sub_id in subheadings[:6]])
            sub_html = f'''          <div class="text-[11px] pl-3 space-y-0.5 mt-1 text-[var(--muted-foreground)]">
{sub_links}
          </div>'''

        toc_items.append(f'''        <li>
          <a href="#{s['id']}" class="font-semibold text-[var(--foreground)] hover:text-[var(--primary)]">{inline(s['raw_title'])}</a>
{sub_html}
        </li>''')

    # Split TOC items into 3 columns
    col_size = (len(toc_items) + 2) // 3
    col1 = "\n".join(toc_items[:col_size])
    col2 = "\n".join(toc_items[col_size:col_size*2])
    col3 = "\n".join(toc_items[col_size*2:])

    # Badges HTML
    badges_html = "\n".join([
        f'        <span class="px-3 py-1 rounded-full text-xs {b_cls}">{html.escape(b_txt)}</span>'
        for b_txt, b_cls in cfg["badges"]
    ])

    # Lead Notice / Attribution
    optional_blocks = []
    if "notice" in cfg:
        optional_blocks.append(f'''    <div class="mb-4 p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-800 dark:text-amber-200 text-xs md:text-sm font-medium">
      <strong>Notice:</strong> {html.escape(cfg["notice"])}
    </div>''')
    if "attribution" in cfg:
        optional_blocks.append(f'''    <div class="p-4 rounded-xl bg-[var(--content)] border border-[var(--border)] text-xs text-[var(--muted-foreground)] mb-6">
      <strong class="text-[var(--foreground)]">Attribution &amp; Scope of Fidont:</strong>
      {html.escape(cfg["attribution"])}
    </div>''')
    extra_lead = "\n".join(optional_blocks)

    nav_grid_cols = min(max(len(sections), 2), 6)

    # HTML Shell
    html_out = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{html.escape(cfg["title"])}</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {{
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
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
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
      }}
    }}
    html {{
      scroll-behavior: smooth;
    }}
    code, pre {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }}
    main td code, main th code, main li code, main p code {{
      background: var(--content);
      padding: 0.1rem 0.3rem;
      border-radius: 0.25rem;
    }}
    main table td, main table th {{
      min-width: 6rem;
    }}
  </style>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css" />
  <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.js"></script>
  <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/contrib/auto-render.min.js"
    onload="renderMathInElement(document.body,{{delimiters:[{{left:'$$',right:'$$',display:true}},{{left:'$',right:'$',display:false}}],ignoredTags:['script','noscript','style','textarea','pre','code'],ignoredClasses:['nokatex','mermaid'],throwOnError:false}});"></script>
  <script type="module">
    import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
    mermaid.initialize({{ startOnLoad: true, theme: window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "default", securityLevel: "loose" }});
  </script>
</head>
<body class="bg-[var(--background)] text-[var(--foreground)] antialiased p-6 md:p-10 leading-relaxed">

  <!-- Header Banner -->
  <header class="max-w-6xl mx-auto mb-8 bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm">
    <div class="flex flex-wrap items-center justify-between gap-2 mb-3">
      <div class="flex flex-wrap items-center gap-2">
{badges_html}
      </div>
      <div class="flex items-center gap-4">
        <a href="./{doc_name}.md" class="text-xs font-semibold text-[var(--muted-foreground)] hover:text-[var(--primary)] hover:underline">Markdown Source (.md)</a>
        <a href="./index.html" class="text-xs font-semibold text-[var(--primary)] hover:underline">&larr; Back to Index</a>
      </div>
    </div>
    <h1 class="text-2xl md:text-3xl font-bold tracking-tight text-[var(--foreground)] mb-3">
      {inline(cfg["title"])}
    </h1>
    <p class="text-sm md:text-base text-[var(--muted-foreground)] mb-4">
      {inline(cfg["desc"])}
    </p>

{extra_lead}

    <!-- Quick Navigation Grid -->
    <div class="pt-4 border-t border-[var(--border)]">
      <div class="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] mb-3">
        Specification Sections &amp; Quick Jump
      </div>
      <nav class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-{nav_grid_cols} gap-2.5 text-xs">
{chr(10).join(nav_cards)}
      </nav>
    </div>

    <!-- Complete Table of Contents (Collapsible / Expandable) -->
    <details open class="mt-4 pt-4 border-t border-[var(--border)] group">
      <summary class="cursor-pointer text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] hover:text-[var(--primary)] flex items-center justify-between select-none">
        <span>Detailed Table of Contents &amp; Subsections</span>
        <span class="text-[10px] font-normal lowercase tracking-normal text-[var(--muted-foreground)] group-open:hidden">(click to expand)</span>
        <span class="text-[10px] font-normal lowercase tracking-normal text-[var(--muted-foreground)] hidden group-open:inline">(click to collapse)</span>
      </summary>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6 pt-3 text-xs">
        <div class="space-y-3">
          <ul class="space-y-2 text-[var(--muted-foreground)]">
{col1}
          </ul>
        </div>
        <div class="space-y-3">
          <ul class="space-y-2 text-[var(--muted-foreground)]">
{col2}
          </ul>
        </div>
        <div class="space-y-3">
          <ul class="space-y-2 text-[var(--muted-foreground)]">
{col3}
          </ul>
        </div>
      </div>
    </details>
  </header>

  <main class="max-w-6xl mx-auto space-y-10">
'''

    # Build Sections inside <main>
    for s in sections:
        sec_num_badge = f'<span class="text-xs font-bold uppercase tracking-wider text-[var(--primary)]">Section {s["num"]}</span>' if s["num"] else ""
        rendered_content = parse_blocks(s["lines"])
        html_out += f'''
    <!-- ===================================================================== -->
    <!-- SECTION {s["id"]} -->
    <!-- ===================================================================== -->
    <section id="{s["id"]}" class="bg-[var(--card)] border border-[var(--border)] rounded-2xl p-6 md:p-8 shadow-sm space-y-5 leading-relaxed">
      <div class="border-b border-[var(--border)] pb-4">
        {sec_num_badge}
        <h2 class="text-xl md:text-2xl font-bold text-[var(--foreground)] mt-1">{inline(s["title"])}</h2>
      </div>
{rendered_content}
    </section>
'''

    html_out += f'''  </main>

  <footer class="max-w-6xl mx-auto mt-10 text-center text-xs text-[var(--muted-foreground)]">
    Generated from <a href="./{doc_name}.md" class="text-[var(--primary)] hover:underline">{doc_name}.md</a> &middot; <a href="./index.html" class="text-[var(--primary)] hover:underline">&larr; Back to Index</a>
  </footer>
</body>
</html>
'''

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    print(f"Generated {out_path} ({len(html_out)} bytes, {len(sections)} sections)")


def main():
    targets = sys.argv[1:] if len(sys.argv) > 1 else list(DOCUMENT_CONFIGS.keys())
    for doc in targets:
        if doc.endswith(".md"):
            doc = doc[:-3]
        if doc.endswith(".html"):
            doc = doc[:-5]
        if doc in DOCUMENT_CONFIGS:
            build_page(doc)
        else:
            print(f"Unknown document: {doc}")


if __name__ == "__main__":
    main()
