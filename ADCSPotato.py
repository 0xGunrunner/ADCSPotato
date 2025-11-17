#!/usr/bin/env python3
import re, json, argparse
from collections import defaultdict

ADMINISH_KEYWORDS = (
    "domain admins",
    "enterprise admins",
    "administrators",
    "domain controllers",
    "enterprise read-only domain controllers",
    "schema admins",
    "enterprise key admins",
    "key admins",
)
STANDARD_LOWPRIV_GROUPS = ("domain users", "authenticated users")
DANGEROUS_OC_CATS = {"WriteOwner","WriteDacl","WriteProperty","GenericAll","GenericWrite","FullControl","AllExtendedRights"}

PRINCIPAL_RE = re.compile(r"[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$ ]+?(?=\s{2,}|\t|$)")

def short_name(p:str)->str:
    return p.split("\\")[-1].strip()

def extract_principals(text:str):
    return PRINCIPAL_RE.findall(text or "")

def is_machine_account(p:str)->bool:
    return p.strip().endswith("$")

def is_adminish(p:str)->bool:
    pl = p.lower()
    if pl.startswith("builtin\\") or pl.startswith("nt authority\\"):
        return True
    return any(k in pl for k in ADMINISH_KEYWORDS)

def is_standard_lowpriv_group(p:str)->bool:
    pl = p.lower()
    return any(g in pl for g in STANDARD_LOWPRIV_GROUPS)

def looks_nonstandard_lowpriv(p:str)->bool:
    if is_adminish(p) or is_machine_account(p) or is_standard_lowpriv_group(p):
        return False
    s = short_name(p).lower()
    bad_tokens = ("admin", "admins", "controller", "controllers", "enterprise", "schema", "krbtgt", "system", "service", "services")
    if any(t in s for t in bad_tokens):
        return False
    if s in ("administrator", "guest"):
        return False
    if s.endswith("computers") or s.endswith("controllers"):
        return False
    return True

def parse_ca(raw:str):
    ca = {"EnrollmentAgentRestrictions": None, "Permissions": []}
    m = re.search(r"\[\*\] Listing info about the Enterprise CA.*?(?=\[\*\] Available Certificates Templates|$)", raw, re.S)
    if not m:
        return ca
    block = m.group(0)
    mm = re.search(r"Enrollment Agent Restrictions\s*:\s*(.+)", block)
    if mm:
        ca["EnrollmentAgentRestrictions"] = mm.group(1).strip()
    for rights, principal in re.findall(r"Allow\s+(.*?)\s+([^\n]+)", block):
        rights_list = rights.strip().replace(",", "").split()
        ca["Permissions"].append((rights_list, principal.strip()))
    return ca

def parse_templates(raw:str):
    templates = []
    # Split into per-template blocks
    for block in re.split(r"\n\s*CA Name\s*:.*?\n\s*Template Name\s*:\s*", raw)[1:]:
        lines = block.splitlines()
        tname = lines[0].strip()
        t = {
            "Template Name": tname,
            "Owner": "",
            "Owner Principals": [],
            "msPKI-Certificate-Name-Flag": "",
            "Authorized Signatures Required": 0,
            "pkiextendedkeyusage": "<null>",
            "mspki-certificate-application-policy": "<null>",
            "Enrollment Rights": [],
            "Object Control": [],
            "Object Control Map": {},
        }
        def grab1(key, default=None):
            mm = re.search(rf"{re.escape(key)}\s*:\s*(.+)", block)
            return (mm.group(1).strip() if mm else default)

        # Owner
        t["Owner"] = grab1("Owner", "") or ""
        t["Owner Principals"] = extract_principals(t["Owner"]) or ([t["Owner"]] if t["Owner"] else [])

        # Numbers/flags
        try:
            t["Authorized Signatures Required"] = int(grab1("Authorized Signatures Required", "0"))
        except:
            t["Authorized Signatures Required"] = 0
        t["msPKI-Certificate-Name-Flag"] = grab1("msPKI-Certificate-Name-Flag", "") or ""
        t["pkiextendedkeyusage"] = grab1("pkiextendedkeyusage", "<null>") or "<null>"
        t["mspki-certificate-application-policy"] = grab1("mspki-certificate-application-policy", "<null>") or "<null>"

        # Enrollment Rights: scan the Enrollment block and extract principals via regex
        enroll_hdr = re.search(r"Enrollment Permissions\s*?\n\s*Enrollment Rights\s*:(.*)", block)
        if enroll_hdr:
            first_tail = enroll_hdr.group(1)
            for p in extract_principals(first_tail):
                t["Enrollment Rights"].append(p)
            # then capture following lines until next section
            enroll_match = re.search(r"Enrollment Permissions\s*?\n\s*Enrollment Rights\s*:\s*((?:.*\n)+?)\s*Object Control Permissions", block)
            if enroll_match:
                for ln in enroll_match.group(1).splitlines():
                    for p in extract_principals(ln):
                        t["Enrollment Rights"].append(p)

        # Object Control Permissions
        ocp_match = re.search(r"Object Control Permissions(?:\s*:)?\s*\n((?:.*\n)+)", block)
        if ocp_match:
            ocp_text = ocp_match.group(1)
            current_cat = None
            for ln in ocp_text.splitlines():
                s = ln.rstrip()
                if not s.strip():
                    continue
                # Detect headers like "WriteDacl Principals       :" (allow spaces before colon)
                hdr = re.match(r"^\s*([A-Za-z][A-Za-z0-9 ]*?)\s+Principals\s*:(.*)$", s)
                if hdr:
                    current_cat = hdr.group(1).strip()
                    t["Object Control Map"].setdefault(current_cat, [])
                    # also parse principals on the same header line
                    tail = hdr.group(2)
                    hits = extract_principals(tail)
                    if hits:
                        t["Object Control"].extend(hits)
                        t["Object Control Map"][current_cat].extend(hits)
                    continue
                # Extract principals on the line
                hits = extract_principals(s)
                if hits:
                    t["Object Control"].extend(hits)
                    if current_cat:
                        t["Object Control Map"].setdefault(current_cat, []).extend(hits)

        templates.append(t)
    return templates

def has_auth_eku(t)->bool:
    ekus = " ".join([(t.get("pkiextendedkeyusage") or ""), (t.get("mspki-certificate-application-policy") or "")]).lower()
    return any(x in ekus for x in ["client authentication", "smart card logon", "kdc authentication"])

def is_any_purpose(t) -> bool:
    ekus = (t.get("pkiextendedkeyusage") or "").strip().lower()
    apps = (t.get("mspki-certificate-application-policy") or "").strip().lower()

    def empty_or_any(s: str) -> bool:
        # Treat empty/<null> as AnyPurpose (legacy behavior) AND match literal "Any Purpose"
        return s in ("", "<null>") or ("any purpose" in s)

    # If either EKUs OR App Policy is AnyPurpose, consider it AnyPurpose overall
    return empty_or_any(ekus) or empty_or_any(apps)


def enrollee_supplies_subject(t)->bool:
    return "ENROLLEE_SUPPLIES_SUBJECT" in t.get("msPKI-Certificate-Name-Flag","")

def is_cra_template(t)->bool:
    ekus = " ".join([(t.get("pkiextendedkeyusage") or ""), (t.get("mspki-certificate-application-policy") or "")]).lower()
    name = t["Template Name"].lower()
    return ("certificate request agent" in ekus) or ("enrollment agent" in ekus) or ("agent" in name)

def collect_all_principals(ca, templates):
    every = set()
    for rights, principal in ca.get("Permissions", []):
        every.add(principal)
    for t in templates:
        if t["Owner"]:
            every.add(t["Owner"])
        for p in t["Owner Principals"]:
            every.add(p)
        for p in t["Enrollment Rights"]:
            every.add(p)
        for p in t["Object Control"]:
            every.add(p)
    return every

def build_watchlists(users_file_set:set, ca, templates):
    observed = collect_all_principals(ca, templates)
    auto_nonstandard = set()
    for p in observed:
        if looks_nonstandard_lowpriv(p):
            auto_nonstandard.add(short_name(p))
    watch_users = set(users_file_set) | auto_nonstandard
    return watch_users, auto_nonstandard

def lowpriv_enrollee_present(t, watch_users:set)->bool:
    for p in t["Enrollment Rights"]:
        pl = p.lower()
        if is_standard_lowpriv_group(pl) or (short_name(p) in watch_users):
            return True
    return False

def build_mentions(templates, watch_users:set):
    mentions = defaultdict(lambda: {"owner": [], "enroll": [], "object_control": []})
    for t in templates:
        for _op in (t.get("Owner Principals") or []):
            if _op and (is_standard_lowpriv_group(_op) or (short_name(_op) in watch_users)):
                mentions[t["Template Name"]]["owner"].append(_op)
        for p in t["Enrollment Rights"]:
            if is_standard_lowpriv_group(p) or (short_name(p) in watch_users):
                mentions[t["Template Name"]]["enroll"].append(p)
        for cat, plist in (t.get("Object Control Map") or {}).items():
            for p in plist:
                if is_standard_lowpriv_group(p) or (short_name(p) in watch_users):
                    mentions[t["Template Name"]]["object_control"].append(f"{p} [{cat}]")
    return mentions

def detect_esc(ca, templates, watch_users:set):
    findings = []
    # Always mark CRA templates as potential ESC3
    for t in templates:
        if is_cra_template(t):
            findings.append({"esc":"POTENTIAL_ESC3", "template": t["Template Name"], "why": "CRA template present (Certificate Request Agent)"})

    # --- ESC2 (evaluate first) ---
    esc2_templates = set()
    for t in templates:
        if (
            is_any_purpose(t)
            and enrollee_supplies_subject(t)
            and t["Authorized Signatures Required"] == 0
            and lowpriv_enrollee_present(t, watch_users)
        ):
            findings.append({"esc":"ESC2", "template": t["Template Name"], "why": "Any Purpose + ENROLLEE_SUPPLIES_SUBJECT + low-priv enrollee + 0 signatures"})
            esc2_templates.add(t["Template Name"])

    # --- ESC1 (only if not ESC2) ---
    for t in templates:
        if t["Template Name"] in esc2_templates:
            continue
        if (
            enrollee_supplies_subject(t)
            and t["Authorized Signatures Required"] == 0
            and lowpriv_enrollee_present(t, watch_users)
            and has_auth_eku(t)
            and not is_any_purpose(t)
        ):
            findings.append({"esc":"ESC1", "template": t["Template Name"], "why": "ENROLLEE_SUPPLIES_SUBJECT + auth EKU (not Any Purpose) + low-priv enrollee + 0 signatures"})

    # ESC3 (strong)

    cra_lowpriv = [t for t in templates if is_cra_template(t) and lowpriv_enrollee_present(t, watch_users)]
    requires_sig = [t for t in templates if t["Authorized Signatures Required"] >= 1]
    if cra_lowpriv and requires_sig and (ca.get("EnrollmentAgentRestrictions","") or "None").strip().lower() in ("none","not set","null",""):
        targets = sorted({x["Template Name"] for x in requires_sig})
        for at in cra_lowpriv:
            findings.append({"esc":"ESC3", "template": at["Template Name"], "why": f"Low-priv can enroll in agent template; EA restrictions None; signature-required templates present: {', '.join(targets[:8])}…"})
    # ESC4
    for t in templates:
        owner_princs = t.get("Owner Principals") or ([] if not t.get("Owner") else [t.get("Owner")])
        owner_hits = [op for op in owner_princs if (is_standard_lowpriv_group(op) or (short_name(op) in watch_users))]
        if owner_hits:
            findings.append({"esc":"ESC4", "template": t["Template Name"], "why": f"Owner contains low-priv/watched principal(s): {', '.join(owner_hits)}"})
        oc_map = t.get("Object Control Map") or {}
        for cat, plist in oc_map.items():
            if cat in DANGEROUS_OC_CATS:
                hits = [p for p in plist if (is_standard_lowpriv_group(p) or (short_name(p) in watch_users))]
                if hits:
                    findings.append({"esc":"ESC4", "template": t["Template Name"], "why": f"{cat} includes low-priv/watched principal(s): {', '.join(hits)}"})
        if owner_hits and any(is_standard_lowpriv_group(p) or (short_name(p) in watch_users) for p in t["Enrollment Rights"]):
            findings.append({"esc":"ESC4", "template": t["Template Name"], "why": "Owner includes watched principal(s) and that principal (or peers) also has enrollment rights"})
    # ESC7
    for rights, principal in ca.get("Permissions", []):
        rights_joined = " ".join(rights).lower() if isinstance(rights, (list, tuple)) else str(rights).lower()
        has_manage_ca = ("manage ca" in rights_joined) or ("manageca" in rights_joined)
        has_manage_certs = ("manage certificates" in rights_joined) or ("managecertificates" in rights_joined)
        if (has_manage_ca or has_manage_certs) and not is_adminish(principal):
            if is_standard_lowpriv_group(principal) or (short_name(principal) in watch_users):
                which = []
                if has_manage_ca: which.append("Manage CA")
                if has_manage_certs: which.append("Manage Certificates")
                findings.append({"esc":"ESC7", "template": "CA", "why": f"Non-admin watched principal '{principal}' has {', '.join(which)}"})
    return findings


def build_report_md(output_path, users_path, findings, ess_templates, mentions, ca_hits, auto_nonstandard):
    lines = []
    lines.append("# AD CS ESC Scan Report (watchlist + auto nonstandard)")
    lines.append("")
    lines.append(f"Scanned: `{output_path}` + `{users_path}`")
    lines.append("")
    lines.append("## Findings")
    if not findings:
        lines.append("- No ESC1/2/3/4/7 triggered given the current watchlist (Domain Users + Users.txt + auto nonstandard low-priv).")
    else:
        for f in findings:
            lines.append(f"- **{f['esc']}** — **{f['template']}**: {f['why']}")
    lines.append("")
    lines.append("## Templates with `ENROLLEE_SUPPLIES_SUBJECT`")
    if ess_templates:
        for n in sorted(ess_templates):
            lines.append(f"- {n}")
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Watchlist principal occurrences")
    any_hits = any(mentions[t]["owner"] or mentions[t]["enroll"] or mentions[t]["object_control"] for t in mentions)
    if not any_hits:
        lines.append("- No appearances of Domain Users / Authenticated Users / Users.txt / auto-nonstandard principals found in Owner/Enrollment/Object Control.")
    else:
        for tname, hit in sorted(mentions.items()):
            if not (hit["owner"] or hit["enroll"] or hit["object_control"]):
                continue
            lines.append(f"### {tname}")
            if hit["owner"]:
                lines.append(f"- **Owner:** {', '.join(sorted(set(hit['owner'])))}")
            if hit["enroll"]:
                lines.append(f"- **Enrollment Rights:** {', '.join(sorted(set(hit['enroll'])))}")
            if hit["object_control"]:
                for oc in sorted(set(hit["object_control"])):
                    lines.append(f"- **Object Control:** {oc}")
    lines.append("")
    lines.append("## CA-level hits (watchlist)")
    if ca_hits:
        for rights, p in ca_hits:
            lines.append(f"- {p} → Rights: {'/'.join(rights)}")
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Auto-discovered nonstandard low-priv principals")
    if auto_nonstandard:
        for s in sorted(auto_nonstandard):
            lines.append(f"- {s}")
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Notes")
    lines.append("- **ESC8** needs web enrollment/NDES checks (e.g., `http(s)://<CA>/certsrv`).")
    lines.append("- **ESC11** needs CA registry/Certify 2.0/Certipy check for `IF_ENFORCEENCRYPTICERTREQUEST`.")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True, help="Path to Certify/Certipy text output")
    ap.add_argument("--users", required=True, help="Path to Users.txt (short names, one per line)")
    ap.add_argument("--write-md", default=None, help="Optional path to write a Markdown report")
    args = ap.parse_args()

    raw = open(args.output, "r", encoding="utf-8", errors="ignore").read()
    users_file_set = set([u.strip() for u in open(args.users, "r", encoding="utf-8", errors="ignore").read().splitlines() if u.strip()])

    ca = parse_ca(raw)
    templates = parse_templates(raw)

    watch_users, auto_nonstandard = build_watchlists(users_file_set, ca, templates)
    mentions = build_mentions(templates, watch_users)

    ca_hits = []
    for rights, principal in ca.get("Permissions", []):
        if is_standard_lowpriv_group(principal) or (short_name(principal) in watch_users):
            ca_hits.append((rights, principal))

    findings = detect_esc(ca, templates, watch_users)
    ess_templates = [t["Template Name"] for t in templates if enrollee_supplies_subject(t)]

    out = {
        "findings": findings,
        "enrollee_supplies_subject": sorted(ess_templates),
        "mentions": mentions,
        "ca_watch_hits": ca_hits,
        "auto_nonstandard_lowpriv": sorted(auto_nonstandard),
        "meta": {"output_file": args.output, "users_file": args.users}
    }
    print(json.dumps(out, indent=2))

    if args.write_md:
        md = build_report_md(args.output, args.users, findings, ess_templates, mentions, ca_hits, auto_nonstandard)
        with open(args.write_md, "w", encoding="utf-8") as f:
            f.write(md)

if __name__ == "__main__":
    main()
