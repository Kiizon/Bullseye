"""Phase 2 features, built the same way for the 2024/2025 backtests and the
2026 scoreboard. Everything here is known at the end of the snapshot month.

Leakage choices:
- Exploitation wording ("exploited in the wild", "is aware of a report"...) is
  stripped from descriptions before any text feature is built.
- Blank CVSS parts are filled with the most common value, never flagged:
  positives almost never have blank CVSS because NIST scores attacked CVEs first.
- Not used: nvd_status, n_references, n_affected_cpes, cvss3_source,
  references.csv, last_modified.
- KEV history counts only entries added on or before the snapshot month end.
  KEV data stops on 2025-12-31, so 2026 rows use the 12 months ending then.

Run: python src/features.py   (writes data_cache/features_{2024,2025,2026}.parquet)
"""
import re

import numpy as np
import pandas as pd

from backtest import FLAGS, load_scoreboard, make_frame
from config import CACHE

KEV_DATA_END = pd.Timestamp("2025-12-31")

EXPLOIT_WORDING = re.compile(
    r"(?:exploited in the wild|exploitation in the wild|in the wild|actively exploited"
    r"|has been exploited|may have been exploited|is aware of (?:a )?reports?"
    r"|known to be exploited|under (?:active|limited|targeted) exploitation"
    r"|limited,? targeted attacks?|extremely sophisticated attack)",
    re.I,
)

# Hunch 1: edge devices. Enterprise edge products by name, plus generic words.
EDGE_PRODUCTS = re.compile(
    r"\b(?:fortios|fortigate|fortiweb|fortiproxy|fortimanager|fortianalyzer|fortisiem|fortiswitch"
    r"|pan-os|globalprotect|netscaler|citrix (?:adc|gateway)|connect secure|policy secure|pulse secure"
    r"|ivanti (?:epmm|neurons|csa|endpoint manager)|mobileiron|sonicos|sonicwall|sma ?1\d\d|watchguard"
    r"|fireware|firebox|adaptive security appliance|firepower|ios xe|identity services engine"
    r"|array networks|arrayos|big-ip|check point|junos|sophos firewall|barracuda|sangfor|versa"
    r"|cyberoam|zyxel|secure access gateway|commvault)\b",
    re.I,
)
EDGE_WORDS = re.compile(
    r"\b(?:vpn|ssl-?vpn|firewall|gateway|appliance|load balancer|remote access|secure access|ngfw|utm)\b",
    re.I,
)
SOHO = re.compile(r"\b(?:router|d-link|tp-link|netgear|tenda|totolink|linksys|draytek|dir-\d+|archer)\b", re.I)

# Hunch 2: pre-auth wording.
PRE_AUTH = re.compile(
    r"\b(?:unauthenticated|pre-?auth(?:entication)?|without (?:any )?authentication|no authentication"
    r"|unauthorized remote)\b",
    re.I,
)

# Hunch 5: bug types, from CWE ids and from description words (multi-hot).
BUG_TYPES = {
    "cmd_injection": ({"CWE-77", "CWE-78"}, r"command injection|os command|inject(?:ion of)? arbitrary commands"),
    "code_injection": ({"CWE-94", "CWE-95", "CWE-917", "CWE-1336"}, r"code injection|template injection|expression language"),
    "deserialization": ({"CWE-502"}, r"deserializ"),
    "traversal": ({"CWE-22", "CWE-23", "CWE-35", "CWE-36"}, r"path traversal|directory traversal|\.\./"),
    "auth_bypass": ({"CWE-287", "CWE-288", "CWE-290", "CWE-306", "CWE-862", "CWE-863", "CWE-639"},
                    r"authentication bypass|bypass (?:the )?authentication|missing authentication|improper authentication"),
    "file_upload": ({"CWE-434"}, r"unrestricted (?:file )?upload|arbitrary file upload|upload arbitrary"),
    "memory": ({"CWE-787", "CWE-416", "CWE-125", "CWE-119", "CWE-120", "CWE-122", "CWE-843", "CWE-190"},
               r"use[- ]after[- ]free|out[- ]of[- ]bounds|heap (?:buffer )?overflow|buffer overflow|type confusion|memory corruption"),
    "sqli": ({"CWE-89"}, r"sql injection"),
    "xss": ({"CWE-79", "CWE-80"}, r"cross[- ]site scripting|\bxss\b"),
    "ssrf": ({"CWE-918"}, r"server[- ]side request forgery|\bssrf\b"),
    "csrf": ({"CWE-352"}, r"cross[- ]site request forgery|\bcsrf\b"),
}
BUG_PRIORITY = ["cmd_injection", "deserialization", "auth_bypass", "file_upload", "traversal",
                "code_injection", "memory", "ssrf", "sqli", "csrf", "xss"]

WORDPRESS_ASSIGNERS = {"audit@patchstack.com", "security@wordfence.com", "contact@wpscan.com"}

CVSS_PARTS = ["attack_vector", "attack_complexity", "privileges_required", "user_interaction",
              "scope", "confidentiality_impact", "integrity_impact", "availability_impact"]


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def base_frames():
    """Backtest years with labels, plus the scoreboard without."""
    frames = {2024: make_frame(2024), 2025: make_frame(2025)}
    sb = load_scoreboard()
    sb["label"] = np.nan
    frames[2026] = sb
    keep = ["cve_id", "published", "snapshot_month", "epss", *FLAGS, "days_left", "label"]
    return {y: f[keep].copy() for y, f in frames.items()}


def add_nvd(df, vulns):
    df = df.merge(vulns, on="cve_id", how="left")
    df["desc_raw"] = df["description"].fillna("")
    df["exploit_wording_stripped"] = df["desc_raw"].str.contains(EXPLOIT_WORDING)
    df["desc"] = df["desc_raw"].str.replace(EXPLOIT_WORDING, " ", regex=True)
    return df


def add_signal_features(df):
    df["epss"] = df["epss"].fillna(0.0)
    # EPSS changed models in March 2025: rank within the snapshot month instead.
    df["epss_pct_month"] = df.groupby("snapshot_month")["epss"].rank(pct=True)
    df["n_flags"] = df[FLAGS].sum(axis=1)
    df["any_flag"] = (df["n_flags"] > 0).astype(int)
    return df


def add_cvss_features(df, modes):
    for c in CVSS_PARTS:
        df[c] = df[c].fillna(modes[c])
    df["cvss3_score"] = df["cvss3_score"].fillna(modes["cvss3_score"])
    df["cvss_pre_auth_remote"] = (
        df["attack_vector"].eq("NETWORK") & df["privileges_required"].eq("NONE") & df["user_interaction"].eq("NONE")
    ).astype(int)
    return df


def add_text_features(df):
    d = df["desc"]
    df["desc_pre_auth"] = d.str.contains(PRE_AUTH).astype(int)
    df["pre_auth_remote"] = (df["cvss_pre_auth_remote"].eq(1) | df["desc_pre_auth"].eq(1)).astype(int)  # hunch 2
    df["edge_product"] = d.str.contains(EDGE_PRODUCTS).astype(int)
    df["edge_word"] = d.str.contains(EDGE_WORDS).astype(int)
    df["is_edge_device"] = (df["edge_product"] | df["edge_word"]).astype(int)                           # hunch 1
    df["is_soho_router"] = d.str.contains(SOHO).astype(int)
    df["is_wordpress_plugin"] = (                                                                       # negative hunch
        d.str.contains(r"wordpress", case=False) | df["assigner"].isin(WORDPRESS_ASSIGNERS)
    ).astype(int)
    df["mentions_rce"] = d.str.contains(r"remote code execution|execute arbitrary code", case=False).astype(int)
    df["desc_len"] = d.str.len()

    cwes = df["cwe_ids"].fillna("").str.split(";").map(lambda xs: {x.strip() for x in xs})
    for name, (ids, pattern) in BUG_TYPES.items():
        by_cwe = cwes.map(lambda s, ids=ids: bool(s & ids))
        by_text = d.str.contains(pattern, case=False, regex=True)
        df[f"bug_{name}"] = (by_cwe | by_text).astype(int)
    df["cwe_group"] = "other"                                                                           # hunch 5
    for name in reversed(BUG_PRIORITY):
        df.loc[df[f"bug_{name}"].eq(1), "cwe_group"] = name
    return df


def assigner_vendor(assigner):
    """psirt@fortinet.com -> fortinet; UUID-style assigners -> None."""
    a = str(assigner).lower()
    if "@" not in a:
        return None
    parts = a.split("@", 1)[1].split(".")
    label = parts[-2] if len(parts) >= 2 else parts[0]
    return label if label not in {"mitre", "github", "vuldb", "wordfence", "patchstack", "wpscan",
                                  "vulncheck", "trendmicro", "huntr", "incibe", "jpcert", "dhs", "cert"} else None


def add_vendor_history(df, kev, kev_cap=KEV_DATA_END):
    """Hunch 3: KEV entries for the CVE's vendor in the 12 and 36 months up to
    the snapshot (capped at the end of KEV data). Vendor = KEV vendor names
    found in the description, plus the assigner's domain when it is a vendor."""
    kev = kev.assign(v=kev["vendor"].map(_norm))
    kev_dates = {v: np.sort(g["date_added"].to_numpy()) for v, g in kev.groupby("v")}
    # Generic language/tool names appear in countless unrelated descriptions
    # ("a PHP application", "git clone"), so they can't identify the vendor.
    ambiguous = {"Multiple", "PHP", "Git", "Docker", "Sudo", "Python", "Java", "JavaScript", "jQuery", "Node.js"}
    names = sorted({n for n in kev["vendor"].dropna().unique() if len(_norm(n)) >= 3 and n not in ambiguous},
                   key=len, reverse=True)
    # Case-sensitive on purpose: "PHP" the vendor, not "upload.php"; "Git", not "git clone".
    pattern = re.compile(r"(?<![\w.])(" + "|".join(re.escape(n) for n in names) + r")(?![\w])")

    found = df["desc"].str.findall(pattern).map(lambda xs: {_norm(x) for x in xs})
    from_assigner = df["assigner"].map(assigner_vendor)
    vendors = [f | ({a} if a in kev_dates else set()) for f, a in zip(found, from_assigner)]

    snap_end = pd.PeriodIndex(df["snapshot_month"], freq="M").end_time.normalize()
    window_end = np.minimum(snap_end.to_numpy(), np.datetime64(pd.Timestamp(kev_cap)))
    out = {"vendor_kev_12m": [], "vendor_kev_36m": [], "vendor_kev_ever": []}
    for vs, end in zip(vendors, window_end):
        best = {"vendor_kev_12m": 0, "vendor_kev_36m": 0, "vendor_kev_ever": 0}
        for v in vs:
            dates = kev_dates[v]
            hi = np.searchsorted(dates, end, side="right")
            for key, days in (("vendor_kev_12m", 365), ("vendor_kev_36m", 1095), ("vendor_kev_ever", None)):
                lo = 0 if days is None else np.searchsorted(dates, end - np.timedelta64(days, "D"), side="right")
                best[key] = max(best[key], int(hi - lo))
        for key in out:
            out[key].append(best[key])
    for key, vals in out.items():
        df[key] = vals
    df["vendor_matched"] = [",".join(sorted(v)) for v in vendors]
    return df


def build():
    vulns = pd.read_parquet(
        CACHE / "vulnerabilities.parquet",
        columns=["cve_id", "description", "assigner", "cwe_ids", "cvss3_score", *CVSS_PARTS],
    )
    kev = pd.read_parquet(CACHE / "known_exploited.parquet", columns=["cve_id", "vendor", "date_added"])
    kev["date_added"] = pd.to_datetime(kev["date_added"])

    frames = base_frames()
    train_like = pd.concat([frames[2024], frames[2025]]).merge(vulns, on="cve_id", how="left")
    modes = {c: train_like[c].mode().iat[0] for c in CVSS_PARTS}
    modes["cvss3_score"] = float(train_like["cvss3_score"].median())

    keep = list(frames[2024].columns)
    full_year = range(1, 13)
    # name -> (frame, cap on KEV history, year tag)
    jobs = {
        # Scoreboard-shaped sets (used by hunch_check.py).
        "2024": (frames[2024], KEV_DATA_END, 2024),
        "2025": (frames[2025], KEV_DATA_END, 2025),
        "2026": (frames[2026], KEV_DATA_END, 2026),
        # Honest fold that mirrors 2026: the model only knows KEV up to the
        # end of the prior year, exactly as we only know KEV to Dec 2025.
        "train2024": (make_frame(2024, cutoff="2024-12-31", months=full_year)[keep], "2024-12-31", 2024),
        "test2025": (frames[2025], "2024-12-31", 2025),
        # Final model for the scoreboard: every 2024-2025 CVE, labels to Dec 2025.
        "trainfinal": (pd.concat([
            make_frame(2024, cutoff="2025-12-31", months=full_year)[keep],
            make_frame(2025, cutoff="2025-12-31", months=full_year)[keep],
        ], ignore_index=True), KEV_DATA_END, None),
    }

    for name, (df, kev_cap, year) in jobs.items():
        df = add_nvd(df.copy(), vulns)
        df = add_signal_features(df)
        df = add_cvss_features(df, modes)
        df = add_text_features(df)
        df = add_vendor_history(df, kev, kev_cap)
        df["year"] = year if year else df["published"].dt.year
        df = df.drop(columns=["description", "desc_raw"])
        df.to_parquet(CACHE / f"features_{name}.parquet", index=False)
        lab = df["label"]
        stripped = df["exploit_wording_stripped"]
        print(f"{name:10s}: {len(df):,} rows, {int(lab.sum()) if lab.notna().any() else '?'} positives | "
              f"exploit wording stripped from {stripped.sum():,}"
              + (f" ({int(lab[stripped].sum())} positives)" if lab.notna().any() else ""))


if __name__ == "__main__":
    build()
