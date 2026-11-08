"""Train the final blend on all 2024-2025 CVEs (KEV known to 2025-12-31)
and rank the 2026 scoreboard.

Blend = rank average of
  - gradient boosting on all features incl. the Granite prior (default params,
    not tuned on the test year)
  - naive Bayes over the binary features (its weights double as reasons)

Writes outputs/top500.csv (one column, cve_id) and outputs/top500_detail.csv.

Run: python src/make_top500.py
"""
import numpy as np
import pandas as pd

from config import CACHE, OUTPUTS
from nb_score import binarize, fit as nb_fit
from train_model import GROUPS, add_assigner_group, fit_score, rank_avg

READABLE = {
    "any_flag": "public exploit code", "epss_top1": "EPSS in top 1% this month",
    "epss_top10": "EPSS in top 10% this month", "edge_product": "named edge, VPN or IT-management product",
    "edge_word": "edge device (VPN/firewall/gateway)", "desc_pre_auth": "no login needed (description)",
    "cvss_pre_auth_remote": "remote, no login, no click (CVSS)", "mentions_rce": "remote code execution",
    "vendor_kev_12m": "vendor on KEV in the past year", "bug_deserialization": "deserialization bug",
    "bug_traversal": "path traversal", "bug_cmd_injection": "command injection",
    "bug_auth_bypass": "authentication bypass", "bug_code_injection": "code injection",
    "bug_file_upload": "file upload", "bug_ssrf": "SSRF", "bug_sqli": "SQL injection",
    "wordpress": "WordPress plugin", "soho_router": "consumer router", "bug_xss": "XSS",
    "bug_csrf": "CSRF", "bug_memory": "memory corruption", "days_left_150plus": "published early in the year",
}


def reasons(Xb, w, top=3):
    """Top positive naive-Bayes contributions per row, in plain words."""
    contrib = Xb * (w["w_on"] - w["w_off"])
    # Exploit code and EPSS top almost every pick and have their own columns,
    # so the reasons list what else sets this CVE apart.
    contrib[["any_flag", "epss_top1", "epss_top10"]] = 0
    # Keep only the stronger of overlapping signals.
    contrib.loc[contrib["epss_top1"] > 0, "epss_top10"] = 0
    contrib.loc[contrib["edge_product"] > 0, "edge_word"] = 0
    contrib.loc[contrib["desc_pre_auth"] > 0, "cvss_pre_auth_remote"] = 0
    out = []
    for _, row in contrib.iterrows():
        best = row[row > 0.3].sort_values(ascending=False).head(top)
        out.append("; ".join(READABLE.get(k, k) for k in best.index))
    return out


def main():
    train = pd.read_parquet(CACHE / "features_trainfinal.parquet")
    sb = pd.read_parquet(CACHE / "features_2026.parquet")
    prior = pd.read_parquet(CACHE / "prior_final.parquet")  # KEV known to 2025-12-31
    train, sb = train.merge(prior, on="cve_id", how="left"), sb.merge(prior, on="cve_id", how="left")
    add_assigner_group(train, [sb])
    cols = [c for g in GROUPS.values() for c in g]
    print(f"training on {len(train):,} CVEs, {int(train['label'].sum())} positives; scoring {len(sb):,}")

    gb, _ = fit_score(train, sb, cols)
    w = nb_fit(binarize(train), train["label"].astype(int))
    Xb = binarize(sb)
    nb = (Xb * w["w_on"] + (1 - Xb) * w["w_off"]).sum(axis=1).to_numpy()
    sb["score"] = rank_avg(gb, nb)
    sb["gb_prob"], sb["nb_score"] = gb, nb

    rng = np.random.default_rng(0)
    order = np.lexsort((rng.random(len(sb)), -sb["score"].to_numpy()))
    sb["our_rank"] = 0
    sb.iloc[order, sb.columns.get_loc("our_rank")] = np.arange(1, len(sb) + 1)

    # Context for the app and the explainer: raw CVSS (not imputed) and its rank,
    # and the cleaned description (exploitation wording already stripped).
    raw = pd.read_parquet(CACHE / "vulnerabilities.parquet", columns=["cve_id", "cvss3_score", "published"])
    raw = raw.rename(columns={"cvss3_score": "cvss3_raw", "published": "published_date"})
    sb = sb.merge(raw, on="cve_id", how="left")
    sb["cvss_rank"] = sb["cvss3_raw"].rank(ascending=False, method="min").astype("Int64")
    sb.to_parquet(CACHE / "scored_2026.parquet", index=False)

    top = sb.sort_values("our_rank").head(500).copy()
    top["rank"] = top["our_rank"]
    top["reasons"] = reasons(Xb.loc[top.index], w)
    top["description"] = top["desc"].str.replace(r"\s+", " ", regex=True).str.strip()

    # Display only, never a model feature: product names from NVD's CPE records
    # (filled in after NVD analysis), falling back to the KEV-vendor match.
    cpe = pd.read_parquet(CACHE / "affected_products.parquet", columns=["cve_id", "vendor", "product"])
    cpe = cpe[cpe["cve_id"].isin(top["cve_id"])].merge(top[["cve_id", "description"]], on="cve_id")
    # Several products per CVE: prefer the one the description names, then the most common.
    cpe["named"] = [str(p).replace("_", " ").lower() in d.lower() for p, d in zip(cpe["product"], cpe["description"])]
    cpe["n"] = cpe.groupby(["cve_id", "product"])["product"].transform("size")
    cpe = cpe.sort_values(["named", "n"], ascending=False).groupby("cve_id").first()
    nice = lambda s: s.fillna("").str.replace("_", " ")
    top["vendor_display"] = nice(top["cve_id"].map(cpe["vendor"])).replace("", None).fillna(
        top["vendor_matched"].replace("", None).str.split(",").str[0].str.lower()).fillna("")
    top["product_display"] = nice(top["cve_id"].map(cpe["product"]))

    OUTPUTS.mkdir(exist_ok=True)
    top[["cve_id"]].to_csv(OUTPUTS / "top500.csv", index=False)
    detail_cols = ["rank", "cve_id", "snapshot_month", "published_date", "score", "gb_prob", "nb_score",
                   "granite_prior", "epss", "epss_pct_month", "exploitdb", "metasploit", "nuclei", "poc_github",
                   "cvss3_raw", "cvss_rank", "vendor_matched", "vendor_display", "product_display", "cwe_group",
                   "is_edge_device", "reasons", "description"]
    top[detail_cols].to_csv(OUTPUTS / "top500_detail.csv", index=False)

    # Validate the submission file.
    check = pd.read_csv(OUTPUTS / "top500.csv")
    sb_ids = set(pd.read_parquet(CACHE / "scoreboard_2026.parquet", columns=["cve_id"])["cve_id"])
    assert list(check.columns) == ["cve_id"], check.columns
    assert len(check) == 500 and check["cve_id"].is_unique
    assert check["cve_id"].isin(sb_ids).all()
    print("top500.csv valid: 500 unique scoreboard CVEs, header cve_id")
    print("\nBy snapshot month:", top["snapshot_month"].value_counts().sort_index().to_dict())
    print("Share with public exploit code:", f"{top['any_flag'].mean():.0%}")
    print("Top vendors:", top["vendor_matched"].replace("", "(none)").value_counts().head(8).to_dict())
    pd.set_option("display.width", 220, "display.max_colwidth", 70)
    print("\nTop 15:")
    print(top[["rank", "cve_id", "snapshot_month", "epss", "vendor_matched", "cwe_group", "reasons"]].head(15).to_string(index=False))


if __name__ == "__main__":
    main()
