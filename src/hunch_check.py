"""Test each hunch on the 2024 + 2025 backtests: how much more often do
flagged CVEs land on KEV than the base rate? Also checks how common each
flag is on the 2026 scoreboard, to catch features that drift.

Run: python src/hunch_check.py
"""
import pandas as pd

from config import CACHE

bt = pd.concat([pd.read_parquet(CACHE / f"features_{y}.parquet") for y in (2024, 2025)])
sb = pd.read_parquet(CACHE / "features_2026.parquet")
base = bt["label"].mean()

FLAGS = {
    "H1 is_edge_device": "is_edge_device",
    "H1  edge product name": "edge_product",
    "H1  edge generic word": "edge_word",
    "H1  SOHO router": "is_soho_router",
    "H2 pre_auth_remote": "pre_auth_remote",
    "H2  CVSS AV:N/PR:N/UI:N": "cvss_pre_auth_remote",
    "H2  'unauthenticated' wording": "desc_pre_auth",
    "H3 vendor_kev_12m >= 1": None,
    "H3 vendor_kev_12m >= 5": None,
    "H3 vendor_kev_36m >= 1": None,
    "Bonus is_wordpress_plugin": "is_wordpress_plugin",
    "ref: any exploit flag": "any_flag",
    "ref: mentions RCE": "mentions_rce",
}


def mask(df, label, col):
    if col:
        return df[col].eq(1)
    n = int(label.split(">= ")[1])
    key = "vendor_kev_36m" if "36m" in label else "vendor_kev_12m"
    return df[key].ge(n)


rows = []
for label, col in FLAGS.items():
    m = mask(bt, label, col)
    rows.append({
        "hunch": label,
        "flagged": int(m.sum()),
        "positives": int(bt.loc[m, "label"].sum()),
        "per_10k": round(bt.loc[m, "label"].mean() * 1e4, 1),
        "lift": round(bt.loc[m, "label"].mean() / base, 1),
        "2024_pos": int(bt.loc[m & bt["year"].eq(2024), "label"].sum()),
        "2025_pos": int(bt.loc[m & bt["year"].eq(2025), "label"].sum()),
        "share_bt": f"{m.mean():.1%}",
        "share_2026": f"{mask(sb, label, col).mean():.1%}",
    })

for g in bt["cwe_group"].unique():
    m = bt["cwe_group"].eq(g)
    rows.append({
        "hunch": f"H5 cwe_group={g}", "flagged": int(m.sum()), "positives": int(bt.loc[m, "label"].sum()),
        "per_10k": round(bt.loc[m, "label"].mean() * 1e4, 1), "lift": round(bt.loc[m, "label"].mean() / base, 1),
        "2024_pos": int(bt.loc[m & bt["year"].eq(2024), "label"].sum()),
        "2025_pos": int(bt.loc[m & bt["year"].eq(2025), "label"].sum()),
        "share_bt": f"{m.mean():.1%}", "share_2026": f"{sb['cwe_group'].eq(g).mean():.1%}",
    })

pd.set_option("display.width", 200)
print(f"Backtest 2024+2025: {len(bt):,} CVEs, {int(bt['label'].sum())} positives, base {base * 1e4:.1f} per 10k\n")
print(pd.DataFrame(rows).to_string(index=False))

print("\nPositives by matched vendor (top 15):")
print(bt[bt["label"].eq(1)]["vendor_matched"].replace("", "(none)").value_counts().head(15).to_string())
