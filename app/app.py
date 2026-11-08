"""Bullseye demo app: what to patch first, and why.

Run: streamlit run app/app.py
Needs: python src/make_top500.py (and optionally src/watsonx_explain.py) first.
"""
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from config import CACHE, OUTPUTS  # noqa: E402

st.set_page_config(page_title="Bullseye: patch what attackers will hit", layout="wide")

EXPLOIT_COLS = {"exploitdb": "Exploit-DB", "metasploit": "Metasploit", "nuclei": "Nuclei", "poc_github": "GitHub"}


@st.cache_data
def load(stamp):
    """stamp = output file times, so the cache refreshes when the pipeline reruns."""
    scored = pd.read_parquet(CACHE / "scored_2026.parquet")
    top = pd.read_csv(OUTPUTS / "top500_detail.csv")
    why_path = OUTPUTS / "why_fix.csv"
    if why_path.exists():
        top = top.merge(pd.read_csv(why_path)[["cve_id", "why_fix"]], on="cve_id", how="left")
    else:
        top["why_fix"] = None
    top["why"] = top["why_fix"].fillna(top["reasons"]).fillna("exploit code and EPSS only")
    top["exploit_code"] = top[list(EXPLOIT_COLS)].apply(
        lambda r: ", ".join(n for c, n in EXPLOIT_COLS.items() if r[c] == 1) or "none", axis=1)
    # Display names from NVD product records (see make_top500.py); not used by the model.
    top["vendor"] = top["vendor_display"].fillna("")
    prod = top["product_display"].fillna("")
    top["product"] = [p if v and v in p else f"{v} {p}".strip() for v, p in zip(top["vendor"], prod)]
    top["product"] = top["product"].replace("", "not named yet")
    # Plain "exploit code, then EPSS" ranking, to show how far our order departs from it.
    base = scored["any_flag"] * 10 + scored["epss"]
    scored["base_rank"] = base.rank(ascending=False, method="first")
    bt = pd.read_csv(OUTPUTS / "backtest_results.csv")
    leak = pd.read_csv(OUTPUTS / "leakage_audit.csv")
    feats = pd.concat([pd.read_parquet(CACHE / f"features_{y}.parquet") for y in (2024, 2025)])
    return scored, top, bt, leak, feats


stamp = tuple(f.stat().st_mtime for f in sorted(OUTPUTS.glob("*.csv")))
scored, top, bt, leak, feats = load(stamp)

st.title("Bullseye")
st.caption("Ranks newly published vulnerabilities by how likely attackers are to exploit them, "
           "using only what was known at the time. IBM track, Sheridan Datathon 2026.")

with st.sidebar:
    st.header("Your week")
    budget = st.slider("How many can you patch this week?", 10, 200, 50, step=10)
    vendors = sorted(v for v in top["vendor"].unique() if v)
    pick_vendors = st.multiselect("Only these vendors", vendors)
    months = sorted(top["snapshot_month"].unique())
    pick_months = st.multiselect("Published in", months)

view = top
if pick_vendors:
    view = view[view["vendor"].isin(pick_vendors)]
if pick_months:
    view = view[view["snapshot_month"].isin(pick_months)]
view = view.head(budget)

tab_list, tab_cvss, tab_found = st.tabs(["This week's list", "Ours vs CVSS", "What we found"])

with tab_list:
    c1, c2, c3 = st.columns(3)
    c1.metric("Patch now", f"{len(view)}")
    c2.metric("With public exploit code", f"{(view['exploit_code'] != 'none').mean():.0%}")
    c3.metric("Outside CVSS's top 500", f"{(view['cvss_rank'] > 500).mean():.0%}")
    n = len(view)
    same = len(set(view["cve_id"]) & set(scored.nsmallest(n, "base_rank")["cve_id"])) if n else 0
    st.caption(f"Public exploit code is the strongest single signal, so it dominates the top of the list. "
               f"What sets the order is everything else: only {same} of these {n} are also in the top {n} "
               f"of a plain 'exploit code, then EPSS' list.")
    st.dataframe(
        view[["rank", "cve_id", "product", "why", "exploit_code", "epss_pct_month", "cvss3_raw"]],
        hide_index=True, use_container_width=True,
        column_config={
            "rank": st.column_config.NumberColumn("#", width=40),
            "cve_id": st.column_config.TextColumn("CVE", width=125),
            "product": st.column_config.TextColumn("Product", width=170),
            "why": st.column_config.TextColumn("Why fix this first", width="large"),
            "exploit_code": st.column_config.TextColumn("Exploit code", width=120),
            "epss_pct_month": st.column_config.NumberColumn("EPSS pct", format="%.3f", width=70,
                                                            help="EPSS percentile within its month"),
            "cvss3_raw": st.column_config.NumberColumn("CVSS", format="%.1f", width=55),
        },
    )
    if top["why_fix"].isna().all():
        st.caption("'Why' shows model reasons. Run src/watsonx_explain.py for Granite-written explanations.")
    pick = st.selectbox("Look closer at", view["cve_id"])
    r = view[view["cve_id"] == pick].iloc[0]
    st.markdown(f"**{r['cve_id']}** · published {r['published_date']} · "
                f"[NVD](https://nvd.nist.gov/vuln/detail/{r['cve_id']})")
    st.write(r["description"])
    st.markdown(f"**Model reasons:** {r['reasons']}  \n**Exploit code:** {r['exploit_code']}  \n"
                f"**Granite exploitability prior:** {r['granite_prior']:.2f} · **Bug type:** {r['cwe_group']}")

with tab_cvss:
    ours = set(top["cve_id"])
    cvss_top = set(scored.nsmallest(500, "cvss_rank")["cve_id"])
    c1, c2 = st.columns(2)
    c1.metric("Our top 500 that CVSS also ranks top 500", f"{len(ours & cvss_top)}")
    c2.metric("Median CVSS rank of our picks", f"{int(top['cvss_rank'].median()):,} of {len(scored):,}")
    st.subheader("High on our list, past 10,000 on a CVSS-first list")
    st.caption("CVSS ties are huge: every 8.1 shares rank 16,932, so a CVSS-first team sorts these by luck.")
    buried = top[top["cvss_rank"] > 10_000]
    st.caption(f"{len(buried)} of our top 500 are in this group.")
    st.dataframe(buried.head(15)[["rank", "cve_id", "product", "cvss3_raw", "cvss_rank", "why"]],
                 hide_index=True, use_container_width=True,
                 column_config={"rank": st.column_config.NumberColumn("Our rank", width="small"),
                                "cve_id": "CVE", "product": "Product",
                                "cvss3_raw": st.column_config.NumberColumn("CVSS", format="%.1f"),
                                "cvss_rank": "CVSS rank", "why": "Why fix this first"})

with tab_found:
    st.subheader("Honest backtest: rank 2025 using only 2024 knowledge")
    st.caption("Hits = CVEs in the top 500 that CISA later added to its Known Exploited list by Nov 4, 2025. "
               "Bootstrap range shows how much luck is in each number.")
    st.dataframe(bt.rename(columns={"ranking": "Ranking", "hits@500": "Hits in top 500", "boot90": "90% range",
                                    "p@50": "Hits in top 50", "p@100": "Hits in top 100"})
                 [["Ranking", "Hits in top 500", "90% range", "Hits in top 50", "Hits in top 100"]],
                 hide_index=True, use_container_width=True)

    st.subheader("What predicts exploitation (2024 + 2025, 75 exploited of 64,119)")
    base = feats["label"].mean()
    signals = {
        "Public exploit code": feats["any_flag"].eq(1),
        "Named edge, VPN or IT-management product": feats["edge_product"].eq(1),
        "Deserialization bug": feats["bug_deserialization"].eq(1),
        "'Unauthenticated' in description": feats["desc_pre_auth"].eq(1),
        "Path traversal": feats["bug_traversal"].eq(1),
        "Remote, no login, no click (CVSS)": feats["cvss_pre_auth_remote"].eq(1),
        "Memory corruption": feats["bug_memory"].eq(1),
        "Consumer router": feats["is_soho_router"].eq(1),
        "XSS": feats["bug_xss"].eq(1),
        "WordPress plugin": feats["is_wordpress_plugin"].eq(1),
    }
    lift = pd.DataFrame([{"Signal": k, "CVEs": int(m.sum()), "Later exploited": int(feats.loc[m, "label"].sum()),
                          "Times the base rate": round(feats.loc[m, "label"].mean() / base, 1)}
                         for k, m in signals.items()])
    st.dataframe(lift, hide_index=True, use_container_width=True)
    st.markdown("**WordPress plugins:** 0 of 14,173 reached the list, in both years. "
                "**Consumer routers** behave the opposite way to enterprise edge devices.")

    st.subheader("Leakage audit: why we left some columns out")
    st.caption("These NIST columns are filled in after an attack. A model that uses them looks better than it is.")
    st.dataframe(leak[["ranking", "hits@500", "boot90"]].rename(
        columns={"ranking": "Naive model adds", "hits@500": "Claimed hits in top 500", "boot90": "90% range"}),
        hide_index=True, use_container_width=True)
