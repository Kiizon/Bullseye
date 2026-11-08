"""Bullseye demo app: what to patch first, and why.

Run: streamlit run app/app.py
Needs: python src/make_top500.py (and optionally src/watsonx_explain.py) first.
"""
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from config import CACHE, OUTPUTS  # noqa: E402
APP_DATA = Path(__file__).resolve().parent / "data"

st.set_page_config(page_title="Bullseye: patch what attackers will hit", layout="wide")

EXPLOIT_COLS = {"exploitdb": "Exploit-DB", "metasploit": "Metasploit", "nuclei": "Nuclei", "poc_github": "GitHub"}
BUG_TYPE = {"auth_bypass": "login bypass", "cmd_injection": "command injection", "deserialization":
            "unsafe data loading (deserialization)", "traversal": "path traversal", "code_injection":
            "code injection", "memory": "memory corruption", "file_upload": "unsafe file upload",
            "ssrf": "server-side request forgery", "sqli": "SQL injection", "xss": "cross-site scripting",
            "csrf": "cross-site request forgery", "other": "other"}
BLUE, GRAY = "#2a78d6", "#a3a19a"


def bars(df, label, value, text, title, color=None, blue=None, tooltip=None, height=None):
    """Horizontal bar chart with the value written at the end of each bar.
    color = column that splits bars in two; rows equal to `blue` are blue, the rest gray."""
    if color:
        other = [v for v in df[color].unique() if v != blue]
        enc_color = alt.Color(f"{color}:N", scale=alt.Scale(domain=[blue, *other], range=[BLUE, GRAY]),
                              legend=alt.Legend(title=None, orient="top"))
    else:
        enc_color = alt.value(BLUE)
    base = alt.Chart(df, title=alt.Title(title, anchor="start")).encode(
        y=alt.Y(f"{label}:N", sort=None, title=None, axis=alt.Axis(labelLimit=330)),
        x=alt.X(f"{value}:Q", title=None, axis=alt.Axis(grid=False, labels=False, ticks=False, domain=False)),
        tooltip=tooltip or [label, text], color=enc_color)
    chart = base.mark_bar(size=22, cornerRadiusEnd=4) + \
        base.mark_text(align="left", dx=6, fontSize=14).encode(text=f"{text}:N", color=alt.value("#7a7974"))
    return chart.properties(height=height or 46 * len(df) + (80 if color else 30)).configure_view(stroke=None)


@st.cache_data
def load(stamp):
    """stamp = output file times, so the cache refreshes when the pipeline reruns."""
    # Full pipeline cache when present; otherwise the slim copies in app/data (used by the hosted app).
    if (CACHE / "scored_2026.parquet").exists():
        scored = pd.read_parquet(CACHE / "scored_2026.parquet")
        feats = pd.concat([pd.read_parquet(CACHE / f"features_{y}.parquet") for y in (2024, 2025)])
    else:
        scored = pd.read_parquet(APP_DATA / "scored_2026.parquet")
        feats = pd.read_parquet(APP_DATA / "features_2024_2025.parquet")
    top = pd.read_csv(OUTPUTS / "top500_detail.csv")
    why_path = OUTPUTS / "why_fix.csv"
    if why_path.exists():
        top = top.merge(pd.read_csv(why_path)[["cve_id", "why_fix", "model_id"]], on="cve_id", how="left")
    else:
        top["why_fix"], top["model_id"] = None, None
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
    return scored, top, bt, leak, feats


stamp = tuple(f.stat().st_mtime for f in sorted(OUTPUTS.glob("*.csv")))
scored, top, bt, leak, feats = load(stamp)

st.title("Bullseye")
st.caption("Ranks newly published vulnerabilities by how likely attackers are to exploit them, "
           "using only what was known at the time. IBM track, Sheridan Datathon 2026.")
with st.expander("Terms used on this page"):
    st.markdown(
        "- **CVE**: one publicly listed security bug, with an ID like CVE-2026-1603.\n"
        "- **Attacked / exploited**: the bug was added to CISA's Known Exploited Vulnerabilities list, "
        "the US government's list of bugs seen used in real attacks.\n"
        "- **Exploit code**: working attack code posted publicly (Exploit-DB, Metasploit, Nuclei, GitHub).\n"
        "- **EPSS**: a public daily estimate of the chance a bug will be attacked. \"Top 1%\" means only 1% of "
        "that month's bugs scored higher.\n"
        "- **Severity score (CVSS)**: a 0–10 score for how bad a bug could be. It does not say whether "
        "attackers are interested in it.")

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

tab_list, tab_cvss, tab_found = st.tabs(["This week's list", "Bullseye vs severity score", "What was found"])

with tab_list:
    c1, c2, c3 = st.columns(3)
    c1.metric("Patch now", f"{len(view)}")
    c2.metric("With public exploit code", f"{(view['exploit_code'] != 'none').mean():.0%}")
    c3.metric("Not among the 500 highest severity scores", f"{(view['cvss_rank'] > 500).mean():.0%}")
    n = len(view)
    same = len(set(view["cve_id"]) & set(scored.nsmallest(n, "base_rank")["cve_id"])) if n else 0
    st.caption(f"Public exploit code is the strongest single warning sign, so most picks have it. "
               f"The order comes from the other signs: only {same} of these {n} are also in the top {n} "
               f"of a simple 'exploit code first, then EPSS' list.")
    view = view.assign(epss_top=[f"top {t:.1f}%" if t < 1 else f"top {t:.0f}%"
                                 for t in ((1 - view["epss_pct_month"]) * 100).clip(lower=0.1)])
    st.dataframe(
        view[["rank", "cve_id", "product", "why", "exploit_code", "epss_top", "cvss3_raw"]],
        hide_index=True, use_container_width=True,
        column_config={
            "rank": st.column_config.NumberColumn("#", width=40),
            "cve_id": st.column_config.TextColumn("CVE", width=125),
            "product": st.column_config.TextColumn("Product", width=150),
            "why": st.column_config.TextColumn("Why fix this first", width=360),
            "exploit_code": st.column_config.TextColumn("Exploit code", width=105),
            "epss_top": st.column_config.TextColumn("EPSS", width=72,
                                                    help="Where the bug's EPSS attack-chance estimate sits among "
                                                         "all bugs published the same month"),
            "cvss3_raw": st.column_config.NumberColumn("Severity", format="%.1f", width=65,
                                                       help="CVSS severity score, 0 to 10"),
        },
    )
    if top["why_fix"].isna().all():
        st.caption("'Why' shows model reasons. Run src/watsonx_explain.py for Granite-written explanations.")
    pick = st.selectbox("Look closer at", view["cve_id"])
    r = view[view["cve_id"] == pick].iloc[0]
    st.markdown(f"**{r['cve_id']}** · published {r['published_date']} · "
                f"[NVD](https://nvd.nist.gov/vuln/detail/{r['cve_id']})")
    if pd.notna(r["why_fix"]):
        who = ("written by IBM Granite, corrected after human review" if "corrected" in str(r["model_id"])
               else "written by IBM Granite")
        st.info(f"**Why fix this first** ({who}): {r['why_fix']}")
    st.write(r["description"])
    beat = (scored["granite_prior"] < r["granite_prior"]).mean()
    signs = r["reasons"] if isinstance(r["reasons"], str) and r["reasons"] else "none beyond exploit code and EPSS"
    st.markdown(f"**Other warning signs:** {signs}  \n**Exploit code:** {r['exploit_code']}  \n"
                f"**Bug type:** {BUG_TYPE.get(r['cwe_group'], r['cwe_group'])}  \n"
                f"**IBM Granite's read of the description:** sounds more like an attacked bug than "
                f"{beat:.0%} of 2026 CVEs")

with tab_cvss:
    c1, c2 = st.columns(2)
    c1.metric("Bullseye's top 500 also among the 500 highest severity scores",
              f"{int((top['cvss_rank'] <= 500).sum())} of 500")
    c2.metric("Typical place of a Bullseye pick on a severity-sorted list",
              f"{int(top['cvss_rank'].median()):,} of {len(scored):,}")
    edges = [0, 500, 5_000, 10_000, 20_000, float("inf")]
    names = ["Top 500", "501 to 5,000", "5,001 to 10,000", "10,001 to 20,000", "Past 20,000"]
    spread = pd.cut(top["cvss_rank"], edges, labels=names).value_counts(sort=False).rename_axis("place").reset_index()
    spread["text"] = spread["count"].astype(str) + " picks"
    st.altair_chart(bars(spread, "place", "count", "text",
                         "Where Bullseye's top 500 sit on a list sorted by severity score"), use_container_width=True)
    st.caption("A team that patches the highest severity scores first would reach most of these only after "
               "thousands of other bugs. Many bugs also share the same score: all 8.1s tie at place 16,932, "
               "so a severity-sorted list puts them in no useful order.")
    st.subheader("Bullseye picks that a severity-sorted list buries past place 10,000")
    buried = top[top["cvss_rank"] > 10_000]
    st.caption(f"{len(buried)} of the Bullseye top 500 are in this group. The first 15:")
    st.dataframe(buried.head(15)[["rank", "cve_id", "product", "cvss3_raw", "cvss_rank", "why"]],
                 hide_index=True, use_container_width=True,
                 column_config={"rank": st.column_config.NumberColumn("Bullseye rank", width=100),
                                "cve_id": "CVE", "product": "Product",
                                "cvss3_raw": st.column_config.NumberColumn("Severity", format="%.1f"),
                                "cvss_rank": st.column_config.NumberColumn("Place on severity list", format="localized"),
                                "why": "Why fix this first"})

with tab_found:
    st.subheader("Test: could Bullseye have predicted 2025's attacks?")
    st.caption("The test pretends it is the start of 2025. Each method ranks the bugs published in 2025 using "
               "only what was known in 2024, and picks the bugs to patch first. Each bar counts how many of "
               "those picks were later used in real attacks (CISA's list). Longer bar = better.")
    main = {"CVSS 3 first": "Highest severity score first", "EPSS first": "Highest EPSS first",
            "Exploit code, then EPSS": "Exploit code first, then EPSS",
            "Blend: boosting(+Granite) + NB": "Bullseye"}
    head = bt[bt["ranking"].isin(main)].assign(method=lambda d: d["ranking"].map(main))
    head["who"] = ["Bullseye" if m == "Bullseye" else "Common ways to sort" for m in head["method"]]
    head["t500"] = head["hits@500"].map(lambda v: f"{v:g}")
    head["t50"] = head["p@50"].astype(str)
    c1, c2 = st.columns(2)
    c1.altair_chart(bars(head, "method", "hits@500", "t500", "Of the top 500 picks, how many were later attacked",
                         color="who", blue="Bullseye"),
                    use_container_width=True)
    c2.altair_chart(bars(head, "method", "p@50", "t50", "Of the first 50 picks, how many were later attacked",
                         color="who", blue="Bullseye"), use_container_width=True)
    st.caption("Only 48 of the 2025 bugs were ever attacked, so a gap of 2 or 3 could be luck. The clearest "
               "gap is in the first 50 picks: 10 for Bullseye against 4 for the best common method. "
               "17.4 and 5.7 are averages: those methods give many bugs the same score, and the count "
               "depends on which tied bugs land in the 500.")
    with st.expander("Every version tested"):
        plain = {"CVSS 3 first": "Highest severity score first", "EPSS first": "Highest EPSS first",
                 "Exploit code, then EPSS": "Exploit code first, then EPSS",
                 "Naive Bayes": "Simple odds model alone", "Granite prior alone": "IBM Granite score alone",
                 "Gradient boosting, no Granite": "Decision trees, no Granite",
                 "Gradient boosting + Granite prior": "Decision trees with Granite",
                 "Blend: boosting + NB (no Granite)": "Blend without Granite",
                 "Blend: boosting(+Granite) + NB": "Bullseye (blend with Granite)",
                 "Blend: boosting(+Granite) + NB + prior": "Blend plus Granite score again"}
        st.dataframe(bt.assign(ranking=bt["ranking"].replace(plain))
                     .rename(columns={"ranking": "Method", "hits@500": "Attacked, of top 500 picks",
                                      "p@50": "Attacked, of first 50", "p@100": "Attacked, of first 100"})
                     [["Method", "Attacked, of top 500 picks", "Attacked, of first 50", "Attacked, of first 100"]],
                     hide_index=True, use_container_width=True)

    st.subheader("Which warning signs matter")
    base = feats["label"].mean()
    signals = {
        "Public exploit code online": feats["any_flag"].eq(1),
        "Edge, VPN or IT-management product (Fortinet, Ivanti...)": feats["edge_product"].eq(1),
        "Unsafe data loading (deserialization)": feats["bug_deserialization"].eq(1),
        "Description says no login is needed": feats["desc_pre_auth"].eq(1),
        "Path traversal (reads files outside the allowed folder)": feats["bug_traversal"].eq(1),
        "Severity score says remote, no login, no click": feats["cvss_pre_auth_remote"].eq(1),
        "Memory corruption": feats["bug_memory"].eq(1),
        "Home router": feats["is_soho_router"].eq(1),
        "Cross-site scripting": feats["bug_xss"].eq(1),
        "WordPress plugin": feats["is_wordpress_plugin"].eq(1),
    }
    lift = pd.DataFrame([{"sign": k, "bugs": int(m.sum()), "attacked": int(feats.loc[m, "label"].sum()),
                          "times": feats.loc[m, "label"].mean() / base} for k, m in signals.items()])
    lift = lift.sort_values("times", ascending=False)
    lift["text"] = [f"{t:.1f}×" if a else f"0 of {b:,} attacked" for t, a, b in
                    zip(lift["times"], lift["attacked"], lift["bugs"])]
    lift["side"] = ["More likely than average" if t > 1 else "Less likely than average" for t in lift["times"]]
    st.altair_chart(bars(lift, "sign", "times", "text",
                         "How many times as likely to be attacked as an average bug (2024–2025)",
                         color="side", blue="More likely than average", tooltip=["sign", alt.Tooltip("bugs", format=","), "attacked", "text"]),
                    use_container_width=True)
    st.caption(f"Out of {len(feats):,} bugs published in 2024 and 2025, {int(feats['label'].sum())} were "
               "attacked. A bar of 1× would mean average. Home routers and big-company edge devices behave in "
               "opposite ways, and none of 14,173 WordPress plugin bugs were attacked.")

    st.subheader("Data left out because it gives the answer away")
    st.markdown(
        "Some data was left out because it gives away the answer, which would skew the model:\n"
        "- **Review status**: whether the US vulnerability database (NIST) has finished reviewing the bug\n"
        "- **Number of reference links**: links to write-ups, advisories and patches\n"
        "- **Number of affected products**: how many product versions are listed as affected\n\n"
        "NIST reviews attacked bugs first, so these fill in mostly *after* an attack. A model that uses them "
        "learns to spot bugs that were already attacked. It scores higher in the test below, but it would "
        "miss new bugs, where these fields are still empty. Other fields that fill in late, such as the "
        "last-updated date, were left out for the same reason.")
    lk = {"Decision trees (Bullseye's fair inputs)": bt.loc[bt["ranking"] == "Gradient boosting + Granite prior", "hits@500"].iat[0],
          "Same, plus the three after-attack fields": leak.loc[leak["ranking"] == "+ nvd_status, n_references, n_affected_cpes", "hits@500"].iat[0],
          "Only exploit code and the after-attack fields": leak.loc[leak["ranking"] == "signals + leaky only", "hits@500"].iat[0]}
    lk = pd.DataFrame({"model": list(lk), "hits": list(lk.values())})
    lk["text"] = lk["hits"].map(lambda v: f"{v:g}")
    lk["kind"] = ["Fair" if i == 0 else "Uses after-attack fields" for i in range(len(lk))]
    st.altair_chart(bars(lk, "model", "hits", "text", "Of the top 500 picks, how many were later attacked",
                         color="kind", blue="Fair"), use_container_width=True)
