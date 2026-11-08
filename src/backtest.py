"""Honest backtest harness: rebuild the scoreboard's shape on past years.

Scoreboard 2026 = every CVE published Jan-Sep 2026, scored with the signals at
the end of its snapshot month (= publish month, except June -> July because
there is no June 2026 snapshot), minus CVEs already on KEV by then. Judges
count KEV additions through Nov 4, 2026.

The backtest copies that for 2024 and 2025 with cutoffs Nov 4, 2024 / 2025.
KEV data ends Dec 31, 2025, so both cutoffs are fully labelled.

Run: python src/backtest.py
"""
import numpy as np
import pandas as pd

from config import CACHE

FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]
TOP_K = 500


def _month_end(period_str):
    return pd.Period(period_str, "M").end_time.normalize()


def make_frame(year, cutoff=None, months=range(1, 10)):
    """One row per CVE published in `months` of `year`, with the signals at the
    end of its publish month and label = added to KEV after that month ended
    and on or before `cutoff`."""
    cutoff = pd.Timestamp(cutoff or f"{year}-11-04")
    vulns = pd.read_parquet(
        CACHE / "vulnerabilities.parquet",
        columns=["cve_id", "published", "cvss3_score"],
    )
    vulns["published"] = pd.to_datetime(vulns["published"])
    df = vulns[vulns["published"].dt.year.eq(year) & vulns["published"].dt.month.isin(months)].copy()
    df["snapshot_month"] = df["published"].dt.strftime("%Y-%m")

    sig = pd.read_parquet(CACHE / f"exploit_signals_{year}.parquet")
    df = df.merge(sig, left_on=["cve_id", "snapshot_month"], right_on=["cve_id", "month"], how="left")
    df = df.drop(columns="month")
    df[FLAGS] = df[FLAGS].fillna(0).astype(int)
    df["has_signal_row"] = df["in_kev"].notna()

    kev = pd.read_parquet(CACHE / "known_exploited.parquet", columns=["cve_id", "date_added"])
    kev["date_added"] = pd.to_datetime(kev["date_added"])
    df = df.merge(kev, on="cve_id", how="left")
    snap_end = df["snapshot_month"].map(_month_end)

    on_kev_at_snapshot = df["date_added"].le(snap_end) | df["in_kev"].eq(1)
    df = df[~on_kev_at_snapshot].copy()
    df["label"] = (df["date_added"] > snap_end.loc[df.index]) & (df["date_added"] <= cutoff)
    df["label"] = df["label"].astype(int)
    df["days_left"] = (cutoff - snap_end.loc[df.index]).dt.days
    return df.reset_index(drop=True)


def load_scoreboard():
    sb = pd.read_parquet(CACHE / "scoreboard_2026.parquet")
    v = pd.read_parquet(CACHE / "vulnerabilities.parquet", columns=["cve_id", "cvss3_score"])
    sb = sb.merge(v, on="cve_id", how="left")
    sb["days_left"] = (pd.Timestamp("2026-11-04") - sb["snapshot_month"].map(_month_end)).dt.days
    return sb


# ---------- scoring ----------

def hits_at(df, score, k=TOP_K, seed=0):
    """Hits in the top k. Ties are broken at random (seeded) so a pile of
    identical scores (e.g. CVSS 9.8) can't flatter or punish a ranking."""
    rng = np.random.default_rng(seed)
    order = np.lexsort((rng.random(len(df)), -np.nan_to_num(np.asarray(score, float), nan=-np.inf)))
    return int(df["label"].to_numpy()[order[:k]].sum())


def evaluate(df, score, name, k=TOP_K, n_seeds=20, n_boot=1000):
    """Hits@k (mean over tie-break seeds), precision@50/100, a bootstrap
    90% range, and hits per snapshot month."""
    score = np.asarray(score, float)
    hits = [hits_at(df, score, k, s) for s in range(n_seeds)]
    order = np.lexsort((np.random.default_rng(0).random(len(df)), -np.nan_to_num(score, nan=-np.inf)))
    lab = df["label"].to_numpy()[order]

    # Poisson bootstrap over CVEs: weight each row, take rows in rank order
    # until the weights fill k slots.
    rng = np.random.default_rng(1)
    boot = []
    for _ in range(n_boot):
        w = rng.poisson(1.0, len(lab))
        cut = np.searchsorted(np.cumsum(w), k, side="right")
        boot.append(int((w[:cut] * lab[:cut]).sum()))
    lo, hi = np.percentile(boot, [5, 95])

    top = df.iloc[order[:k]]
    per_month = top.groupby("snapshot_month")["label"].sum()
    return {
        "ranking": name,
        f"hits@{k}": round(float(np.mean(hits)), 1),
        "tie_range": f"{min(hits)}-{max(hits)}",
        "boot90": f"{lo:.0f}-{hi:.0f}",
        "p@50": int(lab[:50].sum()),
        "p@100": int(lab[:100].sum()),
        "per_month": " ".join(f"{m[-2:]}:{n}" for m, n in per_month.items() if n),
    }


def baseline_scores(df):
    epss = df["epss"].fillna(0).to_numpy()
    any_flag = (df[FLAGS].sum(axis=1) > 0).to_numpy()
    return {
        "CVSS 3 first": df["cvss3_score"].to_numpy(float),
        "EPSS first": epss,
        "Exploit code, then EPSS": any_flag * 10 + epss,
    }


if __name__ == "__main__":
    pd.set_option("display.width", 200)
    for year in (2024, 2025):
        df = make_frame(year)
        n_pos = int(df["label"].sum())
        print(f"\n=== Backtest {year}: {len(df):,} CVEs, {n_pos} later added to KEV "
              f"({n_pos / len(df) * 1e4:.1f} per 10k), {df['has_signal_row'].mean():.0%} have a signal row")
        print(df.groupby("snapshot_month")["label"].agg(["size", "sum"]).T.to_string())
        rows = [evaluate(df, s, name) for name, s in baseline_scores(df).items()]
        print(pd.DataFrame(rows).to_string(index=False))

    sb = load_scoreboard()
    print(f"\n=== Scoreboard 2026: {len(sb):,} CVEs (labels unknown until judging)")
