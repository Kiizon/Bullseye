"""KEV exploration (ported from the original main.py).

Findings this reproduces:
- Repeat-offender vendors/products for KEV additions since 2024.
- The "slow" subset: KEV entries added after their publish month ended.
  Only these can appear on the scoreboard, and their vendor mix differs
  (Linux, Apache, Progress, Craft CMS up; Apple, Google out of the top 15).
- The time-window curve: share of slow additions that would land by the
  Nov 4 cutoff, by 2026 snapshot month (about 0.90 for Jan, 0.25 for Sep).

Run: python src/explore.py
"""
import numpy as np
import pandas as pd

from config import CACHE, SCOREBOARD_CUTOFF

kev = pd.read_parquet(CACHE / "known_exploited.parquet")
vulns = pd.read_parquet(CACHE / "vulnerabilities.parquet")

df = kev.merge(vulns, on="cve_id", how="left")
df["date_added"] = pd.to_datetime(df["date_added"])
df["published"] = pd.to_datetime(df["published"])
df["days_to_kev"] = (df["date_added"] - df["published"]).dt.days

recent = df[df["date_added"] >= "2024-01-01"].sort_values("date_added", ascending=False)

# 1. Read these
pd.set_option("display.max_colwidth", 250)
cols = ["cve_id", "vendor", "product", "date_added", "days_to_kev", "cvss3_score", "description"]
print(recent[cols].head(40).to_string())

# 2. Repeat-offender vendors and products (all KEV additions since 2024)
print(recent["vendor"].value_counts().head(15))
print(recent["product"].value_counts().head(15))

# 3. How fast bugs land on KEV
print(recent["days_to_kev"].describe())
print("share added within 30 days:", round((recent["days_to_kev"] <= 30).mean(), 3))

# 4. The scoreboard-like "slow" subset: published 2024+, added after publish month ended
recent = recent[recent["published"] >= "2024-01-01"].copy()
pub_month_end = recent["published"].dt.to_period("M").dt.end_time
slow = recent[recent["date_added"] > pub_month_end]

print("-------")
print("published 2024+ on KEV:", len(recent), " slow:", len(slow))
print(slow["vendor"].value_counts().head(15))
print(slow["days_to_kev"].describe())
# Lower bound: CVEs with no CVSS 3 score count as "not under 9.0".
print("share with CVSS 3 under 9.0 (at least):", round((slow["cvss3_score"] < 9.0).mean(), 3))

# 5. Time-window curve: share of slow additions landing by the cutoff, per snapshot month.
# Approximate: measures from publish date, not from the end of the snapshot month.
slow_days = np.sort(slow["days_to_kev"].values)


def p_within(days_left):
    return np.searchsorted(slow_days, days_left, side="right") / len(slow_days)


cutoff = pd.Timestamp(SCOREBOARD_CUTOFF)
print("month  days_left  share_landing")
for m in range(1, 10):
    end = pd.Period(f"2026-{m:02d}", "M").end_time
    days_left = (cutoff - end).days
    print(f"{m:>5}  {days_left:>9}  {p_within(days_left):.2f}")
