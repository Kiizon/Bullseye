"""Gate 2 fallback: a transparent naive-Bayes score over binary features.

Each feature's weight = log of how much more common it is among positives
than negatives in the training set (Laplace-smoothed). The score is the sum
of weights, so every pick can be explained as a list of reasons.

Honest fold: weights learned on train2024 (KEV known to 2024-12-31), scored
on test2025. Needs only numpy/pandas.

Run: python src/nb_score.py
"""
import numpy as np
import pandas as pd

from backtest import baseline_scores, evaluate
from config import CACHE
from features import BUG_TYPES

BUGS = [f"bug_{b}" for b in BUG_TYPES]


def binarize(df):
    X = pd.DataFrame(index=df.index)
    X["any_flag"] = df["any_flag"]
    X["epss_top10"] = df["epss_pct_month"].ge(0.90)
    X["epss_top1"] = df["epss_pct_month"].ge(0.99)
    X["edge_product"] = df["edge_product"]
    X["edge_word"] = df["edge_word"]
    X["soho_router"] = df["is_soho_router"]
    X["wordpress"] = df["is_wordpress_plugin"]
    X["desc_pre_auth"] = df["desc_pre_auth"]
    X["cvss_pre_auth_remote"] = df["cvss_pre_auth_remote"]
    X["mentions_rce"] = df["mentions_rce"]
    X["vendor_kev_12m"] = df["vendor_kev_12m"].ge(1)
    X["days_left_150plus"] = df["days_left"].ge(150)
    for b in BUGS:
        X[b] = df[b]
    return X.astype(int)


def fit(X, y, alpha=1.0):
    pos, neg = X[y == 1], X[y == 0]
    p1 = (pos.sum() + alpha) / (len(pos) + 2 * alpha)
    p0 = (neg.sum() + alpha) / (len(neg) + 2 * alpha)
    w_on = np.log(p1 / p0)
    w_off = np.log((1 - p1) / (1 - p0))
    return pd.DataFrame({"w_on": w_on, "w_off": w_off, "pos_on": pos.sum(), "neg_on": neg.sum()})


def score(X, w):
    return (X * w["w_on"] + (1 - X) * w["w_off"]).sum(axis=1).to_numpy()


if __name__ == "__main__":
    pd.set_option("display.width", 200)
    train = pd.read_parquet(CACHE / "features_train2024.parquet")
    test = pd.read_parquet(CACHE / "features_test2025.parquet")

    w = fit(binarize(train), train["label"].astype(int))
    print("Weights learned on train2024 (40 positives):")
    print(w.sort_values("w_on", ascending=False).round(2).to_string())

    s = score(binarize(test), w)
    rows = [evaluate(test, v, name) for name, v in baseline_scores(test).items()]
    rows.append(evaluate(test, s, "Naive Bayes (train 2024)"))
    print("\nHonest 2025 backtest:")
    print(pd.DataFrame(rows).to_string(index=False))
