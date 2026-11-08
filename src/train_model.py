"""Phase 4: gradient-boosted model, ablations and the leakage audit.

Uses scikit-learn's HistGradientBoostingClassifier (same model family as
LightGBM, no system OpenMP needed).

Honest fold: fit on train2024 (KEV known to 2024-12-31), score test2025.
With 40 training positives the model is kept small and heavily regularized.

Run: python src/train_model.py
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from backtest import baseline_scores, evaluate
from config import CACHE
from features import BUG_TYPES, CVSS_PARTS
from nb_score import binarize, fit as nb_fit, score as nb_score

GROUPS = {
    "signals": ["epss", "epss_pct_month", "n_flags", "any_flag", "exploitdb", "metasploit", "nuclei", "poc_github"],
    "cvss": ["cvss3_score", *CVSS_PARTS, "cvss_pre_auth_remote"],
    "text_flags": ["desc_pre_auth", "edge_product", "edge_word", "is_soho_router", "is_wordpress_plugin",
                   "mentions_rce", "desc_len"],
    "bug_types": [f"bug_{b}" for b in BUG_TYPES],
    "vendor_history": ["vendor_kev_12m", "vendor_kev_36m", "vendor_kev_ever"],
    "assigner": ["assigner_group"],
    "days_left": ["days_left"],
    "granite_prior": ["granite_prior"],
}
CATEGORICAL = set(CVSS_PARTS) | {"assigner_group"}
LEAKY = ["nvd_status", "n_references", "n_affected_cpes"]

PARAMS = dict(max_depth=3, max_leaf_nodes=8, min_samples_leaf=80, learning_rate=0.05,
              max_iter=250, l2_regularization=1.0, random_state=0)


def add_assigner_group(train, others, top=25):
    keep = set(train["assigner"].value_counts().head(top).index)
    for df in (train, *others):
        df["assigner_group"] = df["assigner"].where(df["assigner"].isin(keep), "other")


def encode(train, test, cols):
    """Categoricals -> integer codes learned on train (unseen -> missing)."""
    Xtr, Xte = train[cols].copy(), test[cols].copy()
    cat_mask = []
    for c in cols:
        if c in CATEGORICAL or Xtr[c].dtype == object:
            cats = pd.Index(Xtr[c].astype(str).unique())
            Xtr[c] = cats.get_indexer(Xtr[c].astype(str)).astype(float)
            codes = cats.get_indexer(Xte[c].astype(str)).astype(float)
            Xte[c] = np.where(codes < 0, np.nan, codes)
            cat_mask.append(True)
        else:
            cat_mask.append(False)
    return Xtr.astype(float), Xte.astype(float), cat_mask


def fit_score(train, test, cols, params=PARAMS):
    Xtr, Xte, cat_mask = encode(train, test, cols)
    model = HistGradientBoostingClassifier(categorical_features=cat_mask, **params)
    model.fit(Xtr, train["label"].astype(int))
    return model.predict_proba(Xte)[:, 1], model


def rank_avg(*scores):
    return np.mean([pd.Series(s).rank(pct=True).to_numpy() for s in scores], axis=0)


if __name__ == "__main__":
    pd.set_option("display.width", 220)
    train = pd.read_parquet(CACHE / "features_train2024.parquet")
    test = pd.read_parquet(CACHE / "features_test2025.parquet")
    prior = pd.read_parquet(CACHE / "prior_fold.parquet")  # KEV known to 2024-12-31 only
    train, test = train.merge(prior, on="cve_id", how="left"), test.merge(prior, on="cve_id", how="left")
    add_assigner_group(train, [test])
    all_cols = [c for g in GROUPS.values() for c in g]
    no_prior = [c for c in all_cols if c != "granite_prior"]

    rows = [evaluate(test, s, name) for name, s in baseline_scores(test).items()]

    w = nb_fit(binarize(train), train["label"].astype(int))
    nb = nb_score(binarize(test), w)
    rows.append(evaluate(test, nb, "Naive Bayes"))
    rows.append(evaluate(test, test["granite_prior"].to_numpy(), "Granite prior alone"))

    gb0, _ = fit_score(train, test, no_prior)
    rows.append(evaluate(test, gb0, "Gradient boosting, no Granite"))
    gb, _ = fit_score(train, test, all_cols)
    rows.append(evaluate(test, gb, "Gradient boosting + Granite prior"))
    rows.append(evaluate(test, rank_avg(gb0, nb), "Blend: boosting + NB (no Granite)"))
    rows.append(evaluate(test, rank_avg(gb, nb), "Blend: boosting(+Granite) + NB"))
    rows.append(evaluate(test, rank_avg(gb, nb, test["granite_prior"].to_numpy()), "Blend: boosting(+Granite) + NB + prior"))
    print("Honest 2025 backtest (fit on 2024):")
    print(pd.DataFrame(rows).to_string(index=False))

    print("\nAblation: drop one feature group at a time (gradient boosting)")
    abl = []
    for g in GROUPS:
        cols = [c for c in all_cols if c not in GROUPS[g]]
        s, _ = fit_score(train, test, cols)
        abl.append(evaluate(test, s, f"without {g}", n_boot=300))
    print(pd.DataFrame(abl).drop(columns=["per_month"]).to_string(index=False))

    print("\nLeakage audit: what a naive model would claim with post-attack columns")
    vul = pd.read_parquet(CACHE / "vulnerabilities.parquet", columns=["cve_id", *LEAKY])
    tr_l, te_l = train.merge(vul, on="cve_id", how="left"), test.merge(vul, on="cve_id", how="left")
    CATEGORICAL.add("nvd_status")
    leak_rows = []
    for extra in (["nvd_status"], ["n_references"], ["n_affected_cpes"], LEAKY):
        s, _ = fit_score(tr_l, te_l, all_cols + extra)
        leak_rows.append(evaluate(te_l, s, f"+ {', '.join(extra)}", n_boot=300))
    s, _ = fit_score(tr_l, te_l, GROUPS["signals"] + LEAKY)
    leak_rows.append(evaluate(te_l, s, "signals + leaky only", n_boot=300))
    print(pd.DataFrame(leak_rows).drop(columns=["per_month"]).to_string(index=False))
