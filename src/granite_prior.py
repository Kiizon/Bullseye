"""Phase 3b: Granite "exploitability prior".

A logistic regression on Granite description embeddings learns what exploited
vulnerabilities read like, from every KEV entry known at the cutoff (about
1,000+ positives instead of the 40 the main model sees).

Honesty rules:
- Only KEV entries added on or before `kev_cutoff`, and only CVEs published
  on or before it, are used to fit.
- Positives and negatives both come from CVEs published 2015 or later, so the
  prior can't just learn "old writing style".
- CVEs inside the fitting set get out-of-fold scores (5-fold), so a training
  row's prior never comes from a model that saw its label.

Run: python src/granite_prior.py   (writes data_cache/prior_{fold,final}.parquet)
"""
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold

from config import CACHE


def load_embeddings():
    emb = np.load(CACHE / "granite_emb.npy").astype(np.float32)
    ids = pd.read_parquet(CACHE / "granite_emb_ids.parquet")["cve_id"]
    return emb, ids


def build_prior(kev_cutoff, emb, ids, C=0.5, folds=5):
    kev_cutoff = pd.Timestamp(kev_cutoff)
    v = pd.read_parquet(CACHE / "vulnerabilities.parquet", columns=["cve_id", "published"])
    v["published"] = pd.to_datetime(v["published"])
    kev = pd.read_parquet(CACHE / "known_exploited.parquet", columns=["cve_id", "date_added"])
    kev["date_added"] = pd.to_datetime(kev["date_added"])
    known = set(kev.loc[kev["date_added"].le(kev_cutoff), "cve_id"])

    meta = pd.DataFrame({"cve_id": ids}).merge(v, on="cve_id", how="left")
    fit_mask = meta["published"].between("2015-01-01", kev_cutoff).to_numpy()
    y = meta["cve_id"].isin(known).to_numpy().astype(int)

    Xf, yf = emb[fit_mask], y[fit_mask]
    print(f"prior @ {kev_cutoff.date()}: fitting on {fit_mask.sum():,} CVEs, {yf.sum()} KEV positives")

    def model():
        return LogisticRegression(C=C, class_weight="balanced", max_iter=3000)

    score = np.full(len(ids), np.nan)
    oof = np.zeros(len(yf))
    for tr, te in StratifiedKFold(folds, shuffle=True, random_state=0).split(Xf, yf):
        oof[te] = model().fit(Xf[tr], yf[tr]).decision_function(Xf[te])
    score[np.flatnonzero(fit_mask)] = oof
    full = model().fit(Xf, yf)
    score[~fit_mask] = full.decision_function(emb[~fit_mask])

    # Out-of-fold ranking quality inside the fitting set (sanity check).
    order = np.argsort(-oof)
    top = yf[order[:1000]].sum()
    print(f"  out-of-fold: {top} KEV CVEs in the top 1,000 of {len(yf):,} (base rate {yf.mean():.2%})")
    return pd.DataFrame({"cve_id": ids, "granite_prior": score})


if __name__ == "__main__":
    emb, ids = load_embeddings()
    build_prior("2024-12-31", emb, ids).to_parquet(CACHE / "prior_fold.parquet", index=False)
    build_prior("2025-12-31", emb, ids).to_parquet(CACHE / "prior_final.parquet", index=False)
