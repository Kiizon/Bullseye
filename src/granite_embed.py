"""Phase 3a: embed cleaned CVE descriptions with IBM Granite.

Model: ibm-granite/granite-embedding-small-english-r2 (384-dim), run locally.
Corpus (about 200k CVEs):
  - every row scored or trained on: all 2024-2025 CVEs and the 2026 scoreboard
  - every KEV CVE (any year), for the exploitability prior
  - 40,000 random non-KEV CVEs published 2015-2023, as prior negatives
Descriptions are cleaned first: exploitation wording is stripped
(features.EXPLOIT_WORDING), so the prior can't learn from post-attack edits.

Writes data_cache/granite_emb.npy (float16) + granite_emb_ids.parquet.
Resumable: finished chunks are kept in data_cache/emb_chunks/.

Run: python src/granite_embed.py
"""
import sandbox_compat  # noqa: F401  (must come before transformers)

import time

import numpy as np
import pandas as pd
import torch
from sentence_transformers import SentenceTransformer

from config import CACHE
from features import EXPLOIT_WORDING

MODEL = "ibm-granite/granite-embedding-small-english-r2"
CHUNK = 10_000
NEG_SAMPLE = 40_000


def corpus():
    v = pd.read_parquet(CACHE / "vulnerabilities.parquet", columns=["cve_id", "published", "description"])
    v["published"] = pd.to_datetime(v["published"])
    kev = set(pd.read_parquet(CACHE / "known_exploited.parquet", columns=["cve_id"])["cve_id"])
    targets = set(pd.read_parquet(CACHE / "features_trainfinal.parquet", columns=["cve_id"])["cve_id"])
    targets |= set(pd.read_parquet(CACHE / "features_2026.parquet", columns=["cve_id"])["cve_id"])
    targets |= set(v.loc[v["published"].dt.year.isin([2024, 2025]), "cve_id"])
    pool = v[v["published"].dt.year.between(2015, 2023) & ~v["cve_id"].isin(kev)]
    negs = set(pool.sample(min(NEG_SAMPLE, len(pool)), random_state=0)["cve_id"])
    ids = targets | (kev & set(v["cve_id"])) | negs
    df = v[v["cve_id"].isin(ids)].copy()
    df["text"] = df["description"].fillna("").str.replace(EXPLOIT_WORDING, " ", regex=True).str.strip()
    # Length-sorted batches waste less padding.
    return df.assign(n=df["text"].str.len()).sort_values("n")[["cve_id", "text"]].reset_index(drop=True)


def main():
    torch.set_num_threads(max(1, torch.get_num_threads()))
    df = corpus()
    print(f"{len(df):,} descriptions to embed")
    model = SentenceTransformer(MODEL, device="cpu", model_kwargs={"dtype": torch.float32})
    model.max_seq_length = 256

    out_dir = CACHE / "emb_chunks"
    out_dir.mkdir(exist_ok=True)
    t0 = time.time()
    for i in range(0, len(df), CHUNK):
        path = out_dir / f"chunk_{i // CHUNK:03d}.npy"
        if path.exists():
            continue
        texts = df["text"].iloc[i:i + CHUNK].tolist()
        emb = model.encode(texts, batch_size=64, normalize_embeddings=True, show_progress_bar=False)
        np.save(path, emb.astype(np.float16))
        done = min(i + CHUNK, len(df))
        rate = done / (time.time() - t0)
        print(f"{done:>7,} / {len(df):,}  ({rate:,.0f}/s, ~{(len(df) - done) / rate / 60:.0f} min left)", flush=True)

    chunks = [np.load(out_dir / f"chunk_{j:03d}.npy") for j in range((len(df) + CHUNK - 1) // CHUNK)]
    np.save(CACHE / "granite_emb.npy", np.vstack(chunks))
    df[["cve_id"]].to_parquet(CACHE / "granite_emb_ids.parquet", index=False)
    print(f"done in {(time.time() - t0) / 60:.1f} min")


if __name__ == "__main__":
    main()
