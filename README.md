# Bullseye

IBM track, Sheridan Datathon 2026 ("Before the Breach"). Bullseye ranks newly published vulnerabilities by how likely attackers are to exploit them, using only what was known at the time, and explains each pick for the engineers who have to fix it.

Status: work in progress.

## Setup

1. Unzip the IBM track's `data.zip` so the CSVs sit in `../IBM/data/` (next to this repo).
2. Install dependencies into a virtual environment:

   ```sh
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Convert the CSVs to Parquet once (about 5 seconds; 809 MB of CSV becomes 100 MB):

   ```sh
   python src/convert_parquet.py
   ```

4. Rebuild everything, in order:

   ```sh
   python src/explore.py          # KEV exploration
   python src/features.py         # feature tables for 2024, 2025, 2026 and the training folds
   python src/granite_embed.py    # Granite embeddings of every description (~15 min on a laptop)
   python src/granite_prior.py    # exploitability prior learned from the embeddings
   python src/train_model.py      # honest 2025 backtest, ablation, leakage audit
   python src/make_top500.py      # outputs/top500.csv
   python src/watsonx_explain.py  # optional: Granite on watsonx.ai writes "why fix this first"
   ```

   `watsonx_explain.py` reads `WATSONX_APIKEY`, `WATSONX_PROJECT_ID` and `WATSONX_URL` from `.env`.

5. Open the demo app:

   ```sh
   streamlit run app/app.py
   ```

## Layout

| Path | What it holds |
| --- | --- |
| `src/config.py` | Paths and cutoff dates |
| `src/convert_parquet.py` | CSV to Parquet conversion |
| `src/explore.py` | KEV exploration: repeat offenders, slow subset, time-window curve |
| `src/backtest.py` | Scoreboard-shaped backtest frames, baselines, hits@500 with bootstrap ranges |
| `src/features.py` | Features known at snapshot time (signals, CVSS, description flags, bug types, vendor KEV history) |
| `src/nb_score.py` | Naive Bayes over binary features; its weights become the plain-word reasons |
| `src/granite_embed.py`, `src/granite_prior.py` | Granite embeddings and the exploitability prior built on them |
| `src/train_model.py` | Gradient boosting, blends, ablation, leakage audit |
| `src/make_top500.py` | Final model and the submission file |
| `src/watsonx_explain.py` | Granite on watsonx.ai: one-line explanation per pick |
| `app/app.py` | Streamlit demo: this week's list, ours vs CVSS, findings |
| `outputs/` | `top500.csv` (submission), `top500_detail.csv`, backtest and leakage results |

## Leakage policy

Features use only what was known at the end of each vulnerability's snapshot month. Never used as model features: `nvd_status`, `n_references`, `n_affected_cpes`, `last_modified`, and news or threat-report links in `references.csv`. The full column list will go in the write-up.
