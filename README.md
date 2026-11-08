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

4. Reproduce the exploration:

   ```sh
   python src/explore.py
   ```

## Layout

| Path | What it holds |
| --- | --- |
| `src/config.py` | Paths and cutoff dates |
| `src/convert_parquet.py` | CSV to Parquet conversion |
| `src/explore.py` | KEV exploration: repeat offenders, slow subset, time-window curve |
| `notebooks/` | Scratch analysis |
| `outputs/` | `top500.csv` and figures |

## Leakage policy

Features use only what was known at the end of each vulnerability's snapshot month. Never used as model features: `nvd_status`, `n_references`, `n_affected_cpes`, `last_modified`, and news or threat-report links in `references.csv`. The full column list will go in the write-up.
