"""Paths shared by every script. Raw data stays outside the repo."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RAW = REPO.parent / "IBM" / "data"          # unzipped data.zip (not committed)
CACHE = REPO / "data_cache"                  # Parquet copies (not committed)
OUTPUTS = REPO / "outputs"

# Judges count KEV additions through this date.
SCOREBOARD_CUTOFF = "2026-11-04"
# The same shape, one year earlier, for the honest 2025 backtest.
BACKTEST_CUTOFF = "2025-11-04"
