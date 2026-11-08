"""Convert the raw CSVs to Parquet once, so later loads take seconds.

Run: python src/convert_parquet.py
"""
import time

import pyarrow as pa
import pyarrow.csv as pacsv
import pyarrow.parquet as pq

from config import CACHE, RAW

# Version strings must stay text ("1.10" is not 1.1).
STRING_COLS = {
    "affected_products": [
        "version", "update",
        "version_start_including", "version_start_excluding",
        "version_end_including", "version_end_excluding",
    ],
    "vulnerabilities": ["cwe_ids", "cvss3_version"],
    "known_exploited": ["cwe_ids"],
    "exploit_signals_2024": ["month"],
    "exploit_signals_2025": ["month"],
    "scoreboard_2026": ["snapshot_month"],
}


def convert(csv_path):
    name = csv_path.stem
    out = CACHE / f"{name}.parquet"
    t = time.time()
    types = {c: pa.string() for c in STRING_COLS.get(name, [])}
    table = pacsv.read_csv(
        csv_path,
        parse_options=pacsv.ParseOptions(newlines_in_values=True),
        convert_options=pacsv.ConvertOptions(column_types=types),
    )
    pq.write_table(table, out, compression="zstd")
    print(f"{name:24s} {table.num_rows:>10,} rows  {time.time() - t:5.1f}s")


if __name__ == "__main__":
    CACHE.mkdir(exist_ok=True)
    for path in sorted(RAW.glob("*.csv")):
        convert(path)
