"""Phase 5: Granite on watsonx.ai writes a one-line "why fix this first" for
each of the top 500, for the engineer who has to patch it.

Reads credentials from .env (never printed):
  WATSONX_APIKEY, WATSONX_PROJECT_ID, WATSONX_URL (e.g. https://us-south.ml.cloud.ibm.com)
  WATSONX_MODEL_ID (optional; default = newest Granite instruct chat model available)

The model only sees facts we already have (cleaned description, signals,
reasons). It writes explanations; it does not change the ranking.

Run:
  python src/watsonx_explain.py --list-models   # show Granite chat models on your account
  python src/watsonx_explain.py --limit 5       # test on 5 CVEs
  python src/watsonx_explain.py                 # all 500 (resumes where it stopped)
Writes outputs/why_fix.csv (cve_id, why_fix).
"""
import argparse
import csv
import os
import re
import sys
import time

import pandas as pd
from dotenv import load_dotenv
from ibm_watsonx_ai import APIClient, Credentials
from ibm_watsonx_ai.foundation_models import ModelInference

from config import OUTPUTS, REPO

SYSTEM = (
    "You write one-line patch notes for a security team deciding what to fix first.\n"
    "Write exactly one sentence of 15 to 30 words, in this order:\n"
    "1. the affected product name;\n"
    "2. what an attacker can do, taken ONLY from the description (keep words like 'may' or 'potential'; "
    "if the description says something is not possible, do not claim it);\n"
    "3. the strongest reason to act now: public exploit code, the EPSS line exactly as given, or no login needed.\n"
    "Rules: no version numbers at all. Do not say it is exploited in the wild. Do not invent anything. "
    "'Other signals' are hints from a model, not facts about the bug; never use them to describe the attack. "
    "No filler such as 'poses a significant risk', 'should be fixed soon' or 'critical vulnerability'. "
    "Never start with 'This'.\n"
    "Example of the style (fictional product): Acme EdgeGate lets an attacker with no login run "
    "commands as root over the network; public exploit code exists and EPSS puts it in the top 1% this month."
)
REWRITE = ("Too long or wrong opening. Rewrite it as one sentence of at most 30 words that starts with "
           "the product name, with no version numbers.")


def epss_phrase(pct):
    """Precomputed so the model never does percentile arithmetic."""
    for cut, words in ((0.99, "top 1%"), (0.95, "top 5%"), (0.90, "top 10%")):
        if pct >= cut:
            return f"EPSS puts it in the {words} of CVEs this month"
    return "EPSS is not a reason here; do not mention it"


def needs_rewrite(text):
    has_version = re.search(r"\b\d+\.\d+", text.replace("0.1%", "").replace("1%", ""))
    return len(text.split()) > 32 or text.lower().startswith("this") or bool(has_version)


NO_GRANITE = (
    "No Granite chat model in this region. As of Nov 2026 ibm/granite-4-h-small is offered in us-south "
    "and eu-de only (not ca-tor, eu-gb, jp-tok or au-syd). Create a project in Dallas and set "
    "WATSONX_URL=https://us-south.ml.cloud.ibm.com and its WATSONX_PROJECT_ID in .env."
)


def prompt_for(r):
    flags = [n for n, c in (("Exploit-DB", "exploitdb"), ("Metasploit", "metasploit"),
                            ("Nuclei template", "nuclei"), ("GitHub proof of concept", "poc_github")) if r[c] == 1]
    return (
        f"CVE: {r['cve_id']}\n"
        f"Description: {str(r['description'])[:1200]}\n"
        f"Public exploit code: {', '.join(flags) if flags else 'none known'}\n"
        f"EPSS line: {epss_phrase(r['epss_pct_month'])}\n"
        f"CVSS 3 score: {r['cvss3_raw'] if pd.notna(r['cvss3_raw']) else 'not scored yet'}\n"
        f"Other signals: {r['reasons'] if isinstance(r['reasons'], str) and r['reasons'] else 'none'}\n"
        "Write the patch note."
    )


def clean(resp):
    text = resp["choices"][0]["message"]["content"].strip().replace("\n", " ")
    return text.strip('"').strip()


def connect():
    load_dotenv(REPO / ".env")
    missing = [k for k in ("WATSONX_APIKEY", "WATSONX_PROJECT_ID", "WATSONX_URL") if not os.getenv(k)]
    if missing:
        sys.exit(f"Missing in .env: {', '.join(missing)}")
    creds = Credentials(url=os.environ["WATSONX_URL"], api_key=os.environ["WATSONX_APIKEY"])
    return creds, os.environ["WATSONX_PROJECT_ID"]


def granite_chat_models(creds, project_id):
    client = APIClient(creds, project_id=project_id)
    specs = client.foundation_models.get_chat_model_specs() or {}
    ids = [m["model_id"] for m in specs.get("resources", []) if "granite" in m["model_id"].lower()]
    return sorted(ids, reverse=True)


def pick_model(creds, project_id):
    if os.getenv("WATSONX_MODEL_ID"):
        return os.environ["WATSONX_MODEL_ID"]
    ids = granite_chat_models(creds, project_id)
    instruct = [i for i in ids if "instruct" in i or "granite-4" in i] or ids
    if not instruct:
        sys.exit(NO_GRANITE)
    return instruct[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list-models", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    creds, project_id = connect()
    if args.list_models:
        ids = granite_chat_models(creds, project_id)
        print(f"Region: {os.environ['WATSONX_URL']}")
        print("\n".join(ids) if ids else NO_GRANITE)
        return

    model_id = pick_model(creds, project_id)
    print(f"Using {model_id}")
    model = ModelInference(model_id=model_id, credentials=creds, project_id=project_id,
                           params={"max_tokens": 80, "temperature": 0})

    top = pd.read_csv(OUTPUTS / "top500_detail.csv")
    out_path = OUTPUTS / "why_fix.csv"
    new_file = not out_path.exists() or out_path.stat().st_size == 0
    done = set() if new_file else set(pd.read_csv(out_path)["cve_id"])
    todo = top[~top["cve_id"].isin(done)]
    if args.limit:
        todo = todo.head(args.limit)
    print(f"{len(done)} already done, writing {len(todo)}")

    # An editor may save the file without a final newline; don't glue rows together.
    if not new_file and not out_path.read_bytes().endswith(b"\n"):
        with open(out_path, "a") as f:
            f.write("\n")
    with open(out_path, "w" if new_file else "a", newline="") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["cve_id", "why_fix", "model_id"])
        for i, (_, r) in enumerate(todo.iterrows(), 1):
            for attempt in range(3):
                try:
                    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt_for(r)}]
                    text = clean(model.chat(messages=msgs))
                    if needs_rewrite(text):
                        msgs += [{"role": "assistant", "content": text}, {"role": "user", "content": REWRITE}]
                        text = clean(model.chat(messages=msgs))
                    break
                except Exception as e:  # rate limits, timeouts
                    if "token_quota_reached" in str(e):
                        sys.exit(f"watsonx token quota reached after {i - 1} new lines; "
                                 "rerun after the quota resets or the plan is upgraded (it resumes).")
                    if attempt == 2:
                        print(f"  {r['cve_id']}: failed ({type(e).__name__}: {str(e)[:200]}); will retry on next run")
                        text = None
                    time.sleep(2 * (attempt + 1))
            if text:
                w.writerow([r["cve_id"], text, model_id])
                f.flush()
            if i <= 3 or i % 50 == 0:
                print(f"  [{i}/{len(todo)}] {r['cve_id']}: {text}")


if __name__ == "__main__":
    main()
