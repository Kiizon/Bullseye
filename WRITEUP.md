# Bullseye: patch what attackers will hit

IBM track, "Before the Breach", Sheridan Datathon 2026. Solo entry.

Bullseye ranks the 72,670 vulnerabilities (CVEs) on the 2026 scoreboard by how likely attackers are to use them. A CVE counts as exploited when it appears on CISA's Known Exploited Vulnerabilities list (KEV). Bullseye uses only what was known at each CVE's snapshot date, and explains each pick in one plain sentence.

**Result:** in a test that ranks 2025 using only what was known in 2024, Bullseye's top 500 caught **20** CVEs that were later exploited. The best standard ranking caught 17.4, and sorting by severity score (CVSS) caught 5.7. In the top 50, Bullseye caught 10 and the best standard ranking caught 4.

## What was found

1. **Public exploit code is the strongest sign, but most exploited CVEs don't have it.** CVEs with exploit code online were 19 times as likely to be exploited. Yet 44 of the 75 CVEs exploited in 2024–25 had none, so a list built only on exploit code misses most of them.

2. **The type of bug matters more than its severity score.** How likely each kind of CVE was to be exploited, compared with an average CVE (2024–25):

   | Kind of CVE | Compared with average |
   | --- | --- |
   | Edge, VPN or IT-management product (Fortinet, Palo Alto, Ivanti...) | 6.3× |
   | Unsafe data loading (deserialization) | 6.0× |
   | "Unauthenticated" in the description | 4.6× |
   | Path traversal (reading files outside the allowed folder) | 3.9× |
   | Memory corruption | 0.6× |
   | Home routers | 0.3× |
   | Cross-site scripting | 0.1× |
   | WordPress plugins | 0 of 14,173 |

   Severity scores can't capture this, which is why 90% of Bullseye's top 500 fall outside the top 500 by CVSS.

3. **Some descriptions give the answer away.** Phrases like "is aware of a report that this may have been exploited" report an attack that has already happened. In 2025, 5 of the 29 descriptions with this kind of wording later reached KEV. These phrases are removed before any model reads the text. Otherwise the model would learn to look for the phrase, and it would fail on new CVEs, which don't have it yet.

4. **Some database fields also give the answer away.** NIST, which runs the US vulnerability database, reviews attacked CVEs first. So fields such as review status, number of references and number of affected products fill in *after* an attack. A model given only these fields plus exploit signals scores 21 hits, more than Bullseye, without knowing anything about the bug. All of these fields were left out.

5. **Early-year CVEs have more time to be caught.** A January CVE has 276 days before the Nov 4 judging date; a September CVE has 34. Of CVEs added to KEV after their first month, 90% were added within 276 days, but only 25% within 34. So the model is told how many days each CVE has left.

## How it works

1. **Collect the warning signs known at the snapshot** for each CVE:
   - exploit code online;
   - EPSS, a published estimate of the chance of exploitation, ranked within each month because EPSS changed its formula in 2025;
   - severity score, bug type and product type;
   - whether the vendor was on KEV in the past year;
   - days left before judging.
2. **Read each description with IBM Granite** to get a "sounds exploitable" score (see below).
3. **Score each CVE with two models and average their rankings:**
   - a decision-tree model (gradient boosting), kept small because there are only about 120 exploited examples to learn from;
   - a simple model that adds up how much each warning sign raises the odds. Its biggest contributions become the reasons shown for each pick.
4. **Train on 2024–2025 and rank 2026,** with KEV known only up to Dec 31, 2025, as in the data provided.

## Data used

- `scoreboard_2026`: the CVEs to rank, with EPSS and exploit-code flags at the snapshot.
- `exploit_signals_2024`, `exploit_signals_2025`: the same signals for past years, used to build training data shaped like the scoreboard.
- `vulnerabilities`: description, publish date, assigner, bug type (CWE), CVSS score and its parts.
- `known_exploited`: the answers for training, plus vendor history counted only up to each snapshot.

**Left out on purpose,** because they fill in after an attack: `nvd_status`, `n_references`, `n_affected_cpes`, `last_modified`, `cvss3_source`, whether CVSS is blank, and all `references` links. Product names from `affected_products` appear in the demo app to make it readable, but are never used by the model.

**Known gap:** the CVSS score in the data is today's value, which may have changed since the snapshot. CVSS turned out to matter little (removing it didn't hurt the test), so the effect should be small.

No outside data was used.

## Results

The test mirrors the scoreboard: train on 2024 (KEV known to Dec 31, 2024), rank the January–September 2025 CVEs not yet on KEV, then count how many were added by Nov 4, 2025.

| Ranking | Hits in top 500 | Likely range* | Hits in top 50 |
| --- | --- | --- | --- |
| CVSS first | 5.7 | 2–10 | 3 |
| EPSS first | 8 | 4–13 | 3 |
| Exploit code, then EPSS | 17.4 | 11–24 | 4 |
| **Bullseye** | **20** | **13–27** | **10** |

\*90% range from resampling the test set.

- **The numbers are noisy:** only 48 CVEs in the 2025 test were later exploited. Across nine model settings, Bullseye beat the best standard ranking by 2.1 hits on average. The gain is small and could partly be luck. The clearest gain is in the top 50.
- **No tuning on the test year:** model settings were left at their defaults.
- **Which signals matter:** each group of signals was removed in turn. Exploit signals, description flags and days left mattered most. Removing CVSS *raised* the score (15 → 18), more evidence that severity says little about what gets attacked. Nothing was removed from the final model on this basis, since that would be tuning on the test year.
- **Two ideas tested and dropped,** because each added well under 1 hit:
  - weighting the Granite score toward bugs that took longer to be exploited (+0.2);
  - fresher vendor history from a live KEV download (+0.0).

**The 2026 top 500:**
- 72% have public exploit code.
- The most common bug types are login bypass, command injection and unsafe data loading.
- Only 14 of the top 50 also appear in the top 50 of "exploit code, then EPSS".
- Rank 1 is CVE-2026-1603, a login bypass in Ivanti Endpoint Manager that leaks stored credentials. Its CVSS of 7.5 puts it 25,217th by severity.

## How IBM Granite is used

1. **Granite embeddings** (`granite-embedding-small-english-r2`, run locally):
   - The model turns each of 201,940 descriptions into numbers that capture its meaning. The give-away phrases are removed first.
   - A simple model trained on every KEV entry since 2015 then learns what exploited bugs tend to sound like. No CVE is scored by a model that saw its own answer.
   - Alone this score is weak (5 hits), and it didn't help the decision-tree model by itself. Added to the blend, it raised hits by 2.0 on average across nine settings.
2. **Granite chat on watsonx.ai** (`granite-4-h-small`):
   - It writes the one-line "why fix this first" for each pick: the product, what an attacker can do, and the reason to act now. For example: *"Qwik framework allows unauthenticated remote code execution via unsafe deserialization; public exploit code exists and EPSS ranks it in the top 1% this month."*
   - It only sees facts already in the data and doesn't change the ranking.
   - Lines exist for the top 402 picks; the free-tier token quota ran out after that, and the remaining 98 show the model's reasons instead.
   - It is told not to claim attacks or mention versions. Versions were banned after an early test where it named the fixed version as the vulnerable one.

## Impact

A security team can patch maybe 50 things a week, while about 8,000 CVEs come out each month. In the test, sorting by severity found under a third as many exploited CVEs as Bullseye.

The demo app (`streamlit run app/app.py`):
- shows a weekly list sized to the team's patch budget;
- filters by vendor;
- gives a one-line reason for each pick;
- compares the list with a severity-sorted one.

## Limitations

- About 120 exploited examples is very few. New kinds of attack may be missed.
- KEV only lists attacks CISA has confirmed, which leans toward US enterprise products.
- Long descriptions were cut to about 200 words to speed up Granite.
- Next steps: update the list weekly as signals change, and let teams upload what they run so the list covers only their systems.

## Reproduce

See `README.md`. The full pipeline runs on a laptop in under half an hour.
