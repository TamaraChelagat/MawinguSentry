# Data methodology

## Why synthetic data

Two constraints rule out training on live attack data for this project:

1. **Scarcity.** A personal AWS sandbox generates almost entirely benign
   traffic. Real attacks are, by definition, rare — that's what makes them
   attacks. Waiting to be actually breached in order to collect labeled
   positive examples isn't a viable data strategy.
2. **Risk.** Deliberately misconfiguring a real AWS account to invite
   attacks (to generate positive examples) risks actual compromise, cost
   overruns, and violates AWS acceptable use terms in some cases.

The approach used here — generate realistic benign baseline traffic, then
inject labeled synthetic attack sequences on top, validated against a
recognized adversary behavior framework (MITRE ATT&CK for Cloud) — mirrors
how security ML teams commonly bootstrap detection models before enough
real incident data exists. It's the same reasoning applied in
[FraudDetectPro](https://github.com/TamaraChelagat/FraudDetectPro), where
class imbalance and the difficulty of sourcing labeled fraud data motivated
a similar synthetic-augmentation approach.

## How `sample_1k.jsonl` was generated

```bash
python app/data_generator.py --batch-size 1000 --attack-ratio 0.06 --seed 2026 --out data/sample_1k.jsonl
```

- **1,000 events**, generated with a fixed seed (`2026`) for reproducibility
  — anyone can regenerate an identical dataset from this repo.
- **~6% attack ratio** (143 of 1,000 events labeled `malicious` in this
  run). This is deliberately higher than any real-world base rate would be.
  A production system would see attacks at a rate closer to 1 in tens of
  thousands or fewer; this ratio is chosen so the model has enough positive
  examples to learn from during early development, not as a claim about
  real-world prevalence.
- **Five attack scenarios**, each mapped to a MITRE ATT&CK for Cloud
  technique — see [THREAT_SCENARIOS.md](THREAT_SCENARIOS.md) for the full
  table and technique IDs.
- **Benign traffic** is drawn from four synthetic principals (a human user,
  a CI bot, a data pipeline service account, a read-only analyst role) each
  with a consistent home region and IP range, so the "normal" baseline has
  realistic structure rather than being pure noise.

## Known limitations

- Synthetic data cannot capture the full diversity of real attacker
  behavior or benign edge cases (e.g., legitimate travel, unusual but
  authorized admin actions). A model trained only on this data will need
  validation against real-world traffic before any production claim.
- The five scenarios are a starting set, not exhaustive. MITRE ATT&CK for
  Cloud covers many more techniques; scenarios were chosen to be
  detectable from CloudTrail-style event fields alone, without needing
  additional telemetry (e.g., network flow data, host-level logs).
- Label noise is zero by construction (every malicious event is tagged at
  generation time), which is optimistic compared to real labeled data,
  where analyst-assigned labels carry some error rate.

## Regenerating or extending the dataset

See the "Extending this" section of
[THREAT_SCENARIOS.md](THREAT_SCENARIOS.md) for how to add a new attack
scenario to the generator.
