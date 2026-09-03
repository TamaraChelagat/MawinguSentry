# Model results

Trained `CloudThreatPipeline` on 5,000 synthetic events (seed `2026`, 8%
attack ratio at generation time). Numbers below are from a held-out 30%
test split (1,500 events), not training data.

| Metric | Value |
|---|---|
| ROC-AUC | 0.948 |
| Average precision | 0.865 |
| Precision | 0.983 |
| Recall | 0.694 |
| F1 | 0.813 |
| False positive rate | 0.24% |
| Optimal threshold | 0.67 |

At the optimal threshold: **170 threats caught, 75 missed, 3 false alarms**
out of 245 actual attack events in the test set.

## Recall by attack scenario

| Scenario | Caught |
|---|---|
| `privilege_escalation` | 18/18 (100%) |
| `public_bucket_exposure` | 25/25 (100%) |
| `cred_exfil_key_creation` | 14/14 (100%) |
| `unusual_geo_login` | 19/19 (100%) |
| `recon_burst` | 94/169 (56%) |

## Why recon_burst is the exception, and what that means

The other four scenarios are each detectable from a **single event** --
one `AttachUserPolicy` call with an admin policy attached, one
`PutBucketAcl` call making a bucket public, and so on. The model only
needs to recognize one row's features to catch these, and it does, every
time in this test set.

`recon_burst` is different by design: no single event in the sequence is
inherently suspicious on its own (`ListBuckets`, `DescribeInstances` are
completely normal API calls). What makes it an attack is the **rate** --
six of these calls in twelve seconds. The `events_in_last_5min` feature
captures this, but only for events later in the burst; the first one or
two calls in a sequence don't yet have enough history behind them to look
different from an isolated benign call. Since the model classifies each
event independently, those early-burst events are structurally hard to
catch -- and 56% recall reflects that, not a bug or a poorly tuned model.

**This is an honest architectural limitation of per-event classification,
not a training problem.** Fixing it would mean changing what gets
classified, not tuning the model further:

- **Sequence-level aggregation**: instead of scoring each event, aggregate
  a sliding window of events per principal into one feature vector
  (e.g. "how many of the last 10 events were List/Describe calls") and
  classify the window, not the row.
- **Alert-on-pattern instead of alert-on-event**: a rules layer that
  fires when `events_in_last_5min` crosses a threshold for a principal,
  independent of the ML model's per-row verdict, effectively catching the
  cases the classifier structurally can't.

Either is a reasonable Week 3+ extension. Framed for an interview: *"the
model is excellent at catching single-action attacks and structurally
limited on multi-event patterns by design -- which is itself a correct,
useful thing for a security engineer to be able to diagnose and explain,
not a flaw to hide."*

## Reproducing these numbers

```bash
PYTHONPATH=. python app/model.py --generate 5000 --attack-ratio 0.08 --seed 2026
```

## Architecture note

This adapts the ensemble + meta-learner pattern that's actually shipped in
[FraudDetectPro's `pipeline.py`](https://github.com/TamaraChelagat/FraudDetectPro/blob/main/app/pipeline.py)
-- five base models (XGBoost, LightGBM, Random Forest, Logistic Regression,
Isolation Forest) feeding a logistic regression meta-learner that stacks
their outputs with the raw features. Earlier planning documents described
a neural-network feature extractor ahead of the ensemble; that component
was tried and removed in FraudDetectPro itself (see
`notebooks/04_hybrid_model.ipynb`: "Removed Neural Network - using raw
features only"), so this project builds on the architecture that's
actually proven to work, not the one that was tried and dropped.
