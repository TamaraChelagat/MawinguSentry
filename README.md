# MawinguSentry

AI-driven cloud security threat detection — retargeting the hybrid ML
architecture from [FraudDetectPro](https://github.com/TamaraChelagat/FraudDetectPro)
(a final-year fraud detection system) at a different problem: flagging
malicious activity in AWS CloudTrail-style event logs.

**Status:** In progress — Week 1 of 4. See [ROADMAP.md](ROADMAP.md) for the
build plan.

## Why this project

Fraud detection and cloud threat detection are the same underlying problem:
extremely rare positive events buried in a high volume of normal activity,
where both false positives (analyst fatigue) and false negatives (missed
attacks) are costly, and where a black-box "it's fraud" or "it's an attack"
verdict isn't good enough — an analyst needs to know *why*. CloudSentry
reuses FraudDetectPro's two-stage hybrid model (neural network feature
extraction feeding a soft-voting ensemble of Random Forest, XGBoost,
LightGBM, and Logistic Regression) and its SHAP explainability layer,
retrained on a new domain: AWS CloudTrail events instead of credit card
transactions.

## Architecture

```
Log ingestion (CloudTrail + synthetic generator)
        |
Feature engineering (parse events, extract signals)
        |
Hybrid detection model (NN extractor + ensemble vote)
        |
FastAPI + SHAP service (score, explain, tag MITRE ATT&CK)
        |
Alert dashboard (React UI + Postgres storage)
```

## What's built so far

- [x] `app/data_generator.py` — synthetic CloudTrail-style event generator
      producing benign baseline traffic plus five labeled attack scenarios
      mapped to MITRE ATT&CK for Cloud. See
      [docs/THREAT_SCENARIOS.md](docs/THREAT_SCENARIOS.md).
- [x] Test suite + CI (GitHub Actions runs lint + tests on every push)
- [x] Feature engineering pipeline
- [x] Hybrid detection model (retrained on security event features)
- [ ] FastAPI service with `/predict`, `/alerts`, `/stats`, `/explain`
- [ ] Postgres-backed alert storage
- [ ] React alert dashboard
- [ ] Deployment (Fargate/Lambda + Vercel)

## API service docs 

![alt text](image-1.png)

## Model training 
Model results 
![alt text](image.png)

## Quickstart

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Generate a batch of synthetic events
python app/data_generator.py --batch-size 200 --attack-ratio 0.08 --seed 42

# Run tests
pytest tests/ -v
```

## Related projects

- [FraudDetectPro](https://github.com/TamaraChelagat/FraudDetectPro) — the
  fraud detection system this project's model architecture is adapted from.

## Tech stack

FastAPI · scikit-learn · XGBoost · LightGBM · TensorFlow · SHAP · Postgres ·
React · MITRE ATT&CK
