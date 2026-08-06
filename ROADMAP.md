# Roadmap

Four weeks, broken into small enough pieces that most of them are a single,
real commit. Each checkbox below is a reasonable GitHub Issue and a
reasonable commit — that's deliberate (see "Staying consistent" at the
bottom).

## Week 1 — Data & threat model ✅ mostly done
- [x] Define five attack scenarios mapped to MITRE ATT&CK
- [x] Build `CloudTrailEventGenerator` with benign + attack event generation
- [x] Write smoke tests for the generator
- [x] Set up CI (lint + test on every push)
- [ ] Generate and commit a reference dataset (`data/sample_1k.jsonl`, gitignored
      pattern excluded so this one is deliberate) for reproducibility
- [ ] Write a short `docs/DATA_METHODOLOGY.md` explaining the synthetic-data
      approach in interview-ready language

## Week 2 — Feature engineering & model
- [ ] `app/features.py`: parse raw events into structured features
      (event frequency per principal, source-IP entropy, time-since-last-
      similar-action, geo-velocity, permission deltas)
- [ ] Notebook: exploratory analysis of feature distributions, benign vs
      malicious (mirrors `notebooks/02_eda.ipynb` from FraudDetectPro)
- [ ] `app/model.py`: adapt the NN feature extractor + ensemble architecture
- [ ] Train on the synthetic dataset, log metrics (precision/recall/F1/ROC-AUC)
- [ ] Wire up SHAP explainability with MITRE technique tagging

## Week 3 — Service layer
- [ ] `app/main.py`: FastAPI app skeleton, `/health` endpoint
- [ ] `/predict` endpoint
- [ ] `/alerts` endpoint with Postgres persistence
- [ ] `/stats` endpoint
- [ ] `/explain` endpoint (SHAP output + MITRE tag)
- [ ] (stretch) S3-triggered Lambda or EventBridge rule for real-time ingestion

## Week 4 — Dashboard, deploy, write-up
- [ ] React dashboard skeleton (adapt from FraudDetectPro's `Frontend/`)
- [ ] Alert feed view
- [ ] Risk distribution + explainability panel
- [ ] Deploy backend (Fargate or Lambda) and frontend (Vercel/Netlify)
- [ ] Record a short demo GIF for the README
- [ ] Write the "fraud detection → cloud security" narrative paragraph

---

## Staying consistent on GitHub

A few working principles, since the goal is a genuinely active-looking
profile, not a gamed one:

- **Commit at issue granularity, not day granularity.** Each checkbox above
  is sized to be one commit. Finishing 2-3 checkboxes in a sitting still
  means 2-3 honest, meaningful commits, not one giant one.
- **Use Conventional Commits** (`feat:`, `fix:`, `test:`, `docs:`, `chore:`)
  — it's a real convention used at most companies, and it makes your commit
  log itself read like a demonstration of engineering discipline.
- **Open a GitHub Issue for each unchecked box**, then reference it in the
  commit that closes it (`git commit -m "feat: add feature engineering
  pipeline (closes #4)"`). This gives you a visible Issues tab and a project
  board you can screenshot or link in applications.
- **Don't commit just to fill the graph.** An empty commit or a whitespace
  change is easy to spot on a green square with no substance behind it if
  anyone actually opens the repo — and recruiters at the companies you're
  targeting do open repos. Real, small, frequent commits beat fake ones.
- **CI staying green matters more than commit count.** A red X on your
  latest commit is worse for credibility than a quiet day. Run `pytest` and
  `flake8` locally before pushing (or let CI catch it and fix promptly).
