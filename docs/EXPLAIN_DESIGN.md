# Explainability design

## Why `/explain` requires context events, not just one event

While building this endpoint, scoring a single event in isolation produced
wildly wrong results -- a textbook `AttachUserPolicy` privilege escalation,
caught with 97%+ confidence by the full pipeline during evaluation, scored
as **essentially 0% malicious (2.3e-08)** when explained alone.

**Root cause:** several of the engineered features in `app/features.py`
are contextual by design -- they describe a principal's behavior relative
to their *other* recent events:

- `seconds_since_last_event` -- meaningless without a previous event to
  compare against
- `events_in_last_5min` -- a burst-detection feature; needs the actual
  burst present to count
- `is_new_ip_for_principal` / `is_new_event_type_for_principal` -- compare
  against a learned baseline, but still describe *this event relative to
  others*, not this event alone

When `CloudEventFeatureEngineer.transform()` is called with a list
containing only one event, every one of these silently falls back to a
"first event ever seen" default -- **no error, no warning, just a
completely different (and wrong) feature representation** than the model
was ever trained on. This is the same class of bug documented in
`tests/test_features.py`'s regression test: something that produces a
confident, wrong answer with no indication anything went wrong.

## The fix: context, not a patch

The correct fix isn't to special-case single-event scoring -- it's to be
honest that this feature set fundamentally requires history. `/explain`
(and any future real-time single-event scoring path) needs the target
event's principal's recent prior events as context, computed together in
one `transform()` call, with the target event's row picked out afterward.

This mirrors how a real deployment would actually work: a Lambda scoring
a live CloudTrail event wouldn't score it in a vacuum either -- it would
pull that principal's recent event history from a database or cache first.
Requiring context here is the API design being honest about that
requirement rather than hiding it.

## What this means for `/predict`

`/predict` was never affected by this bug -- it already takes a batch of
events and transforms them together, so contextual features are computed
correctly as long as the caller sends related events together (e.g., a
batch of a principal's recent CloudTrail records, not one isolated event
per call). `/explain` is the one endpoint that needs an explicit
`context_events` field to make this requirement visible in the API
contract itself, rather than relying on callers to already know to batch
their requests.
