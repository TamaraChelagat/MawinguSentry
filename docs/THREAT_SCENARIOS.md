# Threat scenarios

CloudSentry's synthetic data generator injects five labeled attack scenarios
into an otherwise benign stream of CloudTrail-style events. Each maps to a
MITRE ATT&CK for Cloud technique so that model alerts can be tagged with a
real, recognized framework rather than an arbitrary internal label.

| Scenario ID | Name | MITRE technique | What it simulates |
|---|---|---|---|
| `unusual_geo_login` | Impossible travel console login | [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/) | A console login from the user's home region followed minutes later by a login from a foreign IP range — physically impossible travel time. |
| `privilege_escalation` | IAM privilege escalation | [T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/) | A principal attaches `AdministratorAccess` to itself. |
| `public_bucket_exposure` | Storage bucket made public | [T1530 – Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) | `PutBucketAcl` grants `public-read-write` on a bucket. |
| `recon_burst` | Reconnaissance API burst | [T1580 – Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/) | A burst of `List*`/`Describe*` calls fired seconds apart — faster than a human clicking through the console. |
| `cred_exfil_key_creation` | Long-lived credential creation | [T1552 – Unsecured Credentials](https://attack.mitre.org/techniques/T1552/) | `CreateAccessKey` called for a principal that has never needed programmatic keys before. |

## Why synthetic data, and why this is a defensible methodology

Real attack data from a personal AWS sandbox is both rare (you'd have to
actually get attacked) and risky (deliberately misconfiguring a real account
to invite attacks is a bad idea). The standard approach in security ML —
including at teams building products like GuardDuty — is to generate
realistic benign baseline traffic and layer labeled synthetic attack
patterns on top, validated against known attacker behavior frameworks like
MITRE ATT&CK. That is exactly what `app/data_generator.py` does.

## Extending this

Each scenario lives in its own `_scenario_<id>` method on
`CloudTrailEventGenerator`. To add a new one:

1. Add an `AttackScenario` entry to `SCENARIOS` in `data_generator.py`.
2. Implement `_scenario_<scenario_id>(self, user, scenario)` returning a
   list of one or more tagged events.
3. Add a row to the table above.
