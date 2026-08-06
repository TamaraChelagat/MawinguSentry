"""
Synthetic CloudTrail Event Generator
Generates realistic AWS CloudTrail-style events: benign baseline traffic
plus five labeled attack scenarios mapped to MITRE ATT&CK for Cloud.

Mirrors the generator pattern used in FraudDetectPro's data_generator.py:
class-based generator, configurable ratios, statistical realism, JSON output.
"""

import json
import logging
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


#reference data mimicking a small aws account

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

# A handful of "normal" principals that generate the benign baseline
BASELINE_USERS = [
    {
        "principal": "arn:aws:iam::123456789012:user/tamara.chelagat",
        "home_region": "us-east-1",
        "usual_ip_prefix": "41.90.",
    },
    {
        "principal": "arn:aws:iam::123456789012:user/ci-deploy-bot",
        "home_region": "us-east-1",
        "usual_ip_prefix": "10.0.",
    },
    {
        "principal": "arn:aws:iam::123456789012:user/data-pipeline-svc",
        "home_region": "eu-west-1",
        "usual_ip_prefix": "10.0.",
    },
    {
        "principal": "arn:aws:iam::123456789012:role/read-only-analyst",
        "home_region": "us-west-2",
        "usual_ip_prefix": "41.90.",
    },
]

BENIGN_EVENTS = [
    "ConsoleLogin",
    "DescribeInstances",
    "ListBuckets",
    "GetObject",
    "AssumeRole",
    "DescribeSecurityGroups",
    "ListRoles",
    "GetCallerIdentity",
    "DescribeLogGroups",
    "PutMetricData",
]



# Attack scenario definitions
# Each maps to a MITRE ATT&CK for Cloud technique so alerts can be tagged



@dataclass
class AttackScenario:
    scenario_id: str
    name: str
    mitre_technique: str
    mitre_name: str
    description: str


SCENARIOS: List[AttackScenario] = [
    AttackScenario(
        scenario_id="unusual_geo_login",
        name="Impossible travel console login",
        mitre_technique="T1078", #
        mitre_name="Valid Accounts",
        description="ConsoleLogin from a foreign IP shortly after a login from the user's home region.",
    ),
    AttackScenario(
        scenario_id="privilege_escalation",
        name="IAM privilege escalation",
        mitre_technique="T1098",
        mitre_name="Account Manipulation",
        description="A principal attaches AdministratorAccess or creates a new access key for itself.",
    ),
    AttackScenario(
        scenario_id="public_bucket_exposure",
        name="Storage bucket made public",
        mitre_technique="T1530",
        mitre_name="Data from Cloud Storage",
        description="PutBucketAcl or PutBucketPolicy grants public read/write on a bucket.",
    ),
    AttackScenario(
        scenario_id="recon_burst",
        name="Reconnaissance API burst",
        mitre_technique="T1580",
        mitre_name="Cloud Infrastructure Discovery",
        description="A short burst of many List*/Describe* calls across services, faster than a human would click.",
    ),
    AttackScenario(
        scenario_id="cred_exfil_key_creation",
        name="Long-lived credential creation",
        mitre_technique="T1552",
        mitre_name="Unsecured Credentials",
        description="CreateAccessKey called for a role that has never needed programmatic keys before.",
    ),
]


class CloudTrailEventGenerator:
    #generating synthetic cloudtrail events for training and testing cloud security detection


    #configs approx likelihood of injecting an attack scenario into the stream of benign events
    def __init__(self, attack_ratio: float = 0.05, seed: Optional[int] = None):
        self.attack_ratio = attack_ratio
        self.event_count = 0
        self.attack_count = 0
        if seed is not None:
            random.seed(seed)

        logger.info("CloudTrailEventGenerator initialized")
        logger.info(f"Attack ratio: {attack_ratio * 100:.1f}%")
        logger.info(f"Scenarios loaded: {[s.scenario_id for s in SCENARIOS]}")

    # -- helpers -----------------------------------------------------------

    def _random_ip(self, prefix: Optional[str] = None) -> str:
        prefix = prefix or random.choice(["41.90.", "197.232.", "10.0.", "203.0."])
        return prefix + f"{random.randint(0, 255)}.{random.randint(0, 255)}"

    def _timestamp(self, offset_seconds: int = 0) -> str:
        return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    #Builds shared CloudTrail structure 
    def _base_event(self, principal: str, event_name: str, region: str, ip: str) -> Dict:
        return {
            "eventVersion": "1.08",
            "eventID": str(uuid.uuid4()),
            "eventTime": self._timestamp(),
            "eventName": event_name,
            "eventSource": self._service_for_event(event_name),
            "awsRegion": region,
            "sourceIPAddress": ip,
            "userAgent": random.choice(["aws-cli/2.15", "Boto3/1.34", "console.amazonaws.com", "python-requests/2.31"]),
            "userIdentity": {"type": "IAMUser", "arn": principal},
            "requestParameters": {},
            "responseElements": None,
            # Ground-truth labels for training/evaluation -- not present in real CloudTrail
            "label": "benign",
            "mitre_technique": None,
            "mitre_name": None,
            "scenario_id": None,
        }

    @staticmethod
    def _service_for_event(event_name: str) -> str:
        mapping = {
            "ConsoleLogin": "signin.amazonaws.com",
            "AssumeRole": "sts.amazonaws.com",
            "GetCallerIdentity": "sts.amazonaws.com",
            "CreateAccessKey": "iam.amazonaws.com",
            "AttachUserPolicy": "iam.amazonaws.com",
            "PutBucketAcl": "s3.amazonaws.com",
            "PutBucketPolicy": "s3.amazonaws.com",
            "ListBuckets": "s3.amazonaws.com",
            "GetObject": "s3.amazonaws.com",
        }
        return mapping.get(event_name, "ec2.amazonaws.com")

    # -- benign traffic ------------------------------------------------------

    # Generates a single benign event from the baseline users and benign event types
    def generate_benign_event(self) -> Dict:
        user = random.choice(BASELINE_USERS)
        event_name = random.choice(BENIGN_EVENTS)
        ip = self._random_ip(user["usual_ip_prefix"])
        event = self._base_event(user["principal"], event_name, user["home_region"], ip)
        return event

    # -- attack scenarios ------------------------------------------------------

    # Generates a short list of events representing one attack scenario, either specified by scenario_id or chosen randomly
    def generate_attack_sequence(self, scenario_id: Optional[str] = None) -> List[Dict]:
        """Returns a short list of events representing one attack scenario."""
        scenario = (
            next((s for s in SCENARIOS if s.scenario_id == scenario_id), random.choice(SCENARIOS))
            if scenario_id
            else random.choice(SCENARIOS)
        )

        user = random.choice(BASELINE_USERS)
        method = getattr(self, f"_scenario_{scenario.scenario_id}")
        events = method(user, scenario)
        self.attack_count += len(events)
        return events

    def _tag(self, event: Dict, scenario: AttackScenario) -> Dict:
        event["label"] = "malicious"
        event["mitre_technique"] = scenario.mitre_technique
        event["mitre_name"] = scenario.mitre_name
        event["scenario_id"] = scenario.scenario_id
        return event

    def _scenario_unusual_geo_login(self, user, scenario) -> List[Dict]:
        home_login = self._base_event(
            user["principal"], "ConsoleLogin", user["home_region"], self._random_ip(user["usual_ip_prefix"])
        )
        foreign_ip = self._random_ip(random.choice(["185.220.", "45.155.", "91.219."]))
        foreign_login = self._base_event(user["principal"], "ConsoleLogin", user["home_region"], foreign_ip)
        foreign_login["eventTime"] = self._timestamp(offset_seconds=180)  # 3 min later, different continent
        return [home_login, self._tag(foreign_login, scenario)]

    def _scenario_privilege_escalation(self, user, scenario) -> List[Dict]:
        event = self._base_event(
            user["principal"], "AttachUserPolicy", user["home_region"], self._random_ip(user["usual_ip_prefix"])
        )
        event["requestParameters"] = {
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "userName": user["principal"].split("/")[-1],
        }
        return [self._tag(event, scenario)]

    def _scenario_public_bucket_exposure(self, user, scenario) -> List[Dict]:
        event = self._base_event(
            user["principal"], "PutBucketAcl", user["home_region"], self._random_ip(user["usual_ip_prefix"])
        )
        event["requestParameters"] = {
            "bucketName": f"cloudsentry-data-{random.randint(100, 999)}",
            "acl": "public-read-write",
        }
        return [self._tag(event, scenario)]

    def _scenario_recon_burst(self, user, scenario) -> List[Dict]:
        recon_calls = [
            "ListBuckets",
            "DescribeInstances",
            "ListRoles",
            "DescribeSecurityGroups",
            "ListBuckets",
            "DescribeLogGroups",
        ]
        events = []
        for i, name in enumerate(recon_calls):
            e = self._base_event(user["principal"], name, user["home_region"], self._random_ip(user["usual_ip_prefix"]))
            e["eventTime"] = self._timestamp(offset_seconds=i * 2)  # every 2 seconds -- too fast for a human
            events.append(self._tag(e, scenario))
        return events

    def _scenario_cred_exfil_key_creation(self, user, scenario) -> List[Dict]:
        event = self._base_event(
            user["principal"], "CreateAccessKey", user["home_region"], self._random_ip(user["usual_ip_prefix"])
        )
        event["requestParameters"] = {"userName": user["principal"].split("/")[-1]}
        return [self._tag(event, scenario)]

    # -- batch generation ------------------------------------------------------

    def generate_batch(self, size: int = 50) -> List[Dict]:
        """Generate a batch of events with attack scenarios injected at attack_ratio."""
        events: List[Dict] = []
        while len(events) < size:
            if random.random() < self.attack_ratio:
                events.extend(self.generate_attack_sequence())
            else:
                events.append(self.generate_benign_event())
                self.event_count += 1
        return events[:size] if len(events) > size else events


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Generate synthetic CloudTrail-style events for CloudSentry")
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--attack-ratio", type=float, default=0.08)
    parser.add_argument("--out", type=str, default="data/synthetic_events.jsonl")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    generator = CloudTrailEventGenerator(attack_ratio=args.attack_ratio, seed=args.seed)
    events = generator.generate_batch(size=args.batch_size)

    with open(args.out, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    malicious = sum(1 for e in events if e["label"] == "malicious")
    logger.info(f"Wrote {len(events)} events to {args.out} ({malicious} malicious, {len(events) - malicious} benign)")


if __name__ == "__main__":
    main()
