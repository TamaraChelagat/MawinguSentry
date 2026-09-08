"""
CLI entry point for training the CloudThreatPipeline.

Run as: python scripts/train_model.py [options]

Deliberately separate from app/model.py: that file only defines the
CloudThreatPipeline class and must never be run directly, because doing
so (`python app/model.py`) makes Python pickle the class under the
`__main__` module -- which then fails to unpickle anywhere the class is
imported normally (e.g. `from app.model import CloudThreatPipeline` in
the FastAPI service). This script imports the class instead of defining
it, so the saved model is always loadable.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.model import train_and_save  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Train the CloudThreatPipeline and save it to disk")
    parser.add_argument("--events", type=str, default=None, help="Path to a JSONL events file")
    parser.add_argument("--generate", type=int, default=5000, help="If --events not given, generate this many")
    parser.add_argument("--attack-ratio", type=float, default=0.08)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--out", type=str, default="models/cloud_threat_pipeline.pkl")
    args = parser.parse_args()

    train_and_save(
        events_path=args.events,
        n_generate=args.generate,
        attack_ratio=args.attack_ratio,
        seed=args.seed,
        out_path=args.out,
    )


if __name__ == "__main__":
    main()
