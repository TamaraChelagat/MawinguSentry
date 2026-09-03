"""
Model pipeline for MawinguSentry.

Adapts the ensemble + meta-learner architecture actually shipped in
FraudDetectPro's app/pipeline.py (ImprovedCreditCardEnsemble +
SimplifiedMetaLearner), not the neural-network-extractor version described
in early planning docs -- that NN was tried and removed in FraudDetectPro
itself ("Removed Neural Network - using raw features only", per
notebooks/04_hybrid_model.ipynb). This pipeline reuses the architecture
that's actually proven to work: five base models (XGBoost, LightGBM,
Random Forest, Logistic Regression, Isolation Forest) feeding a logistic
regression meta-learner that stacks their predictions with the raw
features. "Meta-learner stacking" is the accurate term for this -- it's
related to but not the same as simple soft-voting.
"""

import json
import logging
from typing import Dict, List, Tuple

import numpy as np
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
import lightgbm as lgb
import xgboost as xgb

from app.features import CloudEventFeatureEngineer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class ConservativeSampler:
    """Oversamples the minority (malicious) class toward a target ratio, without fully balancing.

    Fully balancing to 50/50 tends to make models over-trigger on the minority class in
    production, where the real base rate is far lower than the training ratio. Targeting a more
    moderate ratio (e.g. 30%) is a deliberate middle ground, same reasoning FraudDetectPro uses.
    """

    def __init__(self, target_malicious_ratio: float = 0.3, random_state: int = 42):
        self.target_malicious_ratio = target_malicious_ratio
        self.random_state = random_state

    def fit_resample(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        n_malicious = int(np.sum(y == 1))
        n_benign = int(np.sum(y == 0))
        if n_malicious == 0 or n_malicious == len(y):
            return X, y

        desired = int(n_benign * self.target_malicious_ratio / (1 - self.target_malicious_ratio))
        target = max(desired, n_malicious)  # never downsample the minority class
        k_neighbors = min(3, n_malicious - 1) if n_malicious > 1 else 1

        sampler = SMOTE(sampling_strategy={1: target}, random_state=self.random_state, k_neighbors=max(k_neighbors, 1))
        X_res, y_res = sampler.fit_resample(X, y)
        logger.info(
            f"Resampled: malicious {n_malicious} -> {int(np.sum(y_res == 1))} "
            f"(ratio {np.mean(y):.3f} -> {np.mean(y_res):.3f})"
        )
        return X_res, y_res


class CloudThreatEnsemble:
    """Five base models: four supervised classifiers plus an unsupervised anomaly detector."""

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.models: Dict = {}
        self.is_trained = False

    def _initialize_models(self):
        self.models["xgb"] = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=self.random_state,
            eval_metric="aucpr",
            reg_alpha=0.1,
            reg_lambda=0.1,
        )
        self.models["lgb"] = lgb.LGBMClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=self.random_state,
            is_unbalance=True,
            verbose=-1,
        )
        self.models["random_forest"] = RandomForestClassifier(
            n_estimators=150,
            max_depth=10,
            random_state=self.random_state,
            class_weight="balanced_subsample",
            min_samples_leaf=3,
        )
        self.models["logistic"] = LogisticRegression(
            random_state=self.random_state, class_weight="balanced", C=0.1, max_iter=2000, solver="liblinear"
        )
        self.models["isolation_forest"] = IsolationForest(
            n_estimators=150, contamination=0.15, random_state=self.random_state
        )

    def fit(self, X: np.ndarray, y: np.ndarray):
        self._initialize_models()
        for name in ["xgb", "lgb", "random_forest", "logistic"]:
            self.models[name].fit(X, y)
        self.models["isolation_forest"].fit(X)  # unsupervised, doesn't use y
        self.is_trained = True

    def predict_proba(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        if not self.is_trained:
            raise ValueError("Ensemble must be trained first")
        predictions = {}
        for name in ["xgb", "lgb", "random_forest", "logistic"]:
            predictions[name] = self.models[name].predict_proba(X)[:, 1]
        iso_scores = self.models["isolation_forest"].decision_function(X)
        # Isolation Forest scores are unbounded; squash to a 0-1 "risk" range
        predictions["isolation_forest"] = 1 / (1 + np.exp(iso_scores * 2))
        return predictions


class ThreatMetaLearner:
    """Logistic regression stacking the base ensemble's outputs with the raw features."""

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.meta_model = None
        self.scaler = RobustScaler()
        self.base_model_names: List[str] = []

    def fit(self, base_predictions: Dict[str, np.ndarray], features: np.ndarray, y: np.ndarray):
        self.base_model_names = list(base_predictions.keys())
        stacked = np.column_stack([base_predictions[name] for name in self.base_model_names] + [features])
        stacked_scaled = self.scaler.fit_transform(stacked)
        self.meta_model = LogisticRegression(
            random_state=self.random_state, class_weight="balanced", C=0.1, max_iter=2000, solver="liblinear"
        )
        self.meta_model.fit(stacked_scaled, y)

    def predict(self, base_predictions: Dict[str, np.ndarray], features: np.ndarray) -> np.ndarray:
        stacked = np.column_stack([base_predictions[name] for name in self.base_model_names] + [features])
        stacked_scaled = self.scaler.transform(stacked)
        return self.meta_model.predict_proba(stacked_scaled)[:, 1]


class CloudThreatPipeline:
    """End-to-end pipeline: feature engineering -> resampling -> ensemble -> meta-learner."""

    def __init__(self, random_state: int = 42):
        self.feature_engineer = CloudEventFeatureEngineer()
        self.sampler = ConservativeSampler(target_malicious_ratio=0.3, random_state=random_state)
        self.ensemble = CloudThreatEnsemble(random_state=random_state)
        self.meta_learner = ThreatMetaLearner(random_state=random_state)
        self.is_trained = False
        self.optimal_threshold = 0.5
        self.performance_metrics: Dict = {}

    def fit(self, events: List[Dict], test_size: float = 0.3) -> Dict:
        labels = np.array([1 if e["label"] == "malicious" else 0 for e in events])
        scenario_ids = np.array([e.get("scenario_id") or "benign" for e in events])

        train_events, test_events, y_train, y_test, _, scenario_test = train_test_split(
            events, labels, scenario_ids, test_size=test_size, random_state=42, stratify=labels
        )

        X_train = self.feature_engineer.fit_transform(train_events).values.astype(float)

        X_resampled, y_resampled = self.sampler.fit_resample(X_train, y_train)

        self.ensemble.fit(X_resampled, y_resampled)
        base_predictions = self.ensemble.predict_proba(X_resampled)
        self.meta_learner.fit(base_predictions, X_resampled, y_resampled)
        self.is_trained = True

        test_scores = self.predict_proba(test_events)
        self.optimal_threshold = self._find_optimal_threshold(y_test, test_scores)
        self.performance_metrics = self._evaluate(y_test, test_scores, self.optimal_threshold)
        self.performance_metrics["recall_by_scenario"] = self._recall_by_scenario(
            y_test, test_scores, scenario_test, self.optimal_threshold
        )
        return self.performance_metrics

    @staticmethod
    def _recall_by_scenario(
        y_true: np.ndarray, y_scores: np.ndarray, scenario_ids: np.ndarray, threshold: float
    ) -> Dict[str, str]:
        y_pred = (y_scores > threshold).astype(int)
        results = {}
        for scenario in sorted(set(scenario_ids)):
            if scenario == "benign":
                continue
            mask = scenario_ids == scenario
            if mask.sum() == 0:
                continue
            caught = int(y_pred[mask].sum())
            total = int(mask.sum())
            results[scenario] = f"{caught}/{total}"
        return results

    def predict_proba(self, events: List[Dict]) -> np.ndarray:
        if not self.is_trained:
            raise ValueError("Pipeline must be trained first")
        X = self.feature_engineer.transform(events).values.astype(float)
        base_predictions = self.ensemble.predict_proba(X)
        return self.meta_learner.predict(base_predictions, X)

    def predict(self, events: List[Dict], threshold: float = None) -> np.ndarray:
        threshold = threshold if threshold is not None else self.optimal_threshold
        scores = self.predict_proba(events)
        return (scores > threshold).astype(int)

    @staticmethod
    def _find_optimal_threshold(y_true: np.ndarray, y_scores: np.ndarray) -> float:
        best_threshold, best_f1 = 0.5, 0.0
        for threshold in np.arange(0.05, 0.95, 0.02):
            y_pred = (y_scores > threshold).astype(int)
            if len(np.unique(y_pred)) > 1:
                f1 = f1_score(y_true, y_pred)
                if f1 > best_f1:
                    best_f1, best_threshold = f1, threshold
        return best_threshold

    @staticmethod
    def _evaluate(y_true: np.ndarray, y_scores: np.ndarray, threshold: float) -> Dict:
        y_pred = (y_scores > threshold).astype(int)
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        return {
            "roc_auc": roc_auc_score(y_true, y_scores),
            "average_precision": average_precision_score(y_true, y_scores),
            "precision": precision,
            "recall": recall,
            "f1": f1_score(y_true, y_pred),
            "false_positive_rate": fp / (fp + tn) if (fp + tn) > 0 else 0.0,
            "threats_caught": int(tp),
            "threats_missed": int(fn),
            "false_alarms": int(fp),
            "threshold_used": threshold,
            "classification_report": classification_report(
                y_true, y_pred, target_names=["benign", "malicious"], output_dict=True
            ),
        }

    def save(self, filepath: str):
        import joblib

        joblib.dump(self, filepath)

    @staticmethod
    def load(filepath: str) -> "CloudThreatPipeline":
        import joblib

        return joblib.load(filepath)


def main():
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Train the CloudThreatPipeline")
    parser.add_argument("--events", type=str, default=None, help="Path to a JSONL events file")
    parser.add_argument("--generate", type=int, default=5000, help="If --events not given, generate this many")
    parser.add_argument("--attack-ratio", type=float, default=0.08)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--out", type=str, default="models/cloud_threat_pipeline.pkl")
    args = parser.parse_args()

    if args.events:
        events = [json.loads(line) for line in open(args.events)]
    else:
        from app.data_generator import CloudTrailEventGenerator

        logger.info(f"Generating {args.generate} synthetic events (seed={args.seed})")
        gen = CloudTrailEventGenerator(attack_ratio=args.attack_ratio, seed=args.seed, time_spread_days=30)
        events = gen.generate_batch(size=args.generate)

    pipeline = CloudThreatPipeline()
    metrics = pipeline.fit(events)

    logger.info("=" * 60)
    logger.info("EVALUATION RESULTS")
    logger.info("=" * 60)
    for key in ["roc_auc", "average_precision", "precision", "recall", "f1", "false_positive_rate"]:
        logger.info(f"{key}: {metrics[key]:.4f}")
    logger.info(
        f"Threats caught: {metrics['threats_caught']}, missed: {metrics['threats_missed']}, "
        f"false alarms: {metrics['false_alarms']}"
    )
    logger.info(f"Optimal threshold: {metrics['threshold_used']:.2f}")
    logger.info("Recall by scenario:")
    for scenario, ratio in metrics["recall_by_scenario"].items():
        logger.info(f"  {scenario}: {ratio}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    pipeline.save(args.out)
    logger.info(f"Model saved to {args.out}")


if __name__ == "__main__":
    main()
