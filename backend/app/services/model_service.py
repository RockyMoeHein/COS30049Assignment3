from __future__ import annotations

import gc
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from app.services.feature_extractor import extract_features


BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_DIR / "model"


@dataclass(frozen=True)
class ModelConfig:
    key: str
    name: str
    path: Path
    model_type: str
    uses_features: bool
    family: str
    variant: str


MODEL_CONFIGS: dict[str, ModelConfig] = {
    "randomforest": ModelConfig(
        "randomforest",
        "Random Forest",
        MODEL_DIR / "traditional" / "randomforest.pkl",
        "traditional",
        False,
        "random_forest",
        "standard",
    ),
    "xgboost": ModelConfig(
        "xgboost",
        "XGBoost",
        MODEL_DIR / "traditional" / "xgboost.pkl",
        "traditional",
        False,
        "xgboost",
        "standard",
    ),
    "logistic": ModelConfig(
        "logistic",
        "Logistic Regression",
        MODEL_DIR / "traditional" / "logistic.pkl",
        "traditional",
        False,
        "logistic_regression",
        "standard",
    ),
    "linear_svc": ModelConfig(
        "linear_svc",
        "LinearSVC",
        MODEL_DIR / "traditional" / "linearSVC.pkl",
        "traditional",
        False,
        "linear_svc",
        "standard",
    ),
    "ensemble": ModelConfig(
        "ensemble",
        "Ensemble Model",
        MODEL_DIR / "traditional" / "ensemble.pkl",
        "traditional",
        False,
        "ensemble",
        "standard",
    ),
    "features_randomforest": ModelConfig(
        "features_randomforest",
        "Random Forest + Security Features",
        MODEL_DIR / "handcrafted_features" / "features_randomforest.pkl",
        "handcrafted_features",
        True,
        "random_forest",
        "handcrafted",
    ),
    "features_xgboost": ModelConfig(
        "features_xgboost",
        "XGBoost + Security Features",
        MODEL_DIR / "handcrafted_features" / "features_xgboost.pkl",
        "handcrafted_features",
        True,
        "xgboost",
        "handcrafted",
    ),
    "features_logistic": ModelConfig(
        "features_logistic",
        "Logistic Regression + Security Features",
        MODEL_DIR / "handcrafted_features" / "features_logistic.pkl",
        "handcrafted_features",
        True,
        "logistic_regression",
        "handcrafted",
    ),
    "features_linear_svc": ModelConfig(
        "features_linear_svc",
        "LinearSVC + Security Features",
        MODEL_DIR / "handcrafted_features" / "features_linearSVC.pkl",
        "handcrafted_features",
        True,
        "linear_svc",
        "handcrafted",
    ),
    "features_ensemble": ModelConfig(
        "features_ensemble",
        "Ensemble Model + Security Features",
        MODEL_DIR / "handcrafted_features" / "features_ensemble.pkl",
        "handcrafted_features",
        True,
        "ensemble",
        "handcrafted",
    ),
    "codebert": ModelConfig(
        "codebert",
        "CodeBERT Binary-Balanced",
        MODEL_DIR / "codeBERT" / "codebert_vuln_best.pt",
        "codebert",
        False,
        "codebert",
        "standard",
    ),
    "codebert_cwe_balanced": ModelConfig(
        "codebert_cwe_balanced",
        "CodeBERT CWE-Balanced",
        MODEL_DIR / "codeBERT" / "codeBERT-balanced.pt",
        "codebert",
        False,
        "codebert",
        "cwe_balanced",
    ),
}


class ModelService:
    def __init__(self) -> None:
        self._loaded_models: dict[str, Any] = {}
        self._codebert_tokenizer: Any | None = None
        self.default_model_key = "features_randomforest"
        self.history: list[dict[str, Any]] = []

    def list_models(self) -> list[dict[str, Any]]:
        models = []
        for config in MODEL_CONFIGS.values():
            model = self._loaded_models.get(config.key)
            models.append(
                {
                    "key": config.key,
                    "name": config.name,
                    "model_type": config.model_type,
                    "uses_features": config.uses_features,
                    "family": config.family,
                    "variant": config.variant,
                    "supports_probability": (
                        True
                        if config.model_type == "codebert"
                        else None if model is None else hasattr(model, "predict_proba")
                    ),
                }
            )
        return models

    def set_default_model(self, model_key: str) -> None:
        self._get_config(model_key)
        self.default_model_key = model_key

    def clear_history(self) -> None:
        self.history.clear()

    def predict(self, code: str, model_key: str | None = None) -> dict[str, Any]:
        selected_key = model_key or self.default_model_key
        config = self._get_config(selected_key)
        features = extract_features(code)
        if config.model_type == "codebert":
            prediction, probability = self._predict_codebert(code, config)
        else:
            model = self._load_model(config)
            input_df = self._build_input_dataframe(code, features, config.uses_features)
            prediction = int(model.predict(input_df)[0])
            probability = self._predict_probability(model, input_df)
        label = "VULNERABLE" if prediction == 1 else "NON_VULNERABLE"
        confidence = self._confidence_percent(prediction, probability)
        created_at = datetime.now(timezone.utc)

        result = {
            "model_key": config.key,
            "model_name": config.name,
            "prediction": prediction,
            "label": label,
            "vulnerable_probability": probability,
            "confidence_percent": confidence,
            "features": features,
            "created_at": created_at,
        }

        self.history.append(
            {
                "id": len(self.history) + 1,
                "model_key": config.key,
                "model_name": config.name,
                "label": label,
                "vulnerable_probability": probability,
                "confidence_percent": confidence,
                "created_at": created_at,
            }
        )
        self.history = self.history[-100:]
        return result

    def visualization_summary(self) -> dict[str, Any]:
        label_counts = {"VULNERABLE": 0, "NON_VULNERABLE": 0}
        model_usage: dict[str, int] = {}

        for item in self.history:
            label_counts[item["label"]] = label_counts.get(item["label"], 0) + 1
            model_usage[item["model_name"]] = model_usage.get(item["model_name"], 0) + 1

        return {
            "total_predictions": len(self.history),
            "label_counts": label_counts,
            "model_usage": model_usage,
            "latest_predictions": list(reversed(self.history[-10:])),
            "risk_feature_catalog": [
                {"name": "Buffer memory risk", "field": "buffer_memory_risk_level", "max": 2},
                {"name": "Classic overflow risk", "field": "classic_overflow_risk_level", "max": 2},
                {
                    "name": "Pointer subtraction risk",
                    "field": "pointer_subtraction_risk_level",
                    "max": 2,
                },
                {"name": "Null pointer risk", "field": "null_pointer_risk_level", "max": 2},
                {"name": "Other CWE risk", "field": "other_cwe_risk_level", "max": 2},
                {"name": "Integer size risk", "field": "integer_size_risk_level", "max": 2},
            ],
        }

    def _get_config(self, model_key: str) -> ModelConfig:
        try:
            return MODEL_CONFIGS[model_key]
        except KeyError as exc:
            valid_keys = ", ".join(MODEL_CONFIGS)
            raise ValueError(f"Unknown model_key '{model_key}'. Valid values: {valid_keys}") from exc

    def _load_model(self, config: ModelConfig) -> Any:
        if config.key not in self._loaded_models:
            self._release_codebert_models()
            if not config.path.exists():
                raise FileNotFoundError(f"Model file not found: {config.path}")
            self._loaded_models[config.key] = joblib.load(config.path)
        return self._loaded_models[config.key]

    def _predict_codebert(
        self,
        code: str,
        config: ModelConfig,
    ) -> tuple[int, float]:
        import torch
        from transformers import (
            AutoConfig,
            AutoModelForSequenceClassification,
            AutoTokenizer,
        )

        if config.key not in self._loaded_models:
            if not config.path.exists():
                raise FileNotFoundError(f"Model file not found: {config.path}")

            # CodeBERT checkpoints are large, so release traditional models
            # before loading one transformer variation.
            self._loaded_models.clear()
            gc.collect()

            if self._codebert_tokenizer is None:
                self._codebert_tokenizer = AutoTokenizer.from_pretrained(
                    "microsoft/codebert-base"
                )

            model_config = AutoConfig.from_pretrained(
                "microsoft/codebert-base",
                num_labels=2,
            )

            model = AutoModelForSequenceClassification.from_config(model_config)
            state_dict = torch.load(
                config.path,
                map_location="cpu",
                weights_only=True,
                mmap=True,
            )
            model.load_state_dict(state_dict)
            del state_dict
            gc.collect()
            model.eval()
            self._loaded_models[config.key] = model

        model = self._loaded_models[config.key]
        inputs = self._codebert_tokenizer(
            code,
            truncation=True,
            padding="max_length",
            max_length=512,
            return_tensors="pt",
        )

        with torch.no_grad():
            logits = model(**inputs).logits
            probabilities = torch.softmax(logits, dim=1)[0]

        prediction = int(torch.argmax(probabilities).item())
        vulnerable_probability = round(float(probabilities[1].item()), 4)
        return prediction, vulnerable_probability

    def _release_codebert_models(self) -> None:
        codebert_keys = [
            key
            for key in self._loaded_models
            if MODEL_CONFIGS[key].model_type == "codebert"
        ]
        for key in codebert_keys:
            del self._loaded_models[key]
        if codebert_keys:
            gc.collect()

    @staticmethod
    def _build_input_dataframe(
        code: str,
        features: dict[str, Any],
        uses_features: bool,
    ) -> pd.DataFrame:
        if uses_features:
            return pd.DataFrame([{"code": code, **features}])
        return pd.DataFrame({"code": [code]})

    @staticmethod
    def _predict_probability(model: Any, input_df: pd.DataFrame) -> float | None:
        if not hasattr(model, "predict_proba"):
            return None

        try:
            return round(float(model.predict_proba(input_df)[0][1]), 4)
        except Exception:
            return None

    @staticmethod
    def _confidence_percent(prediction: int, probability: float | None) -> float | None:
        if probability is None:
            return None
        confidence = probability if prediction == 1 else 1 - probability
        return round(confidence * 100, 2)
