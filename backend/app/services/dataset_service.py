from functools import lru_cache
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[2]
DATASET_DIR = BASE_DIR / "datasets"

TRAIN_PATH = DATASET_DIR / "notmarked_sard_vdisc_train.csv"
VALIDATION_PATH = DATASET_DIR / "notmarked_sard_and_vdisc_validate.csv"
ZENODO_PATH = DATASET_DIR / "data_C.csv"

COVERED_CWES = ["CWE-119", "CWE-120", "CWE-469", "CWE-476", "CWE-OTHERS"]

NOTEBOOK_TRAINING_SUMMARY = {
    "total_samples": 1_062_515,
    "label_counts": {
        "NON_VULNERABLE": 950_214,
        "VULNERABLE": 112_301,
    },
    "source_counts": {
        "VDISC": 1_015_687,
        "SARD": 46_828,
    },
    "cwe_counts": {
        "CWE-119": 19_171,
        "CWE-120": 37_822,
        "CWE-469": 2_122,
        "CWE-476": 9_933,
        "CWE-OTHERS": 74_210,
    },
    "code_length": {
        "average_characters": 794.05,
        "median_characters": 560,
        "maximum_characters": 75_890,
        "buckets": {
            "0-199": 102_610,
            "200-499": 374_457,
            "500-999": 311_236,
            "1,000-1,999": 211_504,
            "2,000+": 62_708,
        },
    },
}

NOTEBOOK_PROCESSED_TRAINING_SUMMARY = {
    "total_samples": 119_975,
    "label_counts": {
        "NON_VULNERABLE": 59_983,
        "VULNERABLE": 59_992,
    },
    "source_counts": {
        "VDISC": 119_975,
    },
    "cwe_counts": {
        "CWE-119": 17_595,
        "CWE-120": 34_633,
        "CWE-469": 1_904,
        "CWE-476": 8_784,
        "CWE-OTHERS": 25_505,
    },
    "code_length": {
        "average_characters": 832.48,
        "median_characters": 656,
        "maximum_characters": 10_739,
        "buckets": {
            "0-199": 8_368,
            "200-499": 36_869,
            "500-999": 37_654,
            "1,000-1,999": 30_427,
            "2,000+": 6_657,
        },
    },
}

NOTEBOOK_MODEL_COMPARISON = [
    {
        "model": "Random Forest",
        "accuracy": 0.7504,
        "vulnerable_precision": 0.80,
        "vulnerable_recall": 0.67,
        "vulnerable_f1": 0.73,
        "macro_f1": 0.75,
    },
    {
        "model": "Logistic Regression",
        "accuracy": 0.7436,
        "vulnerable_precision": 0.79,
        "vulnerable_recall": 0.67,
        "vulnerable_f1": 0.72,
        "macro_f1": 0.74,
    },
    {
        "model": "XGBoost",
        "accuracy": 0.7338,
        "vulnerable_precision": 0.81,
        "vulnerable_recall": 0.61,
        "vulnerable_f1": 0.70,
        "macro_f1": 0.73,
    },
    {
        "model": "LinearSVC",
        "accuracy": 0.7318,
        "vulnerable_precision": 0.77,
        "vulnerable_recall": 0.66,
        "vulnerable_f1": 0.71,
        "macro_f1": 0.73,
    },
    {
        "model": "Ensemble Hard Voting",
        "accuracy": 0.7512,
        "vulnerable_precision": 0.81,
        "vulnerable_recall": 0.65,
        "vulnerable_f1": 0.72,
        "macro_f1": 0.75,
    },
]


class DatasetService:
    @staticmethod
    @lru_cache(maxsize=1)
    def get_summary() -> dict:
        validation = DatasetService._load_validation()
        zenodo = DatasetService._load_zenodo()
        evaluation = DatasetService._build_evaluation_dataset(validation, zenodo)
        processed_evaluation = DatasetService._build_processed_evaluation(
            evaluation
        )

        return {
            "scope": {
                "task": "Binary C/C++ vulnerability classification",
                "target_classes": ["NON_VULNERABLE", "VULNERABLE"],
                "covered_cwes": COVERED_CWES,
                "sources": ["VDISC", "SARD", "ZEN"],
            },
            "training": {
                **NOTEBOOK_TRAINING_SUMMARY,
                "source": "Original Assignment 2 training dataset",
                "csv_available": TRAIN_PATH.exists() and TRAIN_PATH.stat().st_size > 0,
            },
            "processed_training": {
                **NOTEBOOK_PROCESSED_TRAINING_SUMMARY,
                "source": "Balanced and cleaned Assignment 2 modeling dataset",
                "csv_available": TRAIN_PATH.exists() and TRAIN_PATH.stat().st_size > 0,
            },
            "evaluation": DatasetService._summarize_evaluation(
                evaluation,
                "Validation dataset combined with deduplicated ZEN samples",
            ),
            "processed_evaluation": DatasetService._summarize_evaluation(
                processed_evaluation,
                (
                    "SARD removed, then balanced to 12,424 samples per label "
                    "using random_state=42"
                ),
            ),
            "model_comparison": NOTEBOOK_MODEL_COMPARISON,
            "external_reference": {
                "total_samples": int(len(zenodo)),
                "top_cwes": {
                    str(key): int(value)
                    for key, value in zenodo["cwe_id"].value_counts().head(10).items()
                },
                "note": (
                    "CWE IDs outside CWE-119, CWE-120, CWE-469, and CWE-476 "
                    "are grouped as CWE-OTHERS for the model."
                ),
            },
        }

    @staticmethod
    def _load_validation() -> pd.DataFrame:
        if not VALIDATION_PATH.exists():
            raise FileNotFoundError(f"Dataset file not found: {VALIDATION_PATH}")

        return pd.read_csv(
            VALIDATION_PATH,
            usecols=["code", *COVERED_CWES, "Label", "DataType"],
        )

    @staticmethod
    def _load_zenodo() -> pd.DataFrame:
        if not ZENODO_PATH.exists():
            raise FileNotFoundError(f"Dataset file not found: {ZENODO_PATH}")

        return pd.read_csv(
            ZENODO_PATH,
            usecols=["vul_code", "is_vulnerable", "cwe_id"],
        )

    @staticmethod
    def _build_evaluation_dataset(
        validation: pd.DataFrame,
        zenodo: pd.DataFrame,
    ) -> pd.DataFrame:
        converted = pd.DataFrame(
            {
                "code": zenodo["vul_code"].fillna("").astype(str),
                "Label": zenodo["is_vulnerable"].astype(int),
                "DataType": "ZEN",
            }
        )

        for cwe in COVERED_CWES[:-1]:
            converted[cwe] = zenodo["cwe_id"].eq(cwe)

        converted["CWE-OTHERS"] = ~zenodo["cwe_id"].isin(COVERED_CWES[:-1])
        converted = converted[validation.columns]

        return (
            pd.concat([validation, converted], ignore_index=True)
            .drop_duplicates(subset=["code", "Label"])
            .reset_index(drop=True)
        )

    @staticmethod
    def _build_processed_evaluation(
        evaluation: pd.DataFrame,
    ) -> pd.DataFrame:
        model_data = evaluation[evaluation["DataType"] != "SARD"].copy()
        sample_size = int(model_data["Label"].value_counts().min())

        balanced_classes = [
            model_data[model_data["Label"] == label].sample(
                n=sample_size,
                random_state=42,
            )
            for label in (0, 1)
        ]

        return (
            pd.concat(balanced_classes, ignore_index=True)
            .sample(frac=1, random_state=42)
            .reset_index(drop=True)
        )

    @staticmethod
    def _summarize_evaluation(
        dataset: pd.DataFrame,
        source: str,
    ) -> dict:
        code_lengths = dataset["code"].fillna("").astype(str).str.len()
        length_buckets = pd.cut(
            code_lengths,
            bins=[-1, 199, 499, 999, 1999, float("inf")],
            labels=["0-199", "200-499", "500-999", "1,000-1,999", "2,000+"],
        ).value_counts().sort_index()

        return {
            "total_samples": int(len(dataset)),
            "label_counts": DatasetService._label_counts(dataset),
            "source_counts": {
                str(key): int(value)
                for key, value in dataset["DataType"].value_counts().items()
            },
            "cwe_counts": {
                cwe: int(dataset[cwe].astype(bool).sum())
                for cwe in COVERED_CWES
            },
            "code_length": {
                "average_characters": round(float(code_lengths.mean()), 2),
                "median_characters": int(code_lengths.median()),
                "maximum_characters": int(code_lengths.max()),
                "buckets": {
                    str(key): int(value)
                    for key, value in length_buckets.items()
                },
            },
            "source": source,
        }

    @staticmethod
    def _label_counts(dataset: pd.DataFrame) -> dict[str, int]:
        counts = dataset["Label"].value_counts()
        return {
            "NON_VULNERABLE": int(counts.get(0, 0)),
            "VULNERABLE": int(counts.get(1, 0)),
        }
