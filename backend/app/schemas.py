from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class PredictionRequest(BaseModel):
    code: str = Field(
        ...,
        min_length=20,
        max_length=20000,
        description="C/C++ source code snippet to classify.",
    )
    model_key: str = Field(
        default="features_randomforest",
        description="Model identifier from GET /models.",
    )

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Code snippet cannot be empty.")
        if not any(token in cleaned for token in (";", "{", "}", "#include", "int ", "void ")):
            raise ValueError("Input must look like a C/C++ code snippet.")
        return cleaned


class ModelInfo(BaseModel):
    key: str
    name: str
    model_type: Literal["traditional", "handcrafted_features", "codebert"]
    uses_features: bool
    family: str
    variant: str
    supports_probability: bool | None = None


class FeatureSummary(BaseModel):
    buffer_memory_risk_level: int
    classic_overflow_risk_level: int
    pointer_subtraction_risk_level: int
    null_pointer_risk_level: int
    other_cwe_risk_level: int
    integer_size_risk_level: int
    count_unsafe_buffer_funcs: int
    count_bounded_buffer_funcs: int
    count_pointer_subtractions: int
    count_memory_allocs: int
    count_memory_releases: int
    count_input_sources: int
    count_validation_signals: int
    count_array_accesses: int
    count_pointer_ops: int
    count_null_checks: int
    count_format_string_funcs: int
    count_arithmetic_ops: int
    count_integer_types: int
    snippet_length: int
    token_count: int
    max_brace_depth: int
    char_diversity: float


class PredictionResponse(BaseModel):
    model_key: str
    model_name: str
    prediction: int
    label: Literal["VULNERABLE", "NON_VULNERABLE"]
    vulnerable_probability: float | None
    confidence_percent: float | None
    features: FeatureSummary
    created_at: datetime


class HistoryItem(BaseModel):
    id: int
    model_key: str
    model_name: str
    label: Literal["VULNERABLE", "NON_VULNERABLE"]
    vulnerable_probability: float | None
    confidence_percent: float | None
    created_at: datetime


class DefaultModelRequest(BaseModel):
    model_key: str = Field(..., description="Model identifier from GET /models.")


class MessageResponse(BaseModel):
    message: str


class VisualizationSummary(BaseModel):
    total_predictions: int
    label_counts: dict[str, int]
    model_usage: dict[str, int]
    latest_predictions: list[HistoryItem]
    risk_feature_catalog: list[dict[str, Any]]


class DatasetScope(BaseModel):
    task: str
    target_classes: list[str]
    covered_cwes: list[str]
    sources: list[str]


class DatasetPartitionSummary(BaseModel):
    total_samples: int
    label_counts: dict[str, int]
    source_counts: dict[str, int]
    source: str
    csv_available: bool | None = None


class CodeLengthSummary(BaseModel):
    average_characters: float
    median_characters: int
    maximum_characters: int
    buckets: dict[str, int]


class EvaluationDatasetSummary(DatasetPartitionSummary):
    cwe_counts: dict[str, int]
    code_length: CodeLengthSummary


class ExternalDatasetSummary(BaseModel):
    total_samples: int
    top_cwes: dict[str, int]
    note: str


class ModelPerformanceSummary(BaseModel):
    model: str
    accuracy: float
    vulnerable_precision: float
    vulnerable_recall: float
    vulnerable_f1: float
    macro_f1: float


class DatasetVisualizationSummary(BaseModel):
    scope: DatasetScope
    training: EvaluationDatasetSummary
    processed_training: EvaluationDatasetSummary
    evaluation: EvaluationDatasetSummary
    processed_evaluation: EvaluationDatasetSummary
    model_comparison: list[ModelPerformanceSummary]
    external_reference: ExternalDatasetSummary
