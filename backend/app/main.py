from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import (
    DefaultModelRequest,
    MessageResponse,
    ModelInfo,
    PredictionRequest,
    PredictionResponse,
    VisualizationSummary,
)
from app.services.model_service import ModelService


app = FastAPI(
    title="C Vulnerability Detection API",
    description="Assignment 3 backend for classifying C/C++ code as vulnerable or non-vulnerable.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model_service = ModelService()


@app.get("/", response_model=MessageResponse)
def root() -> MessageResponse:
    return MessageResponse(message="C Vulnerability Detection API is running.")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "assignment3-backend"}


@app.get("/models", response_model=list[ModelInfo])
def list_models() -> list[dict]:
    return model_service.list_models()


@app.put("/settings/default-model", response_model=MessageResponse)
def update_default_model(payload: DefaultModelRequest) -> MessageResponse:
    try:
        model_service.set_default_model(payload.model_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return MessageResponse(message=f"Default model updated to '{payload.model_key}'.")


@app.post("/predict", response_model=PredictionResponse)
def predict(payload: PredictionRequest) -> dict:
    try:
        return model_service.predict(code=payload.code, model_key=payload.model_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {exc}",
        ) from exc


@app.get("/visualizations/summary", response_model=VisualizationSummary)
def visualization_summary() -> dict:
    return model_service.visualization_summary()


@app.delete("/history", response_model=MessageResponse)
def clear_history() -> MessageResponse:
    model_service.clear_history()
    return MessageResponse(message="Prediction history cleared.")
