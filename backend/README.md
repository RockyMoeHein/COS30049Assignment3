# Assignment 3 Backend

FastAPI backend for the C/C++ vulnerability detection web application.

## Main Libraries

- FastAPI
- Uvicorn
- Pydantic
- pandas
- NumPy
- scikit-learn 1.8.0
- joblib
- XGBoost
- PyTorch
- Transformers

## Recommended Run Command

The easiest way is to start both frontend and backend from the frontend folder:

```bash
cd COS30049Assignment3/frontend
npm install
npm run dev
```

The frontend `predev` script creates `backend/.venv313` and installs
`backend/requirements.txt` automatically when needed.

## Manual Backend Setup

Use this only if the backend needs to be run separately.

macOS/Linux:

```bash
cd COS30049Assignment3/backend
python3.13 -m venv .venv313
.venv313/bin/python -m pip install -r requirements.txt
.venv313/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Windows PowerShell:

```powershell
cd COS30049Assignment3/backend
py -3.13 -m venv .venv313
.\.venv313\Scripts\python.exe -m pip install -r requirements.txt
.\.venv313\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Backend root message. |
| GET | `/health` | Check backend status. |
| GET | `/models` | List available ML models. |
| POST | `/predict` | Submit C/C++ code and receive a vulnerability prediction. |
| GET | `/visualizations/summary` | Return prediction-history data. |
| GET | `/visualizations/dataset-summary` | Return dataset statistics. |
| PUT | `/settings/default-model` | Update the default backend model. |
| DELETE | `/history` | Clear in-memory prediction history. |

## Example Prediction Request

```json
{
  "model_key": "features_randomforest",
  "code": "#include <string.h>\nvoid copy(char *src) { char buf[8]; strcpy(buf, src); }"
}
```

## AI Model Integration

The backend uses model artifacts copied from Assignment 2. Assignment 2 files
are not edited by this backend.

Model artifacts must be stored in:

```text
backend/model/traditional/
backend/model/handcrafted_features/
backend/model/codeBERT/
```

The model list and file paths are configured in:

```text
backend/app/services/model_service.py
```

When adding a new model:

1. Place the model artifact in the correct model folder.
2. Add the model path and metadata to `MODEL_CONFIGS`.
3. Confirm that the model appears in `GET /models`.
4. Use its `model_key` in the `POST /predict` request.

## Dataset Integration

Dataset files must be stored in:

```text
backend/datasets/
```

Dataset summaries for the statistics page are generated in:

```text
backend/app/services/dataset_service.py
```

## Error Handling

The backend uses Pydantic validation and FastAPI exceptions to handle:

- missing or invalid C/C++ code input
- unknown model keys
- missing model files
- missing dataset files
- prediction failures

Errors are returned as JSON responses with appropriate HTTP status codes.
