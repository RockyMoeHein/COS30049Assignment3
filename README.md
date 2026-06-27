# COS30049 Assignment 3

Machine-learning web application for detecting vulnerable C/C++ source-code
snippets. The system combines a React frontend, a FastAPI backend, Assignment 2
model artifacts, and D3.js visualisations.

## Project Features

- Analyze pasted or uploaded C/C++ code snippets.
- Select between traditional ML models, handcrafted-feature variants, and
  CodeBERT models.
- Compare classical model variants on the same code snippet.
- Display prediction result, confidence when supported, extracted risk
  indicators, code metrics, and recent analysis history.
- Show dataset statistics with interactive D3.js visualisations.
- Export prediction results as JSON.

## Project Structure

```text
COS30049Assignment3/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── schemas.py
│   │   └── services/
│   ├── datasets/
│   ├── model/
│   │   ├── traditional/
│   │   ├── handcrafted_features/
│   │   └── codeBERT/
│   └── requirements.txt
└── frontend/
    ├── public/
    ├── scripts/
    ├── src/
    └── package.json
```

## Required Software

Install these before running the project:

- Node.js
- Python 3.13
- Git LFS, if cloning the repository with large `.csv`, `.pkl`, or `.pt` files

The backend model files were produced with Python 3.13 and scikit-learn 1.8.0,
so Python 3.13 is required for reliable model loading.

## Main Libraries

Frontend:

- React
- React Router
- D3.js
- Create React App / react-scripts

Backend:

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

## Quick Start

Run both the frontend and backend together from the frontend folder:

```bash
cd COS30049Assignment3/frontend
npm install
npm run dev
```

The first `npm run dev` may take several minutes because it automatically:

1. Creates `backend/.venv313`.
2. Installs the Python packages from `backend/requirements.txt`.
3. Starts the FastAPI backend.
4. Starts the React frontend.

After startup, open:

- Frontend: `http://127.0.0.1:3000`
- Backend API: `http://127.0.0.1:8000`
- FastAPI documentation: `http://127.0.0.1:8000/docs`

## Running Frontend and Backend Separately

Frontend only:

```bash
cd COS30049Assignment3/frontend
npm install
npm start
```

Backend only:

```bash
cd COS30049Assignment3/frontend
npm run start:backend
```

The backend launcher works on macOS, Windows, and Linux. It looks for
`backend/.venv313` first, then falls back to a system Python 3.13 command such
as `py -3.13`, `python3.13`, or `python`.

## Configuration

The frontend uses this backend URL by default:

```text
http://127.0.0.1:8000
```

To use a different backend URL, create a frontend environment file:

```bash
cd COS30049Assignment3/frontend
echo "REACT_APP_API_URL=http://127.0.0.1:8000" > .env
```

The backend port can be changed when starting the backend:

```bash
BACKEND_PORT=8001 npm run start:backend
```

On Windows PowerShell:

```powershell
$env:BACKEND_PORT="8001"
npm run start:backend
```

## AI Model Integration

The backend loads Assignment 2 model artifacts from `backend/model`.

Expected model folders:

```text
backend/model/traditional/
backend/model/handcrafted_features/
backend/model/codeBERT/
```

Traditional model files:

```text
randomforest.pkl
xgboost.pkl
logistic.pkl
linearSVC.pkl
ensemble.pkl
```

Handcrafted-feature model files:

```text
features_randomforest.pkl
features_xgboost.pkl
features_logistic.pkl
features_linearSVC.pkl
features_ensemble.pkl
```

CodeBERT model files:

```text
codebert_vuln_best.pt
codeBERT-balanced.pt
```

The model configuration is defined in:

```text
backend/app/services/model_service.py
```

To add or replace a model:

1. Copy the model artifact into the correct `backend/model` subfolder.
2. Add or update its entry in `MODEL_CONFIGS`.
3. Make sure the model key is returned by `GET /models`.
4. Use that key when calling `POST /predict`.

Assignment 2 files are not edited by this project. The trained model artifacts
are copied into Assignment 3 and loaded by the FastAPI backend.

## Dataset Integration

Dataset files are stored in:

```text
backend/datasets/
```

The statistics page reads dataset summaries from:

```text
GET /visualizations/dataset-summary
```

The backend dataset logic is implemented in:

```text
backend/app/services/dataset_service.py
```

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Check whether the backend is running. |
| GET | `/models` | Return all available model options. |
| POST | `/predict` | Submit C/C++ code and receive a prediction. |
| GET | `/visualizations/summary` | Return prediction-history data. |
| GET | `/visualizations/dataset-summary` | Return dataset statistics for D3 charts. |
| PUT | `/settings/default-model` | Update the backend default model. |
| DELETE | `/history` | Clear prediction history stored in memory. |

Example prediction request:

```json
{
  "model_key": "features_randomforest",
  "code": "#include <string.h>\nvoid copy(char *src) { char buf[8]; strcpy(buf, src); }"
}
```

Example prediction response:

```json
{
  "model_key": "features_randomforest",
  "model_name": "Random Forest + Security Features",
  "prediction": 1,
  "label": "VULNERABLE",
  "vulnerable_probability": 0.61,
  "confidence_percent": 61.0,
  "features": {
    "buffer_memory_risk_level": 2,
    "classic_overflow_risk_level": 2,
    "count_unsafe_buffer_funcs": 1,
    "snippet_length": 70,
    "token_count": 12
  },
  "created_at": "2026-06-26T00:00:00Z"
}
```

The actual `features` object contains more extracted code metrics than the
shortened example above.

## Validation and Error Handling

Frontend validation checks:

- Code is not empty.
- Code has at least 20 characters.
- Code is below 20,000 characters.
- Uploaded files use `.c`, `.cc`, `.cpp`, `.h`, or `.hpp`.
- Uploaded files are below 100 KB.

Backend validation checks:

- Request body matches the Pydantic schema.
- Code input looks like a C/C++ snippet.
- Model key exists in the configured model list.
- Missing model or dataset files return clear API errors.

## Useful Commands

```bash
# Start frontend and backend together
npm run dev

# Start React only
npm start

# Start backend only
npm run start:backend

# Build production frontend
npm run build

# Run frontend tests
npm test -- --watchAll=false
```

## Troubleshooting

If `npm run dev` says Python is not found, install Python 3.13 and ensure one of
these commands works in the terminal:

```bash
python3.13 --version
python --version
```

On Windows:

```powershell
py -3.13 --version
```

If model files are missing after cloning, install Git LFS and pull the files:

```bash
git lfs install
git lfs pull
```

If port `8000` is already used, either stop the existing backend process or run
the backend on another port and set `REACT_APP_API_URL` to match it.
