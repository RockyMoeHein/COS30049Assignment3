# Assignment 3 Backend

FastAPI backend for the C/C++ vulnerability detection web application.

## Setup

```bash
cd COS30049Assignment3/backend
/opt/anaconda3/bin/python3.13 -m venv .venv313 --system-site-packages
source .venv313/bin/activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn app.main:app --reload --port 8000
```

API docs will be available at:

```text
http://127.0.0.1:8000/docs
```

## Main Endpoints

- `GET /health` - check backend status.
- `GET /models` - list available ML models.
- `POST /predict` - submit C/C++ code and receive a vulnerability prediction.
- `GET /visualizations/summary` - return prediction-history data for charts.
- `PUT /settings/default-model` - update the default backend model.
- `DELETE /history` - clear in-memory prediction history.

## Example Prediction Request

```json
{
  "model_key": "features_randomforest",
  "code": "#include <string.h>\nvoid copy(char *src) { char buf[8]; strcpy(buf, src); }"
}
```

## Notes

The backend uses model artifacts copied from Assignment 2 into `backend/model`.
Assignment 2 files are not edited by this backend.

Use Python 3.13 with scikit-learn 1.8.0. The Assignment 2 model files were saved
with scikit-learn 1.8.0, so older sklearn versions can load the files but fail
during prediction.
