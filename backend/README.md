# Assignment 3 Backend

FastAPI backend for the C/C++ vulnerability detection web application.

## Setup

Use Python 3.13 because the Assignment 2 models were created with
scikit-learn 1.8.0.

### Windows

```powershell
cd COS30049Assignment3/backend
py -3.13 -m venv .venv313
.venv313\Scripts\python.exe -m pip install -r requirements.txt
```

### macOS or Linux

```bash
cd COS30049Assignment3/backend
python3.13 -m venv .venv313
source .venv313/bin/activate
python -m pip install -r requirements.txt
```

## Run

From the frontend folder, start React and FastAPI together on any supported
operating system:

```bash
cd ../frontend
npm install
npm run dev
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

The cross-platform launcher checks `.venv313`, `.venv`, and `venv`, then falls
back to an installed Python command. The Assignment 2 model files were saved
with scikit-learn 1.8.0, so older sklearn versions can load the files but fail
during prediction.
