# COS30049 Assignment 3

Machine-learning web application for detecting vulnerabilities in C/C++ code.

## First-Time Setup

Create the Python environment from the `backend` folder.

### Windows

```powershell
py -3.13 -m venv .venv313
.venv313\Scripts\python.exe -m pip install -r requirements.txt
```

### macOS or Linux

```bash
python3.13 -m venv .venv313
.venv313/bin/python -m pip install -r requirements.txt
```

Install the frontend packages:

```bash
cd ../frontend
npm install
```

## Run the Application

From the `frontend` folder:

```bash
npm run dev
```

This cross-platform command starts:

- React at `http://127.0.0.1:3000`
- FastAPI at `http://127.0.0.1:8000`
- API documentation at `http://127.0.0.1:8000/docs`
