# COS30049 Assignment 3

Machine-learning web application for detecting vulnerabilities in C/C++ code.

## Setup and Run

Install these prerequisites:

- Node.js
- Python 3.13

Then run:

```bash
cd COS30049Assignment3/frontend
npm install
npm run dev
```

On the first run, npm automatically creates the Python virtual environment and
installs the backend packages. This may take several minutes. Later runs skip
the installation unless `requirements.txt` changes.

The cross-platform command starts:

- React at `http://127.0.0.1:3000`
- FastAPI at `http://127.0.0.1:8000`
- API documentation at `http://127.0.0.1:8000/docs`
