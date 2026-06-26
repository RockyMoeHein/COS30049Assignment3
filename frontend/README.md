# Assignment 3 Frontend

React frontend for the C/C++ vulnerability detection web application.

## Main Libraries

- React
- React Router
- D3.js
- react-scripts

## Run the Full Application

From this folder:

```bash
npm install
npm run dev
```

This starts both:

- React frontend at `http://127.0.0.1:3000`
- FastAPI backend at `http://127.0.0.1:8000`

The first run also creates the backend Python virtual environment and installs
the backend dependencies.

## Run Frontend Only

```bash
npm install
npm start
```

Use this only when the backend is already running separately.

## Backend URL Configuration

The frontend uses `http://127.0.0.1:8000` by default. To change it, create a
`.env` file in this folder:

```text
REACT_APP_API_URL=http://127.0.0.1:8000
```

Restart React after changing `.env`.

## Pages

- `/` - Home page
- `/analysis` - Code analysis, model selection, classical model comparison, and risk explanation
- `/statistics` - D3.js dataset visualisations
- `/about` - Project and team information

## Useful Commands

```bash
npm run dev
npm start
npm run build
npm test -- --watchAll=false
```
