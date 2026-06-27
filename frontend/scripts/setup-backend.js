const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const backendDir = path.resolve(__dirname, "../../backend");
const venvDir = path.join(backendDir, ".venv313");
const requirementsPath = path.join(backendDir, "requirements.txt");
const markerPath = path.join(venvDir, ".requirements.sha256");
const isWindows = process.platform === "win32";
const venvPython = path.join(
  venvDir,
  isWindows ? "Scripts/python.exe" : "bin/python"
);

const systemPythonCommands = isWindows
  ? [
      { command: "py", args: ["-3.13"] },
      { command: "python", args: [] },
    ]
  : [
      { command: "python3.13", args: [] },
      { command: "python3", args: [] },
      { command: "python", args: [] },
    ];

function run(command, args, options = {}) {
  // Run backend setup commands from the backend folder for consistent paths.
  return spawnSync(command, args, {
    cwd: backendDir,
    encoding: "utf8",
    shell: false,
    stdio: options.quiet ? "pipe" : "inherit",
  });
}

function isPython313(command, args = []) {
  // The saved Assignment 2 model files require Python 3.13 in this project.
  const result = run(
    command,
    [
      ...args,
      "-c",
      "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 13) else 1)",
    ],
    { quiet: true }
  );
  return result.status === 0;
}

function findSystemPython() {
  // Search common Python command names on both Windows and macOS/Linux.
  return systemPythonCommands.find(({ command, args }) =>
    isPython313(command, args)
  );
}

function backendPackagesWork() {
  // Verify the virtual environment can import the backend's required packages.
  if (!fs.existsSync(venvPython)) return false;

  const imports = [
    "import fastapi, uvicorn, pydantic, pandas, numpy, joblib, xgboost, torch, transformers",
    "import sklearn",
    "assert sklearn.__version__ == '1.8.0'",
  ].join("; ");

  return run(venvPython, ["-c", imports], { quiet: true }).status === 0;
}

function requirementsHash() {
  // Track requirement changes so packages reinstall only when needed.
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(requirementsPath))
    .digest("hex");
}

function fail(message) {
  console.error(`\nBackend setup failed: ${message}\n`);
  process.exit(1);
}

if (!fs.existsSync(requirementsPath)) {
  fail(`requirements.txt was not found at ${requirementsPath}`);
}

if (!fs.existsSync(venvPython)) {
  // First run: create backend/.venv313 automatically for the user.
  const python = findSystemPython();
  if (!python) {
    fail(
      "Install Python 3.13 and make it available as py -3.13, python3.13, or python."
    );
  }

  console.log("Creating the Python 3.13 backend environment...");
  const create = run(python.command, [...python.args, "-m", "venv", ".venv313"]);
  if (create.status !== 0) fail("The Python virtual environment could not be created.");
}

if (!isPython313(venvPython)) {
  fail(
    "backend/.venv313 exists but does not use Python 3.13. Delete that folder and run npm run dev again."
  );
}

const currentHash = requirementsHash();
const savedHash = fs.existsSync(markerPath)
  ? fs.readFileSync(markerPath, "utf8").trim()
  : "";

if (savedHash === currentHash && backendPackagesWork()) {
  // Fast path for later runs when requirements have not changed.
  console.log("Backend environment is ready.");
  process.exit(0);
}

if (!savedHash && backendPackagesWork()) {
  fs.writeFileSync(markerPath, currentHash);
  console.log("Backend environment is ready.");
  process.exit(0);
}

console.log("Installing backend packages. The first setup may take several minutes...");
// Install Python dependencies only after the venv and version checks pass.
const install = run(venvPython, [
  "-m",
  "pip",
  "install",
  "-r",
  requirementsPath,
]);

if (install.status !== 0) {
  fail("Python packages could not be installed. Check the internet connection and try again.");
}

if (!backendPackagesWork()) {
  fail("Package installation finished, but the backend dependency check failed.");
}

fs.writeFileSync(markerPath, currentHash);
console.log("Backend environment is ready.");
