const fs = require("fs");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const backendDir = path.resolve(__dirname, "../../backend");
const isWindows = process.platform === "win32";
const backendPort = process.env.BACKEND_PORT || "8000";

const localPythonPaths = isWindows
  ? [
      ".venv313/Scripts/python.exe",
      ".venv/Scripts/python.exe",
      "venv/Scripts/python.exe",
    ]
  : [
      ".venv313/bin/python",
      ".venv/bin/python",
      "venv/bin/python",
    ];

const systemPythonCommands = isWindows
  ? [
      { command: "py", prefixArgs: ["-3.13"] },
      { command: "python", prefixArgs: [] },
    ]
  : [
      { command: "python3.13", prefixArgs: [] },
      { command: "python3", prefixArgs: [] },
      { command: "python", prefixArgs: [] },
    ];

function findPython() {
  for (const relativePath of localPythonPaths) {
    const fullPath = path.join(backendDir, relativePath);
    if (fs.existsSync(fullPath) && isPython313(fullPath, [])) {
      return { command: fullPath, prefixArgs: [] };
    }
  }

  for (const candidate of systemPythonCommands) {
    if (isPython313(candidate.command, candidate.prefixArgs)) return candidate;
  }

  return null;
}

function isPython313(command, prefixArgs) {
  const check = spawnSync(
    command,
    [
      ...prefixArgs,
      "-c",
      "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 13) else 1)",
    ],
    { encoding: "utf8", shell: false }
  );
  return check.status === 0;
}

const python = findPython();

if (!python) {
  console.error(
    [
      "Python was not found.",
      "Install Python 3.13, then create the backend virtual environment:",
      "",
      isWindows
        ? "  cd backend && py -3.13 -m venv .venv313"
        : "  cd backend && python3.13 -m venv .venv313",
      "",
      "Install packages with:",
      isWindows
        ? "  .venv313\\Scripts\\python.exe -m pip install -r requirements.txt"
        : "  .venv313/bin/python -m pip install -r requirements.txt",
    ].join("\n")
  );
  process.exit(1);
}

const backend = spawn(
  python.command,
  [
    ...python.prefixArgs,
    "-m",
    "uvicorn",
    "app.main:app",
    "--host",
    "127.0.0.1",
    "--port",
    backendPort,
  ],
  {
    cwd: backendDir,
    stdio: "inherit",
    shell: false,
  }
);

backend.on("error", (error) => {
  console.error(`Could not start the backend: ${error.message}`);
  process.exit(1);
});

backend.on("exit", (code, signal) => {
  process.exit(signal ? 0 : code ?? 0);
});
