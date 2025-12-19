const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const { exec } = require("child_process");
const util = require("util");
const execPromise = util.promisify(exec);

async function startNextServer() {
  const next = require("next");
  const http = require("http");

  const projectDir = path.join(__dirname, "..");
  process.chdir(projectDir);

  const nextApp = next({ dev: false, dir: projectDir });
  const handle = nextApp.getRequestHandler();
  await nextApp.prepare();

  const server = http.createServer((req, res) => handle(req, res));
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  const port = address && typeof address === "object" ? address.port : 0;
  return { server, port };
}

const createWindow = () => {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    show: false, // Don't show until ready
    fullscreen: process.env.NODE_ENV === 'development' ? true : false, // Fullscreen in dev mode
    webPreferences: {
      preload: path.join(__dirname, "preload.js")
    }
  });

  const showWhenReady = () => {
    if (!win.isVisible()) win.show();
  };

  if (app.isPackaged) {
    startNextServer()
      .then(({ server, port }) => {
        win.on("closed", () => {
          try {
            server.close();
          } catch {
            // ignore
          }
        });
        win.loadURL(`http://127.0.0.1:${port}`);
        win.webContents.once("did-finish-load", showWhenReady);
      })
      .catch(() => {
        app.quit();
      });
  } else {
    win.loadURL("http://localhost:3000");
    // win.webContents.openDevTools(); // Disabled by default
    win.webContents.once("did-finish-load", showWhenReady);

    win.webContents.on("did-fail-load", (e, code, desc) => {
      win.webContents.reloadIgnoringCache();
    });
  }
};

app.on("ready", () => {
    createWindow();
});

app.on("window-all-closed", () => {
    if(process.platform !== "darwin"){
        app.quit();
    }
});

// Handle command execution
ipcMain.handle("execute-command", async (event, command) => {
    try {
        const { stdout, stderr } = await execPromise(command, { 
            shell: "powershell.exe",
            encoding: "utf8",
            cwd: app.getAppPath() // Set working directory to app directory
        });
        return {
            success: true,
            output: stdout,
            error: stderr
        };
    } catch (error) {
        return {
            success: false,
            output: error.stdout || "",
            error: error.stderr || error.message
        };
    }
});