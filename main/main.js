const { app, BrowserWindow, ipcMain } = require("electron");
const serve = require('electron-serve');
const path = require("path");
const { exec } = require("child_process");
const util = require("util");
const execPromise = util.promisify(exec);

const appServe = app.isPackaged ? serve({
  directory: path.join(__dirname, "../out")
}) : null;


const createWindow = () => {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    show: false, // Don't show until ready
    webPreferences: {
      preload: path.join(__dirname, "preload.js")
    }
  });

  const showWhenReady = () => {
    if (!win.isVisible()) win.show();
  };

  if (app.isPackaged) {
    appServe(win).then(() => {
      win.loadURL("app://-");
      win.webContents.once("did-finish-load", showWhenReady);
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