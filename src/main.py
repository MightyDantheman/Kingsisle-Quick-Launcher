import os
import sys
import base64
import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import subprocess
import ctypes
import time
import threading

# =====================================================================
# CONFIGURATION & CONSTANTS
# =====================================================================

# These are kept for future use (screen-relative coordinates), but
# currently the login UI uses keyboard navigation only.
ACCOUNT_CLICK_POS = (0.5, 0.4)
PASSWORD_CLICK_POS = (0.5, 0.5)
OK_BUTTON_CLICK_POS = (0.5, 0.6)

# Filenames (relative to script/exe directory)
CREDS_FILENAME = "creds.txt"       # Stores encrypted username/password + server keys
KI_ICON_FILENAME = "ki_icon.ico"   # Icon for the game selection window

# Wizard101 assets
W101_LOGO_FILENAME = "w101_logo.png"
W101_WINDOW_ICON_FILENAME = "w101_launcher.ico"
W101_SELECTION_ICON_FILENAME = "w101_icon.png"

# Pirate101 assets
P101_LOGO_FILENAME = "p101_logo.png"
P101_WINDOW_ICON_FILENAME = "p101_launcher.ico"
P101_SELECTION_ICON_FILENAME = "p101_icon.png"

# "Encryption" key (simple obfuscation)
SECRET_KEY = b"change_this_key"    # You can change this to any bytes

IS_WINDOWS = (os.name == "nt")

# Server definitions
SERVERS_W101 = {
    "US": "login.us.wizard101.com 12000",
    "EU": "login.eu.wizard101.com 12000",
}

SERVERS_P101 = {
    "US": "login.us.pirate101.com 12000",
    "EU": "login.eu.pirate101.com 12000",
}

# Base game configs (logic uses copies with paths filled in)
GAME_CONFIGS_BASE = [
    {
        "id": "w101",
        "name": "Wizard101",
        "shortcut_dir": "Wizard101",
        "shortcut_name": "Play Wizard101.lnk",
        "client_name": "WizardGraphicalClient.exe",
        "servers": SERVERS_W101,
        "logo_file": W101_LOGO_FILENAME,
        "window_icon_file": W101_WINDOW_ICON_FILENAME,
        "selection_icon_file": W101_SELECTION_ICON_FILENAME,
    },
    {
        "id": "p101",
        "name": "Pirate101",
        "shortcut_dir": "Pirate101",
        "shortcut_name": "Play Pirate101.lnk",
        "client_name": "Pirate.exe",
        "servers": SERVERS_P101,
        "logo_file": P101_LOGO_FILENAME,
        "window_icon_file": P101_WINDOW_ICON_FILENAME,
        "selection_icon_file": P101_SELECTION_ICON_FILENAME,
    },
]

# =====================================================================
# PATH HANDLING
# =====================================================================

def get_dirs() -> tuple[Path, Path]:
    """
    Return (BASE_DIR, RESOURCE_DIR).

    BASE_DIR:
        - Where we store user data like creds.txt.
        - For a frozen EXE: the folder containing the EXE.
        - For a normal script: the folder containing this .py file.

    RESOURCE_DIR:
        - Where bundled assets (icons, PNGs, etc.) live.
        - For a frozen EXE with PyInstaller --onefile: sys._MEIPASS.
        - For a normal script: same as BASE_DIR.
    """
    # PyInstaller onefile: resources extracted to _MEIPASS, exe lives elsewhere
    if hasattr(sys, "_MEIPASS"):
        resource_dir = Path(sys._MEIPASS)
        base_dir = Path(sys.executable).parent
    # Frozen but not onefile – treat exe dir as both
    elif getattr(sys, "frozen", False):
        base_dir = Path(sys.executable).parent
        resource_dir = base_dir
    else:
        base_dir = Path(__file__).parent
        resource_dir = base_dir

    return base_dir, resource_dir


BASE_DIR, RESOURCE_DIR = get_dirs()

# User data (persist between runs)
CREDS_PATH = BASE_DIR / CREDS_FILENAME

# Bundled assets (icons/images)
KI_ICON_PATH = RESOURCE_DIR / KI_ICON_FILENAME

# =====================================================================
# SIMPLE ENCRYPTION / DECRYPTION (OBFUSCATION)
# =====================================================================

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    XOR each byte of `data` with the key (repeating as needed).
    This is NOT strong encryption, just obfuscation.
    """
    if not key:
        raise ValueError("Key must not be empty.")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encrypt_text(plain: str) -> str:
    """Encrypt a string using XOR + base64."""
    if plain == "":
        return ""
    data = plain.encode("utf-8")
    xored = xor_bytes(data, SECRET_KEY)
    return base64.b64encode(xored).decode("ascii")


def decrypt_text(enc: str) -> str:
    """Decrypt a string previously produced by encrypt_text()."""
    if enc == "":
        return ""
    try:
        xored = base64.b64decode(enc.encode("ascii"))
        data = xor_bytes(xored, SECRET_KEY)
        return data.decode("utf-8", errors="replace")
    except Exception:
        # Treat as empty if something goes wrong
        return ""

# =====================================================================
# CREDENTIALS LOAD / SAVE
# =====================================================================

def reset_creds_file():
    """
    Reset the credentials file to four empty lines:
    1: username (encrypted, or empty)
    2: password (encrypted, or empty)
    3: W101 server key (US/EU)
    4: P101 server key (US/EU)
    """
    try:
        with CREDS_PATH.open("w", encoding="utf-8") as f:
            f.write("\n\n\n\n")
    except Exception:
        pass


def load_credentials():
    """
    Read encrypted username/password and server keys from CREDS_PATH.

    Returns:
        (username, password, w101_server_key, p101_server_key)

    Defaults:
        username/password: ""
        server keys: "US" (if missing/invalid)
    """
    if not CREDS_PATH.exists():
        return "", "", "US", "US"

    try:
        with CREDS_PATH.open("r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except Exception:
        return "", "", "US", "US"

    if len(lines) < 4:
        lines += [""] * (4 - len(lines))

    enc_user = (lines[0] or "").strip()
    enc_pass = (lines[1] or "").strip()
    w101_key_raw = (lines[2] or "").strip()
    p101_key_raw = (lines[3] or "").strip()

    username = decrypt_text(enc_user) if enc_user else ""
    password = decrypt_text(enc_pass) if enc_pass else ""

    corrupt_user = bool(enc_user) and username == ""
    corrupt_pass = bool(enc_pass) and password == ""

    if corrupt_user or corrupt_pass:
        reset_creds_file()
        return "", "", "US", "US"

    w101_key = w101_key_raw if w101_key_raw in SERVERS_W101 else "US"
    p101_key = p101_key_raw if p101_key_raw in SERVERS_P101 else "US"

    return username, password, w101_key, p101_key


def save_credentials(username: str, password: str,
                     remember_user: bool, remember_pass: bool,
                     w101_server_key: str, p101_server_key: str):
    """
    Save encrypted username/password and server keys to CREDS_PATH.

    Lines:
        1: encrypted username (or empty)
        2: encrypted password (or empty)
        3: W101 server key (US/EU) or empty if invalid (defaults to US on load)
        4: P101 server key (US/EU) or empty if invalid (defaults to US on load)
    """
    enc_user = encrypt_text(username) if remember_user and username else ""
    enc_pass = encrypt_text(password) if remember_pass and password else ""

    if w101_server_key not in SERVERS_W101:
        w101_server_key = ""
    if p101_server_key not in SERVERS_P101:
        p101_server_key = ""

    try:
        with CREDS_PATH.open("w", encoding="utf-8") as f:
            f.write(enc_user + "\n")
            f.write(enc_pass + "\n")
            f.write(w101_server_key + "\n")
            f.write(p101_server_key + "\n")
    except Exception as e:
        messagebox.showwarning("Warning", f"Failed to save credentials:\n{e}")

# =====================================================================
# POWERSHELL HELPERS (WINDOWS)
# =====================================================================

def _ps_check_output(args: str) -> str:
    """
    Helper to run PowerShell with no window and return decoded output.
    """
    creation_flags = 0
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        creation_flags = subprocess.CREATE_NO_WINDOW

    out = subprocess.check_output(
        ["powershell", "-NoProfile", "-Command", args],
        creationflags=creation_flags
    )
    return out.decode("utf-8", errors="ignore")

# =====================================================================
# SHORTCUT (.LNK) RESOLUTION (WINDOWS)
# =====================================================================

def resolve_shortcut_target(lnk_path: Path) -> Path | None:
    """
    Resolve a Windows .lnk shortcut to its target path using PowerShell
    and WScript.Shell. Uses only standard tools.
    """
    if not IS_WINDOWS:
        return None

    if not lnk_path.exists():
        return None

    try:
        ps_script = (
            f"(New-Object -ComObject WScript.Shell)"
            f".CreateShortcut('{lnk_path}').TargetPath"
        )
        target = _ps_check_output(ps_script).strip()
        if not target:
            return None
        return Path(target)
    except Exception:
        return None

# =====================================================================
# GAME EXECUTABLE DISCOVERY
# =====================================================================

def find_executable_for_game(game_cfg: dict) -> Path | None:
    r"""
    Find the game's graphical executable using the Start Menu shortcut.

    For Wizard101:
        %APPDATA%\Microsoft\Windows\Start Menu\Programs\
          KingsIsle Entertainment\Wizard101\Play Wizard101.lnk
        -> Wizard101.exe -> Bin\WizardGraphicalClient.exe

    For Pirate101:
        %APPDATA%\Microsoft\Windows\Start Menu\Programs\
          KingsIsle Entertainment\Pirate101\Play Pirate101.lnk
        -> Pirate101.exe -> Bin\Pirate.exe
    """
    if not IS_WINDOWS:
        return None

    appdata = os.environ.get("APPDATA")
    if not appdata:
        return None

    start_menu_dir = (
        Path(appdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "KingsIsle Entertainment"
        / game_cfg["shortcut_dir"]
    )

    shortcut = start_menu_dir / game_cfg["shortcut_name"]

    if not shortcut.exists() and start_menu_dir.exists():
        for p in start_menu_dir.glob("*.lnk"):
            if p.stem.startswith("Play " + game_cfg["shortcut_dir"]):
                shortcut = p
                break

    target_exe = resolve_shortcut_target(shortcut)
    if target_exe is None or not target_exe.exists():
        return None

    install_dir = target_exe.parent
    bin_dir = install_dir / "Bin"
    client_exe = bin_dir / game_cfg["client_name"]

    if client_exe.exists():
        return client_exe

    return None


def build_game_args(game_cfg: dict, server_key: str) -> list[str]:
    """
    Build the command-line arguments for the game's graphical client:
        -r -L <host> <port>
    """
    servers = game_cfg["servers"]
    if server_key not in servers:
        server_key = "US"

    host_port = servers[server_key].split()
    return ["-r", "-L", *host_port]


def launch_target_executable(game_cfg: dict, server_key: str) -> bool:
    """
    Launch the game's graphical client with arguments based on
    the selected server, hiding the console window.

    Expects game_cfg["client_path"] to exist.
    """
    exe_path: Path | None = game_cfg.get("client_path")
    if exe_path is None or not exe_path.exists():
        messagebox.showerror(
            "Error",
            f"Could not find {game_cfg['name']} executable.\n\n"
            "Make sure the game is installed and its Start Menu shortcut exists."
        )
        return False

    try:
        args = [str(exe_path), *build_game_args(game_cfg, server_key)]

        creation_flags = 0
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            creation_flags = subprocess.CREATE_NO_WINDOW

        subprocess.Popen(
            args,
            cwd=str(exe_path.parent),
            creationflags=creation_flags
        )
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Failed to launch executable:\n{e}")
        return False

# =====================================================================
# FOREGROUND WINDOW / KEYBOARD INPUT / PIXEL CHECK (WINDOWS)
# =====================================================================

if IS_WINDOWS:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

    KEYEVENTF_KEYUP = 0x0002
    VK_SHIFT = 0x10
    VK_TAB = 0x09
    VK_RETURN = 0x0D
    VK_SPACE = 0x20

    GetForegroundWindow = user32.GetForegroundWindow
    SetForegroundWindow = user32.SetForegroundWindow
    ShowWindow = user32.ShowWindow
    GetSystemMetrics = user32.GetSystemMetrics
    GetDC = user32.GetDC
    ReleaseDC = user32.ReleaseDC
    GetPixel = gdi32.GetPixel

    SM_CXSCREEN = 0
    SM_CYSCREEN = 1

    SW_RESTORE = 9

    CHAR_MAP = {
        " ": (VK_SPACE, False),

        "-": (0xBD, False),
        "_": (0xBD, True),

        "=": (0xBB, False),
        "+": (0xBB, True),

        "[": (0xDB, False),
        "{": (0xDB, True),

        "]": (0xDD, False),
        "}": (0xDD, True),

        "\\": (0xDC, False),
        "|": (0xDC, True),

        ";": (0xBA, False),
        ":": (0xBA, True),

        "'": (0xDE, False),
        '"': (0xDE, True),

        ",": (0xBC, False),
        "<": (0xBC, True),

        ".": (0xBE, False),
        ">": (0xBE, True),

        "/": (0xBF, False),
        "?": (0xBF, True),

        "`": (0xC0, False),
        "~": (0xC0, True),

        "!": (ord("1"), True),
        "@": (ord("2"), True),
        "#": (ord("3"), True),
        "$": (ord("4"), True),
        "%": (ord("5"), True),
        "^": (ord("6"), True),
        "&": (ord("7"), True),
        "*": (ord("8"), True),
        "(": (ord("9"), True),
        ")": (ord("0"), True),
    }


def wait_for_foreground_change(exclude_hwnd: int,
                               timeout: float = 10.0,
                               poll_interval: float = 0.1) -> int | None:
    """
    Wait until the foreground window changes to something that is
    not `exclude_hwnd`. Returns the new foreground HWND, or None on timeout.
    """
    if not IS_WINDOWS:
        return None

    end_time = time.time() + timeout
    while time.time() < end_time:
        hwnd = GetForegroundWindow()
        if hwnd and hwnd != exclude_hwnd:
            return hwnd
        time.sleep(poll_interval)
    return None


def focus_window(hwnd: int) -> bool:
    """Bring the given window to the foreground and restore it if minimized."""
    if not IS_WINDOWS:
        return False

    ShowWindow(hwnd, SW_RESTORE)
    time.sleep(0.05)
    result = SetForegroundWindow(hwnd)
    return bool(result)


def get_corner_pixels():
    """
    Read the RGB values of the four screen corners:
        (0,0), (w-1,0), (0,h-1), (w-1,h-1)
    """
    if not IS_WINDOWS:
        return None

    width = GetSystemMetrics(SM_CXSCREEN)
    height = GetSystemMetrics(SM_CYSCREEN)
    if width <= 0 or height <= 0:
        return None

    hdc = GetDC(0)
    if not hdc:
        return None

    coords = [
        (0, 0),
        (width - 1, 0),
        (0, height - 1),
        (width - 1, height - 1),
    ]
    colors = []

    try:
        for x, y in coords:
            colorref = GetPixel(hdc, x, y)
            if colorref == -1:
                colors.append(None)
            else:
                r = colorref & 0xFF
                g = (colorref >> 8) & 0xFF
                b = (colorref >> 16) & 0xFF
                colors.append((r, g, b))
    finally:
        ReleaseDC(0, hdc)

    return colors


def wait_for_black_corners(timeout: float = 20.0,
                           poll_interval: float = 0.1) -> bool:
    """
    Wait until each corner pixel of the screen is fully black (0,0,0),
    or until timeout expires.
    """
    if not IS_WINDOWS:
        return False

    end_time = time.time() + timeout
    while time.time() < end_time:
        colors = get_corner_pixels()
        if colors and all(c is not None and c == (0, 0, 0) for c in colors):
            return True
        time.sleep(poll_interval)
    return False


def _press_key(vk: int):
    if not IS_WINDOWS:
        return
    user32.keybd_event(vk, 0, 0, 0)


def _release_key(vk: int):
    if not IS_WINDOWS:
        return
    user32.keybd_event(vk, 0, KEYEVENTF_KEYUP, 0)


def _get_vk_for_char(ch: str):
    """
    Return (vk_code, use_shift) for a given character on a US keyboard.
    """
    if not ch:
        return None, False

    if "a" <= ch <= "z":
        return ord(ch.upper()), False
    if "A" <= ch <= "Z":
        return ord(ch), True

    if "0" <= ch <= "9":
        return ord(ch), False

    if ch in CHAR_MAP:
        return CHAR_MAP[ch]

    return None, False


def send_text(text: str, per_char_delay: float = 0.01):
    """Type the given string as keyboard input, handling Shift as needed."""
    if not IS_WINDOWS:
        return

    for ch in text:
        vk, use_shift = _get_vk_for_char(ch)
        if vk is None:
            continue

        if use_shift:
            _press_key(VK_SHIFT)
            time.sleep(per_char_delay)

        _press_key(vk)
        time.sleep(per_char_delay)
        _release_key(vk)
        time.sleep(per_char_delay)

        if use_shift:
            _release_key(VK_SHIFT)
            time.sleep(per_char_delay)


def send_tab():
    if not IS_WINDOWS:
        return
    _press_key(VK_TAB)
    time.sleep(0.01)
    _release_key(VK_TAB)
    time.sleep(0.01)


def send_enter():
    if not IS_WINDOWS:
        return
    _press_key(VK_RETURN)
    time.sleep(0.01)
    _release_key(VK_RETURN)
    time.sleep(0.01)

# =====================================================================
# GAME LOGIN UI (PER-GAME)
# =====================================================================

class LoginApp:
    def __init__(self, root: tk.Tk, game_cfg: dict):
        self.root = root
        self.game = game_cfg
        self.servers = self.game["servers"]

        self.root.title(f"{self.game['name']} Quick Launcher")
        self.root.resizable(False, False)

        # Close behavior: end entire script if user closes this window
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Window icon for this game
        window_icon_path = self.game.get("window_icon_path")
        if IS_WINDOWS and window_icon_path and window_icon_path.exists():
            try:
                self.root.iconbitmap(str(window_icon_path))
            except Exception:
                pass

        # HWND of our own window (for foreground-change detection)
        self.root_hwnd = self.root.winfo_id() if IS_WINDOWS else None

        # Tk variables
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.remember_user_var = tk.BooleanVar(value=False)
        self.remember_pass_var = tk.BooleanVar(value=False)
        self.server_var = tk.StringVar(value="US")

        # Copies used by automation thread (plain Python, no Tk)
        self.auto_username = ""
        self.auto_password = ""

        # Load existing credentials
        self._load_existing_credentials()

        # Build UI
        self._create_widgets()
        self._layout_widgets()

    def on_close(self):
        self.root.destroy()
        sys.exit(0)

    # -----------------------------------------------------------------
    # Helper to show errors from background thread
    # -----------------------------------------------------------------

    def _show_error(self, title: str, message: str):
        def _inner():
            messagebox.showerror(title, message)
            self.login_button.config(state="normal")
        self.root.after(0, _inner)

    # -----------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------

    def _create_widgets(self):
        # Top: logo
        self.logo_frame = tk.Frame(self.root)
        self.logo_label = tk.Label(self.logo_frame, text="Logo goes here")

        self.logo_image = None
        logo_path = self.game.get("logo_path")
        if logo_path and logo_path.exists():
            try:
                self.logo_image = tk.PhotoImage(file=str(logo_path))
                self.logo_label.configure(image=self.logo_image, text="")
            except Exception:
                self.logo_label.configure(text=self.game["name"])

        # Bottom: login fields + button
        self.bottom_frame = tk.Frame(self.root)

        self.username_label = tk.Label(self.bottom_frame, text="Username:")
        self.username_entry = tk.Entry(
            self.bottom_frame, textvariable=self.username_var, width=30
        )
        self.remember_user_cb = tk.Checkbutton(
            self.bottom_frame, text="Remember me?",
            variable=self.remember_user_var
        )

        self.password_label = tk.Label(self.bottom_frame, text="Password:")
        self.password_entry = tk.Entry(
            self.bottom_frame, textvariable=self.password_var,
            show="*", width=30
        )
        self.remember_pass_cb = tk.Checkbutton(
            self.bottom_frame, text="Remember me?",
            variable=self.remember_pass_var
        )

        self.login_button = tk.Button(
            self.bottom_frame, text="Login",
            command=self.on_login_clicked
        )

        # Server selection + credits row
        self.server_frame = tk.Frame(self.root)
        self.server_label = tk.Label(self.server_frame, text="Server:")
        self.server_menu = tk.OptionMenu(
            self.server_frame,
            self.server_var,
            *self.servers.keys()
        )

        # Credits on bottom right (same row as server selection)
        credits_text = "Credits: MightyDantheman | Images © KingsIsle Entertainment"
        self.credits_label = tk.Label(
            self.server_frame,
            text=credits_text,
            font=("Segoe UI", 8)
        )

        # Legal disclaimer line below everything
        legal_text = (
            "Unofficial launcher. Not affiliated with or endorsed by "
            "KingsIsle Entertainment or any of their games."
        )
        self.legal_label = tk.Label(
            self.root,
            text=legal_text,
            font=("Segoe UI", 7)
        )

    def _layout_widgets(self):
        self.logo_frame.pack(fill="x", padx=10, pady=(10, 5))
        self.logo_label.pack(pady=5)

        self.bottom_frame.pack(fill="x", padx=10, pady=(5, 5))

        self.username_label.grid(row=0, column=0, sticky="e", padx=(0, 5), pady=5)
        self.username_entry.grid(row=0, column=1, sticky="we", padx=(0, 5), pady=5)
        self.remember_user_cb.grid(row=0, column=2, sticky="w", padx=(0, 5), pady=5)

        self.password_label.grid(row=1, column=0, sticky="e", padx=(0, 5), pady=5)
        self.password_entry.grid(row=1, column=1, sticky="we", padx=(0, 5), pady=5)
        self.remember_pass_cb.grid(row=1, column=2, sticky="w", padx=(0, 5), pady=5)

        self.login_button.grid(row=0, column=3, rowspan=2, sticky="nswe",
                               padx=(10, 0), pady=5)

        self.bottom_frame.columnconfigure(1, weight=1)

        # Server row + credits
        self.server_frame.pack(fill="x", padx=10, pady=(0, 2))
        self.server_label.pack(side="left")
        self.server_menu.pack(side="left", padx=(5, 0))
        self.credits_label.pack(side="right")

        # Legal disclaimer at very bottom
        self.legal_label.pack(fill="x", padx=10, pady=(0, 8))

    # -----------------------------------------------------------------
    # Logic
    # -----------------------------------------------------------------

    def _load_existing_credentials(self):
        username, password, w101_server_key, p101_server_key = load_credentials()
        if username:
            self.username_var.set(username)
            self.remember_user_var.set(True)
        if password:
            self.password_var.set(password)
            self.remember_pass_var.set(True)

        if self.game["id"] == "w101":
            server_key = w101_server_key
        else:
            server_key = p101_server_key

        if server_key in self.servers:
            self.server_var.set(server_key)
        else:
            self.server_var.set("US")

    def on_login_clicked(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        server_key = self.server_var.get().strip()

        if not username or not password:
            messagebox.showerror(
                "Error",
                "Both username and password must be filled in."
            )
            return

        # Load existing server keys to preserve the other game's setting
        _, _, w101_key, p101_key = load_credentials()

        if self.game["id"] == "w101":
            w101_key = server_key
        else:
            p101_key = server_key

        # Decide what to store for username/password
        store_user = username if self.remember_user_var.get() else ""
        store_pass = password if self.remember_pass_var.get() else ""

        save_credentials(
            store_user,
            store_pass,
            self.remember_user_var.get(),
            self.remember_pass_var.get(),
            w101_key,
            p101_key
        )

        # Save copies for automation thread (no Tk access there)
        self.auto_username = username
        self.auto_password = password

        # Disable button to prevent spamming
        self.login_button.config(state="disabled")

        ok = launch_target_executable(self.game, server_key)
        if not ok:
            self.login_button.config(state="normal")
            return

        # Run automation in a background thread so UI stays responsive
        t = threading.Thread(target=self._automation_thread, daemon=True)
        t.start()

    def _automation_thread(self):
        """
        Background automation:
        - Wait for foreground window to change away from our UI.
        - Try to focus it (but don't abort if it fails).
        - Wait until all four corners are black (or timeout).
        - Ask main thread to hide the UI.
        - Type username, TAB, password, ENTER.
        - Ask main thread to quit the Tk loop.
        """
        if not IS_WINDOWS:
            self._show_error(
                "Error",
                "Post-launch automation is only implemented on Windows."
            )
            return

        hwnd = wait_for_foreground_change(self.root_hwnd, timeout=10.0)
        if not hwnd:
            self._show_error(
                "Error",
                "Failed to detect the game window within the time limit.\n"
                "Automation has been cancelled."
            )
            return

        # Try to focus for up to ~2 seconds, but don't treat failure as fatal.
        end_focus = time.time() + 2.0
        while time.time() < end_focus:
            if focus_window(hwnd):
                break
            time.sleep(0.1)

        # Wait for the fullscreen black background
        wait_for_black_corners(timeout=20.0, poll_interval=0.1)
        time.sleep(0.5)

        # Hide the launcher window so keystrokes go to the game
        self.root.after(0, self.root.withdraw)
        time.sleep(0.2)

        # Type credentials
        send_text(self.auto_username.strip())
        send_tab()
        send_text(self.auto_password.strip())
        send_enter()

        time.sleep(0.5)
        self.root.after(0, self.root.quit)

# =====================================================================
# GAME SELECTION UI
# =====================================================================

class GameSelectionApp:
    def __init__(self, root: tk.Tk, games: list[dict]):
        self.root = root
        self.games = games
        self.selected_game: dict | None = None
        self.icon_images = []

        self.root.title("Game Selection")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Selection window icon
        if IS_WINDOWS and KI_ICON_PATH.exists():
            try:
                self.root.iconbitmap(str(KI_ICON_PATH))
            except Exception:
                pass

        self._create_widgets()

    def on_close(self):
        self.selected_game = None
        self.root.destroy()

    def _on_game_clicked(self, game: dict):
        self.selected_game = game
        self.root.destroy()

    def _create_widgets(self):
        frame = tk.Frame(self.root)
        frame.pack(padx=10, pady=10)

        label = tk.Label(frame, text="Select a game:", font=("Segoe UI", 11, "bold"))
        label.grid(row=0, column=0, columnspan=3, pady=(0, 10))

        num_cols = 3
        for idx, game in enumerate(self.games):
            row = 1 + idx // num_cols
            col = idx % num_cols

            icon_path = game.get("selection_icon_path")
            img = None
            if icon_path and icon_path.exists():
                try:
                    img = tk.PhotoImage(file=str(icon_path))
                except Exception:
                    img = None

            if img is None:
                btn = tk.Button(
                    frame,
                    text=game["name"],
                    width=18,
                    command=lambda g=game: self._on_game_clicked(g)
                )
            else:
                self.icon_images.append(img)
                btn = tk.Button(
                    frame,
                    image=img,
                    text=game["name"],
                    compound="top",
                    width=img.width(),
                    height=img.height() + 20,
                    command=lambda g=game: self._on_game_clicked(g)
                )

            btn.grid(row=row, column=col, padx=10, pady=10)

# =====================================================================
# DISCOVER AVAILABLE GAMES & MAIN FLOW
# =====================================================================

def prepare_game_configs() -> list[dict]:
    """
    Discover which supported games are available (installed + have selection icon),
    and return a list of fully prepared game configs with paths.
    """
    available = []

    for base_cfg in GAME_CONFIGS_BASE:
        exe_path = find_executable_for_game(base_cfg)
        selection_icon_path = RESOURCE_DIR / base_cfg["selection_icon_file"]

        # Game must be installed AND have a selection icon PNG to show up
        if exe_path is None or not selection_icon_path.exists():
            continue

        game_cfg = dict(base_cfg)
        game_cfg["client_path"] = exe_path
        game_cfg["selection_icon_path"] = selection_icon_path
        game_cfg["logo_path"] = RESOURCE_DIR / base_cfg["logo_file"]
        game_cfg["window_icon_path"] = RESOURCE_DIR / base_cfg["window_icon_file"]

        available.append(game_cfg)

    return available


def run_login_for_game(game_cfg: dict):
    root = tk.Tk()
    app = LoginApp(root, game_cfg)
    # Optional geometry tweak:
    # root.geometry("650x300")
    root.mainloop()


def main():
    if not IS_WINDOWS:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Error", "This launcher is only implemented for Windows.")
        root.destroy()
        return

    games = prepare_game_configs()

    if not games:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Error",
            "No supported games were found.\n\n"
            "Make sure Wizard101 and/or Pirate101 are installed and that "
            "their selection icon PNGs are present."
        )
        root.destroy()
        return

    if len(games) == 1:
        # Skip game selection UI; go straight to login UI
        run_login_for_game(games[0])
        return

    # Multiple games: show selection window
    root = tk.Tk()
    app = GameSelectionApp(root, games)
    root.mainloop()

    selected = app.selected_game
    if not selected:
        # User closed selection window
        sys.exit(0)

    run_login_for_game(selected)


if __name__ == "__main__":
    main()
