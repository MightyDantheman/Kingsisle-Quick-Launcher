# KI Quick Launcher (Unofficial)

**KI Quick Launcher** is an unofficial fan-made tool that lets you quickly launch the main KingsIsle games:

- [Wizard101](https://www.wizard101.com/)
- [Pirate101](https://www.pirate101.com/)

Instead of opening the official launcher and having to have your game files scanned every single time, which will take longer the more game files that you have installed, you can use this tool to bypass the main launcher and load directly into the game.

> This tool is designed for the Windows operating system.

> ⚠️ This tool hasn't been widely tested yet, but it works on both of my computers. Please report if you run into any bugs.

This tool launches the graphical client with special parameters `-r` and `-L`, which will skip the launcher and connect to the appropriate server. This tool will then automatically log you in. While all of this could be done manually, the login area does not allow you to paste anything, which can make long and complex passwords difficult. This tool is an all-in-one solution.

The tool will save a `.txt` file in the same folder that the `.exe` or `.py` file is in. This `.txt` file stores launch information for future logins. The username and password, if the "remember" toggle is enabled, will be stored there encrypted as well.

> ⚠️ **Important:** This tool does **not** replace the official launcher. If the game has recently updated, you **must** run the official launcher first so it can patch your files. Trying to launch out-of-date game files may cause errors or prevent you from connecting.
>
> This tool also requires that you have the default Shortcuts in the Start Menu:
> `%APPDATA%\Microsoft\Windows\Start Menu\Programs\KingsIsle Entertainment`

---

## Usage

1. After launching, you'll first select an available game:
   *(This part will be skipped if you only have one game installed.)*
   
   <p align="center">
     <img src="images/KI Quick-Launcher - Game Selection.png" width="441">
   </p>

2. After selecting a game, you'll be able to select the correct server and login:

   <p align="center">
     <img src="images/KI Quick-Launcher - Wizard101.png" width="338">
     <img src="images/KI Quick-Launcher - Pirate101.png" width="338">
   </p>

---

## Download

You can download the latest version from the **Releases** page:

👉 [Download the latest release](https://github.com/MightyDantheman/KI-Quick-Launcher/releases)

Or directly download the `.exe` from the latest release on the right-hand side of this page.

---

## Safety

This tool does not automate gameplay, connect to the internet, or modify game files.

The executable has been scanned and checked with VirusTotal.

- VirusTotal report: [View scan results](https://www.virustotal.com/gui/file/2d089166868ee23d1540fa7061b7fce648d9604d68cb2844ccda49676eb07eaa)

> Note: Antivirus results can vary over time and by vendor. Always verify downloads from the official GitHub releases and scan them with your own antivirus if you have any doubts.

- The source python script's report: [View scan results](https://www.virustotal.com/gui/file/241b39e5769723048b71676d3572e49a645f3f1d07723392c1170d695a6d706a)

> <img src="images/Smart Icon.png" width="16"> **Code insights** *(directly from VirusTotal)*
>
> This code functions as a GUI-based launcher primarily for specific online games on Windows. It identifies installed game client executables by resolving Windows shortcut files (`.lnk`) via PowerShell. It then presents a `tkinter` user interface that allows the user to select a game, enter login credentials (username and password), and choose a game server.
> 
> Credentials provided by the user can be stored locally in a file named `creds.txt` within the script's directory. These stored credentials are obfuscated using a simple XOR cipher with a fixed key, followed by Base64 encoding. The code loads these obfuscated credentials on subsequent runs.
> 
> Upon user initiation, the launcher executes the selected game client process with specific command-line arguments. Following game launch, the launcher uses Windows API calls (`ctypes`) to perform automated actions: it detects when the game window becomes the foreground, attempts to bring it into focus, and then monitors screen pixels to detect a fullscreen black state. Subsequently, it simulates keyboard input to type the stored or entered username, presses the TAB key, types the password, and then presses ENTER, effectively automating the login process within the game's interface. During this automated input sequence, the launcher's own graphical interface is temporarily hidden. The code includes multiple checks and error handling for file operations and API calls. It is specifically designed for the Windows operating system.

---

## Warnings & Limitations

- This is an **unofficial** tool. It is **not** created by or affiliated with KingsIsle Entertainment.
- Using third-party tools to modify how you launch the game **may** be against the game’s Terms of Service or End User License Agreement.  
  I couldn't find anything against this myself, but: **Use at your own risk.**
- This tool relies on your existing game installation; it does **not** install or patch the game.
- If the game updates, you must use the **official launcher** to apply updates before using this tool again.

---

## Source Code

This project is open source. You can browse the code in the [`src/`](./src) directory.

Direct images or icons will not be provided.

If building the tool yourself, this is what the folder should look like:

```text
KI-Quick-Launcher/
├─ ki_icon.ico
├─ main.py
├─ p101_icon.png
├─ p101_launcher.ico
├─ p101_logo.png
├─ w101_icon.png
├─ w101_launcher.ico
└─ w101_logo.png
```

The script will run without any of the other assets, however, that will obviously not produce the the intended appearance:

<p align="center">
  <img src="images/KI Quick-Launcher - Game Selection - No Assets.png" width="338">
  <img src="images/KI Quick-Launcher - Wizard101 - No Assets.png" width="338">
</p>
