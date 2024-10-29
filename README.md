# Moonstone Manipulator
Moonstone Island Save Editor

Currently Supported Features:

- Save Decryption/Encryption
- Automatic File Backup

Potential Features:
- Spirit Editing
- Inventory Editing
- Island Editing

Instructions: 

1. Download Moonstone Island on Steam.
2. Navigate to the game file directory for your OS.
   - Windows: C:\Program Files (x86)\Steam\steamapps\common\Moonstone Island
   - Linux: ~/.local/share/Steam/SteamApps/common
3. Extract the files in "package.nw" into a folder using a Zip tool such as [Winrar](https://www.win-rar.com/start.html?&L=0) or [7Zip](https://www.7-zip.org/).
4. Open the file package.nw\scripts\c3runtime.js in any text editor.
5. Find the save key near "NWJS Enc" and put in this program's startup prompt.
6. Choose the input path for the save file you want to decrypt or encrypt. The default save locations are below.
   - Windows: C:\Users\\(username)\Saved Games\Moonstone Island
   - Linux: ~/Moonstone Island/
7. Choose the output path for the new file to be saved.
