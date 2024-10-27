import subprocess
import shutil
import os
import sys

if __name__ == "__main__":
    # Set icon path with cross-platform separator
    icon_path = os.path.join("src", "Assets", "icon.png")
    script_path = os.path.join("src", "MoonstoneManipulator.py")

    # Build the command
    command = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--icon=" + icon_path,
        "--name=MoonstoneManipulator",
        "--distpath=dist",
        script_path,
    ]

    # Add --windowed only on Windows
    if sys.platform == "win32":
        command.append("--windowed")

    print(command)
    subprocess.run(command)

    # Clean up build directory if it exists
    if os.path.exists("build"):
        shutil.rmtree("build")
