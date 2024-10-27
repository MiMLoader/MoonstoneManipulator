import subprocess
import shutil
import os
import sys

if __name__ == "__main__":
    # Set paths with cross-platform separator
    icon_path = os.path.join("src", "Assets", "icon.png")
    script_path = os.path.join("src", "MoonstoneManipulator.py")
    asset_path = os.path.join("src", "Assets")

    # Clean up dist directory if it exists
    if os.path.exists("dist"):
        shutil.rmtree("dist")

    # Build the command
    command = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--icon=" + icon_path,
        "--name=MoonstoneManipulator",
        "--distpath=dist",
        "--hidden-import=PIL._tkinter_finder",
        script_path,
    ]

    # Add --windowed only on Windows
    if sys.platform == "win32":
        command.append("--windowed")

        # Add icon as data using --add-data; syntax varies by OS
    if sys.platform == "win32":
        command.append(f"--add-data={asset_path};Assets")
    else:
        command.append(f"--add-data={asset_path}:Assets")

    print(command)
    subprocess.run(command)

    # Clean up build directory if it exists
    if os.path.exists("build"):
        shutil.rmtree("build")
