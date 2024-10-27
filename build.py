import subprocess
import shutil
import os
import sys

if __name__ == "__main__":
     # Build the command
    command = ["pyinstaller", "MoonstoneManipulator.spec"]

    # Determine the platform and set the appropriate executable name and argument
    if sys.platform == "win32":
        executable_name = "MoonstoneManipulator.exe" 
    else:
        executable_name = "MoonstoneManipulator"

    # Clean up dist directory if it exists
    executable_path = os.path.join('dist', executable_name)
    if os.path.exists(executable_path):
        os.remove(executable_path)
   
    print(command)
    subprocess.run(command)

    # Clean up build directory if it exists
    if os.path.exists("build"):
        shutil.rmtree("build")
