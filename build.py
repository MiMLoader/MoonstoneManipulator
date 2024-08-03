import subprocess
import shutil;

if __name__ == "__main__":
    command = ["pyinstaller", "--noconfirm", "--onefile", "--windowed", "--icon=src\\Assets\\icon.png" ,"--name=MoonstoneManipulator", "--distpath=dist", "src\\MoonstoneManipulator.py"]
    print(command)
    subprocess.run(command)
    shutil.rmtree('build')