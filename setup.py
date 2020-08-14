#!/usr/bin/env python3
import PyInstaller.__main__
import os
import shutil
import subprocess
import sys

def install():

    #Create binary
    try:
        PyInstaller.__main__.run([
            '--onefile', 
            'discovery.py'
        ])
    except:
        raise
        exit()

    #install to /usr/bin/local
    dir = os.getcwd()
    shutil.copy(dir+'/dist/discovery', '/usr/local/bin/discovery')
    try: 
        shutil.rmtree(dir+'/__pycache__')
    except:
        print(dir+'/__pychache__ already deleted')
    try:
        shutil.rmtree(dir+'/build')
    except:
        print(dir+"/build already deleted")

    print("Executable found in /usr/local/bin/ and "+dir+"/dist/")
    subprocess.Popen("sudo cp discovery.1 /usr/local/man/man1/discovery.1", shell=True)

if __name__ == '__main__':

    #Restart script with admin privileges if launched with normal privileges
    if os.geteuid() == 0:
        install()
    else:
        subprocess.check_call(['sudo', sys.executable] + sys.argv)