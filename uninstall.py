#!/usr/bin/env python3
import subprocess as sp
import sys
import os

pathToBin = '/usr/local/bin/'
manPageLocation = '/usr/local/man/man1/discovery.1'

def uninstall():

    #Remove binary
    try: 
        response = sp.Popen("sudo rm "+pathToBin+'discovery', shell=True, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
        stderr = response.stderr.read().decode('utf-8')
        stdout = response.stdout.read().decode('utf-8')
        
        if "No such file or directory" in stderr:
            print('Unable to find '+pathToBin+'. Is it deleted already?')

            command = "sudo ls "+pathToBin+" -al | grep discovery"
            out = sp.Popen(command, shell=True, stdout=sp.PIPE)
            print(command+":\n"+out.stdout.read().decode('utf-8'))

        else:
            print("Removed "+pathToBin+"discovery successfully.")

    except:
        print("Unknown error.")

    try:
        sp.Popen("sudo rm "+manPageLocation, shell=True)
        print("Removed man page")
    except:
        print("Unableto remove "+manPageLocation)

if __name__ == '__main__':

    #Restart script with admin privileges if launched with normal privileges
    if os.geteuid() == 0:
        uninstall()
    else:
        sp.check_call(['sudo', sys.executable] + sys.argv)