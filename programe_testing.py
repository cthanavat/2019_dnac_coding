import os
import subprocess

if __name__ == "__main__":
    #print ("wow")
    output = subprocess.run(['python','dnac_phrase_control.py', "device status"],  capture_output=True, text=True, shell=True).stdout
    print (output)
