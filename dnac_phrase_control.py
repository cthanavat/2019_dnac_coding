import sys
import subprocess


def dnac_phrase_control (input):
    #print (input)
    if input == 'device status':
        #print ("Device return")
        output = subprocess.run(['python','dnac_deviceStatus.py'],  capture_output=True, text=True, shell=True).stdout
        print (output)
    elif input == 'device list':
        print ("Retrun status")
    else:
        print ("IDK")

if __name__ == "__main__":
    phrase_input = ""
    phrase_input = sys.argv[1]
    dnac_phrase_control (phrase_input)
