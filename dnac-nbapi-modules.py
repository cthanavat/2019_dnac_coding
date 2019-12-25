#!/usr/bin/env python
"""DNAv3 - DNAC Northbound API - Hands on exercise 02
In this exercise we create helper functions to get an auth token
from DNAC - get_auth_token() and also get_url(), create_url(),
dna_ip_to_id(), dna_get_modules() to get a list of all network modules attached
to a device represented by it's IP.

Copyright (c) 2018 Cisco and/or its affiliates.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import csv
import datetime
import json
import os
import pprint
import requests
import sys
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings()

# Get the absolute path for the directory where this file is located "here"
here = os.path.abspath(os.path.dirname(__file__))

# Get the absolute path for the project / repository root
project_root = os.path.abspath(os.path.join(here, ""))


# Extend the system path to include the project root and import the env files
sys.path.insert(0, project_root)
import env_lab

DNAC = env_lab.DNA_CENTER['host']
DNAC_USER = env_lab.DNA_CENTER['username']
DNAC_PASSWORD = env_lab.DNA_CENTER['password']
DNAC_PORT = env_lab.DNA_CENTER['port']

# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------
def get_auth_token(controller_ip, username, password):
    """ Authenticates with controller and returns a token to be used in subsequent API invocations
    """

    login_url = "https://{0}:{1}/dna/system/api/v1/auth/token".format(controller_ip, DNAC_PORT)
    result = requests.post(url=login_url, auth=HTTPBasicAuth(DNAC_USER, DNAC_PASSWORD), verify=False)
    result.raise_for_status()

    token = result.json()["Token"]
    return {
        "controller_ip": controller_ip,
        "token": token
    }
##

def create_url(path, controller_ip=DNAC):
    """ Helper function to create a DNAC API endpoint URL
    """
    return "https://%s:%s/dna/intent/api/v1/%s" % (controller_ip, DNAC_PORT, path)
##

def rest_get_url(url, token):
    url = create_url(path=url)
    headers = {'X-auth-token' : token}
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as cerror:
        print("Error processing request", cerror)
        sys.exit(1)
    return response.json()
##

def dna_ip_to_id(ip, token):
    return rest_get_url("network-device/ip-address/%s" % ip, token)
##

def dna_get_modules(id, token):
    return rest_get_url("network-device/module?deviceId=%s" % id, token)
##

def dna_get_device_list(token):
    return rest_get_url("network-device", token)
##

def print_info(modules):
    #pprint.pprint (modules)
    print("{0:30}{1:15}{2:25}{3:5}".format("Module Name","Serial Number","Part Number","Is Field Replaceable?"))
    for module in modules['response']:
        print("{moduleName:30}{serialNumber:15}{partNumber:25}{moduleType:5}".format(moduleName=module['name'],
                                                           serialNumber=module['serialNumber'],
                                                           partNumber=module['partNumber'],
                                                           moduleType=module['isFieldReplaceable']))
##

def csvFile_read(path):
    """ Read csv file
    input: [Path <str>]
    return: [Lines <list>]
    """
    # Read Text File
    Lines = []
    Keys_of_Column = []
    # Read  HostList as List
    with open(path, "r") as ins:
        for idx_1, line in enumerate(ins):
            if len(line) > 1:
                Lines.append(line.rstrip('\n').split(','))
    # cover list into of Dict (json form)
    Keys_of_Column = Lines[0]
    del Lines[0]
    for idx_1, item_1 in enumerate(Lines):
        Temp_Json = '{'
        for idx_2, item_2 in enumerate(item_1):
            if idx_2 >= 1:
                Temp_Json += ','
            Temp_Json += '"' + Keys_of_Column[idx_2] + '":"' + item_2 + '"'
        Temp_Json += '}'
        Lines[idx_1] = json.loads(Temp_Json)
    return (Lines)
##

def csvFile_write(data, path):
    # Write Confiuration into file
    with open(path, 'w', newline='') as ins:
        writer = csv.writer(ins, delimiter=',')
        for line in data:
            writer.writerow(line)
        ins.close
##

def device_grouping(device_json):
    # input : device list (json)
    # grouping device
    # output : 
    #   switch device (list)
    #   wireless device (list)
    switch_list = []
    wireless_list = []
    for idx_1, item_1 in enumerate (device_list['response']):
        temp_01 = []
        # add table header
        if idx_1 == 0:
            temp_01.append('hostname')
            temp_01.append('id')
            temp_01.append('location')
            temp_01.append('family')
            temp_01.append('platformId')
            temp_01.append('role')
            temp_01.append('serialNumber')
            temp_01.append('upTime')
            temp_01.append('errorCode')
            switch_list.append(temp_01)
            wireless_list.append(temp_01)
            temp_01 = []
        
        # filter Switch device and add to list
        if item_1['family'] == "Switches and Hubs":
            temp_01.append(item_1['hostname'])
            temp_01.append(item_1['id'])
            temp_01.append(item_1['location'])
            temp_01.append(item_1['family'])
            temp_01.append(item_1['platformId'])
            temp_01.append(item_1['role'])
            temp_01.append(item_1['serialNumber'])
            temp_01.append(item_1['upTime'])
            temp_01.append(item_1['errorCode'])
            switch_list.append(temp_01)
            
        # wireless device and add to list
        elif item_1['family'] == "Unified AP":
            temp_01.append(item_1['hostname'])
            temp_01.append(item_1['id'])
            temp_01.append(item_1['location'])
            temp_01.append(item_1['family'])
            temp_01.append(item_1['platformId'])
            temp_01.append(item_1['role'])
            temp_01.append(item_1['serialNumber'])
            temp_01.append(item_1['upTime'])
            temp_01.append(item_1['errorCode'])
            wireless_list.append(temp_01)
    print ("Network device : ", len(switch_list))
    print ("wireless device: ", len(wireless_list))
    return (switch_list, wireless_list)
##

def initial_function ():
    """  
    1. Director check
    2. read credencial file
    3. DNAC authen,

    return token
    """
    # check/create dir
    if not os.path.exists(here + "\_codeData"):
        os.makedirs(here + "\_codeData")
    if not os.path.exists(here + "\_codeData\deviceList"):
        os.makedirs(here + "\_codeData\deviceList")
    
    # Check cache file
    # - get Credencial of DNAC
    # - Check token, timeout
    # -

    # read credencial
    cred_list = csvFile_read(here + "\cred_list.csv")
    # turn hostname as key of each credencial
    temp_cred = {}
    for idx_1, item_1 in enumerate (cred_list):
        temp_key = item_1['hostname']
        del item_1['hostname']
        temp_cred[temp_key] = item_1
    cred_list = temp_cred

    token = ""
    token_cache_list = []
    temp_list = []

    if not os.path.exists(here + "\_codeDat\_init_cache.csv"):
        ## Token file Format list of [token,(token_value),(date-time)]
        temp_list.append('token')
        
        token = (get_auth_token(cred_list['DNAC']['host'],cred_list['DNAC']['username'],cred_list['DNAC']['password']))
        temp_list.append(token['token'])

        temp_list.append(str((datetime.datetime.now()).strftime("%Y%m%d%H%M")))

        token_cache_list.append(temp_list)
        csvFile_write(token_cache_list, here + "\_codeData\_init_cache.txt")
    else:

    # authen dnac to get token 
    #token = get_auth_token (cred_list['DNAC']['host'],cred_list['DNAC']['username'],cred_list['DNAC']['password'])
    return (token)
##

if __name__ == "__main__":
    ## initial
    token = initial_function()['token']
    print ("Main")


    device_list =  dna_get_device_list(token)
    switch_device_list, wireless_device_list = device_grouping(device_list)



    ##
    csvFile_write(switch_device_list, here + "\_codeData\deviceList\switch_device_list.csv")
    csvFile_write(wireless_device_list, here + "\_codeData\deviceList\wireless_device_list.csv")



    #pprint.pprint (cred_list) 

    #device_detail = dna_ip_to_id("10.10.20.81", token)
    #pprint.pprint  (device_detail)
    #modules = dna_get_modules(device_detail['response']['id'], token)
    #print_info(modules)
##