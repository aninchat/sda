"""
Author: Aninda Chatterjee
Input:
    DNAC credentials (username/password and IP address)
    Excel sheet with host onboarding information in .csv file format with specific format as below:
        Row 0 - Device name exactly as it shows in DNAC inventory (example - Edge1.cisco.com)
        Row 1 - Complete interface name (example - GigabitEthernet1/0/15)
        Row 2 - Data pool name as configured on DNAC
        Row 3 - Voice pool name as configured on DNAC
        Row 4 - Authentication Template (Closed Authentication, Open Authentication, No Authentication)
Usage: This script is designed to take a .csv file as input and configure all interfaces listed in the 
file with their respective parameters (as specified in the file).
"""
import rich
import csv
import requests
import warnings
import getpass
import json
from requests.auth import HTTPBasicAuth

class MyError(Exception):
    """Custom base class for exceptions"""
    pass

class AuthenticationError(MyError):
    """To be raised when authentication failure occurs"""
    pass

class DeviceNotFoundException(MyError):
    """To be raised when device is not found in DNAC"""
    pass

class ImageNotFoundException(MyError):
    """To be raised when image is not found in DNAC"""
    pass

def get_dnac_auth_token(dnac_ip_address, dnac_user, dnac_pass):

    # partial URL defined to concatenate later

    url = '/api/system/v1/auth/token'

    # get DNAC IP address and login details
    # commented out for now - a better approach is to
    # source this in the main function and then pass
    # it into this function

    #dnac_ip_address = input("Enter DNAC IP address: ")
    #dnac_user = input("Enter username for DNAC login: ")
    #dnac_pass = input("Enter password for DNAC login: ")

    # concatenate the DNAC IP address obtained from user
    # with the full string to form the complete URL needed to
    # obtain the token

    full_url = 'https://' + dnac_ip_address + url

    # the post request will throw a warning because certification
    # validation is being disabled with verify=False
    # this displays the warning to the user, so we are filtering it

    warnings.filterwarnings("ignore")

    # post request to retreive token in json format and then store it
    # as a string in a variable called token. Return this variable

    response = requests.post(full_url, auth=HTTPBasicAuth(dnac_user,dnac_pass), headers={"Content-Type": "application/json"}, verify=False)
    token = response.json()["Token"]
    return token

def host_assignment(token, dnac_ip_address, fabric_devices, file_path):

    # first, load csv file which contains host onboarding 
    # information

    # note the explicit encoding added when opening the file 
    # without this, the first entry in the first row is prepended
    # with the encoding format

    try:
        with open(file_path, 'r', encoding='utf-8-sig') as host_onboarding_file:
            host_onboarding_reader = csv.reader(host_onboarding_file)

            # each row should be a unique assignment in the format of
            # row[0] = hostname
            # row[1] = interface
            # row[2] = data pool
            # row[3] = authentication template

            for row in host_onboarding_reader:
                # for the device in each row, find the UUID first

                for device in fabric_devices:
                    if device['hostname'] == row[0].strip():
                        device_uuid = device['id']

                # once the device UUID is found, use that in the device details
                # API to find the site hierarchy/location of the device in your fabric
                # this is needed for the host onboarding API

                try:
                    site_hierarchy_api_full_url = 'https://' + dnac_ip_address + '/dna/intent/api/v1/device-detail?searchBy=' + device_uuid + '&' + 'identifier=' + 'uuid'
                    site_hierarchy_api = requests.get(site_hierarchy_api_full_url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, verify=False)
                except:
                    rich.print(f"[red]Device not found in DNAC. Please input device name correctly in file")
                    continue

                # extract device site hierarchy/location and management IP address

                device_location = site_hierarchy_api.json()['response']['location']
                device_ip = site_hierarchy_api.json()['response']['managementIpAddr']

                # once device location and IP address is known, this can now be used in
                # host onboarding API 

                # build the required host onboarding data first. This will need to be
                # converted from json into a string before feeding into the API

                host_onboarding_data = {"siteNameHierarchy": device_location, "deviceManagementIpAddress": device_ip, "interfaceName": row[1].strip(), "dataIpAddressPoolName": row[2].strip(), "voiceIpAddressPoolName": row[3].strip(), "authenticateTemplateName": row[4].strip()}

                # prepare the URL and then call the API

                host_onboarding_full_url = "https://" + dnac_ip_address + '/dna/intent/api/v1/business/sda/hostonboarding/user-device'
                host_onboarding_api_call = requests.post(host_onboarding_full_url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, data=json.dumps(host_onboarding_data), verify=False)
                try:
                    if host_onboarding_api_call.json()['status']:
                        if host_onboarding_api_call.json()['status'] == 'pending':
                            rich.print(f"[green]Device {row[0]}, interface {row[1]} is being configured.")
                        elif host_onboarding_api_call.json()['status'] == 'failed':
                            if host_onboarding_api_call.json()['description'] == 'interfaceName not found for given device.':
                                rich.print(f"[red]Interface name {row[1]} could not be found. Please input the correct (and full) interface name in the file")
                            else:
                                rich.print(f"[red]Device {row[0]}, interface {row[1]} could not be configured. Invalid parameters")
                except:
                    rich.print(f"[red]Device {row[0]}, interface {row[1]} could not be configured. Error with API, possibly rate-limited")
    except:
        rich.print("[red]Could not open file")

def get_all_fabric_devices(token, dnac_ip_address):
    url = '/api/v1/network-device'
    full_url = 'https://' + dnac_ip_address + url
    warnings.filterwarnings("ignore")
    response = requests.get(full_url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, verify=False)

    # strip the response to include only the "response"
    # entry from the json dictionary

    stripped_response = response.json()["response"]
    return stripped_response

def main():
    # get DNAC IP address and login details

    dnac_ip_address = input("Enter DNAC IP address: ")
    dnac_user = input("Enter username for DNAC login: ")
    dnac_pass = getpass.getpass(prompt="Enter password for DNAC login: ")
    try:
        token  = get_dnac_auth_token(dnac_ip_address, dnac_user, dnac_pass)
    except:
        raise AuthenticationError("Authentication failure. Please check DNAC IP address and login credentials.")

    # get list of all fabric devices first

    fabric_devices = get_all_fabric_devices(token, dnac_ip_address)

    file_path = input("Please specify complete path (including file name) to the host onboarding excel sheet: ") 
    host_assignment(token, dnac_ip_address, fabric_devices, file_path)

if __name__ == '__main__':
    main()    
