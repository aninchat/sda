import requests
import warnings
from requests.auth import HTTPBasicAuth
import rich
import csv
import json
import time
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
from functools import partial

def get_dnac_auth_token(dnac_ip_address, dnac_user, dnac_pass):
    """
    function to get authentication token from DNAC to be used
    for subsequent APIs
    """

    url = "https://" + dnac_ip_address + "/dna/system/api/v1/auth/token"

    # the post request will throw a warning because certification
    # validation is being disabled with 'verify=False'
    # this displays the warning to the user, so we are filtering it

    warnings.filterwarnings("ignore")

    # post request to retreive token in json format and then store it
    # as a string in a variable called token. Return this variable

    response = requests.post(url, auth=HTTPBasicAuth(dnac_user,dnac_pass), headers={"Content-Type": "application/json"}, verify=False)
    token = response.json()["Token"]
    return token

def get_all_fabric_devices(dnac_ip_address, token):
    """
    function to return all network devices in DNACs inventory
    """

    url = 'https://' + dnac_ip_address + '/api/v1/network-device'

    warnings.filterwarnings("ignore")
    url_response = requests.get(url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, verify=False)

    network_devices = url_response.json()["response"]
    return network_devices


def execution_status(dnac_ip_address, token, executionId):
    """
    function to find execution status from an APIs intent
    """

    execution_url  = "https://" + dnac_ip_address +"/dna/platform/management/business-api/v1/execution-status/" + executionId

    url_response = requests.get(execution_url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, verify=False)
    execution_status = url_response.json()
    return execution_status

def task_status(dnac_ip_address, token, taskId):
    """
    function to find task status from an APIs intent
    """
    task_url = "https://" + dnac_ip_address + "/dna/intent/api/v1/task/" + taskId
    url_response = requests.get(task_url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, verify=False)

    task_status = url_response.json()
    return task_status
    
def build_network_devices_lookup_dict(network_devices):
    """
    function to return a lookup dictionary for network devices
    """

    network_devices_lookup_dict = {}

    for device in network_devices:
        temp_dict = {
            device['hostname']: {
                'id': device['id'],
                'ip': device['managementIpAddress']
            }
        }
        network_devices_lookup_dict.update(temp_dict)
    return network_devices_lookup_dict

def open_file(file_path):
    """ 
    function to open a .csv file in read mode
    """

    # open file with read permission
    # DictReader allows you to use first row as keys 

    host_onboarding_file = open(file_path, 'r', encoding='utf-8-sig')
    host_onboarding_reader = csv.DictReader(host_onboarding_file)
    return host_onboarding_reader

def find_site_hierarchy(dnac_ip_address, token, device_name, network_devices_lookup_dict):
    """
    function to find site hierarchy from a device name 
    and network devices lookup dict
    """

    # try block because we don't know if the network device
    # in .csv actually exists in DNACs inventory

    # 'network_devices_lookup_dict[device_name]['id']' will fail if
    # it doesn't exist in DNACs inventory, since it will not be in the
    # lookup dict that we built earlier and this will trigger except block 

    try:
        url = "https://" + dnac_ip_address + "/dna/intent/api/v1/device-detail?searchBy=" + network_devices_lookup_dict[device_name]['id'] + "&identifier=uuid"
    except:
        rich.print("[red]Could not find device in DNAC inventory. Moving on to next row[/red]")
        return 0
    
    url_response = requests.get(url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, verify=False)

    # extract site hierarchy from API response

    try:
        site_hierarchy = url_response.json()['response']['location']
        return site_hierarchy
    except:
        if url_response.json()['statusCode'] == 500:
            rich.print("[red]Error in device details API while determining site hierarchy[/red]")
            return 0
        else:
            rich.print("[red]Generic API failure while getting site hierarchy of device[/red]")
            return 0

def host_onboard(dnac_ip_address, token, network_devices_lookup_dict, row):
    retry_interface_list = []
    rich.print(f"[blue]Looking up site hierarchy for {row['device_name']}[/blue]")
    site_hierarchy = find_site_hierarchy(dnac_ip_address, token, row['device_name'], network_devices_lookup_dict)

    # if site_hierarchy is 0, it means we could not find the site
    # in DNAC inventory - see find_site_hierarchy().

    if site_hierarchy == 0:
        return 

    rich.print(f"[green]Found site hierarchy for {row['interface_name']}. Site hierarchy is {site_hierarchy}")
    # once device location and IP address is known, this can now be used in
    # host onboarding API 

    # build the required host onboarding data first. This will need to be
    # converted from json into a string before feeding into the API

    host_onboarding_data = {
        "siteNameHierarchy": site_hierarchy, 
        "deviceManagementIpAddress": network_devices_lookup_dict[row['device_name']]['ip'], 
        "interfaceName": row['interface_name'], 
        "dataIpAddressPoolName": row['data_pool'], 
        "voiceIpAddressPoolName": row['voice_pool'], 
        "authenticateTemplateName": row['authentication_mode']
        }
    
    # create the URL and send a POST request 

    rich.print(f"[blue]Starting port assignment for {row['interface_name']}[/blue]")
    host_onboarding_full_url = "https://" + dnac_ip_address + '/dna/intent/api/v1/business/sda/hostonboarding/user-device'
    host_onboarding_api_response = requests.post(host_onboarding_full_url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, data=json.dumps(host_onboarding_data), verify=False)

    # API will either fail or have a status of 'pending'
    # if it failed outright, print error description and exit

    print(host_onboarding_api_response.json())
    if host_onboarding_api_response.json()['status'] == 'failed':
        rich.print(f"[red]{host_onboarding_api_response.json()['description']}[/red]")
        return
    
    # A 'pending' API status will now have two data points to consider:
    # 1. identify status of execution of API, using execution ID
    # 2. identify status of task, using task ID

    taskId = host_onboarding_api_response.json()['taskId']
    executionId = host_onboarding_api_response.json()['executionId']

    # get task status and execution status

    task_response = task_status(dnac_ip_address, token, taskId)
    execution_response = execution_status(dnac_ip_address, token, executionId)

    wait_time_for_task = 0

    if execution_response['status'] == 'SUCCESS':
        rich.print(f"[green]API '{execution_response['bapiName']}' for interface {row['interface_name']} was executed successfully[/green]")
        
        while 'endTime' not in task_response['response'] and wait_time_for_task <= 10:
            # exponential backoff and more logging
            time.sleep(1)
            wait_time_for_task += 1
            task_response = task_status(dnac_ip_address, token, taskId)
            rich.print(f"[blue]Waiting for port assignment task, for interface {row['interface_name']}, to complete.[/blue]")
        
        if 'endTime' not in task_response['response']:
            rich.print(f"[red]Waited for 10 seconds for interface {row['interface_name']} assignment. Adding interface to retry list.[/red]")
            retry_interface_list.append(host_onboarding_data)
        elif task_response['response']['isError'] == True:
            rich.print(f"[red]{task_response['response']['failureReason']}[/red]")
        else:
            rich.print(f"[green]Successfully completed task for interface {row['interface_name']}[/green]")
    

def host_assignment(dnac_ip_address, token, network_devices_lookup_dict, filepath):
    """
    function to assign ports on a device based on data 
    stored in an excel sheet
    """

    retry_interface_list = []

    # open file to load data

    try:
        host_onboarding_reader = open_file(filepath)
        rich.print("[green]Successfully opened .csv file.[/green]")
    except:
        rich.print("[red]Unable to open file. Please confirm file path and file permissions.[/red]")
        return
    
    with ThreadPoolExecutor() as pool: 

        partial_url = partial(host_onboard, dnac_ip_address, token, network_devices_lookup_dict)
        futures = pool.map(partial_url, host_onboarding_reader)

        for future in futures:
            print(future.result())
       
def main():
    # gather basic data needed for API calls

    dnac_ip_address = input("Enter DNACs IP address: ")
    dnac_username = input("Enter username for DNAC: ")
    dnac_password = input("Enter password for DNAC: ")
    file_path = input("Enter complete file path for csv file: ")

    # get auth token from DNAC for subsequent API calls

    rich.print("[green]Attempting to generate authentication token from DNAC.[/green]")
    try:
        auth_token =  get_dnac_auth_token(dnac_ip_address, dnac_username, dnac_password)
        rich.print("[green]Acquired authentication token from DNAC")
    except:
        rich.print("[red]Unable to generated authentication token from DNAC. Please verify username/password and try again.[/red]")
        return
    
    # get all network devices in DNACs inventory
    # needed for getting site hierarchy per network device

    rich.print("[green]Gathering list of network devices from DNAC.[/green]")
    try:
        network_devices = get_all_fabric_devices(dnac_ip_address, auth_token)
        rich.print("[green]Acquired list of network devices in DNAC.[/green]")
    except:
        rich.print("[red]No devices found in DNAC.[/red]")
        return
    
    # build a network devices lookup dict 

    network_devices_lookup_dict = build_network_devices_lookup_dict(network_devices)

    # start port assignment now

    retry_list = host_assignment(dnac_ip_address, auth_token, network_devices_lookup_dict, file_path)
    if retry_list:
        rich.print(f"[red]Interfaces in retry list: {retry_list}")

if __name__ == "__main__":
    main()
