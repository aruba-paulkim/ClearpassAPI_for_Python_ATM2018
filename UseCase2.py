# pip install requests
# -*- coding: utf-8 -*-
# Use Case
#2. change endpoint status(unknow->known or disable) and get endpoint infomation

import requests, json

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

API_BASE = "https://{CLEARPASS URL}/api/"
CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"
auth = ""


# Step 1. get access token
try:
	headers = {'Content-Type':'application/json'}
	payload = {"grant_type": "client_credentials","client_id":CLIENT_ID,"client_secret": CLIENT_SECRET}
	r = requests.post(API_BASE+"/oauth", headers=headers, json=payload, verify=False)
	r.raise_for_status()
	json_response = json.loads(r.text)
	print("1. get access token : {0} {1}".format(json_response['token_type'], json_response['access_token']))
	auth = "{0} {1}".format(json_response['token_type'], json_response['access_token'])
except Exception as e:
	print(e)
	exit(1)


# Step 2. change endpoint status(unknow->known or disable)
try:
	mac = "112233445566"
	# status is 'Known' or 'Unknown' or 'Disabled'
	status = "Known"
	headers = {'Content-Type':'application/json','Authorization': auth}
	payload = {"mac_address": mac, "description": "Clearpass API for Python","status": status }
	r = requests.put(API_BASE+"/endpoint/mac-address/"+mac, headers=headers, json=payload, verify=False)
	r.raise_for_status()
	if r.status_code == 200:
		print("2. change endpoint(mac:{0}) status to {1} -> OK".format(mac, status))
	else:
		print("2. change endpoint(mac:{0}) status -> Fail({1})".format(mac, r.status_code))
except Exception as e:
	print(e)
	exit(1)


# Step 3. get endpoint infomation
try:
	mac = "112233445566"
	headers = {'Content-Type':'application/json','Authorization': auth}
	r = requests.get(API_BASE+"/endpoint/mac-address/"+mac, headers=headers, verify=False)
	r.raise_for_status()
	json_response = json.loads(r.text)
	print("3. get endpoint(mac:{0})".format(mac))
	print(" - id : {0}".format(json_response['id']))
	print(" - mac_address : {0}".format(json_response['mac_address']))
	print(" - status : {0}".format(json_response['status']))
except Exception as e:
	print(e)
	exit(1)

