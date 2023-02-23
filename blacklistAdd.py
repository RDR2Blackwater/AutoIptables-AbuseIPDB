import requests
import json
import re
import subprocess

# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/check'

# Get your AbuseIPDB API
while True:
	with open('AbuseAPI.text','a+') as API:
		API.seek(0,0)
		abuseAPI_key = API.readline()
		if abuseAPI_key:
			break
		else:
			setAPIKey = input('AbuseIPDB API key is required,please enter your API key here or register in https://www.abuseipdb.com/:')
			API.write(setAPIKey)
			API.close()

# Generate Lists/Stream from system files
detectedIPs = (subprocess.getoutput("lastb -i | awk '{ print $3}' | sort | uniq | sort -n")).split('\n')
whiteList = (subprocess.getoutput("last | awk '{print $3}' | sort | uniq | sort -n").split('\n'))
blackList = open('/root/data/iptables_py/blacklist.text','r+')

# Filter IPs that have been blocked or logged in successfully
while True:
	BlockedIPs = (blackList.readline()).strip('\n')
	if BlockedIPs:
		if BlockedIPs in detectedIPs:
			# Remove IPs that have been blocked
			detectedIPs.remove(BlockedIPs)
	else:
		break
suspectIPs = [x for x in detectedIPs if x not in whiteList]
blackList.close()

# Print suspect IPs
print('\033[33m=========================suspectIPs=========================\033[0m\n',suspectIPs,'\n\033[33m=========================suspectIPs=========================\033[0m')

# Check them or not?
Key = input('\033[33mCheck these ip and drop abuse ones?[Y/N]:\033[0m')

if Key is 'Y' or Key is 'y':
	# Open stream for adding abuse IPs to black list
	blackListExpend = open('/root/data/iptables_py/blacklist.text','a')
	for x in suspectIPs:
		# Is x a legal IP?
		if re.match(r'^((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}$', x):
			querystring = {
			    'ipAddress':x,
			    'maxAgeInDays':'90',
			}
			print('\033[36mSending query...',querystring,'\033[0m')
			headers = {
			    'Accept': 'application/json',
			    'Key': abuseAPI_key
			}
			
			response = requests.request(method='GET', url=url, headers=headers, params=querystring)
			
			# Formatted output
			decodedResponse = json.loads(response.text)
			
			# Print out errors
			if 'data' not in decodedResponse:
				print('\033[31m',decodedResponse,'\033[0m')
			
			# Start Judging & Dropping
			else:
				if int(decodedResponse['data']['abuseConfidenceScore']) <= 75:
					print('\033[32m',decodedResponse,'\nAbuse confidence score is lower than 75, pass','\033[0m')
				else:
					print('\033[32m',decodedResponse,'\nAbuse confidence score is higher than 75!','\033[0m')
					block = subprocess.run(['/usr/sbin/iptables', '-A', 'INPUT', '-s', x, '-j', 'DROP'])
					print('\033[32m',block,'\033[0m')
					fr = blackListExpend.write(x+'\n')
					print('\033[35m',x,'has been recorded in blacklist.text, return:',fr,'\033[0m')
	# Close Stream
	blackListExpend.close()
# Terminated
print('Script terminated')
