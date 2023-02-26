# AutoIptables-AbuseIPDB
A simple script to drop abuse IPs by iptables. It interfaces with [AbuseIPDB](https://www.abuseipdb.com/) to filter IPs that recorded in btmp.

**About the script**

An API key is required to use this script. Input your API key while using this script, if you don't have one, register an account in [AbuseIPDB](https://www.abuseipdb.com/). Your API will be recorded in file `AbuseAPI.text`.


Abuse IPs will be recorded in file `blacklist.text`. Some [abuse IPs](./blacklist.text) have been recorded on this project, you could collection them directly.
