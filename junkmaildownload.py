#!/usr/bin/env python

# Junk email downloader for URL malware analysis, GeoIP lookup and/or VirusTotal.com/Cuckoo Sandbox submitter
# by @catalyst256, catalyst256@gmail.com

import requests, pygeoip, re, poplib, socket, sys # Needed for everything else other than VirusTotal
import simplejson, urllib, urllib2 # Needed for the VirusTotal API submission

# Add some colouring for printing packets later
YELLOW = '\033[93m' # Yellow is for information
GREEN = '\033[92m' # Green is GOOD, means something worked
END = '\033[0m' 
RED = '\033[91m' # Red is bad, means something didn't work

# Things you will need to manually change
gi = pygeoip.GeoIP('/opt/geoipdb/geoipdb.dat') # Change the location if you have saved it somewhere else
vtkey = '' # Enter your VirusTotal.com API key here
cuckoo_host = '' # Enter the IP/hostname of your Cuckoo Sandbox, must be running the API
geoip_file = 'geoip-info.txt' # Name of the file we are going to write with all the GeoIP information in

# List of variables we use
url_list = [] # List of URL's that we are going to check to make sure they work (HTTP 200 Response)
submit_list = [] # List of URL's that we are going to submit to either cuckoo or VirusTotal.com
sender_ip_lookup = [] # Initial list of email sender IP addresses, this is used for GeoIP lookup
url_ip_lookup = [] # Initial list of URL IP addresses, again this is used for GeoIP lookup
geo_ip_data = [] # Combination of sender and url ip geoIP lookup information

# Welcome message
print GREEN + 'Junk Email downloader by @catalyst256' + END

# Connect to the pop3 server of your choice
M = poplib.POP3_SSL('pop3.live.com', 995) # Connect to the pop3 server, (ip/hostname, port)
try:
    M.user("") # Set the username for the pop3 server
    M.pass_("") # Set the password for the pop3 server
except:
    print RED + "[!] username or password incorrect" + END
else:
    print GREEN + "[+] Successful login" + END

# Retrieve the email and look for URL's and sender IP address
try:
	numMessages = len(M.list()[1])
	if numMessages == 0:
		print RED + '[!] Mailbox Empty, try again later' + END
		sys.exit(1)
	else:
		print YELLOW + '[-] Number of messages waiting download: ' + str(numMessages) + END
		for i in range(numMessages):
		    for msg in M.retr(i+1)[1]:
		    	for s in re.finditer('sender IP is (\d*.\d*.\d*.\d*)', msg):
		    		sender_ip_lookup.append(s.group(1))
		    	for t in re.finditer('<a href="(\S*)"', msg):
		    		url_list.append(t.group(1))
except:
	print RED + '[!] Error encountered.. Exiting..' + END
	sys.exit(1)
else:
	print YELLOW + '[+] Emails downloaded and sorted..deleting emails' + END
	numMessages = len(M.list()[1])
	for i in range(numMessages):
	    for msg in M.dele(i+1)[1]:
	    	print YELLOW + '[!] Message Deleted...' + END
M.quit()

# Check the URL's in the url_list stack and then split them so we can resolve the IP addresses
for y in url_list:
	if 'http://' in y:
		split_domain = y.split('/')[2]
		data = socket.gethostbyname(split_domain)
		ip = repr(data)
		if ip not in url_ip_lookup:
			url_ip_lookup.append(ip)

# GeoIP the sender IP address and append to list
for x in sender_ip_lookup:
	rec = gi.record_by_addr(x.strip('"'))
	city = rec['city']
	postcode = rec['postal_code']
	country = rec['country_name']
	lng = rec['longitude']
	lat = rec['latitude']
	ccode = rec['country_code']
	geo_ip = 'sender', x, city, postcode, country, ccode, float(lng), float(lat)
	geo_ip_data.append(geo_ip)

# GeoIP the URL IP address and append to list
for d in url_ip_lookup:
	geo = d.strip('"').strip('\'')
	rec = gi.record_by_addr(geo)
	city = rec['city']
	postcode = rec['postal_code']
	country = rec['country_name']
	lng = rec['longitude']
	lat = rec['latitude']
	ccode = rec['country_code']
	geo_ip = 'malurl', geo, city, postcode, country, ccode, float(lng), float(lat)
	geo_ip_data.append(geo_ip)

#Time to write the GeoIP list to a text file, well we have to do something with it
p = open(geoip_file, 'a')
for line in geo_ip_data:
	p.write(str(line).strip('(').strip(')').strip('\'') + '\n')
print GREEN + '[+] GeoIP data written to file: ' + str(geoip_file) + END
p.close()

# Check the URL's and see if it's active (based on HTTP 200 response)
for req in url_list:
	if 'http://' in req:
		r = requests.get(req)
		if r.status_code == 200:
			submit_list.append(req)
		else:
			print RED + "[!] URL Not Active!! - " + req + END
	else:
		pass

# Print the list of URL's we are going to submit (for reference really)
for f in submit_list:
	print YELLOW + '[-] URL to be submitted: ' + f + END

# Submit the URL's to VirusTotal.com
print YELLOW + '[-] Submitting the URLs to VirusTotal.com' + END
for x in submit_list:
	url = 'https://www.virustotal.com/vtapi/v2/url/scan'
	parameters = {'url': x,'apikey': vtkey}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json = response.read()
	for key, value in json:
		print key, value + '\n'


