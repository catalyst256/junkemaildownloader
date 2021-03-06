#!/usr/bin/env python

# Junk email downloader for URL malware analysis, GeoIP lookup and/or VirusTotal.com/Cuckoo Sandbox submitter
# by @catalyst256, catalyst256@gmail.com

import requests, pygeoip, re, poplib, socket, sys # Needed for everything else other than VirusTotal
import json, urllib, urllib2 # Needed for the VirusTotal API submission
from time import time as ttime # Needed to generate random time for filename

# Add some colouring for printing packets later
YELLOW = '\033[93m' # Yellow is for information
GREEN = '\033[92m' # Green is GOOD, means something worked
END = '\033[0m' # It's the end of the world as we know it
RED = '\033[91m' # Red is bad, means something didn't work

# Things you will need to manually change
gi = pygeoip.GeoIP('/opt/geoipdb/geoipdb.dat') # Change the location if you have saved it somewhere else
vtkey = '' # Enter your VirusTotal.com API key here
cuckoo_host = '' # Enter the IP/hostname of your Cuckoo Sandbox, must be running the API
geoip_file = 'geoip-info.txt' # Name of the file we are going to write with all the GeoIP information in

use_vt = 1 # Defines if it should upload to VirusTotal of not, change to 0 if you don't want it to (useful for testing)
use_cuckoo = 0 # Defines if it should upload to Cuckoo of not, change to 0 if you don't want it to (useful for testing)

# List of variables we use
url_list = [] # List of URL's that we are going to check to make sure they work (HTTP 200 Response)
submit_list = [] # List of URL's that we are going to submit to either cuckoo or VirusTotal.com
sender_ip_lookup = [] # Initial list of email sender IP addresses, this is used for GeoIP lookup
url_ip_lookup = [] # Initial list of URL IP addresses, again this is used for GeoIP lookup
geo_ip_data = [] # Combination of sender and url ip geoIP lookup information
msg_data = [] # Somewhere to dump the email message to so I can write it to a file later


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
		print YELLOW + '[-] Number of messages waiting for download: ' + str(numMessages) + END
		for i in range(numMessages):
		    for msg in M.retr(i+1)[1]:
		    	msg_data.append(msg) # Now we save the messages to a list and then search through them later
except:
	print RED + '[!] Error encountered.. Exiting..' + END
	sys.exit(1)
else:
	print YELLOW + '[+] Emails downloaded and sorted..deleting emails' + END
	numMessages = len(M.list()[1])
	for i in range(numMessages):
	    for msg in M.dele(i+1)[1]:
	    	print RED + '[!] Message Deleted...' + END
M.quit()

# Time to write the msg(s) to a text file so we have them for further analysis
t = int(ttime())
filename = str(t) + '.txt'
f = open(filename, 'a')
for m in msg_data:
	f.write('%s\n' % m)
	for s in re.finditer('sender IP is (\d*.\d*.\d*.\d*)', m):
		sender_ip_lookup.append(s.group(1))
	for t in re.finditer('http://\S*', m):
		url_list.append(t.group().strip('"'))
print GREEN + '[+] Msg(s) written to: ' + filename + END
f.close()

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
	lng = rec['longitude']
	lat = rec['latitude']
	geo_ip = 'sender', x, float(lng), float(lat)
	geo_ip_data.append(geo_ip)

# GeoIP the URL IP address and append to list
for d in url_ip_lookup:
	geo = d.strip('"').strip('\'')
	rec = gi.record_by_addr(geo)
	lng = rec['longitude']
	lat = rec['latitude']
	geo_ip = 'malurl', geo, float(lng), float(lat)
	geo_ip_data.append(geo_ip)

#Time to write the GeoIP list to a text file, well we have to do something with it
p = open(geoip_file, 'a')
for line in geo_ip_data:
	p.write(str(line).strip('(').strip(')') + '\n')
print GREEN + '[+] GeoIP data written to file: ' + str(geoip_file) + END
p.close()

# Check the URL's and see if it's active (based on HTTP 200 response)
print YELLOW + '[!] Checking to see if the URL is alive' + END
for req in url_list:
	if 'http://' in req:
		r = requests.get(req)
		if r.status_code == 200:
			if req not in submit_list:
				submit_list.append(req)
		else:
			print RED + "[!] URL Not Active!! - " + req + ' - ' + str(r.status_code) + END
	else:
		pass

# Print the list of URL's we are going to submit (for reference really)
for f in submit_list:
	print YELLOW + '[-] URL to be submitted: ' + f + END

# Submit the URL's to VirusTotal.com
if use_vt == 1:
	print YELLOW + '[-] Checking the URLs with VirusTotal.com (will scan if not seen before)' + END
	for x in submit_list:
		url = 'https://www.virustotal.com/vtapi/v2/url/report'
		parameters = {'resource': x,'apikey': vtkey,'scan': 1}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		json = json.load(response)
		print GREEN + '[+] Scan on: ' + x + ' complete' + END
		print YELLOW + '[+] Link to report is here: ' + json['permalink'] + END
		print YELLOW + '[+] Scan Date: ' + json['scan_date'] + END
else:
	print RED + '[!] No upload to VirusTotal!!' + END