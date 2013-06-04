junkemaildownloader
===================

Download email via POP3 then sort and submit the URL's to VirusTotal.com via API

This script will connect to a pop3 mail server (you need to supply username and password) and download the emails.
It will then find the sender ip, and any URL's listed (looks for href tags). It then does some GeoIP stuff to them
before submitting the URL's for analysis (you need to supply a VT API key).

Coming Soon!!

Cuckoo Sandbox submission
VirusTotal IP/Domain check

Usage:
./junkmaildownload.py

Any questions, feedback etc etc let me know.

Adam
