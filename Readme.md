FileLookup.py
=============

Searches various online resources to try and get as much info about a file as possible without submitting it, requiring third party modules or performing any analysis on the file.

Requirements
------------
	* Internet Access :)
	* VirusTotal API key if you want prettier reports with more information from the JSON object
	
Optional
--------
* SimpleJson module to print the pretty reports (optional but is nicer)

Usage
-----
	usage: FileLookup.py [-h] [-f FILE] [-H HASH]

	Searches various online resources to try and get as much info about a file as
	possible without submitting it, requiring third party modules or performing
	any analysis on the file.

	optional arguments:
	  -h, --help            show this help message and exit
	  -f FILE, --file FILE  Path to directory/file(s) to be scanned
	  -H HASH, --hash HASH  MD5 hash to be queried