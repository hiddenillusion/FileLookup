#!/usr/bin/env python
# encoding: utf-8
#
# This program is intended to run on a Linux machine, but you could
# easily use it on Windows (remove the Wine stuff and run exe's directly)
#
"""
av_multi_scanner.py

Created by Matthew Richard on 2010-01-1.
Copyright (c) 2010. All rights reserved.

original source: http://malwarecookbook.googlecode.com/svn/trunk/3/7/av_multiscan.py
"""

# Modified by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
#		@hiddenillusion
# Changelog:
# =========
# Date: 12-05-2012
#	- changed some formatting
#	- added McAfee local scan (http://malware-hunters.net/2011/06/23/mcafee-command-line-scanner-project-mclsp-v-1-2-released/)
#	- added the ability to import some functions from my FileLookup script
#		- added 'online' switch to enable this
#			- https://github.com/hiddenillusion/FileLookup
#	
# To-do:
# =====
#	- add AVG & suppress AVG out of date engine warning
#	- suppress f-prot's scanning bar
#	- suppress ssdeep's too short of file warning
#	- add option to update sigs/dats?
#	- add engine/DAT info since sometimes different sources show different sig names based on when they were scanned?
#	- something better than subprocess & wine?
#		- eicar test: ~16/17 seconds
#		- eicar test w/ online: ~17/20 seconds

import sys
import os
import yara
from hashlib import md5, sha1, sha256
import subprocess
import socket
from time import localtime, strftime
import re
from optparse import OptionParser
try:
    # To find other REMnux scripts to import, you can disregard otherwise
    sys.path.insert(0, '/usr/local/bin')
    import FileLookup
    looky = True
except ImportError:
    print "Couln't import FileLookup"
    looky = False

"""
configuration information to use when processing the various AV products
mentioned files are available at:
	http://malwarecookbook.googlecode.com/svn-history/r5/trunk/3/6/magic.yara
	http://malwarecookbook.googlecode.com/svn-history/r5/trunk/3/4/packer.yara
	http://malwarecookbook.googlecode.com/svn-history/r5/trunk/3/2/clam_shellcode.ndb
	http://www.f-prot.com/download/home_user/download_fplinux.html
	http://www.reconstructer.org/code.html
	http://free.avg.com/us-en/download.prd-alf
	ftp://ftp.mcafee.com/commonupdater/
"""

yara_include_file = "/path/to/include.yara" # I use this as an index to 'include' other rule files
yara_magic_file = "/path/to/magic.yara"
yara_packer_file = "/path/to/packer.yara"
clam_conf_file = "/path/to/clam_shellcode.ndb"
path_to_ssdeep = "/path/to/ssdeep"
path_to_clamscan = "/path/to/clamscan"
path_to_fpscan = "/path/to/fpscan"
path_to_officemalscanner = "/path/to/OfficeMalScanner.exe"
path_to_avg = "/path/to/avgscan"
path_to_mcafee = "/path/to/scan.exe"

# add new functions by invoking the scanner
# and returning a dictionary that contains
# the keys 'name' and 'result'
# where 'name' is the name of the scanner
# and 'result' contains a string representing the results

def md5sum(data):
	m = md5()
	m.update(data)
	return ('md5:\t\t\t%s' % m.hexdigest())

def sha1sum(data):
	m = sha1()
	m.update(data)
	return ('sha1:\t\t\t%s' % m.hexdigest())

def sha256sum(data):
	m = sha256()
	m.update(data)
	return ('sha256:\t\t\t%s' % m.hexdigest())

def ssdeep(fname):
	if os.path.isfile(path_to_ssdeep):
		output = subprocess.Popen([path_to_ssdeep, "-l", fname], stdout=subprocess.PIPE).communicate()[0]
		response = output.split()[1].split(',')[0]
	else:
		response = 'ERROR - SSDEEP NOT FOUND'
	return ('ssdeep:\t\t\t%s' % response)

def yarascan(data2):
	if os.path.isfile(yara_include_file):
		rules = yara.compile(yara_include_file)
		result = rules.match(data=data2)
		out = ''
                if len(result):
                    for m in result:
		        out += "'%s' " % m
		        response = out
                else: response = "No Match"
	else:
		response = "ERROR - YARA Config Missing"
	return ('yara:\t\t\t%s' % response)

def yara_magic(data2):
	if os.path.isfile(yara_magic_file):
		rules = yara.compile(yara_magic_file)
		result = rules.match(data=data2)
		out = ''
                if len(result):
                    for m in result:
		        out += "'%s' " % m
		        response = out
                else: response = "No Match"
	else:
		response = "ERROR - YARA Config Missing"
	return ('yara_magic:\t\t%s' % response)

def yara_packer(data2):
	if os.path.isfile(yara_packer_file):
		rules = yara.compile(yara_packer_file)
		result = rules.match(data=data2)
		out = ''
                if len(result):
                    for m in result:
		        out += "'%s' " % m
		        response = out
                else: response = "No Match"
	else:
		response = "ERROR - YARA Config Missing"
	return ('yara_packer:\t\t%s' % response)

def clam_custom(fname):
	if os.path.isfile(path_to_clamscan) and os.path.isfile(clam_conf_file):
		output = subprocess.Popen([path_to_clamscan, "-d",clam_conf_file, fname], stdout = subprocess.PIPE).communicate()[0]
		result = output.split('\n')[0].split(': ')[1]
	else:
		result = 'ERROR - %s not found' % path_to_clamscan
	return ('clam_custom:\t\t%s' % result)

def clamscan(fname):
        if os.path.isfile(path_to_clamscan):
		output = subprocess.Popen([path_to_clamscan, fname], stdout = subprocess.PIPE).communicate()[0]
		result = output.split('\n')[0].split(': ')[1]
	else:
		result = 'ERROR - %s not found' % path_to_clamscan
	return ('clamav:\t\t\t%s' % result)

def fpscan(fname):
        """ Depending on the version of FPROT you use, you may need
        to adjust the RESULTLINE number. """
        RESULTLINE = 10
        if os.path.isfile(path_to_fpscan):
            output = subprocess.Popen([path_to_fpscan,"--report",fname], stdout = subprocess.PIPE, stderr = None).communicate()[0]
	    result = output.split('\n')[RESULTLINE].split('\t')[0]
            if not len(result): result = "No Match"
        else:
            result = 'ERROR - %s not found' % path_to_fpscan
        return ('f-prot:\t\t\t%s' % result)
	
def mcafee(fname):
        if os.path.isfile(path_to_mcafee):
            output = subprocess.Popen(["wine",path_to_mcafee,fname], stdout = subprocess.PIPE, stderr = None).communicate()[0]
	    result = output.split('\n')[11]
            if "Found: " in result:
                result = result.split('Found: ')[1]
            else:
                result = "No Match"
        else:
            result = 'ERROR - %s not found' % path_to_mcafee
        return ('mcafee:\t\t\t%s' % result)

def officemalscanner(fname):
	if os.path.isfile(path_to_officemalscanner):
		env = os.environ.copy()
		env['WINEDEBUG'] = '-all'
		output = subprocess.Popen(["wine", path_to_officemalscanner,
			fname, "scan", "brute"], stdout = subprocess.PIPE, stderr = None, env=env).communicate()[0]
		if "Analysis finished" in output:
			output = output.split('\r\n')
			while "Analysis finished" not in output[0]:
				output = output[1:]
			result = output[3]
		else:
			result = "Not an MS Office file"
	else:
		result = 'ERROR - %s not found' % path_to_officemalscanner
	return ('officemalscanner:\t%s' % result)

def avg(fname):	
	if os.path.isfile(path_to_avg):
		output = subprocess.Popen([path_to_avg, fname], stdout = subprocess.PIPE).communicate()[0]
		result = output.split('\n')[0].split(': ')[1]
	else:
		result = 'ERROR - %s not found' % path_to_avg
	return ('avg\t\t: %s' % result)

def filesize(data):
        return ('filesize:\t\t%s bytes' % str(len(data)))
	
def filename(filename):
	return ('filename:\t%s'% filename)
	
def lookup(filename):
        #return ({'name': 'ss_av:', 'result': FileLookup.ss_av(md5sum(data)['result'])})
        ret = []
        ret.append('ShadowServer AV:\t%s' % FileLookup.ss_av(filename))
        ret.append('ShadowServer Known:\t%s' % FileLookup.ss_known(filename))
        ret.append('Cymru: %s' % FileLookup.cymru(filename))
        ret.append('VirusTotal: %s' % FileLookup.virustotal(filename))

        return '\n'.join(ret)

def main():
	parser = OptionParser()
	parser.add_option("-f", "--file", action="store", dest="filename",
	             type="string", help="scanned FILENAME")
	parser.add_option("-o", "--online", action="store_true", dest="online",
	             help="Enable querying the file(s) hash to online resourses")

	(opts, args) = parser.parse_args()

	if opts.filename == None:
		parser.print_help()
		parser.error("You must supply a filename!")
	if not os.path.isfile(opts.filename):
		parser.error("%s does not exist" % opts.filename)
		
	data = open(opts.filename, 'rb').read()
	results = []
    results.append(("#" * 80) + "\nFile:\t %s\n" % opts.filename + ("#" * 80))
	results.append(filesize(data))
	results.append(md5sum(data))
	results.append(sha1sum(data))
	results.append(sha256sum(data))
	results.append(ssdeep(opts.filename))
	results.append(clamscan(opts.filename))
	results.append(clam_custom(opts.filename))
	results.append(yarascan(data))
	results.append(yara_magic(data))
	results.append(yara_packer(data))
	results.append(officemalscanner(opts.filename))
	results.append(fpscan(opts.filename))
	#results.append(avg(opts.filename))
	results.append(mcafee(opts.filename))
		
    print '\n'.join(results)
    if opts.online == True and looky == True:
        print lookup(opts.filename)

if __name__ == '__main__':
	main()
