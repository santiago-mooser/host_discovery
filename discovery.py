#!/usr/bin/env python3
#***************************************************************************
#
#   discovery.py is used to discover live hosts on a network through TCP
#   pinging and various ICMP types.
#
#   Based on scripts by dww, Zamanry, Jason, and Mark Wolfgang
#
#***************************************************************************
#
#   ver 0.3.0 dww
#       initial public release
#
#   ver 0.3.1 dww 12/12/2006 10:59AM
#       added new TCP ping ports
#
#   ver 0.3.2 jason 08/01/2007
#       re-program w/o function changed
#
#   ver 0.3.3-4 jason 21/01/2010
#       make change to fix it latest nmap format
#
#   ver 0.3.5-p Santiago ~02/08/20
#       re-written in python to make it easier to debug
#       added option to output raw JSON results
#       added support for JSON output to file (-o path/to/file )
#       added support to read targets from file (-f path/to/file)
#
#   ver 0.3.6-p Santiago 07/08/20
#       added support for CIDR and IP validation 
#
#   ver 0.3.7-p Santiago 10/08/20
#       domains are now resolved to assure validity
#       made script trully multithreaded (x5 times speed improvement)
#       added --dry-run, --quick and --version flags
#       added module support
#       added absolute paths for nmap and ike-scan
#       changed default output to markdown
#       added further safeguards for bad targets
#
#   ver 0.3.8-p Santiago 11/08/20
#       removed hard-coded paths for nmap & ike-scan
#       removed typos 
#   
#   ver 0.3.9-p Santiago 14/08/20
#       removed module support
#       fixed up code comments and appearance
#       initial public release for python version
#
#***************************************************************************
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License Version 3 for more details.
#
# ***************************************************************************

version = "0.3.9-p"

import os
import sys
import json
import argparse
import ipaddress
import socket as sock
import itertools as it
import subprocess as sp
import datetime as datetime
import xml.etree.ElementTree as ET
from multiprocessing import Pool as tp

#Declare global variables so that threads & functions can access them
global time
global verbose
global debug
global raw
global dryRun
global quickRun

global nmapResults
global ikeScanResults
global fullResults
global outputFile

time           = str(datetime.datetime.utcnow().strftime('%Y-%m-%d_%H%M.%S'))
verbose        = False
debug          = False
raw            = False
dryRun         = False
quickRun       = False

nmapResults    = {}
ikeScanResults = {}
fullResults    = {}
outputFile     = ""

#This is the full probe list that nmap tries when testing for online hosts
probeList = {
    'echo' : "-sP -PE",
    'mask' : "-sP -PM",
    'time' : "-sP -PP",
    'tcp21' : "-sP -PS21 -g 53",
    'tcp25' : "-sP -PS25 -g 53",
    'tcp53' : "-sP -PS53 -g 53",
    'tcp80' : "-sP -PS80 -g 53",
    'tcp113' : "-sP -PS113 -g 53",
    'tcp139' : "-sP -PS139 -g 53",
    'tcp256' : "-sP -PS256 -g 53",
    'tcp264' : "-sP -PS264 -g 53",
    'tcp265' : "-sP -PS265 -g 53",
    'tcp443' : "-sP -PS443 -g 53",
    'tcp445' : "-sP -PS445 -g 53",
    'tcp1494' : "-sP -PS1494 -g 53",
    'tcp1720' : "-sP -PS1720 -g 53",
    'tcp1723' : "-sP -PS1723 -g 53",
    'tcp8080' : "-sP -PS8080 -g 53",
    'tcp8888' : "-sP -PS8888 -g 53"}


#This is the list used when the --quick flag is set
quickProbeList={
    'tcp21' : "-sP -PS21 -g 53",
    'tcp80' : "-sP -PS80 -g 53",
    'tcp443' : "-sP -PS443 -g 53",
    'tcp8080' : "-sP -PS8080 -g 53",
    'tcp8888' : "-sP -PS8888 -g 53"}



###############################################################################
# Main function. Can figure out the sctructure of the program here
def targetDiscovery(targets):

    #Convert any IPranges in targets to individual IPs & validate ragets
    targets = convertRanges(targets)

    if targets == []:
        print("List is empty!")
        return

    verbosePrint("\nStarting discovery "+version+" at "+time+"\n")

    if dryRun:
        nonModulePrint("Targets:")
        for target in targets:
            nonModulePrint(target)
        exit()

    # Run ike-scan on multiple threads
    ikeScan(targets)

    # Run nmap scan on multiple threads
    nmapScan(targets)

    #add results to a single variable
    global fullResults
    fullResults.update( {"nmap": nmapResults} )
    fullResults.update( {"ike-scan": ikeScanResults} )

    #Print results to screen & to file if not module & raw flag not set
    if (__name__ == "__main__" and raw == False):
        printToScreen()
        printToFile(outputFile)

    #Output raw results instead of formatted tables if raw flag set
    if raw:
        print( json.dumps(fullResults, indent=4) )

    return



###############################################################################
# Nmap threads initializer and manager. Also compiles (puts together) results
def nmapScan(targets):
    #Perform nmap scan 

    global nmapResults
    global quickRun

    debugPrint("Due to multithreading, commands and outputs might be in the wrong order.\n")
    verbosePrint("--------------------\nStarting nmap scan\n")

    #Choose which probe list based on tags
    if quickRun:
        testList = quickProbeList
        verbosePrint("Using shorter probe list!\n")
    else:
        testList = probeList

    for host in targets:

        #initiate dictionary for this target
        nmapResults.update( { host:{} } )

        for key in testList:
            nmapResults[host].update( { key :{} } )

        #Generate threads for nmap. One thread per probe type.
        pool = tp(8)
        results = pool.map( nmapScanThread, zip( it.repeat(host), list(testList), list(testList.values()) ) )

        for result in results:
            nmapResults[host].update(result)

    verbosePrint("\nFinished Nmap scan\n--------------------\n")



###############################################################################
# Thread that is called to actually run nmap and save results in "results"
def nmapScanThread(zippedValues):

    global nmapResults

    target, key, probe = list(zippedValues)

    #Set nmap command
    command = "sudo nmap -oX - "+target+" "+probe
    try:
        debugPrint(command)
        response = sp.Popen([command], shell=True, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
        xmlstring = response.stdout.read().decode('utf-8')

        root = ET.ElementTree(ET.fromstring(xmlstring))

        #update records based on commands output
        if(root.find("runstats").find("hosts").attrib["up"] == "1"):
            verbosePrint("Host "+root.find("host").find("address").attrib["addr"]+" seems to be up using "+key)
            results =  { key : { "up" : True, "results" : xmlstring } }

        else:
            results = { key : { "up" : False, "results" : xmlstring } }

    #In case the command fails (eg. nmap not installed), update results too
    except:
        verbosePrint("Exception: " +xmlstring)
        results = { key : { "up" : False, "results" : xmlstring } }

    return results



###############################################################################
# Main thread manager for ike-scan. Initializes and runs all ike-scan threads
def ikeScan(targets):
    #Perform ike-scan on list of targets

    global ikeScanResults

    verbosePrint("\n--------------------\nStarting ike-scan\n")
    #Check for ike-scan in system
    noIke = False
    try:
        os.system('/usr/bin/ike-scan --version 2>/dev/null')
    except:
        print("Unable to find /usr/bin/ike-scan. Trying 'ike-scan --version'")
        noIke = True
    if noIke:
        try:
            os.system("ike-scan --version")
        except:
            print("ike-scan not found.")
            return ""

    #Create ike-scan threads
    pool = tp(8)

    results = pool.map(ikeScanThread, targets)

    for result in results:
        ikeScanResults.update(result)

    verbosePrint("\nFinished ike-scan\n--------------------\n\n")



###############################################################################
# Thread that actually runs the ike-scan command
def ikeScanThread(target):

    try:
        command = "sudo ike-scan " + target
        debugPrint(command)
        response = sp.Popen(command, shell=True, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
        results = response.stdout.read().decode('utf-8')

        if (results.find('1 returned handshake' ) != -1):
            verbosePrint("Host "+target+" seems to be up using ike-scan")
            results =  { target : { "up" : True, "results" : results } }
        else:
            verbosePrint("Host "+target+" is not responding to ike-scan")
            results = { target : { "up" : False, "results" : results } }

    except:
        results =  { target : { "up" : False, "results" : "Non-zero return code from ike-scan" } }

    return results



###############################################################################
# Print values to output file if specified
def printToFile(outputFile):
    #Prints 

    fileOutput = fullResults

    if outputFile == "":
        return

    f = open(outputFile, "w+")
    json.dump(fileOutput, f, indent=4)
    f.close()



###############################################################################
# Print values to screen in markdown format
def printToScreen():
    #Prints results to screen in markdown format

    verbosePrint("\n\n----------------------------------------------------------") 

    for target in nmapResults:

        #List of methods with which target has been identified as online:
        icmpMethods =[]
        tcpMethods = []
        ikeMethods = []
        up = False
        nonModulePrint("* "+target)
        
        for method in nmapResults[target]:

            if nmapResults[target][method]["up"] == True:
                if ( method == 'echo' or method == 'mask' or method == 'time'):
                    icmpMethods.append( method )
                else:
                    tcpMethods.append( int(str(method).replace('tcp', '')) )
                up =True

        if ( ikeScanResults[target]["up"] == True ):
            ikeMethods.append("ike-scan")
            up = True

        if up:
            nonModulePrint("    ICMP: "+",".join(icmpMethods))
            nonModulePrint("    tcp: "+",".join(map(str, sorted(tcpMethods))))
            nonModulePrint("    ike-scan: "+",".join(ikeMethods))

        else:
            nonModulePrint("")



###############################################################################
# If verbose flag is set, print string to screen
def verbosePrint(verboseString):
    #Print if verbose flag is set & if not a module
    if (verbose == True) and (__name__ == "__main__"):
        print(verboseString)



###############################################################################
# Print if not a module (deprecated)
def nonModulePrint(NMOString):
    #Print if not a module and if output is not being send to stdout
    if raw == False:
        print(NMOString)



###############################################################################
# If debug flag is set, print to screen
def debugPrint(debugString):
    if debug:
        print(debugString)



###############################################################################
# Retrieve targe list from file
def getTargetsFromFile(hostsFile):
    #Reads targets from list & returns target list
    try:
        f = open(hostsFile, "r")
    except:
        print("Unable to open file!")
        exit()
    lines = f.read().splitlines()
    f.close()
    return lines



###############################################################################
# Convert and validate IP ranges, IPs, and hostnames
def convertRanges(targets):
    #Converts IP ranges to IP address lists and verifies IPs and domains
    #Returns target list minus invalid targets

    tempTargets = []
    ipList      = []

    for arg in targets:
        try:
            ipaddress.ip_address(arg)
            debugPrint(arg+" is a valid IP")
            tempTargets.append(arg)
        except:
            try:
                ipNetworkList= list(ipaddress.ip_network(arg, strict=False).hosts())
                debugPrint(arg+" is a valid IP network")
                for ip in ipNetworkList:
                    ipList.append(str(ip))

                for items in ipList:
                    tempTargets.append(items)
            except:
                if (hostnameResolves(arg)):
                    verbosePrint("Hostname "+arg+" resolves" )
                    tempTargets.append(arg)
                else:
                    verbosePrint(arg+" is not a valid IP, IP network or hostname. Removing from list")

    targets = tempTargets
    return targets



###############################################################################
# Resolve hostnames in order to check whether it is a valid domain 
def hostnameResolves(hostname):
    #Check if hostname resolves using socker method 

    try:
        sock.gethostbyname(hostname)
        return True
    except sock.error :
        return False



###############################################################################
# Parse Commandline
def parseCommandline():

    targets = []

    description = "This is discover-ng.pl revamped: A script to run nmap & ike-scan to discover live hosts on a network through TCP Pinging and various ICMP types."
    usage= "\t\t./discovery -t target(s) [options]\nexample:\t./discovery -t 192.168.1.0/24 -v -o myresults"
    
    parser = argparse.ArgumentParser(description=description, usage=usage)
    group = parser.add_mutually_exclusive_group()

    parser.add_argument('--version',  action='version', version='%(prog)s '+version)
    parser.add_argument('t', nargs="+", help='Target IPs to check status of', default="")
    parser.add_argument('stdin', nargs='?', type=argparse.FileType('r'), default=sys.stdin)
    
    parser.add_argument('-dr', '--dry-run', help='dry run to see which IPs would be scanned', action='store_true', default=False)
    parser.add_argument('-i', help="hosts file containing one host per line", default='')
    parser.add_argument('-o', '--out', help='output file (default is raw JSON output)', type=str, default='')

    group.add_argument('-r','--raw', help='output raw results to stdout without anything else (useful for piping JSON results to another script)', action='store_true', default=False)

    parser.add_argument('-q', '--quick', help='quick host discovery with fewer scanned ports', action='store_true', default=False)

    group.add_argument('-v', help='verbose mode', action='store_true', default=False)
    group.add_argument('-vv', help='debug mode', action='store_true', default=False)
    
    args = parser.parse_args()

    if not sys.stdin.isatty():
        for line in args.stdin.read().split("\n"):
            targets.append(line)
    elif ( args.i != "" ):
        targets = getTargetsFromFile(args.file)
    elif (args.t != ""):
        for target in args.t:
            targets.append(target)
    else:
        print("Please specify or pipe at least one host or host file.")
        exit()

    global verbose
    global debug
    global outputFile
    global raw
    global dryRun
    global quickRun

    if args.vv:
        verbose = True
    else:
        verbose    = args.v

    debug      = args.vv
    raw        = args.raw
    outputFile = args.out
    dryRun     = args.dry_run
    quickRun   = args.quick

    if raw and verbose:
        print("Only one flag of --raw and -v can be enabled")
        exit()

    return targets



###############################################################################
# If script is not called as a module, and no stdin input is detected, parse
# commandline.
# Call main function -- targetDiscovery()
if __name__ == "__main__":
    targets= parseCommandline()
    targetDiscovery(targets)
