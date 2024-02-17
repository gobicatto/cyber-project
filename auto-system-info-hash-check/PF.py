#!/usr/bin/python3

#Date 		: 17/01/2024
#How To     : Run PF.py in your shell
#Objective  : Create automation to display the operating system information.
#Written by : Renald Taurusdi / S18 / CFC01102023-2
#Trainer    : James Lim

##Import modules needed for this script to run
import os
import sys
import platform
import shutil
import netifaces
import urllib.request
import time
import psutil

#1. Display the OS version – if Windows, display the Windows details; if executed on Linux, display the Linux details.
##FUNCTION
##Convert size in bytes into a more readable version with suffix
##This function will be used throughout the script, so have to be declared first
def convertSizeReadable(size):
    suffixes=['B','KB','MB','GB']
    suffixIndex = 0
    ##Divide the size by 1024 and increase index for each iteration
    #Only stop once size is smaller than 1024 and index bigger than 2
    while size > 1024 and suffixIndex < 3:
        suffixIndex += 1
        size = size/1024.0
    return '%.2f %s' % (size,suffixes[suffixIndex])

##Print platform information using platform module    
print('\nSECTION 1: SYSTEM INFORMATION')
print('[>] Operating system:', platform.system())
print('[>] Platform release:', platform.release())
print('[>] Platform version:', platform.version())
print('[>] Architecture:', platform.machine())
print('[>] RAM:', str(convertSizeReadable(psutil.virtual_memory()[0])))

#2. Display the private IP address, public IP address, and the default gateway.
##FUNCTION
##Check local IP address using netifaces module
def checkLocalIP():
	#Get all the interfaces available such as lo and eth0
	interfaces = netifaces.interfaces()
	
	for i in interfaces:
		#Interface lo IP is 127.0.0.1, we don't need that
		if i != 'lo':
			#The method returns dictionaries, we're using keys to get what we need
			localip = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr']
			netmask = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['netmask']
			gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
			
			#Print IP information
			print('IP address information for', i)
			print('[>] Private IP address:', localip)
			print('[>] Subnet mask:', netmask)
			print('[>] Default Gateway:', gateway)

##Check public IP using urllib.request module
def checkPublicIP():
	#It returns in binary, so we decode it
	publicip = urllib.request.urlopen('https://ident.me').read().decode()
	
	#Print IP information
	print('[>] Public IP address:', publicip)


print('\nSECTION 2: IP ADDRESS')
##Call function to check private and public IP
checkLocalIP()
checkPublicIP()

#3. Display the hard disk size; free and used space.

##Check disk usage using shutil module
linuxpath='/'

##The method return a tuple, so we store each info in its own variable
total_bytes, used_bytes, free_bytes = shutil.disk_usage(linuxpath)

print('\nSECTION 3: HARD DISK USAGE')

##Print hard disk info and use function convertSizeReadble for readibility
print('[=] Total hard disk size: ', convertSizeReadable(total_bytes))
print('[x] Total used space: ', convertSizeReadable(used_bytes))
print('[+] Total free space: ', convertSizeReadable(free_bytes))

#4. Display the top five (5) directories and their size.
##FUNCTION
##Return the user home path using os module
def getHomePath():
	return os.path.expanduser('~')

##Get the total size of folder
def getFolderSize(folder):
	folder_size = os.path.getsize(folder)
	for eachitem in os.listdir(folder):
		itempath = os.path.join(folder, eachitem)
		#If the item is a file, combine the size with total folder size
		if os.path.isfile(itempath):
			folder_size = folder_size + os.path.getsize(itempath)
		#If the item is a folder, call this function again to for recursive check
		elif os.path.isdir(itempath):
			folder_size = folder_size + getFolderSize(itempath)
	return folder_size

def getTopFiveFolder(folder):
	folders = {}
	sizelist = []
	count = 0
	
	print('Top 5 directories in %s and their size:' %(folder))
	
	#Check folder size recursively with function getFolderSize
	for eachitem in os.listdir(folder):
		itempath = os.path.join(folder, eachitem)
		if os.path.isdir(itempath):
			folder_size = getFolderSize(itempath)
			folders[folder_size] = itempath
			sizelist.append(folder_size)
			count += 1
	
	#If there's no directories, get out of the function
	if count == 0:
		print('[!] No directories found in this path')
		return
	
	#Sort the size list to check the top 5 folders with biggest size
	sizelist.sort(reverse=True)
	top5list = sizelist[:5]
	
	#Convert size for readibility and print size information
	for eachsize in top5list:
		size = convertSizeReadable(eachsize)
		print('[*]', folders[eachsize], size)

print('\nSECTION 4: DIRECTORIES (Default to home user directories)')

##User can provide one specific folder path when running the script
##The script will run input valitadtion to check the user path with sys.arg and os.path
if len(sys.argv) > 1:
	if os.path.exists(sys.argv[1]):
		#If user path is valid and is a folder
		if os.path.isdir(sys.argv[1]):
			folder_path = sys.argv[1]
		#If user path is valid, but is a file
		elif os.path.isfile(sys.argv[1]):
			print('\n[!] You provided a file path.\n[!] Scanning parent directory...\n')
			folder_path = os.path.dirname(sys.argv[1])
	else:
		#If user path is invalid
		print('\n[!] You provided an invalid path.\n[!] Default to scanning top 5 directories in user home directory...\n')
		folder_path = getHomePath()
else:
	#If no user path provided, it will run home user directory
	folder_path = getHomePath()
	
##Call main function to check top 5 folders
getTopFiveFolder(folder_path)

#5. Display the CPU usage; refresh every 10 seconds.

print('\nSECTION 5: CPU USAGE (Refreshing every 10s...)')

##Use while True to keep running this script portion until interupted
while True:
	#Get cpu and memory percentage usage using psutil module
	cpu = psutil.cpu_percent()
	mem = psutil.virtual_memory()[2]
	
	#Print usage information
	print('[@] CPU usage: ', cpu, '%') 
	print('[&] RAM usage: ', mem, '%')
	print('-----------------------')
	
	#Wait 10 seconds before continue running the script using time module
	time.sleep(10)
