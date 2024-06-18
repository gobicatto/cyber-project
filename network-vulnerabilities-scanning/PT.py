#!/usr/bin/python3

#Date 		: 15/03/2024
#How To     : Run PT.py in your shell
#Objective  : Create automation to map services and vulnerabilities on the entire local network.
#Written by : Renald Taurusdi / S18 / CFC01102023-2
#Trainer    : Tushar Ismail

#Import modules needed for this script to run
import os
import ipaddress
import subprocess
import sys
import netifaces
import re
import time
import datetime
import zipfile

#Variable Declaration
svc_lst = ['ssh','rdp','ftp','telnet']
port_dict = {'ssh':'22','rdp':'3389','ftp':'21','telnet':'23'}
user_file = 'PT_user_lst.txt'
passwd_file = 'PT_passwd_lst.txt'
nmap_xml_file = 'nmap.xml'
log_file = 'PT_scan_report.txt'
zip_file = 'PT_scan_report.zip'
timeout_mult = 1


#Function to validate IP provided by user
def check_ip(input_ip):
	valid_ip = False
	try:
		#Check if / in the input, means it is IP with CIDR notation
		if '/' in input_ip:
			ip_add = ipaddress.ip_network(input_ip, strict = False)
		#If not, it is just one IP
		else:
			ip_add = ipaddress.ip_address(input_ip)
		valid_ip = True		
	#Will reject others
	except ValueError:
		valid_ip = False
	return valid_ip

#Function to get IP from user
def get_ip():
	#Get IP input from user
	target_ip = input('[?] Provide IP address (accept CIDR notation): ')
	
	#Call function check_ip to validate IP input
	if check_ip(target_ip) != True:
		print('[!] You have provided invalid IP/CIDR notation!\n')
		#If invalid IP, recall its own function to request IP from user again
		target_ip = get_ip()
	return target_ip

#Function to get local machine IP
def self_ip():
	#Get all the interfaces available such as lo and eth0
	interfaces = netifaces.interfaces()
	
	for i in interfaces:
		#Interface lo IP is 127.0.0.1, we don't need that
		if i != 'lo':
			#The method returns dictionaries, we're using keys to get what we need which is local ip
			localip = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr']
	return localip

#Function to retrieve IP address from a text log, such as nmap result
def find_ip(ip_log):
	#Define IPv4 pattern which is [0-255].[0-255].[0-255].[0-255]
	pattern =re.compile('''((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)''')
	
	#Splitting text for easier manipulation
	scan_lst = ip_log.split()
	ip_lst = []
	
	#Find local machine IP by calling function self_ip()
	ip_self = self_ip()
	
	#Finding a pattern match for IPv4 in the text. Ignore if it is IP of the local machine
	for each in scan_lst:
		ip_match = pattern.search(each)
		if ip_match and each != ip_self:
			ip_lst.append(each)
	return ip_lst

#Function to scan target IP with Nmap command
def scan_ip(target_ip):
	#Nmap using flag -sn for ping only, and --unprivileged assuming not sudo user for cleaner result
	nmap_cmd = f'nmap -sn --unprivileged {target_ip}'
	
	#Decode subprocess output and store in a variable
	nmap_output= subprocess.check_output(nmap_cmd, shell=True).decode('utf-8')
	print(nmap_output)
	
	#Find IP in the text by calling find_ip() function
	ip_lst = find_ip(nmap_output)
	return ip_lst

#Function to validate user path input
def check_userpath(userpath):
	path = ''
	#Get current directory path
	currentdir = os.getcwd()
	
	#Check if path is valid and a directory
	if os.path.exists(userpath) and os.path.isdir(userpath):
		path = userpath
	else:
		#If user input is invalid, revert to default current directory
		path = currentdir
	print(f'[*] Output will be saved in {path} directory.')
	return path

#Function to get user path input
def get_userpath():
	userpath = input(f'[?] Provide full path for output directory (Press Enter to use default path in current directory): ')
	
	#Call funtion check_userpath() to validate input
	userpath = check_userpath(userpath)
	return userpath

#Function to check expected combination of user and password. This will be used to estimate appropriate function timeout.
def userpass_comb(user,passwd):
	#Run command cat and count the number of lines for user file and password file.
	cat_user = f'cat {user} | wc -l'
	output_user = subprocess.check_output(cat_user,shell=True).decode('utf-8')
	cat_passwd = f'cat {passwd} | wc -l'
	output_passwd = subprocess.check_output(cat_passwd,shell=True).decode('utf-8')
	
	#Simple multiplication formula to determine possible combination
	userpass_combination = int(output_user)*int(output_passwd)
	return userpass_combination

#Function to define Nmap command, run it and obtain the result
def nmap_scan(ip_add):
	#Nmap command, with flag -sV for verbose and -p- to scan all ports
	nmap_cmd = f'nmap -sV -p- {ip_add}'
	
	#Run command with subprocess, decode the results and store it in the variable
	nmap_output = subprocess.check_output(nmap_cmd, shell=True).decode('utf-8')
	return nmap_output

#Function to define Nmap with NSE command, run it and obtain the result
def nse_scan(ip_add, nmap_path):
	#Nmap with flag -sV for verbose, -sC to scan with NSE, -p- to scan all ports, and -oX to store output as xml
	nse_cmd = f'nmap -sV -sC -p- {ip_add} -oX {nmap_path}'
	
	#Run command with subprocess, decode the results and store it in the variable
	nse_output = subprocess.check_output(nse_cmd, shell=True).decode('utf-8')
	return nse_output

#Function to define Masscan command, run it and obtain the result
def masscan_scan(ip_add):
	#Masscan command with flag -pU to scan UDP on all ports with --rate 10000 for quick results
	masscan_cmd = f'masscan -pU:0-65535 --rate=10000 {ip_add}'
	
	#Run command with subprocess, decode the results and store it in the variable
	masscan_output = subprocess.check_output(masscan_cmd, shell=True).decode('utf-8')
	return masscan_output

#Function to define Hydra command, run it and obtain the result
def hydra_scan(ip_add,svc,user_lst,passwd_lst,seconds):
	print('[>] Starting Hydra scanning...')
	
	#Hydra bruteforce with user and password files, flag -f to stop if there's a match, and -I to ignore restore file
	hydra_cmd = f'hydra -L {user_lst} -P {passwd_lst} {ip_add} {svc} -f -I'
	
	#Run command with subprocess and timeout, decode the results and store it in the variable
	hydra_output = subprocess.check_output(hydra_cmd, shell=True, timeout=seconds).decode('utf-8')
	return hydra_output

#Function to define Searchsploit command, run it and obtain the result
def sploit_scan(nmap_log):
	#Searchsploit command to search exploit with Nmap xml output file
	sploit_cmd = f'searchsploit --nmap {nmap_log}'
	
	#Run command with subprocess, decode the results and store it in the variable
	sploit_output = subprocess.check_output(sploit_cmd, shell=True).decode('utf-8')
	return sploit_output

#Funtion to define main menu
def main_menu():
	print('\n')
	print('[>] Available scanning services to scan the IP list:')
	print('[>] 1) Basic ::: Scan network for TCP and UDP, service version, weak passwords')
	print('[>] 2) Full  ::: Scan includes NSE, weak passwords, vulnerability analysis')
	print('[>] 9) Exit')
	user_choice = input('[?] Choose which scan to run: ')
	
	#User choice input validation
	option_lst = ['1','2','9']
	if user_choice not in option_lst:
		print('[!] Please choose option 1, 2, or 9 to exit.')
		user_choice = main_menu()
	return user_choice

#Function to define menu one for Basic Scan
def menu_one(ip_lst, user_lst, passwd_lst, logfile):
	print('\n')
	print('='*100)
	print(f'[1] Commencing BASIC SCAN on {len(ip_lst)} IP address')
	print('='*100)
	
	logfile.write(f'\n[1] Commencing BASIC SCAN on {len(ip_lst)} IP address\n')

	#Calculating estimated timeout
	timeout = userpass_comb(user_lst, passwd_lst) * timeout_mult

	#Loop through each IP address and run the scan
	for each in ip_lst:
		print('='*100)
		print(f'[>>>] BASIC SCAN {each} for TCP, UDP, Services, and Weak Passwords')
		print('='*100)
		logfile.write(f'\n[>>>] BASIC SCAN {each} for TCP, UDP, Services, and Weak Passwords\n')
		time.sleep(1)
		
		print(f'[*] Nmap Scan TCP')
		logfile.write(f'[*] Nmap Scan TCP\n')
		
		#Calling Nmap scan function
		nmap_output = nmap_scan(each)
		print(nmap_output)
		logfile.write(nmap_output)
		
		print(f'[*] Masscan Scan UDP')
		logfile.write(f'[*] Masscan Scan UDP\n')
		
		#Calling Masscan scan function
		masscan_output = masscan_scan(each)
		if masscan_output != '':
			print(masscan_output)
			logfile.write(masscan_output)
		else:
			#If output is empty, return status as follows
			print(f'[x] No UDP service found on {each}.')
			logfile.write(f'[x] No UDP service found on {each}.\n')
		
		print(f'[*] Weak Passwords Scan')
		logfile.write(f'[*] Weak Passwords Scan\n')
		
		#Loop through four service for Weak Password scan
		for svc in svc_lst:
			try:
				#Checking if port is open or not
				checkport_cmd = f'nmap {each} {port_dict[svc]} | grep open'
				checkport_output = subprocess.check_output(checkport_cmd,shell=True).decode('utf-8')
				
				#If port is open
				if svc in checkport_output:	
					try:
						print(f'[*] Hydra scan for weak password on {svc.upper()} service')
						logfile.write(f'[*] Hydra scan for weak password on {svc.upper()} service\n')
						
						#Calling Hydra scan function
						hydra_output = hydra_scan(each,svc,user_lst,passwd_lst,timeout)
						print(hydra_output)
						logfile.write(hydra_output)
					
					#Exception if function run exceeding timeout variable
					except subprocess.TimeoutExpired:
						print(f'[x] Response from {svc.upper()} service on {each} taking too long. Skipping to the next stage...')
						logfile.write(f'[x] Response from {svc.upper()} service on {each} taking too long. Skipping to the next stage...\n')
						pass					
					#Exception if function returns error
					except subprocess.CalledProcessError:
						print(f'[x] Unable to reach {svc.upper()} service on {each}')
						logfile.write(f'[x] Unable to reach {svc.upper()} service on {each}\n')
						pass
				#All other failure return status as follow
				else:
					print(f'[x] Unable to reach {svc.upper()} service on {each}')
					logfile.write(f'[x] Unable to reach {svc.upper()} service on {each}\n')
			#Exception if function returns error
			except subprocess.CalledProcessError:
				print(f'[x] Unable to reach {svc.upper()} service on {each}')
				logfile.write(f'[x] Unable to reach {svc.upper()} service on {each}\n')
				pass
		
		print('='*100)
		print(f'[>>>] End of BASIC SCAN for {each}.')
		print('='*100)
		logfile.write(f'[>>>] End of BASIC SCAN for {each}.\n')
		time.sleep(1)

	return
#Function to define menu two for Full Scan
def menu_two(ip_lst, user_lst, passwd_lst, nmap_xml, logfile):
	print('\n')
	print('='*100)
	print(f'[2] Commencing FULL SCAN on {len(ip_lst)} IP address')
	print('='*100)
	logfile.write(f'\n[2] Commencing FULL SCAN on {len(ip_lst)} IP address\n')
	time.sleep(1)

	currentdir = os.getcwd()
	nmap_path = os.path.join(currentdir,nmap_xml)
	
	#Calculating estimated timeout
	timeout = userpass_comb(user_lst, passwd_lst) * timeout_mult
	
	for each in ip_lst:
		print('='*100)
		print(f'[>>>] FULL SCAN {each} for Nmap NSE, Weak Passwords, and Vulnerability Analysis')
		print('='*100)
		logfile.write(f'\n[>>>] FULL SCAN {each} for Nmap NSE, Weak Passwords, and Vulnerability Analysis\n')
		time.sleep(1)
		print(f'[*] Nmap NSE Scan')
		logfile.write(f'[*] Nmap NSE Scan\n')
		
		#Calling Nmap NSE scan function
		nse_output = nse_scan(each, nmap_path)
		print(nse_output)
		logfile.write(nse_output)
				
		print(f'[*] Weak Passwords Scan')
		logfile.write(f'[*] Weak Passwords Scan\n')
		
		#Loop through four service for Weak Password scan
		for svc in svc_lst:
			try:
				#Check if port is open
				checkport_cmd = f'nmap {each} {port_dict[svc]} | grep open'
				checkport_output = subprocess.check_output(checkport_cmd,shell=True).decode('utf-8')
				
				#If port is open
				if svc in checkport_output:	
					try:
						print(f'[*] Hydra scan for weak password on {svc.upper()} service')
						logfile.write(f'[*] Hydra scan for weak password on {svc.upper()} service\n')
						
						#Calling Hydra scan function
						hydra_output = hydra_scan(each,svc,user_lst,passwd_lst,timeout)
						print(hydra_output)
						logfile.write(hydra_output)
					#Exception if function run exceeding timeout variable
					except subprocess.TimeoutExpired:
						print(f'[x] Response from {svc.upper()} service on {each} taking too long. Skipping to the next stage...')
						logfile.write(f'[x] Response from {svc.upper()} service on {each} taking too long. Skipping to the next stage.\n')
						pass
					#Exception if function returns error
					except subprocess.CalledProcessError:
						print(f'[x] Unable to reach {svc.upper()} service on {each}')
						logfile.write(f'[x] Unable to reach {svc.upper()} service on {each}\n')
						pass
				#All other failure return status as follow
				else:
					print(f'[x] Unable to reach {svc.upper()} service on {each}')
					logfile.write(f'[x] Unable to reach {svc.upper()} service on {each}\n')
			#Exception if function returns error
			except subprocess.CalledProcessError:
				print(f'[x] Unable to reach {svc.upper()} service on {each}')
				logfile.write(f'[x] Unable to reach {svc.upper()} service on {each}\n')
				pass
		
		print(f'\n[*] Searchsploit Scan')
		print(f'[*] Loading Nmap scan file in xml format {nmap_path}')
		logfile.write(f'\n[*] Searchsploit Scan\n')
		logfile.write(f'[*] Loading Nmap scan file in xml format {nmap_path}\n')
		
		#Calling Searchsploit function
		sploit_output = sploit_scan(nmap_path)
		
		#If there's Exploit Title in result, print result
		if "Exploit Title" in sploit_output:
			print(sploit_output)
			logfile.write(sploit_output)
		#If not, return status as follow
		else:
			print(f'[x] Unable to searchsploit {each}')
			logfile.write(f'[x] Unable to searchsploit {each}\n')
		
		print('='*100)
		print(f'[>>>] End of FULL SCAN for {each}.')
		print('='*100)
		logfile.write(f'[>>>] End of FULL SCAN for {each}.\n')
		time.sleep(1)
		
		#Remove temporary files
		try:
			remove_cmd = f'rm -f {nmap_path}'
			remove_output = subprocess.check_output(remove_cmd, shell = True).decode('utf-8')
			print(f'\n[*] Clearing temporary files:')
			print(f'[>] Deleting {nmap_path}')
			logfile.write(f'\n[*] Clearing temporary files:\n')
			logfile.write(f'[>] Deleting {nmap_path}\n')
		#Exception if function returns error
		except subprocess.CalledProcessError:
			print(f'[x] Failed to delete {nmap_path}. Skipping to the next stage.')
			logfile.write(f'[x] Failed to delete {nmap_path}. Skipping to the next stage.\n')
			pass
	return

#Function to exit the script	
def menu_exit():
	sys.exit(0)

#Function to get user keyword during Search Mode
def user_search():
	keyword = input('[?] Please provide keyword to search through the log (e.g password, tcp open, udp): ')
	return keyword

#Function to define main script function
def main():
	print('Welcome to Automated Network and Vulnerabilities Scanning')

	#Get user IP input
	target_ip = get_ip()
	
	#Get user path input
	userpath = get_userpath()
	
	#Get date and time for naming prefix
	date_now = datetime.date.today()
	date_format = date_now.strftime('%Y-%m-%d')
	time_now = datetime.datetime.now().time()
	time_format = time_now.strftime('%H-%M-%S')
	nmap_xml = f'{date_format}_{time_format}_{target_ip.split("/")[0]}_{nmap_xml_file}'
	
	#Log file name preparation and opening it for writing
	log_name = f'{date_format}_{time_format}_{target_ip.split("/")[0]}_{log_file}'
	log_path = os.path.join(userpath,log_name)
	logfile = open(log_path, 'a')
	logfile.write(f'[*] Output is saved in {userpath} directory.\n')
	
	#Zip file name preparation
	zip_name = f'{date_format}_{time_format}_{target_ip.split("/")[0]}_{zip_file}'
	zip_path = os.path.join(userpath,zip_name)
	
	current_path = os.getcwd()
	user_lst = os.path.join(current_path,user_file)
	passwd_lst = os.path.join(current_path,passwd_file)
	#Get user password list
	passwd_user = input(f'[?] Provide custom password lists (Press Enter to use default {passwd_file}: ')
	#Validate password list input
	if os.path.isfile(passwd_user):
		passwd_lst = passwd_user
	print(f'[*] Weak password scan will use {os.path.abspath(passwd_lst)} for password list.')
	logfile.write(f'[*] Weak password scan uses {os.path.abspath(passwd_lst)} for password list.\n')

	
	print('\n[*] Retrieving IP from Nmap Host Discovery scan on target network...')
	logfile.write('\n[*] Retrieving IP from Nmap Host Discovery scan on target network.\n')
	#Scan network for host discovery
	ip_lst = scan_ip(target_ip)
	#Get localhost IP
	ip_ignore = self_ip()
	
	#Print results in shell and log
	print('[&] IP found in the network:')
	logfile.write('\n[&] IP found in the network:\n')
	for each in ip_lst:
		print(f'[o] {each}')
		logfile.write(f'[o] {each}\n')
	
	print('\n[&] IP of this local machine will be ignored by scanning:')
	print(f'[x] {ip_ignore}')
	logfile.write('\n[&] IP of this local machine will be ignored by scanning:\n')
	logfile.write(f'[x] {ip_ignore}\n')
	
	time.sleep(2)
	
	#Prompt user with choices
	user_choice=main_menu()
	if user_choice == '1':
		menu_one(ip_lst, user_lst, passwd_lst, logfile)
	elif user_choice == '2':
		menu_two(ip_lst, user_lst, passwd_lst, nmap_xml, logfile)
	else:
		print('[x] Exiting ...')
		menu_exit()	
	
	#Close opened log file after done writing
	logfile.close()
	
	#Reopen log file for reading, use readlines for iteration
	with open(log_path, 'r') as file:
		data = file.readlines()
	
	print('\n')
	print('='*100)
	print(f'[>>>] LOG SEARCH MODE')
	print('='*100)
	print(f'[&] Opening log file {log_path}...')
	print('[&] Press CTRL+C to exit.\n')
	
	#Create zip file object
	with zipfile.ZipFile(zip_path, 'w') as zip_object:
		zip_object.write(log_path)
	
	#Start endless loop of Search Mode, until user interrupted
	search_mode = True
	
	while search_mode:
		try:
			#Call user_search function
			keyword = user_search()
			match = 0
			print('\n')
			
			#Search each line for keyword
			for line in data:
				if keyword in line:
					print(data.index(line)+1, line)
					match += 1
			
			#If there's no match
			if match == 0:
				print('[x] Could not find keyword in the log.\n')
		
		#Exception for user interruption to exit endless loop
		except KeyboardInterrupt:
			search_mode = False
	
	print('\n\n')
	print(f'Log file is saved at {log_path}')
	
	#Zip file validation
	if os.path.exists(zip_path):
		print(f'Zipfile has been created at {zip_path}')
			
	print('\n[>>>] Exiting...')
		
#Run the script
main()
