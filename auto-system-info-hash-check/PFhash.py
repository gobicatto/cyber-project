#!/usr/bin/python3

#Date 		: 17/01/2024
#How To     : Run PFhash.py <file> in your shell
#Objective  : Create automation to check for malicious hash
#Written by : Renald Taurusdi / S18 / CFC01102023-2
#Trainer    : James Lim

# Modules Import
import os
import hashlib
import sys
import requests
import zipfile

# Function Definition

# Get user home path
def getHomePath():
	return os.path.expanduser('~')

# Check if user has provided with arguments. If no argument, exit the script
def argsCheck():
	if len(sys.argv) == 1:
		print('[!] No file path provided. Please provide a file path after the script.')
		sys.exit(0)

# Check if the database zipfile exists on local. If not, download the database from url	
def getDatabase(url, zipfile):
	print('[>] Checking for database...')
	if not os.path.exists(zipfile):
		response = requests.get(url, stream=True)
		with open(zipfile,'wb') as output:
			output.write(response.content)
		print(f'[o] Downloaded malicious hash database from {url}.\n[o] Saved into {zipfile}.')
	else:
		print(f'[o] Database {zipfile} exists.')
	
	return zipfile

# Extract a zipfile into a target directory
def extractFiles(database,targetdir):
	filename = zipfile.ZipFile(database).namelist()
	with zipfile.ZipFile(database,'r') as zip_ref:
		zip_ref.extractall(targetdir)
	return filename[0]

# Generate a md5 hash to the given files
def hashFiles(files):
	hashlist = []
	hashdict = {}
	
	for eachfile in files:
		if os.path.exists(eachfile):
			with open(eachfile,'rb') as file:
				data = file.read()
				md5hash = hashlib.md5(data)
				filehash = md5hash.hexdigest()
			# Append hash to a list for comparing with database
			hashlist.append(filehash)
			
			# Put hash and file pair in dictionary for easy retrieval
			hashdict[filehash] = eachfile
	return hashlist, hashdict

# Main function 
def main():
	
	# Variables
	homepath = getHomePath()
	currentdir = os.getcwd()
	database_path = os.path.join(currentdir,'hash_database.zip')
	database_url ='https://bazaar.abuse.ch/export/txt/md5/full/'
	files = []
	cleaned_database = []
	status = ''
	
	# Calling argsCheck to check for user arguments
	argsCheck()
	
	# Arguments starts from index 1, as index 0 is the script itself
	files=sys.argv[1:]
	
	# Calling hashFiles and storing the result into each corresponding variables
	hashlist,hashdict = hashFiles(files)
	
	# Database check and download from url
	database_zip = getDatabase(database_url, database_path)
	
	# Database extraction
	database_file = extractFiles(database_zip,'.')
	
	# Database file open for read and store in variable
	with open(database_file,'r') as file:
		database=file.readlines()
	
	# Clean each entry database, remove whitespace
	for eachdata in database:
		cleaned = eachdata.strip()
		cleaned_database.append(cleaned)
		
	database = cleaned_database
	
	print('\n[>] Hashing files and checking against malicious hash database...')
	
	# Print information of hash, its file from dictionary, and status
	for eachhash in hashlist:
		
		if eachhash in database:
			status = '**FOUND**' 
		else:
			status = 'Not found'
		
		print(f'[-] {eachhash} -- {hashdict[eachhash]} : {status}')

# Calling main function	
main()
