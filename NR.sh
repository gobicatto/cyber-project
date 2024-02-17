#!/bin/bash

#Date 		: 14/12/2023
#How To     : Run NR.sh in your terminal
#Objective  : Create automation to display the Linux operating system information.
#Written by : Renald Taurusdi / S18 / CFC01102023-2
#Trainer    : Ryan Tan

## VARIABLES
## =========
## LIST OF REQUIRED PACKAGES
## These are list of packages that needed by the script to be able to run properly
## The script will check through each pacakges in the variable, and if there's missing pakcages, the script will install automatically
listpkg="
geoip-bin
sshpass
whois
tor
nipe
"

## LOG FILE
## There are two log files created by the script, both logs is stored in /var/log/
## Variables are set below and contain full path to each log

## nr-user.log has information related to the script execution
userlog=$(touch /var/log/nr-user.log | readlink -f /var/log/nr-user.log)

## nr.log has information of the scanned target data and the files location in local machine
datalog=$(touch /var/log/nr.log | readlink -f /var/log/nr.log)


## REMOTE SERVER AND LOCAL USER INFORMATION

## Remote server variables store remote server information, such as ip address, username, and password
server_ip="170.64.166.76"
server_user="nrproject"
server_pass="nrproject"

## Local user variables store current username, current user home directory, and current working directory from which the script is running
current_user=$(logname)
current_homedir="/home/$current_user"
current_workdir=$(pwd)


## FUNCTIONS
## =========

## Function to check if nipe is installed in the localhost
function check_nipe_installed()
{
	## Get current username and setting file path for nipe.pl
	current_user=$(logname)
	nipe_file="/home/$current_user/nipe/nipe.pl"
	
	## Check if nipe.pl exist in the specified path
	if [ -f "$nipe_file" ]
	then
		## If installed, print out confirmation
		echo "[o] nipe is already installed."
	else
		## If not installed, it will call the function install_nipe for nipe installation
		echo "[x] nipe is not installed. Installing nipe."
		install_nipe
	fi
}

## Function to install nipe
function install_nipe()
{
	## Set to current home directory
	cd $current_homedir
	
	## Git clone nipe installation folder and set current directory to ./nipe
	git clone https://github.com/htrgouvea/nipe && cd "/home/$current_user/nipe"
	
	## Install dependencies scripts for nipe to run
	## -q will run silent output and <<< yes will automatically provide yes to continue running the installation
	cpanm -q --installdeps .
	cpan install Switch JSON LWP::UserAgent Config::Simple <<< yes
	
	## Install perl nipe.pl
	perl nipe.pl install
	echo "[o] nipe is installed."
	
	## Log package check into nr-user.log
	echo "$(date) Package check. Installed missing packages: nipe" >> $userlog
}

## Function to run nipe
function run_nipe()
{
	## Set current directory to ./nipe
	cd "/home/$current_user/nipe"
	
	## Stop nipe service and start it again to clear any buggy connection
	perl nipe.pl stop
	perl nipe.pl start
	
	## Get nipe service status if it's running or not. Awk command will get the nipe running status True or False
	nipe_status=$(perl nipe.pl status | grep -i status | awk '{print $NF}')
	
	## Due to nipe known buggy connection error, it will fail to connect and the status will return empty
	## The code block below will only run if nipe_status variable is not empty to avoid messy error output
	if [ -n "$nipe_status" ]
	then
		## Get nipe spoofed ip address with grep and awk text manipulation
		nipe_ip=$(perl nipe.pl status | grep -i ip | awk '{print $NF}')
		
		## Get nipe spoofed country with geoiplookup and awk text manipulation
		## Sed will remove extra white space at the start of the line for cleaner output
		nipe_country=$(geoiplookup $nipe_ip | awk -F, '{print $NF}' | sed 's/^\ *//')
	fi
	
	## Check if nipe status is running and connection is anonymous
	if [ -n "$nipe_status" ] && [ "$nipe_status" = "true" ]
	then
		## If nipe_status is not empty and its value equal true, connection is anonymous and script can proceed running
		## Print out information of ip address and country for user
		echo ""
		echo "[*] You are now anonymous."
		echo "[*] Your spoofed IP address is $nipe_ip"
		echo "[*] Your spoofed country is $nipe_country"
		
		## Log spoofed ip address information to nr-user.log
		echo "$(date) Running on spoofed IP: $nipe_ip" >> $userlog	
	else
		## If nipe_status is empty or its value equal false, connection is not anonymous and script will exit
		## Due to nipe known buggy connection error, it might be worth to try rerunning the script again before further debugging
		echo ""
		echo "[x] You are not anonymous. Please try to rerun the script."
		echo "[x] Exiting..."
		
		## Log exit with fail reason to nr-user.log
		echo "$(date) EXIT. Reason: FAIL not anonymous" >> $userlog
		
		## Exit the script immediately
		exit
	fi
}

## MAIN SECTION
## ============

## Log start of the script to nr-user.log
echo "$(date) START. Checking all required packages." >> $userlog

## CHECK REQUIRED PACKAGES
## Loop through each package in the listpkg variable to check if it's already installed or not
for eachpkg in $listpkg
do
	## Since nipe requires special installation, when checking for nipe, it will call function check_nipe_installed instead
	if [ "$eachpkg" = "nipe" ]
	then
		## Call function check_nipe_installed to check for nipe
		check_nipe_installed
	else
		## For other packages, the script is using apt-cache policy to check if it's installed or not.
		## If it's not installed, it will show (none) instead of installed version number.
		pkg_ok=$(apt-cache policy $eachpkg | grep none)
		
		## Check if variable pkg_ok is empty or not
		if [ "" = "$pkg_ok" ]
		then
			## If the variable returns empty, that means there's no word none in the output and package is already installed with version number
			echo "[o] $eachpkg is already installed."
		else
			## Otherwise variable will return with none, which means the package are not installed yet
			echo "[x] $eachpkg is not installed. Installing $eachpkg."
			
			## Use apt-get with -qq for silent output and -y for yes confirmation and install the missing package
			apt-get -qq -y install $eachpkg
			echo "[o] $eachpkg is installed."
			
			## Log package check into nr-user.log
			echo "$(date) Package check. Installed missing packages: $eachpkg" >> $userlog
		fi
	fi
done

## Log package check into nr-user.log
echo "$(date) Package check. OK all installed" >> $userlog


## RUN NIPE
## Call function run_nipe to start anonymouse connection
run_nipe


## INPUT TARGET DOMAIN OR IP TO SCAN
## User need to specify a target domain or ip address and will be stored in scan_ip variable
echo ""
echo -n "[?] Specify a target domain or IP address to scan: "
read scan_ip

## Log target address to nr-user.log
echo "$(date) Target domain or IP to scan: $scan_ip" >> $userlog

## CONNECT TO REMOTE SERVER AND RUN UPTIME
echo ""
echo "[*] Connecting to Remote Server: "

## Connect to server with sshpass and server credentials and run command uptime in the server
## Return uptime output and store in the uptime_ssh variable
## -o StrictHostKeyChecking=no means to ignore ssh key exchange confirmation when requesting ssh connection for the first time
## -o LogLevel=ERROR means to hide unneccessary warning when making ssh connection and only output error message
uptime_ssh=$(sshpass -p "$server_pass" ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR "$server_user@$server_ip" "uptime")

## Get country with geoiplookup and awk text manipulation
## Sed will remove extra white space at the start of the line for cleaner output
server_country=$(geoiplookup $server_ip | awk -F, '{print $NF}' | sed 's/^\ *//')

## Print out server uptime information, server ip address and server country
echo "[>] Uptime: $uptime_ssh"
echo "[>] IP Address: $server_ip"
echo "[>] Country: $server_country"

## Log ssh server connection and uptime execution to nr-user.log
echo "$(date) Connected to $server_user@$server_ip, uptime $uptime_ssh" >> $userlog

## CONNECT TO REMOTE SERVER AND RUN WHOIS
## Set whois file for target
whois_file="whois_$scan_ip"

## Connect to server with sshpass and server credentials and run command whois with target information stored in scan_ip variable
## Whois result is written into a file, and readlink will return the full path of the file
## The full path will be stored in whois_ssh variable
## This ssh connection doesn't need -o flag because it only need those option when connecting to ssh for the first time
whois_ssh=$(sshpass -p "$server_pass" ssh "$server_user@$server_ip" "whois $scan_ip > $whois_file;readlink -f $whois_file")

## Print out whois target and file path
echo ""
echo "[*] Whois target's address: $scan_ip"
echo "[>] Whois data was saved into remote server: $whois_ssh"

## Log ssh server connection and whois execution to nr-user.log
echo "$(date) Connected to $server_user@$server_ip, whois $scan_ip" >> $userlog

## CONNECT TO REMOTE SERVER AND RUN NMAP
## Set nmap file for target
nmap_file="nmap_$scan_ip"

## Connect to server with sshpass and server credentials and run command nmap with target information stored in scan_ip variable
## Nmap is using flag -sV for verbose and -Pn to avoid ping and directly scan the ports. Result is written into a file, and readlink will return the full path of the file
## The full path will be stored in nmap_ssh variable
## This ssh connection doesn't need -o flag because it only need those option when connecting to ssh for the first time
nmap_ssh=$(sshpass -p "$server_pass" ssh "$server_user@$server_ip" "nmap $scan_ip -sV -Pn > $nmap_file;readlink -f $nmap_file")

## Print out nmap target and file path
echo ""
echo "[*] Nmap target's address: $scan_ip"
echo "[>] Nmap data was saved into remote server: $nmap_ssh"

## Log ssh server connection and nmap execution to nr-user.log
echo "$(date) Connected to $server_user@$server_ip, nmap $scan_ip" >> $userlog

## DOWNLOAD SCAN DATA FROM REMOTE SERVER TO LOCAL
## Set to current working directory where the script is running from
cd "$current_workdir"

## Use wget to download scanned data from remote server to localhost
## -q will run silet output, and -np will not ascend to parent directory
wget -q -np "http://$server_ip/$server_user/$whois_file"
wget -q -np "http://$server_ip/$server_user/$nmap_file"

## Print out file download and local file path information
echo ""
echo "[+] Scan data whois is downloaded to $(readlink -f $whois_file)"
echo "[+] Scan data nmap is downloaded to $(readlink -f $nmap_file)"

## Log file download and local file path information to nr-user.log
echo "$(date) Whois data is downloaded to $(readlink -f $whois_file)" >> $userlog
echo "$(date) Nmap data is downloaded to $(readlink -f $nmap_file)" >> $userlog

## Log target and local file path information to nr.log for easy audit
echo "$(date) Whois data is collected for $scan_ip: $(readlink -f $whois_file)" >> $datalog
echo "$(date) Nmap data is collected for $scan_ip: $(readlink -f $nmap_file)" >> $datalog

## Print out end of script and log location
echo ""
echo "Run success. Please find log at /var/log/nr-user.log, /var/log/nr.log"

## Log end of the script to nr-user.log
echo "$(date) EXIT. Reason: OK success" >> $userlog
