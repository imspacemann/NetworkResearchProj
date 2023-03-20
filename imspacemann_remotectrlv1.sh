#!/bin/bash
echo "
#*-- REMOTE CONTROL v1.2 --*#"

function REMOTE()
{
echo -e "\n--------------------------------------"
echo "What do you like to do? Choose number.
1 Update Operating System (if you have error with Pre-Operation Check)
2 Run Pre-Operation Check (check whether all commands needed are installed)
3 EXECUTION (Collect Info through a compromised machine)
"
read choice
if [[ "$choice" =~ [[:digit:]] && "$choice" -gt 0 && "$choice" -le 3 ]]
then

	case $choice in
#This Option allows user to check for update and upgrade of Operating System
#sudo -S receives password input by echo-ing password'kali' before sudo command
	1)
	echo "Checking and updating Linux System.."
	echo kali | sudo -S apt-get update 2>/dev/null
	
	sudo apt-get -u upgrade --assume-no >/dev/null 2>&1
	function UPDATER() 
	{
		echo "Ready to upgrade? It will take a while. (y/n)"
		read answer
		case $answer in
			y|Y)
				echo
				echo "---UPGRADING PACKAGES---"
				echo
				sudo apt-get upgrade -y
				echo "All done! Going back to Main Menu.."
				REMOTE
				;;
			n|N)
				echo "OK. Going back to Main Menu.."
				REMOTE
				;;
			*)
				echo
				echo "Wrong Input. Please answer 'y or 'n'."
				UPDATER
				;;
		esac
	
	REMOTE
	}
	UPDATER
	;;


#~ # PRECHECK checks if the needed applications needed are installed, else, it will proceed to install it
#~ # command -v checks if the applications are installed, >/dev/null is used to throw/hide the stdout message from terminal
#~ # echo {password} | sudo -S {command} eliminates the interactive prompt for password when executing sudo
	2)
	function PRECHECK()
	{
		# sshpass is a non-interactive ssh password authentication tool to remote access the compromised machine to do recon activities
		function installsshpass()
		{
		if command -v sshpass >/dev/null
		then 
			echo '[+] sshpass is installed'
			return
		else
			echo '[-] sshpass NOT installed, installing...'
			echo kali | sudo -S apt-get install sshpass -y 2>/dev/null

		fi
		installsshpass
		}
		installsshpass
		
		# Whois is used find out information about a website's record, like ip address, site's owner and site's origin etc
		function installwhois()
		{
		if command -v whois >/dev/null
		then 
			echo '[+] whois is installed'
			return
		else
			echo '[-] whois NOT installed, installing...'
			echo kali | sudo -S apt-get install whois -y 2>/dev/null
		fi
		installwhois
		}
		installwhois
		
		# Nipe is an engine that makes the Tor network our default network gateway.
		function installnipe()
		{
		# 'test -d' tests if this application exist in the directory as it is not installed in /usr/bin like other common applications
		if test -d /home/kali/nipe
		then 
			echo '[+] Nipe is installed'
			cd /home/kali/nipe
			return
		else 
			echo '[-] Nipe not found. Installing nipe..'
			cd ~
			git clone https://github.com/htrgouvea/nipe && cd nipe
			echo kali | sudo -S cpan install Try::Tiny Config::Simple JSON 2>/dev/null
			echo kali | sudo -S perl nipe.pl install 2>/dev/null
			cd /home/kali/nipe
			return
		fi
		installnipe
		}
		installnipe
		
		# LOGDIR checks if the directory that will store our log and collected info exists, if not it will create it.
		function LOGDIR()
		{
		if test -d ~/exploited && test -d ~/exploited/whois && test -d ~/exploited/nmap
			then 
				echo "[+] Directory '~/exploited' ready for storing log"
				return
			else
				echo -e "\n>> no log directory. creating in process.. <<"
				mkdir ~/exploited && mkdir ~/exploited/whois && mkdir ~/exploited/nmap 
		fi
		LOGDIR
		}
		LOGDIR
		
	REMOTE
	}
	PRECHECK
	;;
	


	3)
	cd /home/kali/nipe
	# ANONCHECK checks if User have successfully spoofed a foreign IP address using Nipe application
	# This is to ensure identity anonimity to prevent traceback before executing activities
	function ANONCHECK()
	{
	clear -x
	echo "Checking Anonymity..."
	# Declaring variables. 
	# myip is User's machine IP, which can be changed when this script is used by another machine
	# niperr is used to start Nipe
	# spoofip and spoofcc stores the spoofed ip and country code
	myip='101.127.159.84'
	niperr=$(echo 'kali' | sudo -S perl nipe.pl restart 2>/dev/null)
	spoofip=$(curl -s ifconfig.io)
	spoofcc=$(curl -s ifconfig.io/country_code)
	echo -e "\n[*] Your Public IP is $myip"
	# if spoofip returns an empty string, it will call function ANONCHECK to start nipe again	
	if [[ -z "$spoofip" ]]
	then 
		echo "spoof is warming up.."
		ANONCHECK
	# once spoofip is not empty, it will compare with User's IP to ensure anonimity
	elif [[ "$myip" != "$spoofip" ]]
	then
		echo "[+] You are ANONYMOUS now!"
		echo "[*] Your spoofed IP address is: $spoofip" 
		echo "[*] Your spoofed Country: $spoofcc"
		sleep 2
		return	
	elif [[ "$myip" == "$spoofip" ]]
	then
		echo "[X] ALERT ALERT! You are traceable! Exiting.."
		cd /home/kali/nipe
		sudo perl nipe.pl stop
		sleep 2
		exit	
	fi
	ANONCHECK
	}
	ANONCHECK
	
	echo '
	## # # # # # # # # # # # # # ###
	# R  e  M  o  T  e  C  t  r  L #
	### # # # # # # # # # # # # # ##
	'
	# EXPLOIT checks if you have entered a valid ip address or domain name and proceed to execute NMAP & WHOIS and log activity in my local computer
	# My ubuntu(192.168.48.129) is used as the compromised Remote Server
	function EXPLOIT()
	{
	echo -e "\n[?] Specify the Domain/IP Address to scan:"
	read ipd

	if [[ $ipd =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; 
	then
		if [[ $(echo $ipd | awk -F. '{print $1}') -le 255 && $(echo $ipd | awk -F. '{print $2}') -le 255 && $(echo $ipd | awk -F. '{print $3}') -le 255 && $(echo $ipd | awk -F. '{print $4}') -le 255 ]]
		then
			export SSHPASS='tc'
			echo -e "\n[*] Connecting to Remote Server:"
			if sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129 w >/dev/null 2>&1
			then
				echo "System Uptime is:"
				sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129 "w|grep "up""
				echo "System IP Address:"
				sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129 "curl -s ifconfig.io"
				echo "System Country:"
				sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129 "curl -s ifconfig.io/country_code"
				echo -e "\n[*] whoising target address:"
				sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129  "whois $ipd" > /home/kali/exploited/whois/whois_$ipd
				# $? is the exit status of the most recently-executed command; by convention, 0 means success and anything else indicates failure.
				if [ $? -eq 0 ]
				then
				echo "[@] whois data is saved into /home/kali/exploited/whois/whois_$ipd"; echo "$(date) whois data collected for: $ipd" >> /home/kali/exploited/remotectrl.log
				echo -e "\n[*] Scanning victim address:"
				sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129 "nmap -sV -Pn -p 1-100 $ipd" > /home/kali/exploited/nmap/nmap_$ipd 
				echo "[@] nmap data is saved into /home/kali/exploited/nmap/nmap_$ipd"; echo "$(date) nmap data collected for: $ipd" >> /home/kali/exploited/remotectrl.log
				else
				echo "whois/nmap not successful"
				fi
			else
				echo "Remote Server is offline.. Please find another Online Remote Server"
			fi
			return
		else
			echo "an invalid ip"
			EXPLOIT
		fi

	else
		export SSHPASS='tc'
			echo -e "\n[*] Connecting to Remote Server:"
			if sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129 w >/dev/null 2>&1
			then 
				echo "System Uptime is:"
				sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129 "w|grep "up""
				echo "System IP Address:"
				sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129 "curl -s ifconfig.io"
				echo "System Country:"
				sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129 "curl -s ifconfig.io/country_code"
				echo -e "\n[*] whoising target address:"
				sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129  "whois $ipd" > /home/kali/exploited/whois/whois_$ipd
				if [ $? -eq 0 ]
				then
				echo "[@] whois data is saved into /home/kali/exploited/whois/whois_$ipd"; echo "$(date) whois data collected for: $ipd" >> /home/kali/exploited/remotectrl.log
				echo -e "\n[*] Scanning victim address:"
				sshpass -e ssh -o StrictHostKeyChecking=no tc@192.168.48.129 "nmap -sV -Pn -p 1-100 $ipd" > /home/kali/exploited/nmap/nmap_$ipd 
				echo "[@] nmap data is saved into /home/kali/exploited/nmap/nmap_$ipd"; echo "$(date) nmap data collected for: $ipd" >> /home/kali/exploited/remotectrl.log
				else
				echo "whois/nmap not successful"
				fi
			else
				echo "Remote Server is offline.. Please find another Online Remote Server"
			fi
			return
	fi
	REMOTE
	}
	EXPLOIT
	;;
	esac

else
	echo "Invalid input.
	"
	REMOTE
fi

}
REMOTE
