#!/bin/bash
#--------------------------------------------------------------------------------
#	hashchecker_apikey.sh (For Linux)
#	Creator: Poji
#	Group: Centre for Cybersecurity
#	whatis:		hashchecker_apikey.sh 	To quickly scan multiple hashes to identify its malicious level via hash.cymru.com & virustotal.com (Top 4 Malicious)
#				<api key file>	file that contains api key (Private) when signed up with VirusTotal Community. (see https://support.virustotal.com/hc/en-us/articles/115002100149-API)
#				<hash list>	 file that contains list of hashes for scanning.
#
#	To run: bash hashchecker_apikey.sh <api key file> <hash list>
#--------------------------------------------------------------------------------
rm -r /tmp/tempfile.txt /tmp/tempfile2.txt 2>/dev/null # new temp file will be created later with append
function trap_all(){  	# set up for any interruptions and exit program cleanly
		rm -r /tmp/tempfile.txt /tmp/tempfile2.txt 2>/dev/null
		echo -e "\nProgram interrupted."
		exit
}
function check_hash(){	# check all hashes if it is malicious
	if [ -z "$1" ] || [ -z "$2" ]
	then
		echo -e "Incomplete input.\nExample: \033[0;36mbash hashchecker_apikey.sh <api key file> <hash list>\033[0m"	 # if no arguments was passed
		exit
	else
		echo -e "\033[1m\e[4mTYPE      HASH             EPOCH Time  AV Hit\e[0m\033[0m"	# create Title Head
		
		# Determine the Hash Type. Only MD5, SHA-1 and SHA-256 is supported for hash.cymru.com
		while read line	
		do 
			hsh_len=$(echo -n $line | wc -c)
			case $hsh_len in
					32)	echo -n "(MD5)     " ;;
					40) echo -n "(SHA1)    " ;;
					64) echo -n "(SHA256)  " ;;
					128) echo -e "(SHA512)  \033[0;33mNot Supported.\033[0m"; continue ;;
					*)   echo -e "(Unknown) \033[0;33mInput Error. Not Supported.\033[0m"; continue ;;
					esac
			# Analyzing the hash and output into table format		
			echo -e "$(whois -h hash.cymru.com $line | awk '{
			if ( $2 == "NO_DATA" )
			{
				print substr($1, 1, 5)"....."substr($1, length($1)-4)"  ----------  "" N.A" 
				}
			else 
			{
				print substr($1, 1, 5)"....."substr($1, length($1)-4)"  "$2"   ""\033[1;31m" $3"%""\033[0m  " $1
				} 
			}' | tee -a /tmp/tempfile.txt
			)" 
		done < $2 # from file that was pass into the script
		echo -e "\033[1m\e[4m\nExtended Scan to virustotal.com (Top 4 Highest %)\e[0m\033[0m:"
		cat /tmp/tempfile.txt | sort -k 3 -Vr | grep -v "N.A" | head -n 4 | awk '{print$3"  "$4}' > /tmp/tempfile2.txt # sort in highest order and save in temp file
		while read -r first second # The -r option passed to read command prevents backslash escapes from being interpreted
		do
			echo -n $first $second " => "	# only able to send 4 hashes per minute to virustotal.com. Require API key!
			curl -s -X POST "https://www.virustotal.com/vtapi/v2/file/report?apikey=$(cat $1)&resource=$second" | awk -F 'total\":' '{print$2}' | awk '{printf "Malicious: \033[1m" $3"\033[0m out of total "$1 " Scans. Percentage: \033[1;31m%.2f%\033[0m\n",($3/$1)*100}' |  tr -d ","
		done < /tmp/tempfile2.txt
		rm -r /tmp/tempfile.txt /tmp/tempfile2.txt 2>/dev/null
		echo -e "\033[0;32m\e[1m<<< Complete >>>\e[0m\033[0m"
	fi
}
trap "trap_all" 2
check_hash $1 $2
