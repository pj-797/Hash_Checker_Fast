# hashchecker_apikey.sh
Scan list of hashes via hash.cymru.com for malicious level, and select top 4 results to be scanned to virustotal.com.

Requires:
  1) api key from virustotal.com
  2) file with list of hashes
  
Usage:

	bash hashchecker_apikey.sh <api key file> <hash list>
