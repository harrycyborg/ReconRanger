# ReconRanger
ReconRanger is an open-source reconnaissance tool designed to automate the initial information-gathering phase of penetration testing. It uses various techniques such as DNS enumeration, port scanning, web crawling, and search engine scraping to collect information about the target system and its components.

Website Reconnaissance Tool
This is a Python tool for performing reconnaissance on a target website. The tool uses various techniques to gather information on the target, such as finding the IP address, open ports, web server information, DNS enumeration, Whois lookup, email harvesting, SSL certificate details, firewall information, and identifying the framework used.

Requirements
The tool requires the following libraries to be installed:

subprocess
socket
requests
dns.resolver
bs4 (BeautifulSoup)
re
ssl
In addition, the tool uses the following external tools:

nmap (for port scanning and DNS enumeration)
whatweb (for identifying the framework used)
wafw00f (for identifying firewall information)
Usage
To run the tool, simply run the main.py script and enter the target website when prompted:

python main.py
Enter the target website: example.com

Limitations
Please note that this tool is for educational and testing purposes only. The tool should only be used on websites that you have permission to scan. Performing reconnaissance on websites without permission is illegal and can result in severe consequences.

Contributing
If you would like to contribute to the project, feel free to fork the repository and submit a pull request with your changes.

License
This tool is licensed under the MIT License. See LICENSE for more information.
