import subprocess
import socket
import requests
import dns.resolver
from bs4 import BeautifulSoup
import re
import ssl


#function

# function to find IP address
def find_ip_address(website):
    try:
        ip_address = socket.gethostbyname(website)
        print(f"\033[32mThe IP address of {website} is {ip_address}\033[0m")
    except socket.gaierror:
        print("Error: Invalid URL entered.")
 
# function to find IP address
def find_open_ports(website):
    command = "nmap " + website
    output = subprocess.check_output(command, shell=True)
    output_str = output.decode("utf-8")
    output_lines = output_str.split("\n")
    port_lines = [line for line in output_lines if "/tcp" in line]
    ports = [int(line.split("/")[0]) for line in port_lines]
    return ports

# function to scan for information on target website
def scan_website(website):
    
    if not website.startswith("http://") and not website.startswith("https://"):
        website = "http://" + website
    response = requests.get(website)
    page_content = response.text
    soup = BeautifulSoup(page_content, "html.parser")
    title = soup.title.string.strip()
    meta_description = soup.find("meta", attrs={"name": "description"})
    if meta_description:
        meta_description = meta_description["content"].strip()
    else:
        meta_description = ""
    meta_keywords = soup.find("meta", attrs={"name": "keywords"})
    if meta_keywords:
        meta_keywords = meta_keywords["content"].strip()
    else:
        meta_keywords = ""
    num_links = len(soup.find_all("a"))
    num_images = len(soup.find_all("img"))

  
    print("Title:", title)
    print("Meta description:", meta_description)
    print("Meta keywords:", meta_keywords)
    print("Number of links:", num_links)
    print("Number of images:", num_images)


# function to perform DNS enumeration on target website
def dns_enumeration(website):
    command = f"nmap -T4 -p 80 --script dns-brute {website}"
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    output = output.decode('utf-8')
    dns_records = []
    for line in output.splitlines():
        if "DNS brute-force hostnames" in line:
            _, dns_record = line.split(":")
            dns_records.append(dns_record.strip())
    if dns_records:
        print("\n".join(dns_records))
    else:
        print("No DNS records found.")
    return 

# function to perform Whois lookup 
def whois_lookup(website):
    result = subprocess.run(['whois', website], capture_output=True, text=True)
    print(result.stdout)


# function to perform email harvesting on target website
def email_harvesting(website):
    if not website.startswith('http'):
        website = 'http://' + website
    response = requests.get(website)
    html = response.text
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', html)
    print(emails)

# whatweb
def whatweb(website):
    command = f'whatweb {website}'
    output = subprocess.check_output(command, shell=True, text=True)
    print(output)

# nikto
# def nikto(website):
#     # run the nikto command and capture the output
#     command = f'nikto -h {website}'
#     output = subprocess.check_output(command, shell=True, text=True)

#     # print the output
#     print(output)

def print_certificates(website):
    port = 443

    
    context = ssl.create_default_context()
    with socket.create_connection((website, port)) as sock:
        with context.wrap_socket(sock, server_hostname=website) as ssock:
            cert = ssock.getpeercert()
            print(f'Issuer: {cert["issuer"]}')
            print(f'Subject: {cert["subject"]}')
            print(f'Valid From: {cert["notBefore"]}')
            print(f'Valid Until: {cert["notAfter"]}')
            print(f'Serial Number: {cert["serialNumber"]}')

#firewall info

def Firewallinfo(website):
    process = subprocess.Popen(['wafw00f', website], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, errors = process.communicate()
    print(output.decode('utf-8'))
    if 'Firewall' in output.decode('utf-8'):
        firewall_info_list = output.decode('utf-8').split('Firewall: ')
        if len(firewall_info_list) > 1:
            firewall_info = firewall_info_list[1].split('\n')[0]
            print(f'Firewall: {firewall_info}')
        else:
            print('Firewall information not found')
    else:
        print('Could not extract firewall information from the output')

#framework used

def Frameworkused(website):
    if not website.startswith('http'):
        website = 'http://' + website
    response = requests.get(website)
    headers = response.headers
    if 'X-Powered-By' in headers:
        framework_info = headers['X-Powered-By']
        print(f'Framework: {framework_info}')
    else:
        print('Could not extract framework information from the response headers')


#void main

website = input('Enter the target website URL(website.com): ')
print("\n")
find_ip_address(website)
print("\n")
open_ports = find_open_ports(website)
print("The open ports on", website, "are:", open_ports)
print("\n")
scan_website(website)
print("\n")
dns_enumeration(website)
print("\n")
whois_lookup(website)
print("\n")
email_harvesting(website)
print("\n")
whatweb(website)
print("\n")
print_certificates(website)
print("\n")
Firewallinfo(website)
print("\n")
Frameworkused(website)
