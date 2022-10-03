#     ______                      ________              
#    / ____/___  __  ______ ___  / ____/ /___ _________ 
#   / __/ / __ \/ / / / __ `__ \/ /_  / / __ `/ ___/ _ \
#  / /___/ / / / /_/ / / / / / / __/ / / /_/ / /  /  __/
# /_____/_/ /_/\__,_/_/ /_/ /_/_/   /_/\__,_/_/   \___/ 
#                                                     
# Created by @Juuso1337
# This program tries to find the origin IP address of a website protected by Cloudflare.
# Download the latest version from github.com/juuso1337/enumflare

############################################ All libraries required by this program
import pydig                               # Wrapper for the dig command
import sys                                 # System-specific parameters and functions
from pyfiglet import Figlet                # Render ASCII art
import requests                            # Simple HTTP library
import socket                              # Basic networking
import threading                           # Threads
import argparse                            # Parse commmand line arguments
import shodan                              # IoT search engine
import pydig                               # DNS resolver
import time                                # Time
from lists import *                        # Separate file containing arrays
############################################

PARSER = argparse.ArgumentParser(description = 'EnumFlare - A simple cloudflare config auditor')

PARSER.add_argument('TARGET_DOMAIN', metavar ='domain', help ='Domain to scan')
PARSER.add_argument('SHODAN_API_KEY', metavar ='shodan', help ='Your Shodan API key', nargs='?')

ARGS = PARSER.parse_args()

###################################### All command line arguments
TARGET_DOMAIN = ARGS.TARGET_DOMAIN   #
SHODAN_API_KEY = ARGS.SHODAN_API_KEY #
######################################

######################## All global variables
VALID_SUBDOMAINS = []  # Valid subdomains get stored in this list
IP_ADDRESSES     = []  # Subdomain IP addresses get stored in this list
NOT_CLOUDFLARE   = []  # Non Cloudflare IP addresses get stored in this list
########################

############################### ANSII color codes
class COLORS:                 #
    HEADER = '\033[95m'       #
    OKBLUE = '\033[94m'       #
    OKCYAN = '\033[96m'       #
    OKGREEN = '\033[92m'      #
    WARNING = '\033[93m'      #
    FAIL = '\033[91m'         #
    BOLD = '\033[1m'          #
    UNDERLINE = '\033[4m'     #
    RESET = '\033[0m'         #
###############################

##############################
#      Define functions      #
##############################

def IS_POINTING_TO_CF():

        print(f"{COLORS.HEADER}[i]{COLORS.RESET} Checking if {COLORS.HEADER}{TARGET_DOMAIN}{COLORS.RESET} is pointing to Cloudflare nameservers . . .")

        NS_RECORD = pydig.query(TARGET_DOMAIN, "NS")

        if 'cloudflare.com' in str(NS_RECORD):
            print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} {COLORS.HEADER}{TARGET_DOMAIN}{COLORS.RESET} is pointing to Cloudflares nameservers")
            print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} Cloudflare nameservers: {COLORS.HEADER}{NS_RECORD}{COLORS.RESET}")
        else:
            print(f"{COLORS.FAIL}[-]{COLORS.RESET} {COLORS.HEADER}{TARGET_DOMAIN}{COLORS.RESET} is not pointing to Cloudflares nameservers")

def SUB_ENUM():

    print(f"{COLORS.HEADER}[i]{COLORS.RESET} Checking common subdomains . . .")

    for SUBDOMAIN in SUBDOMAINS:

        URL = f'http://{SUBDOMAIN}.{TARGET_DOMAIN}'      # Requests needs a valid HTTP(s) schema

        try:
            requests.get(URL)

        except requests.ConnectionError:
            pass

        else:
            FINAL_URL = URL.replace("http://", "")       # (?) socket.gethostbyname doesn't like "http://"

            print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} {COLORS.OKBLUE}{FINAL_URL}{COLORS.RESET} is a valid domain")
            VALID_SUBDOMAINS.append(FINAL_URL)

def SUB_IP():

     try:

        print(f"{COLORS.HEADER}[i]{COLORS.RESET} Getting subdomain IP addresses . . .")

        for SUBDOMAIN in VALID_SUBDOMAINS:
            SUBDOMAIN_IP = socket.gethostbyname(SUBDOMAIN)
            print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} {COLORS.OKBLUE}{SUBDOMAIN}{COLORS.RESET} has an IP address of {COLORS.OKBLUE}{SUBDOMAIN_IP}{COLORS.RESET}")

            if SUBDOMAIN_IP in IP_ADDRESSES is not None:
                pass
            else:
                IP_ADDRESSES.append(SUBDOMAIN_IP)

     except socket.gaierror as ge:
            print(f"{COLORS.FAIL}[-]{COLORS.RESET} Temporary failure in name resolution")
            sys.exit()

def IS_CF_IP():

    for IP in IP_ADDRESSES:

            print(f"{COLORS.HEADER}[i]{COLORS.RESET} Checking if {COLORS.OKBLUE}{IP}{COLORS.RESET} is Cloudflare . . .")

            HEAD = requests.head(f"http://{IP}")
            HEADERS = HEAD.headers

            IP_COUNTRY = requests.get(f"http://ip-api.com/csv/{IP}?fields=country").text.strip()
            
            if 'CF-ray' in HEADERS is not None:
                print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} {COLORS.OKCYAN}{IP}{COLORS.RESET} is Cloudflare")
                RAY_ID = HEAD.headers['CF-ray']
                print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} Ray-ID: {COLORS.OKCYAN}{RAY_ID}{COLORS.RESET}")
                print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} Country: {IP_COUNTRY}")

            if 'CF-ray' not in HEADERS:
                print(f"{COLORS.OKGREEN}[!]{COLORS.RESET} {COLORS.FAIL}{IP}{COLORS.RESET} is NOT cloudflare")
                print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} Country: {IP_COUNTRY}")

                if IP in NOT_CLOUDFLARE is not None:
                    pass
                else:
                    NOT_CLOUDFLARE.append(IP)

def CHECK_TLDS():

    HEAD, SEP, TAIL = TARGET_DOMAIN.partition('.')

    for TLD in TLDS:

        URL = f"http://{HEAD}.{TLD}"

        try:
            NEW_DOM = requests.get(URL)

        except requests.ConnectionError:
            pass

        else:
            FINAL_URL = URL.replace("http://", "")
            print(f"{COLORS.HEADER}[i]{COLORS.RESET} Possible TLD found: {COLORS.OKBLUE}{FINAL_URL}{COLORS.RESET}")


def SHODAN_LOOKUP():

    if not NOT_CLOUDFLARE:
        print(f"{COLORS.FAIL}[-]{COLORS.RESET} No non Cloudflare IP addresses found\n")
        sys.exit()

    try:
        API = shodan.Shodan(SHODAN_API_KEY)

        for IP in NOT_CLOUDFLARE:

            print(f"{COLORS.HEADER}[i]{COLORS.RESET} Shodan results for {COLORS.OKBLUE}{IP}{COLORS.RESET}")

            RESULTS = API.host(IP)
            COUNTRY = RESULTS["country_name"]
            ISP = RESULTS['isp']
            HOSTNAME = RESULTS['hostnames']
            DOMAINS = RESULTS['domains']
            PORTS = RESULTS['ports']

            print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} ISP: {COLORS.OKBLUE}{ISP}{COLORS.RESET}")
            print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} Country: {COLORS.OKBLUE}{COUNTRY}{COLORS.RESET}")
            print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} Hostname(s): {COLORS.OKBLUE}{HOSTNAME}{COLORS.RESET}")
            print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} Domain(s): {COLORS.OKBLUE}{DOMAINS}{COLORS.RESET}")
            print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} Open port(s): {COLORS.OKBLUE}{PORTS}{COLORS.RESET}")

    except shodan.APIError as api_error:
        print(f"{COLORS.FAIL}[-]{COLORS.RESET} No shodan API key supplied or the key is invalid")
        pass

def SEPARATOR():

    print(f"{COLORS.WARNING}={COLORS.RESET}" * 50)

def THREAD(FUNCTION):

    SEPARATOR()
    THREAD = threading.Thread(target=FUNCTION)
    THREAD.start()
    THREAD.join()
      
def MAIN():

        try:

            START_TIME = time.perf_counter()

            ASCII = Figlet(font='slant')
            ASCII_RENDER = ASCII.renderText("EnumFlare")
            print (f"{COLORS.WARNING}{ASCII_RENDER}")

            IS_POINTING_TO_CF()
            THREAD(SUB_ENUM)
            THREAD(SUB_IP)
            THREAD(IS_CF_IP)
            # THREAD(CHECK_TLDS) Work in progress
            THREAD(SHODAN_LOOKUP)
            
            with open(f"{TARGET_DOMAIN}-results.txt", "w") as FILE:

                for SUBDOMAIN in VALID_SUBDOMAINS:
                        FILE.write(f"VALID SUBDOMAIN: {SUBDOMAIN}\n")

                for IP in NOT_CLOUDFLARE:
                        FILE.write(f"LEAKED IP: {IP}\n")
                
                PERF = (time.perf_counter() - START_TIME)
                TOOK = int(PERF)

                print(f"{COLORS.HEADER}[i]{COLORS.RESET} Finished in {TOOK} seconds")
                print(f"{COLORS.OKCYAN}[+]{COLORS.RESET} Saved results in {COLORS.OKBLUE}{TARGET_DOMAIN}-results.txt{COLORS.RESET}")

        except KeyboardInterrupt:
            print("[i] Keyboard interrupt detected, exiting...")

        except Exception as e:
            print(f"[-] Exception occured\n--> {e}")

if __name__ == "__main__":
        MAIN()

##############################
#      End of program        #
##############################