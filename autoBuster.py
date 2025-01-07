#Initialize necessarry python library
import builtwith
import pyfiglet
import argparse
import os
import threading
import requests
import sys
import time
import json
import csv
from queue import Queue
from colorama import Fore, Style, Back, init


# initialize colorama to auto reset the color settings after each line print
init(autoreset=True)

# global var for ctrl + C exit
stop_bruteforce = False

# Create empty list for storing found directory
found_dirs = []

#Prints AutoBuster name in ASCII art.
def print_Tool_Name():
    ascii_banner = pyfiglet.figlet_format("~AutoBuster~", font = "speed")
    print(Fore.CYAN + Style.BRIGHT + ascii_banner) 
    print(Fore.CYAN + "Version: 1.0")

def analyze_Website(url):
    print(Fore.YELLOW + f"\nAnalyzing {Fore.GREEN + url}" + Fore.YELLOW + f" for web technologies...\n")
    try:
        technologies = builtwith.parse(url) #Parse URL for analyze with builtwith API
        if not technologies:
            print(Fore.RED + "No technologies detected.")
            return None
        else:
            #loop to check for technology match
            print(Fore.YELLOW + "Detected technologies:")
            for category, techs in technologies.items(): 
                #display item in categories
                print(f"{Fore.GREEN}- {category}: {', '.join(techs)}")
            return technologies
    except Exception as e:
        print(Fore.RED + f"Error analyzing the website: {e}")
        return None

def suggest_Wordlist(technologies, wordlist_dir):
    #create a list to store matched and unmatched technologies
    tech_wordlists = {}
    nomatch_wordlist_techs = []
    for category, techs in technologies.items():
        #code to detect if there's wordlists matching detected technology and categorize it
        for tech in techs:
            wordlists = find_Wordlist(tech, wordlist_dir)
            if wordlists:
                tech_wordlists[tech] = wordlists
            else:
                nomatch_wordlist_techs.append(tech)
    return tech_wordlists, nomatch_wordlist_techs

def find_Wordlist(tech_name, wordlist_dir):
    # Create an empty list to store matched wordlists with their full paths
    found_wordlists = []
    for root, dirs, files in os.walk(wordlist_dir):  # Traverse the wordlist directory recursively
        for file in files:
            if tech_name.lower() in file.lower():  # Match technology name with filename (case-insensitive)
                # Append the full path of the matched wordlist
                found_wordlists.append(os.path.join(root, file))
    return found_wordlists

def choose_Technology(tech_wordlists, no_wordlist_techs, wordlist_dir):
    if no_wordlist_techs:
        print(Fore.YELLOW + "\nThe following technologies do not have relevant wordlists and will not be displayed:")
        for tech in no_wordlist_techs:
            print(f"{Fore.RED}- {tech}")
    
    while True:
        print(Fore.CYAN + "\nSelect from the options:")
        techs = list(tech_wordlists.keys())
        for i, tech in enumerate(techs, 1):
            print(f"{i}. {tech}")
        print(f"{len(techs) + 1}. Specify your own wordlist")

        # + Fore.White is to make user input white, improve the looking
        choice = input(Fore.CYAN + f"\nEnter your choice (1-{len(techs) + 1}): " + Fore.WHITE + f"")
        try:
            choice = int(choice)
            if 1 <= choice <= len(techs):
                selected_tech = techs[choice - 1]
                wordlists = tech_wordlists[selected_tech]  # Directly use the full paths
                return wordlists
            elif choice == len(techs) + 1:
                custom_path = input(Fore.CYAN + "Enter the full path to your wordlist: " + Fore.WHITE + f"")
                if os.path.isfile(custom_path):
                    return [custom_path]
                else:
                    print(Fore.RED + f"The file '{custom_path}' does not exist. Please try again.")
            else:
                print(Fore.RED + "Invalid choice, please try again.")
        except ValueError:
            print(Fore.RED + "Please enter a valid number.")

def choose_Wordlist(available_wordlists):
    #just in case if only one wordlist available, automatically select
    if len(available_wordlists) == 1:
        return available_wordlists[0]

    while True:
        print(Fore.CYAN + "\nSelect a wordlist to use for brute forcing:")
        for i, wordlist in enumerate(available_wordlists, 1):
            #only extract the file base name for cleaner display
            print(f"{i}. {os.path.basename(wordlist)}")
        print(f"{len(available_wordlists) + 1}. Back")
        
        choice = input(Fore.CYAN + f"\nEnter your choice (1-{len(available_wordlists) + 1}): " + Fore.WHITE + f"")
        try:
            #process the user choice and returning the selected wordlists entries
            choice = int(choice)
            if 1 <= choice <= len(available_wordlists):
                return available_wordlists[choice - 1]
            elif choice == len(available_wordlists) + 1:
                return "back"
            else:
                print(Fore.RED + "Invalid choice, please try again.")
        except ValueError:
            print(Fore.RED + "Please enter a valid number.")

def output_Results(found_dirs, output_format, config):
    #check if no directories has been found and print error message
    if not found_dirs:
        print(Fore.RED + "\nNo directories found to save.")
        return
    
    #initalize a file for saving if user specified specific output format
    filename = f"autobuster_results.{output_format}"

    # scan info for reporting
    scan_info = {
        "Target URL": config.get("target_url"),
        "Recursive": config.get("recursive"),
        "Recursion Depth": config.get("recursion_depth"),
        "Thread Count": config.get("thread_count"),
        "Status Codes": config.get("status_codes"),
        "Timeout": config.get("timeout"),
        "User-Agent": config.get("user_agent"),
        "HTTP Method": config.get("http_method"),
        "Extensions": config.get("extensions"),
        "Wordlist": config.get("wordlist"),
    }

    #saves the result in specified format and write the file extension
    if output_format == "json":
        # save as JSON
        report = {"Scan Info": scan_info, "Found Directories": found_dirs}
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
    elif output_format == "csv":
        # save as CSV
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Scan Info"])
            for key, value in scan_info.items():
                writer.writerow([key, value])
            writer.writerow([])
            writer.writerow(["Found Directories"])
            for directory in found_dirs:
                writer.writerow([directory])
    elif output_format == "txt":
        # save as TXT
        with open(filename, 'w') as f:
            f.write("Scan Info:\n")
            for key, value in scan_info.items():
                f.write(f"{key}: {value}\n")
            f.write("\nFound Directories:\n")
            for directory in found_dirs:
                f.write(directory + "\n")

    print(Fore.GREEN + f"\n[+] Results saved to {filename}")

def brute_Start(url, wordlist, output_format=None):
    #ask if user wants to enable recursive search, default no
    recursive_input = input(Fore.CYAN + "Do you want to enable recursive search? (y/n, default = no): " + Fore.WHITE + f"").lower()
    recursive = True if recursive_input == 'y' else False
    
    #if user wants to search recursively, ask for depth, else default 2
    if recursive:
        recursion_depth = input(Fore.MAGENTA + "Enter recursion depth (default is 2): " + Fore.WHITE + f"")
        recursion_depth = int(recursion_depth) if recursion_depth else 2
    else:
        recursion_depth = 0

    #ask for number of threads else default 50
    thread_count = input(Fore.CYAN + "Enter the number of threads to use (default is 50): " + Fore.WHITE + f"")
    thread_count = int(thread_count) if thread_count else 50

    #ask for status code, default 200
    status_codes_input = input(Fore.CYAN + "Enter status codes to track (comma separated, e.g., 200,301,302) (default is 200): " + Fore.WHITE + f"")
    if status_codes_input:
        status_codes = [int(code.strip()) for code in status_codes_input.split(',')]
    else:
        status_codes = [200]

   #ask for user-agent, http_method, specify file ext
    user_agent = input(Fore.CYAN + "Enter custom user-agent (default is 'AutoBuster/1.0'): " + Fore.WHITE + f"") or 'AutoBuster/1.0'

    http_method = input(Fore.CYAN + "Enter HTTP method to use (default is GET): " + Fore.WHITE + f"").upper() or 'GET'

    extensions = input(Fore.CYAN + "Enter file extensions to try (comma separated, e.g., .php,.html) or leave empty: " + Fore.WHITE + f"").split(',')

     #ask for timeout, else 5 seconds
    timeout_input = input(Fore.CYAN + "Enter timeout in seconds (default is 5): " + Fore.WHITE + f"")
    timeout = int(timeout_input) if timeout_input else 5

    #print the configured options as information in MAGENTA with the title in YELLOW
    print(Fore.YELLOW + f"\nStarting brute-force with the following settings:")
    print(Fore.MAGENTA + 
        f"- Recursive: {'Enabled' if recursive else 'Disabled'} (Depth: {recursion_depth})\n"
        f"- Thread count: {thread_count}\n"
        f"- Status codes: {status_codes}\n"
        f"- Timeout: {timeout} seconds\n"
        f"- User-Agent: {user_agent}\n"
        f"- HTTP method: {http_method}\n"
        f"- Extensions: {extensions if extensions != [''] else 'None'}\n"
        f"- Wordlist: {wordlist}\n"
        f"- Target URL: {url}\n")
    
    # Create the config for parsing to output function
    config = {
        "target_url": url,
        "recursive": recursive,
        "recursion_depth": recursion_depth,
        "thread_count": thread_count,
        "status_codes": status_codes,
        "timeout": timeout,
        "user_agent": user_agent,
        "http_method": http_method,
        "extensions": extensions,
        "wordlist": wordlist,
    }

    #use library to start the time
    start_time = time.time()
    #start the brute-force attack with the tailoring inputs and end the time when finished
    dir_Brute(url, wordlist, recursive=recursive, threads=thread_count, status_codes=status_codes,
                          timeout=timeout, user_agent=user_agent, http_method=http_method, extensions=extensions,
                          recursion_depth=recursion_depth)
    end_time = time.time()
    
    #Count the elapse time and display it in seconds with 2 decimal points after display result
    elapsed_time = end_time - start_time
    print(Fore.YELLOW + "\n\n[+] Brute force complete. Found directories:")
    for directory in found_dirs:
        print(Fore.GREEN + directory)
    print(Fore.YELLOW + f"\n[+] Scan completed in {elapsed_time:.2f} seconds.")

    if output_format:
        output_Results(found_dirs, output_format, config)

def dir_Brute(url, wordlist, recursive=False, threads=50, status_codes=[200], timeout=5,
                          user_agent='AutoBuster/1.0', http_method='GET', extensions=[], recursion_depth=2):
    global stop_bruteforce

    def worker():
        #Worker function for each thread.
        #continue fetch entries from queue until it is empty or the attack is finished
        while not word_queue.empty() and not stop_bruteforce:
            directory = word_queue.get()
            try:
                for ext in ([''] + extensions):
                    #append extension if user specified
                    full_path = f"{url.rstrip('/')}/{directory}{ext}"
                    #using \r carriage return to make the printing stays in one line for cleaner terminal
                    sys.stdout.write(f"\r{Fore.CYAN}[*] Testing: {full_path}")
                    sys.stdout.flush()
                    
                    #craft HTTP requests with user agent etc. and then send to the target URL
                    headers = {'User-Agent': user_agent}
                    response = requests.request(http_method, full_path, timeout=timeout, headers=headers)

                    #if user specified status codes, append it into found dir if applicable
                    if response.status_code in status_codes:
                        print(Fore.GREEN + f"\n[+] Found: {full_path} (Status: {response.status_code})")
                        found_dirs.append(full_path)
                        #if recursive is enabled, when found a valid dir, re-call the function
                        if recursive and recursion_depth > 1:
                            dir_Brute(full_path, wordlist, recursive=recursive, threads=threads,
                                        status_codes=status_codes, timeout=timeout, user_agent=user_agent,
                                        http_method=http_method, extensions=extensions, recursion_depth=recursion_depth - 1)
                        break
            except requests.RequestException:
                pass
            finally:
                word_queue.task_done()

    #fetch stripped wordlist data
    with open(wordlist, 'r') as f:
        directories = [line.strip() for line in f.readlines()]

    #create a queue to store the wordlist entries
    word_queue = Queue()
    for directory in directories:
        word_queue.put(directory)

    thread_list = []
    for _ in range(threads):
        #create and start worker thread 
        thread = threading.Thread(target=worker)
        thread_list.append(thread)
        thread.start()
    #waits for all threads to complete tasks
    for thread in thread_list:
        thread.join()

def main():
    print_Tool_Name()

    #Initializes argument for CLI inputs
    parser = argparse.ArgumentParser(description='AutoBuster: Directory Brute Forcing Tool with Application Detection')
    parser.add_argument('url', type=str, help='The target URL to analyze')
    parser.add_argument('-o', '--output', type=str, choices=['txt', 'json', 'csv'],
                        help='Output format for the results (txt, json, or csv)')
    args = parser.parse_args()

    current_dir = os.path.dirname(os.path.abspath(__file__))
    #constructs the default directory path for wordlists
    wordlist_dir = os.path.join(current_dir, 'wordlists', 'Web-Content')
    print(Fore.YELLOW + f"\nWordlist directory being used: {Fore.GREEN + wordlist_dir}")
    #detects technology
    technologies = analyze_Website(args.url)

    if technologies:
        while True:
            tech_wordlists, no_wordlist_techs = suggest_Wordlist(technologies, wordlist_dir)
            chosen_tech = choose_Technology(tech_wordlists, no_wordlist_techs, wordlist_dir)

            if isinstance(chosen_tech, list):
                wordlist_choice = choose_Wordlist(chosen_tech)
            else:
                wordlist_choice = chosen_tech[0]

            if wordlist_choice == "back":
                continue
            
            print(Fore.YELLOW + f"\nStarting directory brute-forcing on {Fore.GREEN + args.url}" + Fore.YELLOW + f" using {Fore.GREEN +wordlist_choice}...\n")
            #start brute force with user defined wordlists and settings
            brute_Start(args.url, wordlist_choice, output_format=args.output)
            break

if __name__ == "__main__":
    main()