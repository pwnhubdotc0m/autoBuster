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
from tqdm import tqdm
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
    print(Fore.CYAN + "Version: 2.0")

def analyze_Website(url):
    print(Fore.YELLOW + f"\nAnalyzing {Fore.GREEN + url}" + Fore.YELLOW + f" for web technologies...\n")
    try:
        technologies = builtwith.parse(url)  # Parse URL with builtwith API
        if not technologies:
            print(Fore.RED + "No technologies detected.")
            return None
        else:
            print(Fore.CYAN + "=" * 50)
            print(Fore.YELLOW + Style.BRIGHT + "Detected Technologies")
            print(Fore.CYAN + "=" * 50)
            
            for category, techs in technologies.items():
                print(Fore.BLUE + Style.BRIGHT + f"{category:20}" + Fore.RESET + f": {Fore.GREEN + ', '.join(techs)}")
            
            print(Fore.CYAN + "=" * 50)
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
    found_wordlists = []
    for root, dirs, files in os.walk(wordlist_dir):  # Traverse the wordlist directory recursively
        for file in files:
            if tech_name.lower() in file.lower():  # Match technology name with filename (case-insensitive)
                file_path = os.path.join(root, file)
                # Get file size in KB
                file_size = os.path.getsize(file_path) / 1024  # Convert bytes to KB
                # Get line count
                with open(file_path, 'r') as f:
                    line_count = sum(1 for _ in f)
                # Append wordlist details
                found_wordlists.append((file_path, file_size, line_count))
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
    """
    Let the user choose a wordlist from available options, or automatically select the only option.
    """
    # Handle case where only one wordlist is available
    if len(available_wordlists) == 1:
        wordlist_entry = available_wordlists[0]
        if isinstance(wordlist_entry, tuple):  # Handle standard wordlist entries with size and line count
            wordlist_path, file_size, line_count = wordlist_entry
            print(Fore.CYAN + "\nOnly one wordlist available, automatically selecting it:")
            print(f"{os.path.basename(wordlist_path)} ({file_size:.2f} KB, {line_count} lines)")
            return wordlist_path
        elif isinstance(wordlist_entry, str):  # Handle custom wordlist entries
            print(Fore.CYAN + "\nOnly one custom wordlist available, automatically selecting it:")
            print(f"{os.path.basename(wordlist_entry)}")
            return wordlist_entry

    # Handle case where multiple wordlists are available
    while True:
        print(Fore.CYAN + "\nSelect a wordlist to use for brute-forcing:")
        for i, wordlist_entry in enumerate(available_wordlists, 1):
            if isinstance(wordlist_entry, tuple):  # Display details for standard wordlists
                wordlist_path, file_size, line_count = wordlist_entry
                print(f"{i}. {os.path.basename(wordlist_path)} ({file_size:.2f} KB, {line_count} lines)")
            elif isinstance(wordlist_entry, str):  # Display details for custom wordlists
                print(f"{i}. {os.path.basename(wordlist_entry)}")

        print(f"{len(available_wordlists) + 1}. Back")

        choice = input(Fore.CYAN + f"\nEnter your choice (1-{len(available_wordlists) + 1}): " + Fore.WHITE)
        try:
            choice = int(choice)
            if 1 <= choice <= len(available_wordlists):
                selected_entry = available_wordlists[choice - 1]
                if isinstance(selected_entry, tuple):  # Return the wordlist path for standard entries
                    return selected_entry[0]
                elif isinstance(selected_entry, str):  # Return the custom wordlist path
                    return selected_entry
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
# Updated functions with input validation

def validate_status_codes(input_str):
    """Validate status code input to ensure it contains valid numeric codes."""
    try:
        status_codes = [int(code.strip()) for code in input_str.split(",")]
        if all(100 <= code <= 599 for code in status_codes):  # HTTP status codes range
            return status_codes
        else:
            raise ValueError
    except ValueError:
        print(Fore.RED + "Invalid status codes. Enter comma-separated numbers between 100 and 599.")
        return None

def validate_user_agent(input_str):
    """Validate user-agent string to ensure it's non-empty and valid."""
    if input_str.strip():
        return input_str.strip()
    print(Fore.RED + "Invalid user-agent. Please provide a non-empty string.")
    return None

def validate_http_method(input_str):
    """Validate HTTP method to ensure it's a common valid method."""
    valid_methods = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]
    if input_str.upper() in valid_methods:
        return input_str.upper()
    print(Fore.RED + f"Invalid HTTP method. Choose from: {', '.join(valid_methods)}")
    return None

def validate_recursion_depth(input_str):
    """Validate recursion depth to ensure it's a non-negative integer."""
    try:
        depth = int(input_str)
        if depth >= 0:
            return depth
        else:
            raise ValueError
    except ValueError:
        print(Fore.RED + "Invalid recursion depth. Enter a non-negative integer.")
        return None

def validate_timeout(input_str):
    """Validate timeout value to ensure it's a positive integer."""
    try:
        timeout = int(input_str)
        if timeout > 0:
            return timeout
        else:
            raise ValueError
    except ValueError:
        print(Fore.RED + "Invalid timeout. Enter a positive integer.")
        return None

def validate_extensions(input_str):
    """Validate file extensions input to ensure valid format (e.g., .php, .html)."""
    extensions = [ext.strip() for ext in input_str.split(",") if ext.startswith(".")]
    if extensions:
        return extensions
    print(Fore.RED + "Invalid extensions. Ensure each extension starts with a dot (e.g., .php, .html).")
    return None

def validate_file_path(file_path):
    """Validate if a file path exists."""
    if os.path.isfile(file_path):
        return file_path
    print(Fore.RED + f"File '{file_path}' does not exist. Please provide a valid file path.")
    return None

# Update brute_Start function to include input validation
def brute_Start(url, wordlist, output_format=None):
    # Recursive search validation
    while True:
        recursive_input = input(Fore.CYAN + "Do you want to enable recursive search? (y/n, default = no): " + Fore.WHITE).lower()
        if recursive_input in ["y", "n", ""]:
            recursive = recursive_input == "y"
            break
        print(Fore.RED + "Invalid input. Enter 'y' or 'n'.")

    recursion_depth = 0
    if recursive:
        while True:
            depth_input = input(Fore.MAGENTA + "Enter recursion depth (default is 2): " + Fore.WHITE)
            if not depth_input:
                recursion_depth = 2
                break
            recursion_depth = validate_recursion_depth(depth_input)
            if recursion_depth is not None:
                break

    # Thread count validation
    while True:
        thread_input = input(Fore.CYAN + "Enter the number of threads to use (default is 50): " + Fore.WHITE)
        if not thread_input:
            thread_count = 50
            break
        thread_count = validate_recursion_depth(thread_input)
        if thread_count is not None:
            break

    # Status codes validation
    while True:
        status_input = input(Fore.CYAN + "Enter status codes to track (comma-separated, e.g., 200,301) (default is 200): " + Fore.WHITE)
        if not status_input:
            status_codes = [200]
            break
        status_codes = validate_status_codes(status_input)
        if status_codes is not None:
            break

    # User-agent validation
    while True:
        user_agent_input = input(Fore.CYAN + "Enter custom user-agent (default is 'AutoBuster/1.0'): " + Fore.WHITE)
        if not user_agent_input:
            user_agent = "AutoBuster/1.0"
            break
        user_agent = validate_user_agent(user_agent_input)
        if user_agent is not None:
            break

    # HTTP method validation
    while True:
        http_method_input = input(Fore.CYAN + "Enter HTTP method to use (default is GET): " + Fore.WHITE)
        if not http_method_input:
            http_method = "GET"
            break
        http_method = validate_http_method(http_method_input)
        if http_method is not None:
            break

    # File extension validation
    while True:
        extensions_input = input(Fore.CYAN + "Enter file extensions to try (comma-separated, e.g., .php,.html) or leave empty: " + Fore.WHITE)
        if not extensions_input:
            extensions = []
            break
        extensions = validate_extensions(extensions_input)
        if extensions is not None:
            break

    # Timeout validation
    while True:
        timeout_input = input(Fore.CYAN + "Enter timeout in seconds (default is 5): " + Fore.WHITE)
        if not timeout_input:
            timeout = 5
            break
        timeout = validate_timeout(timeout_input)
        if timeout is not None:
            break

    # Display configured options
    print(Fore.YELLOW + f"\nStarting brute-force with the following settings:")
    print(Fore.MAGENTA +
          f"- Recursive: {'Enabled' if recursive else 'Disabled'} (Depth: {recursion_depth})\n"
          f"- Thread count: {thread_count}\n"
          f"- Status codes: {status_codes}\n"
          f"- Timeout: {timeout} seconds\n"
          f"- User-Agent: {user_agent}\n"
          f"- HTTP method: {http_method}\n"
          f"- Extensions: {extensions if extensions else 'None'}\n"
          f"- Wordlist: {wordlist}\n"
          f"- Target URL: {url}\n")

    # Continue with the brute-force process as before
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
    start_time = time.time()
    dir_Brute(url, wordlist, recursive=recursive, threads=thread_count, status_codes=status_codes,
              timeout=timeout, user_agent=user_agent, http_method=http_method, extensions=extensions,
              recursion_depth=recursion_depth)
    end_time = time.time()

    elapsed_time = end_time - start_time
    print(Fore.YELLOW + f"\n[+] Scan completed in {elapsed_time:.2f} seconds.")
    if output_format:
        output_Results(found_dirs, output_format, config)

def dir_Brute(url, wordlist, recursive=False, threads=50, status_codes=[200], timeout=5,
              user_agent='AutoBuster/1.0', http_method='GET', extensions=[], recursion_depth=2):
    global stop_bruteforce

    def worker(progress_bar):
        # Worker function for each thread
        while not word_queue.empty() and not stop_bruteforce:
            directory = word_queue.get()
            try:
                for ext in ([''] + extensions):
                    # Append extension if user specified
                    full_path = f"{url.rstrip('/')}/{directory}{ext}"
                    
                    # Use tqdm.write to avoid overwriting the progress bar
                    tqdm.write(f"{Fore.CYAN}[*] Testing: {full_path}")

                    # Craft HTTP requests and send to target URL
                    headers = {'User-Agent': user_agent}
                    response = requests.request(http_method, full_path, timeout=timeout, headers=headers)

                    # If user specified status codes, append valid directories
                    if response.status_code in status_codes:
                        tqdm.write(Fore.GREEN + f"[+] Found: {full_path} (Status: {response.status_code})")
                        found_dirs.append(full_path)

                        # If recursive is enabled, re-call the function for valid directories
                        if recursive and recursion_depth > 1:
                            dir_Brute(full_path, wordlist, recursive=recursive, threads=threads,
                                      status_codes=status_codes, timeout=timeout, user_agent=user_agent,
                                      http_method=http_method, extensions=extensions, recursion_depth=recursion_depth - 1)
                        break
            except requests.RequestException:
                pass
            finally:
                word_queue.task_done()
                progress_bar.update(1)  # Update the progress bar

    # Read the wordlist and fetch stripped lines
    with open(wordlist, 'r') as f:
        directories = [line.strip() for line in f.readlines()]

    # Create a queue to store wordlist entries
    word_queue = Queue()
    for directory in directories:
        word_queue.put(directory)

    # Create and start a progress bar
    with tqdm(total=len(directories), desc="Brute-forcing Progress", unit="directory") as progress_bar:
        thread_list = []
        for _ in range(threads):
            # Create and start worker threads
            thread = threading.Thread(target=worker, args=(progress_bar,))
            thread_list.append(thread)
            thread.start()

        # Wait for all threads to complete tasks
        for thread in thread_list:
            thread.join()

    print(Fore.YELLOW + "\nBrute-forcing complete. Directories found:")
    for directory in found_dirs:
        print(Fore.GREEN + directory)

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