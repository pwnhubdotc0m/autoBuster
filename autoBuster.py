import builtwith
import pyfiglet
import argparse
import os
import threading
import requests
import sys
import signal
from queue import Queue
from colorama import Fore, Style, init

######9/12 color done

# Initialize colorama for cross-platform support
init(autoreset=True)

# Global flag for handling graceful exit
stop_bruteforce = False

# Initialize found_dirs as an empty list
found_dirs = []

def print_tool_name():
    """Prints the tool's name in ASCII art."""
    ascii_banner = pyfiglet.figlet_format("AutoBuster")
    print(Fore.CYAN + Style.BRIGHT + ascii_banner)

def analyze_website(url):
    """Analyzes the given URL for technologies using builtwith."""
    print(Fore.YELLOW + f"\nAnalyzing {url} for web technologies...\n")
    try:
        technologies = builtwith.parse(url)
        if not technologies:
            print(Fore.RED + "No technologies detected.")
            return None
        else:
            print(Fore.GREEN + "Detected technologies:")
            for category, techs in technologies.items():
                print(f"{Fore.GREEN}- {category}: {', '.join(techs)}")
            return technologies
    except Exception as e:
        print(Fore.RED + f"Error analyzing the website: {e}")
        return None

def find_wordlist(tech_name, wordlist_dir):
    """Search for a wordlist that contains the technology name, recursively."""
    found_wordlists = []
    for root, dirs, files in os.walk(wordlist_dir):
        for file in files:
            if tech_name.lower() in file.lower():
                found_wordlists.append(file)
    return found_wordlists

def suggest_wordlists(technologies, wordlist_dir):
    """Suggest wordlists based on detected technologies from SecLists."""
    tech_wordlists = {}
    no_wordlist_techs = []
    for category, techs in technologies.items():
        for tech in techs:
            wordlists = find_wordlist(tech, wordlist_dir)
            if wordlists:
                tech_wordlists[tech] = wordlists
            else:
                no_wordlist_techs.append(tech)
    return tech_wordlists, no_wordlist_techs

def choose_technology(tech_wordlists, no_wordlist_techs):
    """Prompts the user to choose a technology for which to use the wordlist."""
    if no_wordlist_techs:
        print(Fore.YELLOW + "\nThe following technologies do not have relevant wordlists and will not be displayed:")
        for tech in no_wordlist_techs:
            print(f"{Fore.YELLOW}- {tech}")
    
    if tech_wordlists:
        while True:
            print(Fore.CYAN + "\nSelect from the options:")
            techs = list(tech_wordlists.keys())
            for i, tech in enumerate(techs, 1):
                print(f"{i}. {tech}")
            print(f"{len(techs) + 1}. Specify your own wordlists")

            choice = input(Fore.CYAN + f"\nEnter your choice (1-{len(techs) + 1}): ")
            try:
                choice = int(choice)
                if 1 <= choice <= len(techs):
                    return techs[choice - 1]
                elif choice == len(techs) + 1:
                    return input("Specify your own wordlists: ")
                else:
                    print(Fore.RED + "Invalid choice, please try again.")
            except ValueError:
                print(Fore.RED + "Please enter a valid number.")
    else:
        print(Fore.RED + "\nNo technologies with available wordlists. Please specify your own.")
        return input("Specify your own wordlists: ")

def choose_wordlist(available_wordlists, wordlist_dir):
    """Prompts the user to choose a wordlist or go back. Search recursively in the wordlist directory."""
    def find_wordlist_file(wordlist_name, base_dir):
        """Recursively search for the wordlist file in the given directory."""
        for root, dirs, files in os.walk(base_dir):
            if wordlist_name in files:
                return os.path.join(root, wordlist_name)
        return None

    while True:
        print(Fore.CYAN + "\nSelect a wordlist to use for brute forcing:")
        for i, wordlist in enumerate(available_wordlists, 1):
            print(f"{i}. {wordlist}")
        print(f"{len(available_wordlists) + 1}. Back")
        
        choice = input(Fore.CYAN + f"\nEnter your choice (1-{len(available_wordlists) + 1}): ")
        try:
            choice = int(choice)
            if 1 <= choice <= len(available_wordlists):
                selected_wordlist = available_wordlists[choice - 1]
                full_wordlist_path = find_wordlist_file(selected_wordlist, wordlist_dir)
                
                if full_wordlist_path:
                    return full_wordlist_path
                else:
                    print(Fore.RED + f"Wordlist '{selected_wordlist}' not found in directory '{wordlist_dir}'")
                    continue
            elif choice == len(available_wordlists) + 1:
                return "back"
            else:
                print(Fore.RED + "Invalid choice, please try again.")
        except ValueError:
            print(Fore.RED + "Please enter a valid number.")

# Signal handler to handle Ctrl+C for graceful exit
def signal_handler(sig, frame):
    global stop_bruteforce
    print(Fore.YELLOW + "\n[!] Stopping brute-force operation... Please wait.")
    stop_bruteforce = True

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

def start_brute_force(url, wordlist):
    """Starts the brute force operation by asking user for settings like recursion, timeout, user-agent, and thread count."""
    
    recursive_input = input(Fore.CYAN + "Do you want to enable recursive search? (y/n): ").lower()
    recursive = True if recursive_input == 'y' else False

    if recursive:
        recursion_depth = input(Fore.CYAN + "Enter recursion depth (default is 2): ")
        recursion_depth = int(recursion_depth) if recursion_depth else 2
    else:
        recursion_depth = 0
    
    thread_count = input(Fore.CYAN + "Enter the number of threads to use (default is 50): ")
    thread_count = int(thread_count) if thread_count else 50

    status_codes_input = input(Fore.CYAN + "Enter status codes to track (comma separated, e.g., 200,301,302) (default is 200): ")
    if status_codes_input:
        status_codes = [int(code.strip()) for code in status_codes_input.split(',')]
    else:
        status_codes = [200]

    timeout_input = input(Fore.CYAN + "Enter timeout in seconds (default is 5): ")
    timeout = int(timeout_input) if timeout_input else 5

    user_agent = input(Fore.CYAN + "Enter custom user-agent (default is 'AutoBuster/1.0'): ") or 'AutoBuster/1.0'

    http_method = input(Fore.CYAN + "Enter HTTP method to use (default is GET): ").upper() or 'GET'

    extensions = input(Fore.CYAN + "Enter file extensions to try (comma separated, e.g., .php,.html) or leave empty: ").split(',')

    print(Fore.YELLOW + f"\nStarting brute-force with the following settings:\n"
          f"- Recursive: {'Enabled' if recursive else 'Disabled'} (Depth: {recursion_depth})\n"
          f"- Thread count: {thread_count}\n"
          f"- Status codes: {status_codes}\n"
          f"- Timeout: {timeout} seconds\n"
          f"- User-Agent: {user_agent}\n"
          f"- HTTP method: {http_method}\n"
          f"- Extensions: {extensions if extensions != [''] else 'None'}\n"
          f"- Wordlist: {wordlist}\n"
          f"- Target URL: {url}\n")

    brute_force_directory(url, wordlist, recursive=recursive, threads=thread_count, status_codes=status_codes,
                          timeout=timeout, user_agent=user_agent, http_method=http_method, extensions=extensions,
                          recursion_depth=recursion_depth)

def brute_force_directory(url, wordlist, recursive=False, threads=50, status_codes=[200], timeout=5,
                          user_agent='AutoBuster/1.0', http_method='GET', extensions=[], recursion_depth=2):
    """Brute force directories on the given URL using the provided wordlist."""
    
    global stop_bruteforce

    def worker():
        """Worker function for each thread."""
        while not word_queue.empty() and not stop_bruteforce:
            directory = word_queue.get()
            try:
                for ext in ([''] + extensions):
                    full_path = f"{url.rstrip('/')}/{directory}{ext}"
                    sys.stdout.write(f"\r{Fore.CYAN}[*] Testing: {full_path}         ")
                    sys.stdout.flush()

                    headers = {'User-Agent': user_agent}
                    response = requests.request(http_method, full_path, timeout=timeout, headers=headers)

                    if response.status_code in status_codes:
                        print(Fore.GREEN + f"\n[+] Found: {full_path} (Status: {response.status_code})")
                        found_dirs.append(full_path)

                        if recursive and recursion_depth > 1:
                            brute_force_directory(full_path, wordlist, recursive=recursive, threads=threads,
                                                status_codes=status_codes, timeout=timeout, user_agent=user_agent,
                                                http_method=http_method, extensions=extensions, recursion_depth=recursion_depth - 1)
                        break
            except requests.RequestException:
                pass
            finally:
                word_queue.task_done()

    with open(wordlist, 'r') as f:
        directories = [line.strip() for line in f.readlines()]

    word_queue = Queue()
    for directory in directories:
        word_queue.put(directory)

    thread_list = []
    try:
        for _ in range(threads):
            thread = threading.Thread(target=worker)
            thread_list.append(thread)
            thread.start()

        for thread in thread_list:
            thread.join()

    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Process interrupted by user. Exiting...")
        sys.exit(0)

    print(Fore.GREEN + "\n[+] Brute force complete. Found directories:")
    for directory in found_dirs:
        print(Fore.GREEN + directory)

def main():
    print_tool_name()

    parser = argparse.ArgumentParser(description='AutoBuster: Directory Brute Forcing Tool with Application Detection')
    parser.add_argument('url', type=str, help='The target URL to analyze')
    args = parser.parse_args()

    current_dir = os.path.dirname(os.path.abspath(__file__))
    wordlist_dir = os.path.join(current_dir, 'wordlists', 'Web-Content')
    print(Fore.CYAN + f"\nWordlist directory being used: {wordlist_dir}")

    technologies = analyze_website(args.url)

    if technologies:
        while True:
            tech_wordlists, no_wordlist_techs = suggest_wordlists(technologies, wordlist_dir)
            chosen_tech = choose_technology(tech_wordlists, no_wordlist_techs)

            if chosen_tech == "back":
                continue

            available_wordlists = tech_wordlists.get(chosen_tech, [])
            wordlist_choice = choose_wordlist(available_wordlists, wordlist_dir)

            if wordlist_choice == "back":
                continue
            
            print(Fore.CYAN + f"\nStarting directory brute-forcing on {args.url} using {wordlist_choice}...\n")
            start_brute_force(args.url, wordlist_choice)
            break

if __name__ == "__main__":
    main()
