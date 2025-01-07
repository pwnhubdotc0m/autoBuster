# autoBuster

An intelligent directory brute-forcing tool with automated application detection

## Easy Installation

### For `Linux` and `MacOS`
1. Open Terminal
2. Clone the repository

```bash
git clone https://github.com/pwnhubdotc0m/autoBuster.git
```

3. Navigate to the project directory

```bash
cd autoBuster
```
4. Install dependencies

```bash
sudo pip3 install -r requirements.txt
```
### For `Windows`
1. `Open Command Prompt` or `PowerShell`
2. Ensure you have Python and Git installed. To check,
   
```bash
python --version
git --version
```
If not installed, download and install [Python](https://www.python.org/) & [Git](https://git-scm.com/)

3. Clone the repository using 'Git'

```bash
git clone https://github.com/pwnhubdotc0m/autoBuster.git
```
3. Navigate to the project directory

```bash
cd autoBuster
```
4. Install dependencies

```bash
pip install -r requirements.txt
```
## Options
```bash
usage: autoBuster.py [-h] [-o {txt,json,csv}] url

AutoBuster: Directory Brute Forcing Tool with Application Detection

positional arguments:
  url                   The target URL to analyze

options:
  -h, --help            show this help message and exit
  -o {txt,json,csv},    --output {txt,json,csv}
                        Output format for the results (txt, json, or csv)
```

## Examples
```bash
python autoBuster.py -o json https://xyz.com
```
