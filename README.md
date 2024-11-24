# HTB

## Overview

Repo for working through HTB machines.

## Setup

For basic exploration the following tools are useful:

```bash
brew install nmap            # Network exploration tool and security scanner
brew install masscan         # Fast port scanner
brew install wireshark       # Network protocol analyzer
brew install nikto           # Web server scanner
brew install gobuster        # Directory/DNS/VHost bruteforcing tool
```

For password cracking and brute forcing the following tools are useful:

```bash
brew install hashcat         # Advanced password recovery utility
brew install hydra           # HTTP-based password cracking tool
```

You will need the rockyou wordlist for password cracking and user enumeration.

```bash
mkdir -p data
curl -o data/rockyou.txt https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/rockyou.txt
```

For windows exploitation the following tools are useful:

```bash
brew install smbclient       # SMB client
brew install kerbrute        # Kerberos brute forcer
brew install heimdal         # Kerberos client
brew install smbmap          # SMB mapping tool
brew install smbcacls        # SMB ACLs tool
```

Metaspoit requires the docker compose to be running as well since it needs to save data in a postgres database.

```bash
docker compose up -d          # Start docker compose for metasploit db

brew install metasploit        # Penetration testing framework
```

Then initialize the metasploit database.

```bash
msfdb init
```

Python scripts are also used. We use pyenv to manage the python versions.

```bash
brew install pyenv-virtualenv       # Python version manager
```

For sql injection the following tools are useful:

```bash
brew install sqlmap          # Automatic SQL injection tool
```
