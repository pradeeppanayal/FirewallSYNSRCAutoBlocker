# FirewallSYNSRCAutoBlocker
Python script to identify the source IP from firwall logs and block them 

# Working
Step 1: The script will identify the lines which contains keywords `Firewall` and `SYN`
Step 2: Extract the the src ip from the line identified 
Step 3: Register the IP address to block list using the command `csf -d <IP Address>` 

# How to run
Syntax

    python AutoBlock.py <path to message file> [<run interval>]
Example

    python AutoBlock.py  /var/log/messages 
    
Example with custom message file read interval

    python AutoBlock.py  /var/log/messages admin 5
