A Python-based Windows Firewall with a GUI to block websites, apps, and ports dynamically.

Features

1.Block Websites – Add domains (e.g., instagram.com, tiktok.com)

2.Block Applications – Prevent apps from accessing the internet (e.g., chrome.exe, steam.exe)

3.Block IP Addresses – Prevent access to specific IPs (e.g., 8.8.8.8, 157.240.221.35)

4.Block Ports – Disable ports for security (e.g., 80, 443, 6881-6889 for torrents)

5.Persistent Rules – Automatically saves blocked rules and reloads them on restart

6.Real-Time Logging – See blocked traffic in a log file (firewall_log.txt)

7.Automated Firewall Service – Can run as a Windows background service

#Installation
 
#Prerequisites


Before running, install the required dependencies:

Run this Command in Terminal:

**pip install pydivert psutil tkinter**

Also, download and install WinDivert:

**Download WinDivert**

Extract the ZIP file

Copy WinDivert.dll to C:\Windows\System32\

**Run the Firewall**

Run the Python script in terminal : 

**python firewall_gui.py**

convert it to an EXE:

**pyinstaller --onefile --console firewall_gui.py**

note : To run this firewall always open terminal as Administrator ctrl+s then right click and select run as administrator
