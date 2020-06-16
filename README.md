# Aircrack-automated

## Prerequisites
I'm running this script on a raspberry pi 4 that has the kali os installed. This means not much has to be installed before this script can be used. Check that you have the latest version of aircrack-ng and you should be good to go.

## What does this script do?
This script will try to capture the wep/wpa/wpa2-handshake of all nearby wireless networks and save them in a .cap file. Afterwards it will perform a dictionary attack on the captured handshakes. If the script successfully cracked the password of a wireless connection, it will try to login to that network.

## Disclaimer
Please use this script only if you are in a controlled environment and have permission of the owner of all surrounding wireless networks.

This script is still under construction. You can and probably will encounter bugs so use it with caution.
