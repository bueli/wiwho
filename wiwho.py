#!/usr/bin/python

#
# Capture command 
# /usr/bin/tshark -i[interface] -l -Y wlan.fc.type == 0 && wlan.fc.type_subtype == 4 -n -T fields -e wlan.sa -e wlan_mgt.ssid -e wlan_mgt.tag.oui -e wlan.bssid -e radiotap.dbm_antsignal -e wps.device_name
#
# all fields `tshark -G fields`
#

import subprocess

from threading import Thread
from queue import Queue

tshark_binary = "/usr/bin/tshark"
wifi_interface = "wlx00c0ca973b72"



def reader(pipe, queue):
    try:
        with pipe:
            for line in iter(pipe.readline, b''):
                queue.put((pipe, line))
    finally:
        queue.put(None)

def tsharklineprocessor(pipe):
    try:
        with pipe:
            for line in iter(pipe.readline, b''):
                linestring = line.decode('utf-8')
                #print("r %s" % linestring)
                fields = linestring.split('\t')
                print("|".join(fields))
    finally:
        print("bailing out of processing loop")

def stopped(process, queue):
    print("waiting for end ...")
    try:
        with pipe:
            if process.poll() != None:
                print("done")
                queue.put(None)
    finally:
        queue.put(None)

command = [tshark_binary, "-i", wifi_interface]
command.extend(["-l"])
command.extend(["-Y", "wlan.fc.type == 0 && wlan.fc.type_subtype == 4"])
command.extend(["-n"])
command.extend(["-T", "fields"])
command.extend(["-e", "wlan.sa"])
command.extend(["-e", "wlan.addr"])
command.extend(["-e", "radiotap.dbm_antsignal"])
command.extend(["-e", "wlan.antenna.id"])
command.extend(["-e", "wps.ssid"])
command.extend(["-e", "wlan.tag.oui"])
command.extend(["-e", "wlan.bssid"])
command.extend(["-e", "wps.device_name"])


#command = ["echo", "hi"] 

print(command)

line = " ".join(command)
print(line)

process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)

q = Queue()
data = Thread(target=tsharklineprocessor, args=[process.stdout]).start()
error = Thread(target=reader, args=[process.stderr, q]).start()

print("started subprocess with pid %d" % (process.pid))

for i in range(2):
    print("reading %d" % i)
    for source, line in iter(q.get, None):
        print("%s: %s" % (source, line))

process.wait()

print("child process ended with returncode %d" % (process.returncode))

exit(process.returncode)

