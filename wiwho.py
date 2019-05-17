#!/usr/bin/python

#
# Capture command 
# `/usr/bin/tshark -i[interface] -l -Y wlan.fc.type == 0 && wlan.fc.type_subtype == 4 -n -T fields -e wlan.sa -e wlan_mgt.ssid -e wlan_mgt.tag.oui -e wlan.bssid -e radiotap.dbm_antsignal -e wps.device_name`
#
# all fields `tshark -G fields`
#
# Tested with `tshark --version`:
"""
TShark (Wireshark) 2.6.7 (Git v2.6.7 packaged as 2.6.7-1~deb9u1)

Copyright 1998-2019 Gerald Combs <gerald@wireshark.org> and contributors.
License GPLv2+: GNU GPL version 2 or later <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>
This is free software; see the source for copying conditions. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Compiled (32-bit) with libpcap, with POSIX capabilities (Linux), with libnl 3,
with GLib 2.50.3, with zlib 1.2.8, with SMI 0.4.8, with c-ares 1.12.0, with Lua
5.2.4, with GnuTLS 3.5.8, with Gcrypt 1.7.6-beta, with MIT Kerberos, with
MaxMind DB resolver, with nghttp2 1.18.1, with LZ4, with Snappy, with libxml2
2.9.4.

Running on Linux 4.14.79-v7+, with 927 MB of physical memory, with locale
en_GB.UTF-8, with libpcap version 1.8.1, with GnuTLS 3.5.8, with Gcrypt
1.7.6-beta, with zlib 1.2.8, binary plugins supported (13 loaded).

Built using gcc 6.3.0 20170516.
"""
#
#

import time
import subprocess
from threading import Thread
from sched import scheduler
from functools import partial

tshark_binary = "/usr/bin/tshark"
wifi_interface = "5"

# milliseconds => seconds => 10s
absence = 30
housekeeper_interval = 10

class WiFiDevice(object):
    mac = ""
    oui = ""
    last_seen = 0   # stamp in microseconds
    # how many times did it reappear
    recurrence = 0
    # cumulated airtime
    airtime = 0
    count = 0
    
def make_wifi_device(mac, oui):
    device = WiFiDevice()
    device.mac = mac
    device.oui = oui
    device.last_seen = time.time()
    return device

devices = { }

def print_devices(devices):
    for mac in devices:
        device = devices.get(mac)
        print("device: %s (%s), airtime: %fs, last: %s, reappeared: %d" % (device.mac, device.oui, device.airtime, device.last_seen, device.recurrence))
    print("number of devices %d" % len(devices))


def run_housekeeper(interval, action, actionargs=()):
    s = scheduler(time.time, time.sleep)
    housekeeper(s, interval, action, actionargs)
    print("starting scheduler")
    s.run()

def housekeeper(scheduler, interval, action, actionargs=()):
    scheduler.enter(interval, 1, housekeeper, (scheduler, interval, action, actionargs))
    action(*actionargs)

def sample(devices, mac, oui):
    node = devices.get(mac, None)
    if node:
        previous = node.last_seen
        node.last_seen = time.time()
        span = node.last_seen - previous
        if (span > absence):
            print("device has been away for %d - hello again")
            node.recurrence += 1
        else:
            node.airtime += span 
        node.count += 1
    else:
        node = make_wifi_device(mac, oui)
        devices[mac] = node
        print("new wifi device encountered %s (%s)" % (mac, oui))
    return node

def tsharkoutput_handler(pipe):
    try:
        with pipe:
            for line in iter(pipe.readline, b''):
                linestring = line.decode('utf-8').rstrip()
                #print("r %s" % linestring)
                fields = linestring.split('\t')
                print("|".join(fields))
                device = sample(devices, fields[0], fields[1])

    finally:
        print("bailing out of processing loop")

def stderr_handler(pipe):
    try:
        with pipe:
            for line in iter(pipe.readline, b''):
                print("err: %s" % line.decode('utf-8').rstrip())
    finally:
        print("stderr reader done")


command = [tshark_binary, "-i", wifi_interface]
command.extend(["-l"])
command.extend(["-Y", "wlan.fc.type == 0 && wlan.fc.type_subtype == 4"])
command.extend(["-n"])
command.extend(["-T", "fields"])
command.extend(["-e", "wlan.sa"])
command.extend(["-e", "wlan.tag.oui"])
command.extend(["-e", "wlan.bssid"])
command.extend(["-e", "radiotap.dbm_antsignal"])
command.extend(["-e", "radiotap.present.db_antnoise"])
command.extend(["-e", "wlan.ext_tag"])
command.extend(["-e", "radiotap.vht.user"])

#command = ["echo", "hi"] 
print(command)

line = " ".join(command)
print(line)

process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)
print("started subprocess with pid %d" % (process.pid))

Thread(target=tsharkoutput_handler, args=[process.stdout]).start()
Thread(target=stderr_handler, args=[process.stderr]).start()

# start the housekeeper / dumper
scheduler_thread = Thread(target=run_housekeeper, args=(housekeeper_interval, print_devices, (devices,)))
scheduler_thread.daemon = True
scheduler_thread.start()

try:
    process.wait()
except KeyboardInterrupt:
    print("CTRL-C stopping")
finally:
    print("tshark suprocess ended")

print("with returncode %s" % (process.returncode))
exit(process.returncode)

