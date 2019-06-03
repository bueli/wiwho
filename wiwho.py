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

import logging
from logging.handlers import RotatingFileHandler
from logging import Formatter

# nonstandard dependency. install with `python3 -m pip install jsonpickle`
import jsonpickle

from optparse import OptionParser

tshark_binary = "/usr/bin/tshark"
wifi_interface = "3"

# milliseconds => seconds => 10s
absence = 600

# run housekeeper very n seconds.
housekeeper_interval = 60

# don't show devices with smaller airtime (seconds).
hide_below_airtime = 10

logger = logging.getLogger(__name__)
events = logging.getLogger("events")

class WiFiDevice(object):
    mac = ""
    last_seen = None   # stamp in microseconds
    session_start = None
    # how many times did it reappear
    recurrence = 0
    # cumulated airtime
    airtime = 0
    count = 0
    comment = ""
    oui = ""
    is_away = True
    networks = { }
    sessions = [ ]
    
    def key(self):
        return self.mac

    def text(self):
       lastseen = time.strftime(u"%Y-%m-%d %H:%M", time.localtime(self.last_seen))
       return u"{0}, sum: {1:4.0f}s, last: {2}, show: {3}, sessions: {4} '{5}' - {6} {7}".format(self.mac, self.airtime, lastseen, self.recurrence, len(self.sessions), self.comment, self.oui, u",".join(self.networks).encode('utf-8'))


def make_wifi_device(mac, oui):
    device = WiFiDevice()
    # only the follwoing fields will be present in devices.json before assignment
    device.mac = mac
    device.oui = oui
    device.last_seen = time.time()
    device.session_start = device.last_seen
    device.networks = { }
    device.sessions = [ ]
    device.airtime = 0.0
    device.comment = ""
    # has the device been marked as absent?
    device.is_away = True
    return device

class Session(object):
    begin = None
    duration = None

def make_session(begin, duration):
    session = Session()
    session.begin = begin
    session.duration = duration
    return session

def new_session(node):
    if node.session_start == None:
        node.session_start = node.last_seen
        return
    duration = node.last_seen - node.session_start
    node.sessions.append(make_session(node.session_start, duration))

devices = { }

def load_devices():
    with open('devices.json', "r") as file_read:        
        content = file_read.read()
        device_list = jsonpickle.decode(content)
        return device_list

def save_devices(device_list):
    with open('devices.json', "w") as file_write:
        sorted_devices = sorted(device_list, key=lambda d : d.airtime, reverse=False)
        content = jsonpickle.encode(sorted_devices)
        file_write.write(content)
        logger.info("persisted %d devices to devices.json" % len(device_list))

def print_devices(devices):
    sorted_devices = sorted(devices.values(), key=lambda d : d.last_seen, reverse=False)
    for device in sorted_devices:
        if (device.airtime > 30):
            logger.info(device.text())
        if (device.is_away == False and device.last_seen < (time.time() - absence)):
            events.info(u"contact lost to device: {}".format(device.text()))
            device.is_away = True
    logger.info("total number of devices %d" % len(devices))

def run_housekeeper(interval, action, actionargs=()):
    s = scheduler(time.time, time.sleep)
    housekeeper(s, interval, action, actionargs)
    s.run()

def housekeeper(scheduler, interval, action, actionargs=()):
    scheduler.enter(interval, 1, housekeeper, (scheduler, interval, action, actionargs))
    action(*actionargs)

def sample(devices, mac, oui, network):
    node = devices.get(mac, None)
    if node:
        previous = node.last_seen
        node.last_seen = time.time()
        span = node.last_seen - previous
        if (span > absence):
            logger.info(u"been away for {0}s - hello again {1}".format(span, node.text()))
            node.recurrence += 1
            new_session(node)
            if device.is_away:
                events.info(u"new session for device: {0}".format(node.text()))
        else:
            node.airtime += span
        node.count += 1
    else:
        node = make_wifi_device(mac, oui)
        devices[node.key()] = node
        logger.info(u"new wifi device encountered %s (%s)" % (mac, oui))
        events.info(u"new device discovered: {0}".format(node.text()));
    
    if len(network) > 0:
        entry = node.networks.get(network, 0)
        entry += 1
        node.networks[unicode(network)] = entry
        logger.debug(u"known networks {}".format(u",".join(node.networks.keys()).encode('utf-8')))
    
    node.is_away = False
    return node

def tsharkoutput_handler(pipe):
    try:
        with pipe:
            for line in iter(pipe.readline, b''):
                linestring = line.decode('utf-8').rstrip()
                fields = linestring.split(u'\t')
                logger.debug(u'|'.join(fields).encode('utf-8'))
                device = sample(devices, fields[0], fields[1], fields[2])

    finally:
        logger.error("bailing out of processing loop")

def stderr_handler(pipe):
    try:
        with pipe:
            for line in iter(pipe.readline, b''):
                logger.error(u"err: %s" % line.decode('utf-8').rstrip())
    finally:
        logger.info("stderr reader done")

logging.basicConfig(format=u'%(asctime)s [%(levelname)5s] %(message)s', datefmt=u'%Y-%m-%d %H:%M:%S', level=logging.DEBUG)

try:
    device_list = load_devices()
    for device in device_list:
        logger.info(u"loaded device {0}".format(device.text()))
        device.is_away = True
        devices[ device.key() ] = device
except IOError as error:
    logger.warn(u"no 'devices.json' found. starting with empty list {}".format(error))
except Exception as error:
    logger.exception(u"failed to load devices.json".format(error))

parser = OptionParser()
parser.add_option("-i", "--interface", dest="wifi_interface", help="interface to use", metavar="INTERFACE")

(options, args) = parser.parse_args()

eventLogHandler = RotatingFileHandler("event.log", backupCount=10)
eventLogHandler.setFormatter( Formatter(u'%(asctime)s [%(levelname)5s] %(message)s', u'%Y-%m-%d %H:%M:%S') )
events.addHandler(eventLogHandler)

command = [tshark_binary, "-i", wifi_interface]
command.extend(["-l"])
command.extend(["-Y", "wlan.fc.type == 0 && wlan.fc.type_subtype == 4"])
command.extend(["-n"])
command.extend(["-T", "fields"])
command.extend(["-e", "wlan.sa"])
command.extend(["-e", "wlan.tag.oui"])
command.extend(["-e", "wlan.ssid"])
command.extend(["-e", "radiotap.dbm_antsignal"])
command.extend(["-e", "radiotap.present.db_antnoise"])
command.extend(["-e", "wlan.ext_tag"])

#command = ["echo", "hi"] 

line = " ".join(command)
logger.debug("command {}".format(line))

process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)
logger.debug("started subprocess with pid %d" % (process.pid))

Thread(target=tsharkoutput_handler, args=[process.stdout]).start()
Thread(target=stderr_handler, args=[process.stderr]).start()

# start the housekeeper / dumper
scheduler_thread = Thread(target=run_housekeeper, args=(housekeeper_interval, print_devices, (devices,)))
scheduler_thread.daemon = True
scheduler_thread.start()

try:
    process.wait()
except KeyboardInterrupt:
    logger.warn("CTRL-C stopping")
finally:
    logger.info("tshark suprocess ended")

logger.debug("with returncode %s" % (process.returncode))

save_devices(list(devices.values()))

exit(process.returncode)

