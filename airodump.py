import pyshark
import sys
from io import StringIO
import re

beacon_list = {}
p = re.compile('SSID:.*')

BEACON_FORMAT = '{bssid}    {channel}    {signal}     {ssid}'

print('BSSID               CH    PWR     BEACONS      ESSID')

def return_print(*message):
    io = StringIO()
    print(*message, file=io, end="")
    return io.getvalue()

def display(data, beacon):
    line = 0
    for key, value in data.items():
        print('%-19s %-5s %-9s %-10s %-20s' %(value['bssid'], value['channel'], value['signal'], beacon[key], value['ssid']))
        line += 1

    sys.stdout.write("\033[{}A".format(line))
    
    return

def ap_info(packet):
    data = {}
    data['bssid'] = packet.wlan.bssid
    data['channel'] = packet.wlan_radio.channel
    data['signal'] = packet.wlan_radio.signal_dbm

    text = return_print(packet)
    m = p.findall(text)
    ssid = m[0][7:-1]
    data['ssid'] = ssid

    return data

def wlan_sniffer(capture):
    bssid_list = {}

    for num, packet in enumerate(capture):
        data = ap_info(packet)
        if(data['bssid'] in beacon_list):
           beacon_list[data['bssid']] += 1
        else:
           beacon_list[data['bssid']] = 1
        bssid_list[data['bssid']] = data
        display(bssid_list, beacon_list)
    
    return

def main(**kwargs):
    capture = pyshark.LiveCapture(display_filter="wlan.fc.type_subtype == 0x0008", **kwargs)
    wlan_sniffer(capture)

    return

if __name__=='__main__':
    args = sys.argv

    if len(args) != 2:
        print("[*] Please Provide Interface Name :\n :~# python {} [Interface_name]".format(args[0]))
        sys.exit(0)

    interface = args[1]
    main(interface=interface)
