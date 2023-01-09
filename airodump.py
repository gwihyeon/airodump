import pyshark
import sys
from io import StringIO
import re

p = re.compile('SSID:.*')

BEACON_FORMAT = '{bssid}    {channel}    {signal}      {num}       {ssid}'

print('BSSID               CH    PWR    Beacons     ESSID')

def return_print(*message):
    io = StringIO()
    print(*message, file=io, end="")
    return io.getvalue()

def display_info(data):
    line = 0
    for a,b in data.items():
        print(BEACON_FORMAT.format(**b))
        line += 1

    sys.stdout.write("\033[{}A".format(line))
    
    return

def ap_info_extractor(packet):
    ref = {}
    ref['bssid'] = packet.wlan.bssid
    ref['channel'] = packet.wlan_radio.channel
    ref['signal'] = packet.wlan_radio.signal_dbm

    text = return_print(packet)
    m = p.findall(text)
    ssid = m[0][7:-1]
    ref['ssid'] = ssid

    return ref

def wlan_sniffer(capture):
    bssid_list = {}

    for num, packets in enumerate(capture):
        data = ap_info_extractor(packets)
        data['num'] = num
        bssid_list[data['bssid']] = data
        display_info(bssid_list)
    
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