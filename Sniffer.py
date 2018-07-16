from scapy.all import *
from datetime import datetime

def get_interfaces():
    """returns a list of available network interfaces"""
    interfaces = []
    for iface_name in sorted(ifaces.data.keys()):
        dev = ifaces.data[iface_name]
        i = name=str(dev.name).ljust(4)
        interfaces.append(i)
    return interfaces

def SniffPackets(f):
    prn_func=Wrapper(f)
    sniff(iface='Broadcom 802.11n Network Adapter',
          prn=prn_func,
          lfilter=lambda pkt: (IP in pkt) and (TCP in pkt))


def Wrapper(file_name):
    def Packet2Log(packet):
        date=str(datetime.now()).split('.')[0]
        log="{} {} {} {} {}".format(date,
                                      packet[IP].src,
                                      packet[IP].dst,
                                      packet[TCP].dport,
                                      "PASS")
        print log
        file_name.write(log+'\n' )
        file_name.flush()
    return Packet2Log

def main():
    with open("log_file.txt", 'a') as log_file:
        SniffPackets(log_file)

if __name__ == '__main__':
    main()
# sniff(iface='VMware Virtual Ethernet Adapter for VMnet8',prn=lambda x:x.summary())