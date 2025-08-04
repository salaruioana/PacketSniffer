# sniffer.py
from scapy.all import sniff, IP, TCP, UDP
import threading

class PacketSniffer:
    def __init__(self, protocol="ALL", port="", packet_callback=None):
        self.protocol = protocol.upper()
        self.port = str(port)
        self.packet_callback = packet_callback
        self.sniffing = False
        self.thread = None

    def _filter_packet(self, packet):
        if IP not in packet:
            return False

        if self.protocol == "ALL":
            return True

        if self.protocol == "TCP" and TCP in packet:
            return self.port == "" or self.port in [str(packet[TCP].sport), str(packet[TCP].dport)]

        if self.protocol == "UDP" and UDP in packet:
            return self.port == "" or self.port in [str(packet[UDP].sport), str(packet[UDP].dport)]

        return False

    def _packet_handler(self, packet):
        if not self._filter_packet(packet):
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = "IP"
        sport = None
        dport = None
        payload = b""

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            payload = bytes(packet[TCP].payload)

        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            payload = bytes(packet[UDP].payload)

        if self.packet_callback:
            self.packet_callback(src_ip, dst_ip, proto, sport, dport, payload)

    def start(self):
        if not self.sniffing:
            self.sniffing = True
            self.thread = threading.Thread(target=self._sniff, daemon=True)
            self.thread.start()

    def _sniff(self):
        try:
            sniff(prn=self._packet_handler, store=False, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            print(f"Sniffing error: {e}")

    def stop(self):
        self.sniffing = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
            self.thread = None  # <-- make sure it’s reset
