import threading
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP

class PacketSnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("Python Packet Sniffer")
        master.geometry("800x400")

        self.text_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=100, height=20)
        self.text_area.pack(padx=10, pady=10)

        self.start_button = tk.Button(master, text="Start Capture", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=5)

        self.stop_button = tk.Button(master, text="Stop Capture", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10, pady=5)

        self.sniff_thread = None
        self.stop_sniff = threading.Event()

    def packet_callback(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = str(proto)
            payload = bytes(packet.payload)
            payload_str = payload[:32].hex()
            info = f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {protocol} | Payload (hex): {payload_str}\n"
            self.text_area.insert(tk.END, info)
            self.text_area.see(tk.END)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: self.stop_sniff.is_set())

    def start_sniffing(self):
        self.text_area.insert(tk.END, "Starting packet capture...\n")
        self.stop_sniff.clear()
        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_sniffing(self):
        self.text_area.insert(tk.END, "Stopping packet capture...\n")
        self.stop_sniff.set()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
