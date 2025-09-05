# modules/scan.py
import socket
from threading import Thread

open_ports = []

def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"\033[92mPort {port} ouvert\033[0m")
            open_ports.append(port)
        s.close()
    except:
        pass

def scan_network(ip, ports):
    threads = []
    for port in ports:
        t = Thread(target=scan_port, args=(ip, port))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print(f"Scan terminé. Ports ouverts: {open_ports}")
