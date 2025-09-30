from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

trafego = defaultdict(lambda: defaultdict(int))
JANELA = 5
inicio = time.time()

def processa(pacote):
    global inicio
    if time.time() - inicio >= JANELA:
        mostrar()
        trafego.clear()
        inicio = time.time()

    if IP in pacote:
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst
        if TCP in pacote:
            proto = "TCP"
        elif UDP in pacote:
            proto = "UDP"
        else:
            proto = "Outro"
        trafego[ip_origem][proto] += len(pacote)
        trafego[ip_destino][proto] += len(pacote)

def mostrar():
    print("\n--- Janela ---")
    for cliente, protos in trafego.items():
        total = sum(protos.values())
        print(f"{cliente} -> {total} bytes")
        for p, b in protos.items():
            print(f"   {p}: {b} bytes")

def iniciar(interface=None):
    print("Capturando pacotes... Ctrl+C para parar.")
    sniff(iface=interface, prn=processa, store=False)

if __name__ == "__main__":
    try:
        iniciar()
    except KeyboardInterrupt:
        print("\nFim da captura.")
