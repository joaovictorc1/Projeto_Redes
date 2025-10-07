from scapy.all import sniff, get_if_list, IP, TCP, UDP
import sys
import time
from collections import defaultdict
import os
import csv
from datetime import datetime

# --- Configurações ---
SERVER_IP = "192.168.1.27" 
JANELA_SEGUNDOS = 5

# Constrói o caminho completo para o arquivo CSV
diretorio_script = os.path.dirname(__file__)
ARQUIVO_CSV = os.path.join(diretorio_script, "trafego_final.csv")

# --- Estrutura de Dados ---
dados_janela = defaultdict(lambda: defaultdict(lambda: {'ENTRADA': 0, 'SAÍDA': 0}))
inicio_janela = time.time()

def inicializar_csv():
    try:
        with open(ARQUIVO_CSV, "x", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "client_ip", "protocolo", "traffic_in_bytes", "traffic_out_bytes"])
    except FileExistsError:
        pass 

def processa_pacote(pacote):
    global inicio_janela
    
    if time.time() - inicio_janela > JANELA_SEGUNDOS:
        salvar_e_resetar_janela()

    if not pacote.haslayer(IP) or (pacote[IP].src != SERVER_IP and pacote[IP].dst != SERVER_IP):
        return

    ip_origem = pacote[IP].src
    ip_destino = pacote[IP].dst
    tamanho_pacote = len(pacote)

    if pacote.haslayer(TCP):
        protocolo = "TCP"
    elif pacote.haslayer(UDP):
        protocolo = "UDP"
    else:
        protocolo = "Outro"
    
    if ip_origem == SERVER_IP:
        client_ip = ip_destino
        dados_janela[client_ip][protocolo]['SAÍDA'] += tamanho_pacote
    else:
        client_ip = ip_origem
        dados_janela[client_ip][protocolo]['ENTRADA'] += tamanho_pacote

def salvar_e_resetar_janela():
    global dados_janela, inicio_janela
    
    timestamp_fim_janela = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with open(ARQUIVO_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for cliente, protocolos in dados_janela.items():
                for proto, dados in protocolos.items():
                    if dados['ENTRADA'] > 0 or dados['SAÍDA'] > 0:
                        writer.writerow([timestamp_fim_janela, cliente, proto, dados['ENTRADA'], dados['SAÍDA']])
        
        status_salvo = f"salvos em '{ARQUIVO_CSV}'"
    except PermissionError:
        status_salvo = "[AVISO] FALHA AO SALVAR! O arquivo CSV está aberto em outro programa (Excel?)."

    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"--- Dados da janela (às {timestamp_fim_janela}) {status_salvo} ---")
    if not dados_janela:
        print("Nenhum tráfego relevante capturado.")
    else:
        for cliente, protocolos in sorted(dados_janela.items()):
             for proto, dados in protocolos.items():
                print(f"Cliente: {cliente} [{proto}] | ENTRADA: {dados['ENTRADA']} B | SAÍDA: {dados['SAÍDA']} B")
    
    dados_janela.clear()
    inicio_janela = time.time()

def escolher_interface():
    print("Detectando interfaces de rede...")
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        for i, iface in enumerate(interfaces):
            print(f"  {i}: {iface['name']} ({iface.get('description', 'N/A')})")
        escolha = int(input("Digite o NÚMERO da interface que você quer monitorar: "))
        return interfaces[escolha]['name']
    except Exception:
        interfaces = get_if_list()
        for i, iface_name in enumerate(interfaces):
            print(f"  {i}: {iface_name}")
        try:
            escolha = int(input("Digite o NÚMERO da interface: "))
            return interfaces[escolha]
        except (ValueError, IndexError):
            print("[ERRO] Escolha inválida. Saindo.")
            sys.exit(1)

if __name__ == "__main__":
    inicializar_csv()
    interface_selecionada = escolher_interface()
    
    print(f"\n[INFO] O arquivo CSV será salvo em: {ARQUIVO_CSV}")
    print(f"Iniciando captura na interface: '{interface_selecionada}'...")
    print(f"Salvando dados a cada {JANELA_SEGUNDOS} segundos.")
    print("Pressione Ctrl+C para parar.")
    time.sleep(2)

    try:
        sniff(iface=interface_selecionada, prn=processa_pacote, store=False)
    except KeyboardInterrupt:
        print("\n\n--- Captura finalizada. Salvando última janela de dados... ---")
        salvar_e_resetar_janela()

