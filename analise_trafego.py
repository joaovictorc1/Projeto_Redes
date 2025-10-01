from scapy.all import sniff, get_if_list, IP
import sys
import time
from collections import defaultdict
import os
import csv
from datetime import datetime

# --- Configurações ---
SERVER_IP = "192.168.1.27" 
JANELA_SEGUNDOS = 5
ARQUIVO_CSV = "analise_trafego.csv"

# --- Estrutura de Dados ---
# Dicionário para guardar os dados agregados da janela atual
# Formato: { 'ip_cliente': {'ENTRADA': X, 'SAÍDA': Y} }
dados_janela = defaultdict(lambda: {'ENTRADA': 0, 'SAÍDA': 0})
inicio_janela = time.time()

def inicializar_csv():
    # Cria o arquivo CSV com cabeçalho, se ele não existir
    try:
        with open(ARQUIVO_CSV, "x", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "client_ip", "traffic_in_bytes", "traffic_out_bytes"])
    except FileExistsError:
        pass # O arquivo já existe, não faz nada

def processa_pacote(pacote):
    global inicio_janela
    
    # Verifica se a janela de tempo acabou
    if time.time() - inicio_janela > JANELA_SEGUNDOS:
        salvar_e_resetar_janela()

    # Filtra pacotes irrelevantes
    if not pacote.haslayer(IP) or (pacote[IP].src != SERVER_IP and pacote[IP].dst != SERVER_IP):
        return

    # Agrega os dados
    ip_origem = pacote[IP].src
    tamanho_pacote = len(pacote)
    
    if ip_origem == SERVER_IP:
        client_ip = pacote[IP].dst
        dados_janela[client_ip]['SAÍDA'] += tamanho_pacote
    else:
        client_ip = ip_origem
        dados_janela[client_ip]['ENTRADA'] += tamanho_pacote

def salvar_e_resetar_janela():
    global dados_janela, inicio_janela
    
    timestamp_fim_janela = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Salva os dados agregados no arquivo CSV
    with open(ARQUIVO_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for cliente, dados in dados_janela.items():
            if dados['ENTRADA'] > 0 or dados['SAÍDA'] > 0:
                writer.writerow([timestamp_fim_janela, cliente, dados['ENTRADA'], dados['SAÍDA']])

    # Exibe no terminal para feedback
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"--- Dados da janela encerrada às {timestamp_fim_janela} salvos em '{ARQUIVO_CSV}' ---")
    if not dados_janela:
        print("Nenhum tráfego relevante capturado.")
    else:
        for cliente, dados in sorted(dados_janela.items()):
             print(f"Cliente: {cliente} | ENTRADA: {dados['ENTRADA']} bytes | SAÍDA: {dados['SAÍDA']} bytes")
    
    # Reseta para a próxima janela
    dados_janela.clear()
    inicio_janela = time.time()

def escolher_interface():
    # (Função sem alterações)
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
    
    print(f"\nIniciando captura e agregação na interface: '{interface_selecionada}'...")
    print(f"Salvando dados agregados a cada {JANELA_SEGUNDOS} segundos em '{ARQUIVO_CSV}'.")
    print("Pressione Ctrl+C para parar.")
    time.sleep(2)

    try:
        sniff(iface=interface_selecionada, prn=processa_pacote, store=False)
    except KeyboardInterrupt:
        print("\n\n--- Captura finalizada. Salvando última janela de dados... ---")
        salvar_e_resetar_janela()


