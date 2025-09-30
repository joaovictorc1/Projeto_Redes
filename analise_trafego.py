# Importações necessárias
from scapy.all import sniff, get_if_list, IP, TCP, UDP
import sys
import csv
from datetime import datetime

SERVER_IP = "192.168.1.27"
ARQUIVO_CSV = "captura.csv"

# --- FUNÇÃO PARA INICIALIZAR O CSV ---
def inicializar_csv():
    """Cria o arquivo CSV com cabeçalho, caso ainda não exista."""
    try:
        with open(ARQUIVO_CSV, "x", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "direcao", "client_ip", "protocolo", "tamanho"])
        print(f"[INFO] Arquivo CSV '{ARQUIVO_CSV}' criado.")
    except FileExistsError:
        print(f"[INFO] Arquivo CSV '{ARQUIVO_CSV}' já existe, dados serão adicionados.")

# --- FUNÇÃO DE PROCESSAMENTO DE PACOTE ---
def processa_pacote_analise(pacote):
    """Analisa pacotes e salva no CSV apenas os relevantes para o servidor alvo."""
    if not pacote.haslayer(IP) or (pacote[IP].src != SERVER_IP and pacote[IP].dst != SERVER_IP):
        return

    # Dados principais
    ip_origem = pacote[IP].src
    ip_destino = pacote[IP].dst
    tamanho_pacote = len(pacote)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Direção
    if ip_origem == SERVER_IP:
        direcao = "SAÍDA"
        client_ip = ip_destino
    else:
        direcao = "ENTRADA"
        client_ip = ip_origem

    # Protocolo
    if pacote.haslayer(TCP):
        protocolo = "TCP"
    elif pacote.haslayer(UDP):
        protocolo = "UDP"
    else:
        protocolo = "Outro"

    # Exibir no terminal
    print(f"[{timestamp}] [{direcao}] Cliente: {client_ip} | Protocolo: {protocolo} | Tamanho: {tamanho_pacote} bytes")

    # Salvar no CSV
    try:
        with open(ARQUIVO_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, direcao, client_ip, protocolo, tamanho_pacote])
    except Exception as e:
        print(f"[ERRO] Não foi possível escrever no CSV: {e}")

# --- FUNÇÃO AUXILIAR PARA ESCOLHA DA INTERFACE ---
def escolher_interface():
    print("Detectando interfaces de rede...")
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces_disponiveis = get_windows_if_list()
        for i, iface in enumerate(interfaces_disponiveis):
            print(f"  {i}: {iface['name']} ({iface.get('description', 'N/A')})")
        escolha = int(input("Digite o NÚMERO da interface que você quer monitorar: "))
        return interfaces_disponiveis[escolha]['name']
    except (ImportError, KeyError, ValueError, IndexError):
        print("[AVISO] Método alternativo para detectar interfaces...")
        interfaces_disponiveis = get_if_list()
        for i, iface_name in enumerate(interfaces_disponiveis):
            print(f"  {i}: {iface_name}")
        try:
            escolha = int(input("Digite o NÚMERO da interface: "))
            return interfaces_disponiveis[escolha]
        except (ValueError, IndexError):
            print("[ERRO] Escolha inválida. Saindo.")
            sys.exit(1)

# --- PONTO DE ENTRADA ---
if __name__ == "__main__":
    if SERVER_IP == "192.168.1.10":
        print("[AVISO] O IP do servidor ainda é o padrão, altere para o seu IP real!")

    inicializar_csv()
    interface_selecionada = escolher_interface()
    
    print(f"\nIniciando análise na interface: '{interface_selecionada}'")
    print(f"Monitorando tráfego para o servidor: {SERVER_IP}")
    print(f"Resultados sendo salvos em: {ARQUIVO_CSV}")
    print("Pressione Ctrl+C para parar a captura...")

    try:
        sniff(iface=interface_selecionada, prn=processa_pacote_analise, store=False)
    except PermissionError:
        print("\n[ERRO] Permissão negada. Execute como Administrador/root.")
    except OSError as e:
        print(f"\n[ERRO] Não foi possível usar a interface '{interface_selecionada}'. Detalhes: {e}")
    except KeyboardInterrupt:
        print("\n\n--- Fim da Captura da Fase 2 ---")
