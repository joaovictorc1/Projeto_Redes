from scapy.all import sniff, get_if_list
import sys

def processa_pacote_simples(pacote):
    print("--- Pacote Capturado! ---")
    print(pacote.summary())

def escolher_interface():
    print("Detectando interfaces de rede...")
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        for i, iface in enumerate(interfaces):
            print(f"{i}: {iface['name']} ({iface.get('description', 'N/A')})")
        escolha = int(input("Digite o número da interface: "))
        return interfaces[escolha]['name']
    except (ImportError, KeyError):
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces):
            print(f"{i}: {iface}")
        escolha = int(input("Digite o número da interface: "))
        return interfaces[escolha]
    except (ValueError, IndexError):
        print("[ERRO] Escolha inválida. Saindo.")
        sys.exit(1)

if __name__ == "__main__":
    interface = escolher_interface()
    print(f"\nIniciando captura na interface: {interface}")
    print("Capturando os próximos 5 pacotes... (Ctrl+C para parar)")

    try:
        sniff(iface=interface, prn=processa_pacote_simples, count=5, store=False)
    except PermissionError:
        print("\n[ERRO] Permissão negada. Execute como Administrador/root.")
    except OSError as e:
        print(f"\n[ERRO] Erro ao usar a interface '{interface}': {e}")
    except KeyboardInterrupt:
        print("\nCaptura interrompida.")

    print("\n--- Fim da Captura da Fase 1 ---")
