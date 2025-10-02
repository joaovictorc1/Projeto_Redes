# 📡 Análise de Tráfego de Rede com Python + Excel

Este projeto captura pacotes de rede de um servidor específico, salva os dados em um arquivo CSV e permite a análise interativa no Excel por meio de Tabelas Dinâmicas e Gráficos.

---

## 🚀 Funcionalidades
- Captura pacotes de rede em tempo real usando a biblioteca Scapy.
- Filtra pacotes relacionados a um IP de servidor definido.
- Salva os dados em captura.csv com os campos:
  - timestamp
  - direcao (ENTRADA ou SAÍDA)
  - client_ip
  - protocolo (TCP, UDP, Outro)
  - tamanho (bytes)
- Permite análise no Excel com Tabelas Dinâmicas e Gráficos.

---

## 🛠️ Pré-requisitos
- Python 3.12+ (recomendado, pois o Scapy pode falhar em versões mais novas como 3.13).
- Npcap instalado no Windows (necessário para captura de pacotes).
- Bibliotecas Python:
  ```bash
  pip install scapy
