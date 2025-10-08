# 🧭 Dashboard de Análise de Tráfego de Servidor

## 📋 Visão Geral do Projeto

Este projeto implementa um sistema em **Python** para capturar e analisar o tráfego de rede de um servidor específico **em tempo real**.
Os dados agregados são salvos em um arquivo **CSV**, que pode ser visualizado através de um **dashboard interativo no Microsoft Excel**.

A solução foi desenvolvida para cumprir os requisitos de **análise de tráfego de rede**, focando na **captura**, **processamento** e **visualização** de dados de forma eficiente e intuitiva.

---

## ⚙️ Funcionalidades Principais

* **Captura de Pacotes:**
  Utiliza a biblioteca **Scapy** para monitorar o tráfego de uma interface de rede selecionada pelo usuário.

* **Análise e Agregação:**
  Processa pacotes em tempo real, diferenciando tráfego de **entrada** e **saída**.
  Os dados são agrupados por **cliente (endereço IP)** e **protocolo (TCP/UDP)** em janelas de tempo de **5 segundos**.

* **Saída em CSV:**
  Salva os dados agregados em um arquivo `trafego_final.csv`, formatado para ser facilmente consumido por outras ferramentas.

* **Dashboard Interativo no Excel:**
  Permite a criação de um dashboard com **Tabela Dinâmica** e **Gráfico Dinâmico**, incluindo funcionalidade de **drill down** para uma análise detalhada do tráfego.

---

## 🚀 Como Utilizar

### 🔧 Pré-requisitos

* **Python 3.x**
* **Biblioteca Scapy** (`pip install scapy`)
* **Microsoft Excel**

---

### 🧩 Passo 1: Configuração do Script

Antes de executar, é necessário configurar o endereço IP do servidor a ser monitorado.

1. Abra o arquivo `analise_trafego.py` 
2. Localize a linha:

   ```python
   SERVER_IP = "192.168.1.27"
   ```
3. Altere o endereço IP para o **IPv4 da sua máquina**.

---

### ▶️ Passo 2: Execução da Captura de Dados

O script deve ser executado com **privilégios de administrador** para ter permissão de acessar a placa de rede.

1. Abra um terminal (**Prompt de Comando** ou **PowerShell**, no Windows) **como Administrador**.
2. Navegue até a pasta do projeto.
3. Execute o script:

   ```bash
   python analise_trafego.py
   ```
4. O script irá listar as **interfaces de rede disponíveis**.
   Digite o número da interface que deseja monitorar (ex: Ethernet ou Wi-Fi) e pressione **Enter**.
5. A captura será iniciada. Gere tráfego de rede para o servidor (usando outro dispositivo) para coletar dados.
6. Para encerrar, pressione **Ctrl + C** no terminal.

O arquivo `trafego_final.csv` será **gerado ou atualizado** na pasta do projeto.

---

### 📊 Passo 3: Configuração do Dashboard no Excel

Com os dados capturados, siga os passos para criar a visualização:

1. **Importar Dados:**

   * Abra o **Excel**.
   * Vá em **Dados > De Texto/CSV** e selecione o arquivo `trafego_final.csv`.
   * Clique em **Carregar**.

2. **Criar Tabela Dinâmica:**

   * Selecione a tabela de dados.
   * Vá em **Inserir > Tabela Dinâmica**.

3. **Configurar Campos:**

   * **Linhas:** `ip` e logo abaixo `protocolo`.
   * **Colunas:** `∑ Valores`.
   * **Valores:** `trafego_entrada` e `trafego_saida`.

4. **Criar Gráfico Dinâmico:**

   * Clique na Tabela Dinâmica.
   * Vá em **Análise de Tabela Dinâmica > Gráfico Dinâmico**.
   * Escolha o tipo **Coluna Empilhada**.

---

### 📈 Resultado Final

O dashboard estará pronto!

* Para ver o **detalhamento por protocolo (drill down)**, clique nos sinais de **+** ao lado dos IPs na Tabela Dinâmica.
* Para **atualizar com novos dados**, vá em **Dados > Atualizar Tudo**.
