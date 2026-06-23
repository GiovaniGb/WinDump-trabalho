# WinDump-trabalho

Este projeto demonstra como executar o **WinDump** junto ao PCAP utilizando 15 pacotes de teste que contêm as extensões **AltMark**, **IOAM** e **PDM**.

> **Nota:** Todos os arquivos necessários para a execução já estão inclusos na pasta `executar`.

## Estrutura do Projeto

Abaixo está a descrição dos arquivos e pastas que compõem este repositório:

```text
├── .vscode/                        # Configurações do VS Code para compilação
├── executar/                       # Executável, pcap de testes e instalador do driver
├── windump-3.9.5/                  # Código-fonte modificado com as implementações
├── winpcap/
│   └── WpdPack/                    # Arquivos de desenvolvimento do WinPcap
├── WpdPack_4_1_2.zip               # Pacote compactado do WpdPack
└── tcpdump-windump_3.9.5.diff     # Arquivo de diferenças do código-fonte
```

## Pré-requisitos e Instalação

1. Acesse a pasta `executar`.
2. Instale o arquivo `WinPcap_4_1_3.exe`. 
   * *Atenção: É obrigatório utilizar esta versão específica do instalador fornecida na pasta.*

---

## Como Executar

Siga os passos abaixo para realizar a análise dos pacotes:

1. Abra o **Prompt de Comando (CMD)** diretamente na pasta `executar`.
2. No CMD, execute o seguinte comando:

```cmd
.\windump.exe -vvv -XX -s 0 -r .\pacotes_teste.pcap
```
---
## Parâmetros Utilizados

* **`-vvv`**: Ativa o modo de saída extremamente detalhado (*verbose*).
* **`-XX`**: Exibe o conteúdo de cada pacote tanto em formato hexadecimal quanto em ASCII.
* **`-s 0`**: Define o tamanho do *snapshot* como 0 (captura o pacote inteiro, sem cortes).
* **`-r`**: Lê os pacotes a partir do arquivo `.pcap` especificado, em vez de capturar o tráfego de uma interface de rede ativa.
