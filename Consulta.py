import requests
import subprocess
import sys
import time
from scapy.all import Ether, ARP, srp1


def consulta_ip(arg):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    set1 = set()
    for arg in sys.argv[1:]:
        print(f"Consultando IP: {arg}")
        try:
            time.sleep(1)
            dados = (f"https://ipapi.co/{arg}/json/")
            response = requests.get(dados, headers=headers)
            time.sleep(1)
            if response.status_code == 200:
                print("IP encontrado.")
                set1.add(arg)
            elif response.status_code == 404:
                print("IP não encontrado.")
                pass
            elif response.status_code == 403:
                print("Acesso negado. Limite de consultas atingido.")
                pass
            else:
                print("Erro ao consultar IP.")
                pass
        except requests.exceptions.RequestException as e:
            print(f"Erro na requisição: {e}")
            pass

            for arg in set1:
                    if arg in set1:
                         varredura_consulta(arg)

def varredura_consulta(arg):
            sub = {}
            
            try:
                execute = subprocess.run(["nmap", "-sS", "-Pn", "-p-", arg], check=True, text=True)
                sub["Shell"] = execute.stdout
            except subprocess.CalledProcessError as e:
                print(f"Erro ao executar a Shell: {e}")

def arping(arg):
    pacote = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=arg)
    resposta = srp1(pacote, timeout=2, verbose=0)
    if resposta is None:
        print(f"O IP: {arg} não respondeu (timeout ou offline).")
    if resposta is not None and ARP in resposta and resposta[ARP].op == 2:
        mac = resposta[ARP].hwsrc
        ip = resposta[ARP].psrc
        print(f"O IP: {ip} está no MAC: {mac}")
        print(f"Resumo:", resposta.summary())
        return mac
    else:
        if resposta is not None:
            print("Recebeu um pacote, mas não é uma resposta ARP esperada.")
        return None
    
def info_mac(mac_encontrado):
    set2 = set()
    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
    try:
        time.sleep(1)
        dados2 = (f"https://api.macvendors.com/{mac_encontrado}")
        response = requests.get(dados2, headers=headers)
        time.sleep(1)
        if response.status_code == 200:
            fabricante = response.text
            print(f"MAC encontrado: {mac_encontrado} - Fabricante: {fabricante}")
            set2.add(mac_encontrado)
        elif response.status_code == 404:
            print("MAC não encontrado.")
            pass
        elif response.status_code == 403:
            print("Acesso negado. Limite de consultas atingido.")
            pass
        else:
            print("Erro ao consultar MAC.")
            pass
    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição: {e}")
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python Consulta.py <IP>")
        sys.exit(1)

arg = sys.argv[1]
consulta_ip(arg)
varredura_consulta(arg)
mac_encontrado = arping(arg)
if mac_encontrado:
   info_mac(mac_encontrado)
