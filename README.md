# Consulta.ip

Desenvolvimento de uma ferramenta de reconhecimento de rede que integra múltiplas fontes de inteligência, permitindo a coleta automatizada de informações de geolocalização, fabricante de hardware e serviços ativos. O projeto inclui funcionalidades de consulta a APIs públicas, varredura de portas com Nmap e descoberta de endereços MAC via ARP, consolidando os resultados em um único fluxo de trabalho.

## Instalação

- Clone este repositório.
- Crie um ambiente virtual: `python3 -m venv venv && source venv/bin/activate`
- Instale as dependências: `pip install -r requirements.txt`
- Execute: `sudo python3 Consulta.py <IP>`

## Dependências

- Python 3
- Scapy
- Requests
- Nmap

## Uso

```bash
sudo python3 Consulta.py 8.8.8.8
```
## Licença

Este projeto está licenciado sob a Licença MIT. Você tem permissão para utilizar, copiar, modificar, distribuir e sublicenciar este software, desde que o aviso de direitos autorais e a licença original sejam mantidos.

Este software é fornecido "como está", sem qualquer garantia expressa ou implícita. Os autores não se responsabilizam por quaisquer danos, prejuízos ou consequências decorrentes do uso deste software.

O uso desta ferramenta deve estar em conformidade com as leis e regulamentações aplicáveis. O autor não se responsabiliza por usos indevidos, ilegais ou não autorizados realizados por terceiros.

Consulte o arquivo LICENSE para o texto completo da Licença MIT.
