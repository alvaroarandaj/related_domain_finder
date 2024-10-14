import dns.resolver
import requests
import whois
import tldextract
from colorama import Fore, Style
import ssl
import socket
from urllib.parse import urlparse
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
import idna
import dns.reversename

def get_ns_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [rdata.to_text() for rdata in answers]
    except Exception as e:
        #print(f"Error getting NS records for {domain}: {e}")
        return []

def get_a_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [rdata.to_text() for rdata in answers]
    except Exception as e:
        #print(f"Error getting A records for {domain}: {e}")
        return []
    
def get_aaaa_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        return [rdata.to_text() for rdata in answers]
    except Exception as e:
        #print(f"Error getting A records for {domain}: {e}")
        return []

def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [rdata.exchange.to_text() for rdata in answers]
    except Exception as e:
        #print(f"Error getting MX records for {domain}: {e}")
        return []

def get_txt_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        return [rdata.to_text() for rdata in answers]
    except Exception as e:
        #print(f"Error getting TXT records for {domain}: {e}")
        return []

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        #print(f"Error getting WHOIS info for {domain}: {e}")
        return {}

def is_subdomain(domain1, domain2):
    # Extraer las partes de los dominios
    ext1 = tldextract.extract(domain1)
    ext2 = tldextract.extract(domain2)
    
    # Construir dominios completos sin subdominio y TLD
    full_domain1 = f"{ext1.domain}.{ext1.suffix}"
    full_domain2 = f"{ext2.domain}.{ext2.suffix}"
    
    # Verificar si uno está contenido en el otro
    if full_domain1 == full_domain2:
        print(f"NS {domain1} y {domain2} son el mismo dominio BASE")
        print(f"")
        return True  # Son el mismo dominio base
    if full_domain1 in domain2:
        print(f"NS {full_domain1} es subdominio de {domain2}")
        print(f"")
        return True
    if full_domain2 in domain1:
        print(f"NS {full_domain2} es subdominio de {domain1}")
        print(f"")
        return True
    
    return False


def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        print(f"Error resolving domain {domain}: {e}")
        return None
    
def get_cert(domain):
    # Normalize the domain name using IDNA encoding
    hostname_idna = idna.encode(domain)
    
    # Establish a connection using requests
    conn = requests.get(f'https://{domain}', stream=True)
    
    # Extract the certificate
    peer_cert = conn.raw.connection.sock.getpeercert(binary_form=True)
    
    # Parse the certificate
    cert = x509.load_der_x509_certificate(peer_cert, default_backend())
    
    # Extract and return certificate details
    #cert_details =

def get_cert_info(domain):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    
    try:
        conn.connect((domain))
        cert = conn.getpeercert()
    except Exception as e:
        #print(f"Error connecting to {domain}: {e}")
        return None
    finally:
        conn.close()
    
    return cert

def parse_cert(cert):
    if not cert:
        return None
    
    issuer = dict(x[0] for x in cert['issuer'])
    subject = dict(x[0] for x in cert['subject'])
    return {
        'issuer': issuer,
        'subject': subject,
        'serialNumber': cert.get('serialNumber')
    }

def compare_certs(cert1, cert2):
    if not cert1 or not cert2:
        return False
    
    # Compare issuer
    if cert1['issuer'] == cert2['issuer']:
        print("Issuers are the same.")
    
    # Compare subject
    if cert1['subject'] == cert2['subject']:
        print("Subjects are the same.")
    
    # Compare serial number
    if cert1['serialNumber'] == cert2['serialNumber']:
        print("Serial numbers are the same.")
    
    return cert1['issuer'] == cert2['issuer'] or cert1['subject'] == cert2['subject'] or cert1['serialNumber'] == cert2['serialNumber']


# Función para determinar si dos dominios están relacionados o no
def domainsAreRelated(domain1, domain2):

    print(f"## Comparing domains: {domain1} vs {domain2} #####")

    # Comprobar si compraten mismos servidores de dominio NS (Name Server)
    ns1 = get_ns_records(domain1)
    if ns1:
        ns2 = get_ns_records(domain2)
        if ns2:
            same_ns = set(ns1) == set(ns2)
            if same_ns:
                #print(f"NS records for {domain1}: {ns1}")
                #print(f"NS records for {domain2}: {ns2}")
                #print(f"NS records are {'the same' if same_ns else 'different'}")
                print(f"## -- SAME NS")
            else: #Miramos a ver si uno está contenido en el otro.
                same_ns = False
                for item in ns1:
                    if is_subdomain(item, domain2):
                        same_ns = True
                        print(f"## -- SAME NS")
                for item in ns2:
                    if is_subdomain(item, domain1):
                        same_ns = True
                        print(f"## -- SAME NS")
        else:
            same_ns = False
            print(f"## -- DIFFERENT NS")
    else:
        same_ns = False
        print(f"## -- DIFFERENT NS")

    a1 = get_a_records(domain1)
    if a1:
        a2 = get_a_records(domain2)
        if a2:
            same_a = set(a1) == set(a2)
            #print(f"A records for {domain1}: {a1}")
            #print(f"A records for {domain2}: {a2}")
            #print(f"A records are {'the same' if same_a else 'different'}")
            print(f"## -- SAME A RECORDS IP V4")
        else:
            same_a = False
            print(f"## -- DIFFERENT A RECORDS IP V4")
    else:
        same_a = False 
        print(f"## -- DIFFERENT A RECORDS IP V4")          

    aaaa1 = get_a_records(domain1)
    if aaaa1:
        aaaa2 = get_a_records(domain2)
        if aaaa2:
            same_aaaa = set(aaaa1) == set(aaaa2)
            #print(f"A records for {domain1}: {aaaa1}")
            #print(f"A records for {domain2}: {aaaa2}")
            #print(f"A records are {'the same' if same_aaaa else 'different'}")
            print(f"## -- SAME A RECORDS IP V6")
        else:
            same_aaaa = False
            print(f"## -- DIFFERENT A RECORDS IP V6")
    else:
        same_aaaa = False
        print(f"## -- DIFFERENT A RECORDS IP V6")

    mx1 = get_mx_records(domain1)
    if mx1:
        mx2 = get_mx_records(domain2)
        if mx2:
            same_mx = set(mx1) == set(mx2)
            #print(f"MX records for {domain1}: {mx1}")
            #print(f"MX records for {domain2}: {mx2}")
            #print(f"MX records are {'the same' if same_mx else 'different'}")
            print(f"## -- SAME MX RECORDS")
        else:
            same_mx = False
            print(f"## -- DIFFERENT MX RECORDS")
    else:
        same_mx = False 
        print(f"## -- DIFFERENT MX RECORDS")

    txt1 = get_txt_records(domain1)
    if txt1:
        txt2 = get_txt_records(domain2)
        if txt2:
            same_txt = set(txt1) == set(txt2)
            #print(f"TXT records for {domain1}: {txt1}")
            #print(f"TXT records for {domain2}: {txt2}")
            #print(f"TXT records are {'the same' if same_txt else 'different'}")
            print(f"## -- SAME TXT RECORDS")
        else:
            same_txt = False
            print(f"## -- DIFFERENT TXT RECORDS")
    else:
        same_txt = False
        print(f"## -- DIFFERENT TXT RECORDS")

    whois1 = get_whois_info(domain1)
    whois2 = get_whois_info(domain2)
    #print(f"WHOIS info for {domain1}: {whois1}")
    #print(f"WHOIS info for {domain2}: {whois2}")
    #print(f"")

    if whois1 and whois2:
        print(f"## -- WHOIS registrants are {'the same' if whois1.get('registrant_name') == whois2.get('registrant_name') else 'different'}")
        print(f"## -- WHOIS emails are {'the same' if whois1.get('emails') == whois2.get('emails') else 'different'}")
    else:
        print("## -- WHOIS information could not be fully retrieved")
    #print(f"")

    same_cert = False
    #if resolve_domain(domain1) and resolve_domain(domain2):
    cert1 = get_cert_info(domain1)
    cert2 = get_cert_info(domain2)
    
    if cert1 and cert2:
        parsed_cert1 = parse_cert(cert1)
        parsed_cert2 = parse_cert(cert2)

        if parsed_cert1 and parsed_cert2:
            same_cert = compare_certs(parsed_cert1, parsed_cert2)

    if same_ns or same_a or same_aaaa or same_mx or same_txt or same_cert:
        return True
    else:
        return False
    

def find_domains_by_ns_reverse(dominio):
    try:
        # Resolver la IP del dominio usando dnspython
        respuesta = dns.resolver.resolve(dominio, 'A')  # 'A' record para obtener la IP
        ip = respuesta[0].to_text()  # Convertir la respuesta en texto (dirección IP)
        print(f"La IP de {dominio} es: {ip}")

        # Convierte la IP a una dirección apta para un lookup inverso
        reversename = dns.reversename.from_address(ip)
        
        # Realiza la consulta de registros PTR
        respuesta = dns.resolver.resolve(reversename, 'PTR')
        
        # Obtiene todos los nombres de dominio relacionados con la IP
        dominios_relacionados = [str(rdata) for rdata in respuesta]
        return dominios_relacionados

    except dns.resolver.NXDOMAIN:
        print(f"El dominio {dominio} no existe.")
        return None
    except dns.resolver.NoAnswer:
        print(f"No se pudo obtener una respuesta para {dominio}.")
        return None
    except Exception as e:
        print(f"Error al resolver el dominio {dominio}: {e}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"No se encontraron registros PTR para la IP: {ip}")
        return []
    except Exception as e:
        print(f"Ocurrió un error al obtener los registros PTR: {e}")
        return []

    

def find_domains_by_google(api_key, cx, search_term, num_results):
    url = "https://www.googleapis.com/customsearch/v1"
    results = []
    start_index = 1

    while len(results) < num_results:
        params = {
            'key': api_key,
            'cx': cx,
            'q': f'intext:{search_term}',
            'start': start_index,
            'num': min(num_results - len(results), 10)  # Máximo 10 resultados por solicitud
        }
        response = requests.get(url, params=params)

        if response.status_code == 200:
            data = response.json()
            if 'items' in data:
                for item in data['items']:
                    results.append(item['link'])
                start_index += len(data['items'])
            else:
                break  # No more results available
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            break

    # for item in results:
    #     print(f"Title: {item['title']}")
    #     print(f"Snippet: {item['snippet']}")
    #     print(f"Link: {item['link']}")
    #     print("="*50)

    return results


if __name__ == "__main__":
   
    mode = input("Select mode. [0] DEBUG [1] NORMAL: ")
    input_domain = input("Enter the domain: ")

    #dominios_relacionados = find_domains_by_ns_reverse(input_domain)

    if mode == '0':
        domains = ['as.com', 'elmundo.es', 'sport.es', 'viu.es', 'administracion.gob.es', 'sanidad.gob.es']

        for domain in domains:
            #print(f"")
            if domainsAreRelated(input_domain, domain):
                print(Fore.GREEN + f"Los dominios {input_domain} y {domain} están relacionados.")
                print(Style.RESET_ALL)
            else:
                print(Fore.RED + f"Los dominios {input_domain} y {domain} NO están relacionados.")
                print(Style.RESET_ALL)
            #print(f"")
            continue

    elif mode == '1':
        
        print(f"MODO NORMAL")
        api_key = 'xxx'  # Reemplaza con tu clave de API de Google
        cx = 'yyy'  # Reemplaza con tu ID de motor de búsqueda
        
        domains = find_domains_by_google(api_key, cx, input_domain, 1000)

        i = 0
        related_domains = []
        for domain in domains:
            #print(f"{i} - {domain}")
            #i += 1
            domain_aux = domain
               # Eliminar 'https://'
            if domain_aux.startswith("https://"):
                domain_aux = domain_aux[len("https://"):]
    
            # Eliminar 'www.'
            if domain_aux.startswith("www."):
                domain_aux = domain_aux[len("www."):]

                    # Eliminar todo después del primer '/'
            if '/' in domain_aux:
                domain_aux = domain_aux.split('/', 1)[0]

            if domainsAreRelated(input_domain, domain_aux):
                print(Fore.GREEN + f"Los dominios {input_domain} y {domain} están relacionados.")
                print(Style.RESET_ALL)
                related_domains.append(domain)
            else: 
                print(Fore.RED + f"Los dominios {input_domain} y {domain} NO están relacionados.")
                print(Style.RESET_ALL)
            #print(f"")                
            #si el link es un subdominio, lanzamos otra búsqueda con partes de su cadena.

        print(f"DOMINOS RELACIONADOS ENCONTRADOS:")
        if related_domains:
            for domain in related_domains:
                 print(domain)
        else:
            print(f"Ninguno.")

