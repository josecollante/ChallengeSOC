import os
import json
import requests
from dotenv import load_dotenv
from simple_term_menu import TerminalMenu

load_dotenv()

API_KEY = os.getenv("ABUSE_IPDB_API_KEY")

def select_file():
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    if not files:
        print("En el directorio actual NO hay archivos para seleccionar.")
        return None
    menu = TerminalMenu(files, title="Seleccione un archivo .JSON:")
    index_menu = menu.show()
    if index_menu is None:
        return None
    return files[index_menu]

def read_json_file(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        if "_source" in data and "httpRequest" in data["_source"] and "clientIp" in data["_source"]["httpRequest"]:
            return data["_source"]["httpRequest"]["clientIp"]
        else:
            print("No se encontro una variable de Client IP en el archivo seleccionado")
            return None
    except json.JSONDecodeError:
        print("El archivo seleccionado no tiene las propiedades de un JSON.")
        return None
    except Exception as e:
        print(f"Ocurrió un error al leer el archivo: {e}")
        return None
    
def check_abuse_ipdb(ip_value):
    if not API_KEY:
        print("La clave de API de AbuseIPDB no está configurada.\n" \
        "Por favor, configure la variable de entorno VT_API_KEY.")
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_value,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print("El IP no se encontró en la web de AbuseIPDB.")
            return None
        else:
            print(f"Error al consultar AbuseIPDB: {response.status_code}")
            return None
    except Exception as e:
        print(f"Ocurrió un error al conectarse con VirusTotal: {e}")
        return None
    
def check_results (abuse_ipdb_data, ip_value):
    try:
        info = abuse_ipdb_data["data"]

        ip = info.get("ipAddress", "N/A")
        score = info.get("abuseConfidenceScore", "N/A")
        isp = info.get("isp", "N/A")
        country = info.get("countryCode", "N/A")
        total_reports = info.get("totalReports", "N/A")
        last_reported_at = info.get("lastReportedAt", "N/A")

        print(f"\nResultados de AbuseIPDB para la IP: {ip}\n")
        print(f"Abuse Confidence Score: {score}")
        print(f"ISP: {isp}")
        print(f"País: {country}")
        print(f"Total de Reportes: {total_reports}")
        print(f"Último Reporte: {last_reported_at}")

        if score >= 80:    
            print("\nEsta IP tiene un alto nivel de abuso.\n")
        elif score >= 30:
            print("\nEsta IP tiene un nivel moderado de abuso.\n")
        else:
            print("\nEsta IP tiene un bajo nivel de abuso.\n")

        Link = f"https://www.abuseipdb.com/check/{ip_value}"
        print(f"Para más detalles, puede consultar el siguiente enlace:\n {Link}\n\n")
        
    except Exception as e:
        print(f"Ocurrió un error al procesar los resultados de AbuseIPDB: {e}")

def main():
    selected_file = select_file()
    if not selected_file:
        print("No se seleccionó ningún archivo.")
        return
    print(f"\nArchivo seleccionado: {selected_file}")
    ip_value = read_json_file(selected_file)
    if ip_value:
        print(f"\nValor de IP de origen encontrado: {ip_value}")
        abuseipdb_data = check_abuse_ipdb(ip_value)
        if abuseipdb_data:
            check_results(abuseipdb_data, ip_value)
    else:
        print("No se encontró un valor de IP de origen en el archivo seleccionado.")

if __name__ == "__main__":
    main()