import os
import json
import requests
from dotenv import load_dotenv
from simple_term_menu import TerminalMenu

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

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
        if "_source" in data and "targethash" in data["_source"]:
            return data["_source"]["targethash"]
        else:
            print("No se encontro una variable de Hash en el archivo seleccionado")
            #print(data)
            return None
    except json.JSONDecodeError:
        print("El archivo seleccionado no tiene las propiedades de un JSON.")
        return None
    except Exception as e:
        print(f"Ocurrió un error al leer el archivo: {e}")
        return None
    
def check_virustotal(hash_value):
    if not API_KEY:
        print("La clave de API de VirusTotal no está configurada. Por favor, configure la variable de entorno VT_API_KEY.")
        return None
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print("El hash no se encontró en la web de VirusTotal.")
            return None
        else:
            print(f"Error al consultar VirusTotal: {response.status_code}")
            return None
    except Exception as e:
        print(f"Ocurrió un error al conectarse con VirusTotal: {e}")
        return None
    
def check_results (virus_total_data, hash_value):
    try:
        stats = virus_total_data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        harmless = stats.get("harmless", 0)
        suspicious = stats.get("suspicious", 0)
        Undetected = stats.get("undetected", 0)
        print(f"\nResultados del análisis de VirusTotal:\n")
        print(f"Malicious: {malicious}")
        print(f"Harmless: {harmless}")
        print(f"Suspicious: {suspicious}")
        print(f"Undetected: {Undetected}")

        if malicious > 0:
            print("\nDEFINICIÓN: El HASH del archivo escaneado es potencialmente malicioso.\n")
        elif suspicious > 0:
            print("\nDEFINICIÓN: El HASH del archivo escaneado es potencialmente sospechoso.\n")
        else:
            print("\nDEFINICIÓN: El HASH del archivo escaneado no muestra indicios de ser malicioso.\n")
        Link = f"https://www.virustotal.com/gui/file/{hash_value}/detection"
        print(f"Para más detalles, puede consultar el siguiente enlace:\n {Link}\n\n")
        
    except Exception as e:
        print(f"Ocurrió un error al procesar los resultados de VirusTotal: {e}")

def main():
    selected_file = select_file()
    if not selected_file:
        print("No se seleccionó ningún archivo.")
        return
    print(f"\nArchivo seleccionado: {selected_file}")
    hash_value = read_json_file(selected_file)
    if hash_value:
        print(f"\nValor de Hash encontrado: {hash_value}")
        virus_total_data = check_virustotal(hash_value)
        if virus_total_data:
            check_results(virus_total_data, hash_value)
    else:
        print("No se encontró un valor de Hash en el archivo seleccionado.")

if __name__ == "__main__":
    main()