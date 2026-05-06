import os
import json
from simple_term_menu import TerminalMenu

def select_file():
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    if not files:
        print("En el directorio actual NO hay archivos para seleccionar.")
        return None
    menu = TerminalMenu(files, title="Seleccione un archivo . JSON:")
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
            
def main():
    selected_file = select_file()
    if not selected_file:
        print("No se seleccionó ningún archivo.")
        return
    print(f"\nArchivo seleccionado: {selected_file}")
    hash_value = read_json_file(selected_file)
    if hash_value:
        print(f"Valor de Hash encontrado: {hash_value}")
    else:
        print("No se encontró un valor de Hash en el archivo seleccionado.")

if __name__ == "__main__":
    main()