import requests

def obtener_contenido(url):
    try:
        respuesta = requests.get(url)
        respuesta.raise_for_status()  # Verifica si la solicitud tuvo éxito
        return respuesta.text
    except requests.exceptions.RequestException as e:
        return f"Error al realizar la solicitud: {e}"

def main():
    url = input("Por favor, ingrese una URL: ")
    contenido = obtener_contenido(url)
    print(contenido) 

if __name__ == "__main__":
    main()
