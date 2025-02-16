from scapy.all import ARP, Ether, srp
import time
import os
from pyfiglet import Figlet
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

# Archivo donde se guardan los dispositivos confiables
DISPOSITIVOS_CONFIABLES = "dispositivos_confiables.txt"

# Dibujo de un fantasma caricaturesco
FANTASMA_ASCII = r"""
⠀⠀⠀⠀⠀⢀⡠⠔⠂⠉⠉⠉⠉⠐⠦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⠔⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡄⠀⠀⠀⠀⠀
⠀⠀⢠⠋⠀⠀⠀⠀⠖⠉⢳⠀⠀⢀⠔⢢⠸⠀⠀⠀⠀⠀
⠀⢠⠃⠀⠀⠀⠀⢸⠀⢀⠎⠀⠀⢸⠀⡸⠀⡇⠀⠀⠀⠀
⠀⡜⠀⠀⠀⠀⠀⠀⠉⠁⠾⠭⠕⠀⠉⠀⢸⠀⢠⢼⣱⠀
⠀⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡌⠀⠈⠉⠁⠀
⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⣖⡏⡇
⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢄⠀⠀⠈⠀
⢸⠀⢣⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡬⠇⠀⠀⠀
⠀⡄⠘⠒⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠀⠀
⠀⢇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡀⠀⠀⠀
⠀⠘⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡤⠁⠀⠀⠀
⠀⠀⠘⠦⣀⠀⢀⡠⣆⣀⣠⠼⢀⡀⠴⠄⠚⠀⠀⠀⠀⠀
"""

def cargar_dispositivos_confiables():
    if not os.path.exists(DISPOSITIVOS_CONFIABLES):
        return set()
    with open(DISPOSITIVOS_CONFIABLES, "r") as f:
        return set(line.strip() for line in f)

def guardar_dispositivos_confiables(dispositivos):
    with open(DISPOSITIVOS_CONFIABLES, "w") as f:
        for dispositivo in dispositivos:
            f.write(dispositivo + "\n")

def escanear_red(red):
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=red)
    resultado = srp(paquete, timeout=2, verbose=False)[0]
    dispositivos = []
    for enviado, recibido in resultado:
        dispositivos.append(f"{recibido.psrc} {recibido.hwsrc}")  # (IP, MAC)
    return dispositivos

def detectar_nuevas_conexiones(red):
    dispositivos_confiables = cargar_dispositivos_confiables()
    dispositivos_alertados = set()
    
    while True:
        dispositivos_actuales = escanear_red(red)
        
        for dispositivo in dispositivos_actuales:
            if dispositivo not in dispositivos_confiables and dispositivo not in dispositivos_alertados:
                print(f"{Fore.RED}⚠️ ¡Nuevo dispositivo detectado! {dispositivo}{Style.RESET_ALL}")
                dispositivos_alertados.add(dispositivo)
        
        time.sleep(10)  # Escanear cada 10 segundos

def agregar_dispositivo_manual():
    ip = input(f"{Fore.YELLOW}Ingrese la IP del dispositivo: {Style.RESET_ALL}")
    mac = input(f"{Fore.YELLOW}Ingrese la MAC del dispositivo: {Style.RESET_ALL}")
    dispositivo = f"{ip} {mac}"
    
    dispositivos_confiables = cargar_dispositivos_confiables()
    if dispositivo in dispositivos_confiables:
        print(f"{Fore.YELLOW}⚠️ El dispositivo ya está en la lista de confiables.{Style.RESET_ALL}")
    else:
        dispositivos_confiables.add(dispositivo)
        guardar_dispositivos_confiables(dispositivos_confiables)
        print(f"{Fore.GREEN}✅ Dispositivo agregado a la lista de confiables.{Style.RESET_ALL}")

def mostrar_banner():
    # Crear texto ASCII art para el nombre del script
    figlet = Figlet(font="slant")
    banner = figlet.renderText("Shadow Tracker")
    
    # Dividir el banner y el dibujo del fantasma en líneas
    banner_lines = banner.split("\n")
    fantasma_lines = FANTASMA_ASCII.split("\n")
    
    # Asegurarse de que ambas listas tengan la misma longitud
    max_lines = max(len(banner_lines), len(fantasma_lines))
    banner_lines.extend([""] * (max_lines - len(banner_lines)))
    fantasma_lines.extend([""] * (max_lines - len(fantasma_lines)))
    
    # Combinar las líneas del banner y el fantasma
    for banner_line, fantasma_line in zip(banner_lines, fantasma_lines):
        print(f"{Fore.GREEN}{banner_line.ljust(40)}{Fore.CYAN}{fantasma_line}")
    
    # Mensaje de bienvenida
    print(Fore.YELLOW + "Bienvenido a Shadow Tracker: Tu guardián de la red.")
    print(Style.RESET_ALL)

def menu():
    red = "192.168.1.0/24"  # Ajustar según la red local
    mostrar_banner()
    
    while True:
        print(f"\n{Fore.BLUE}=== Menú Principal ===")
        print(f"{Fore.GREEN}1. Escanear red y detectar nuevas conexiones")
        print(f"{Fore.GREEN}2. Guardar dispositivos actuales como confiables (Safe Point)")
        print(f"{Fore.GREEN}3. Mostrar dispositivos confiables")
        print(f"{Fore.GREEN}4. Agregar dispositivo manualmente")
        print(f"{Fore.RED}5. Salir{Style.RESET_ALL}")
        opcion = input(f"{Fore.YELLOW}Seleccione una opción: {Style.RESET_ALL}")

        if opcion == "1":
            detectar_nuevas_conexiones(red)
        elif opcion == "2":
            dispositivos_actuales = escanear_red(red)
            guardar_dispositivos_confiables(dispositivos_actuales)
            print(f"{Fore.GREEN}✅ Dispositivos actuales guardados como confiables.{Style.RESET_ALL}")
        elif opcion == "3":
            confiables = cargar_dispositivos_confiables()
            print(f"{Fore.CYAN}📋 Dispositivos confiables:{Style.RESET_ALL}")
            for dispositivo in confiables:
                print(f"- {dispositivo}")
        elif opcion == "4":
            agregar_dispositivo_manual()
        elif opcion == "5":
            print(f"{Fore.RED}👋 Saliendo...{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}❌ Opción no válida, intente de nuevo.{Style.RESET_ALL}")

if __name__ == "__main__":
    menu()