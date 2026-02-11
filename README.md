# 🔴 DHCP Rogue / DHCP Spoofing Attack

## 📌 Nombre del Proyecto

**DHCP Spoofing Server Attack - Ataque de Suplantación de Servidor DHCP**

---

## 📖 Descripción Técnica del Ataque

El **DHCP Spoofing** o **DHCP Rogue** es un ataque de red donde yo, como atacante, implemento un servidor DHCP malicioso en la red para interceptar y responder solicitudes DHCP legítimas antes que el servidor DHCP real.

Cuando un dispositivo se conecta a la red y solicita una configuración IP mediante DHCP DISCOVER, mi servidor falso responde con una oferta (DHCP OFFER) que incluye:

- Una dirección IP falsificada
- Un **gateway por defecto controlado por mí**
- Servidores DNS maliciosos (opcional)

De esta forma, logro que todo el tráfico de la víctima pase por mi máquina atacante, permitiéndome realizar **Man-in-the-Middle (MITM)**, capturar credenciales, interceptar tráfico HTTP/HTTPS, o redirigir a sitios de phishing.

El ataque funciona porque **DHCP no tiene autenticación nativa**, y el cliente aceptará la primera respuesta válida que reciba, incluso si proviene de un servidor no autorizado.

---

## 🎯 Objetivo del Script

El script `dhcp_spoofing.py` tiene como objetivo:

1. **Escuchar solicitudes DHCP DISCOVER** en la red
2. **Responder antes que el servidor DHCP legítimo** con un DHCP OFFER malicioso
3. **Asignar una configuración IP controlada por mí**, redirigiendo el gateway hacia mi máquina Kali Linux
4. **Confirmar la asignación mediante DHCP ACK**, consolidando el ataque
5. **Convertirme en el punto de paso obligatorio** para todo el tráfico de la víctima

Con este script, logro interceptar y manipular todo el tráfico de red de los dispositivos comprometidos.

---

## 🗺️ Topología Detallada

Mi topología de laboratorio está configurada de la siguiente manera:

```
┌─────────────────────────────────────────────────────────┐
│                    Router vIOS                          │
│                 (Router-on-a-Stick)                     │
│                                                         │
│  Gi0/0.10 → 12.0.10.1/24 (VLAN 10 - Windows)          │
│  Gi0/0.20 → 12.0.20.1/24 (VLAN 20 - Kali Linux)       │
│  Servidor DHCP legítimo configurado                    │
└─────────────────┬───────────────────────────────────────┘
                  │ Trunk (VLANs 10, 20)
                  │
         ┌────────▼─────────┐
         │     SW-1         │
         │  (Switch Core)   │
         └────┬────────┬────┘
              │        │
    ┌─────────▼─┐   ┌─▼──────────┐
    │   SW-2    │   │   SW-3     │
    │ (Acceso)  │   │ (Acceso)   │
    └─────┬─────┘   └─────┬──────┘
          │               │
    ┌─────▼──────┐  ┌────▼────────┐
    │  Windows   │  │ Kali Linux  │
    │  (Víctima) │  │ (Atacante)  │
    │  VLAN 10   │  │  VLAN 20    │
    │ DHCP Auto  │  │ 12.0.20.2   │
    └────────────┘  └─────────────┘
```

### 🔧 Direccionamiento IP Utilizado

| Dispositivo | Interfaz/VLAN | Dirección IP | Máscara | Gateway |
|------------|---------------|--------------|---------|---------|
| **Router vIOS** | Gi0/0.10 | 12.0.10.1 | 255.255.255.0 | - |
| **Router vIOS** | Gi0/0.20 | 12.0.20.1 | 255.255.255.0 | - |
| **Kali Linux** | eth0 (VLAN 20) | 12.0.20.2 | 255.255.255.0 | 12.0.20.1 |
| **Windows** | eth0 (VLAN 10) | DHCP (12.0.10.x) | 255.255.255.0 | 12.0.10.1 |

### 📡 DHCP Pools Configurados en el Router

**VLAN 10 (Windows):**
- Red: `12.0.10.0/24`
- Pool: `12.0.10.10 - 12.0.10.100`
- Gateway: `12.0.10.1`

**VLAN 20 (Kali Linux):**
- Red: `12.0.20.0/24`
- Pool: `12.0.20.10 - 12.0.20.100`
- Gateway: `12.0.20.1`

---

## ⚙️ Parámetros Usados en el Script

### 🚀 Comando de Ejecución

```bash
sudo python3 dhcp_spoofing.py
```

### 📝 Configuración Interna del Script

El script está configurado con los siguientes parámetros para mi topología:

- **INTERFACE** = "eth0" → Interfaz de red que uso en Kali
- **FAKE_DHCP** = "12.0.20.2" → Mi Kali se hace pasar por servidor DHCP
- **FAKE_GW** = "12.0.20.2" → Redirijo todo el tráfico hacia mí
- **OFFER_IP** = "12.0.10.50" → IP que ofrezco a la víctima (dentro de VLAN 10)
- **SUBNET** = "255.255.255.0" → Máscara de subred

---

## 🔍 Explicación Paso a Paso de la Ejecución

### **Paso 1: Preparación del Entorno**

Antes de ejecutar el ataque, verifico mi configuración de red en Kali Linux:

```bash
ip addr show eth0
```

Debo ver:
```
eth0: 12.0.20.2/24
```

También verifico que puedo alcanzar el gateway legítimo:

```bash
ping 12.0.20.1 -c 4
```

### **Paso 2: Habilitar el IP Forwarding**

Para que mi Kali funcione como un router intermedio y pueda reenviar el tráfico de las víctimas (evitando que se queden sin internet), activo el reenvío de paquetes:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Verifico:
```bash
cat /proc/sys/net/ipv4/ip_forward
```

Debe devolver `1`.

### **Paso 3: Configurar Reglas de NAT (Opcional pero Recomendado)**

Para que las víctimas mantengan conectividad (y no sospechen), configuro NAT para reenviar su tráfico:

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT
```

### **Paso 4: Ejecutar el Script de DHCP Rogue**

Lanzo mi servidor DHCP falso:

```bash
sudo python3 dhcp_rogue.py
```

El script queda escuchando en modo pasivo y muestra:
```
[*] DHCP Spoofing activo...
```

### **Paso 5: Forzar Renovación DHCP en la Víctima (Windows)**

Desde el equipo Windows (víctima), ejecuto:

```cmd
ipconfig /release
ipconfig /renew
```

### **Paso 6: Observar el Ataque en Acción**

En mi terminal de Kali veo:
```
[+] DISCOVER de 00:0c:29:3a:bc:12
[→] OFFER enviado (12.0.10.50)
[+] REQUEST de 00:0c:29:3a:bc:12
[✓] ACK enviado – víctima comprometida
```

### **Paso 7: Verificar la Configuración en Windows**

Desde Windows, verifico que recibió mi configuración maliciosa:

```cmd
ipconfig /all
```

Debo ver:
```
   IPv4 Address: 12.0.10.50
   Subnet Mask: 255.255.255.0
   Default Gateway: 12.0.20.2
   DHCP Server: 12.0.20.2
```

**🎯 Éxito:** Ahora todo el tráfico de Windows pasa por mi Kali Linux.

### **Paso 8: Capturar Tráfico (MITM)**

Para interceptar el tráfico de la víctima, uso Wireshark o tcpdump:

```bash
sudo tcpdump -i eth0 -w captura_mitm.pcap
```

O para ver tráfico HTTP en tiempo real:

```bash
sudo tcpdump -i eth0 -A | grep -i 'GET\|POST\|Host:'
```

---

## 🖥️ Qué se Observa en el Router

Desde el router vIOS, puedo verificar el estado del servidor DHCP legítimo:

### **Verificar Pool DHCP**

```cisco
Router# show ip dhcp pool

Pool VLAN10 :
 Utilization mark (high/low)    : 100 / 0
 Subnet size (first/next)       : 0 / 0
 Total addresses                : 254
 Leased addresses               : 1
 Pending event                  : none
 1 subnet is currently in the pool :
 Current index        IP address range                    Leased addresses
 12.0.10.11           12.0.10.1        - 12.0.10.254       0
```

### **Ver Bindings Activos**

```cisco
Router# show ip dhcp binding
Bindings from all pools not associated with VRF:
IP address          Client-ID/              Lease expiration        Type
                    Hardware address/
                    User name
12.0.10.11          0100.0c29.3abc.12       Feb 11 2026 02:30 PM    Automatic
```

**Nota importante:** El servidor DHCP legítimo NO verá las asignaciones de mi servidor falso. La víctima aparecerá con la configuración maliciosa en su sistema, pero el router vIOS no tendrá registro de ella porque mi ataque bypasea completamente el servidor legítimo.

### **Monitorear Tráfico Anómalo**

Si el router tiene logging habilitado, podría detectar múltiples servidores DHCP respondiendo:

```cisco
Router# show logging | include DHCP
*Feb 11 14:25:33.123: %DHCP-6-ADDRESS_ASSIGN: Interface GigabitEthernet0/0.10 assigned DHCP address 12.0.10.11
```

---

## 📸 Capturas de Pantalla

Para documentar el ataque, incluyo las siguientes capturas en la carpeta `screenshots/`:

### **1. Configuración inicial de Kali Linux**
![Kali Config](screenshots/01_kali_config.png)
_Salida de `ip addr show eth0` mostrando 12.0.20.2/24_

### **2. Ejecución del script dhcp_rogue.py**
![Script Running](screenshots/02_script_running.png)
_Terminal con el mensaje "[*] DHCP Spoofing activo..."_

### **3. Intercepción exitosa**
![Attack Success](screenshots/03_attack_success.png)
_Mensajes de DISCOVER, OFFER, REQUEST y ACK en la terminal_

### **4. Configuración IP de la víctima comprometida**
![Victim Compromised](screenshots/04_victim_ipconfig.png)
_`ipconfig /all` en Windows mostrando gateway 12.0.20.2_

### **5. Captura de tráfico con Wireshark**
![Wireshark Capture](screenshots/05_wireshark_dhcp.png)
_Wireshark filtrando `bootp` mostrando paquetes DHCP maliciosos_

### **6. Verificación en el router**
![Router Verification](screenshots/06_router_dhcp_pool.png)
_`show ip dhcp binding` en el router vIOS_

---

## 🛠️ Requisitos para Ejecutar la Herramienta

### **Requisitos de Software**

- **Kali Linux** (o cualquier distribución Linux con Python 3)
- **Python 3.7+**
- **Scapy** (biblioteca de manipulación de paquetes)

### **Instalación de Dependencias**

```bash
sudo apt update
sudo apt install python3 python3-pip -y
sudo pip3 install -r requirements.txt
```

O manualmente:

```bash
sudo pip3 install scapy
```

### **Requisitos de Red**

- Estar en la misma red o VLAN desde donde se quiere realizar el ataque
- Tener conectividad de capa 2 con las víctimas (misma red broadcast)
- **Permisos de root** para enviar paquetes a nivel de capa 2

### **Permisos Necesarios**

```bash
sudo chmod +x dhcp_rogue.py
```

---

## 🛡️ Medidas de Mitigación Específicas

### **1. DHCP Snooping**

La protección más efectiva contra ataques DHCP Rogue es **DHCP Snooping**, que permite definir qué puertos son confiables para enviar mensajes DHCP.

#### **Configuración en el Switch Core (SW-1):**

```cisco
SW-1(config)# ip dhcp snooping
SW-1(config)# ip dhcp snooping vlan 10,20

! Definir el puerto que conecta al router como trusted
SW-1(config)# interface GigabitEthernet0/1
SW-1(config-if)# ip dhcp snooping trust

! Los puertos de acceso quedan como untrusted por defecto
SW-1(config)# interface range GigabitEthernet0/2-24
SW-1(config-if-range)# ip dhcp snooping limit rate 10

! Verificar configuración
SW-1# show ip dhcp snooping
```

Con esto, cualquier respuesta DHCP OFFER proveniente de puertos untrusted (como el de Kali Linux) será bloqueada.

### **2. Port Security**

Limito el número de direcciones MAC permitidas por puerto:

```cisco
SW-3(config)# interface GigabitEthernet0/5
SW-3(config-if)# switchport mode access
SW-3(config-if)# switchport port-security
SW-3(config-if)# switchport port-security maximum 2
SW-3(config-if)# switchport port-security violation restrict
SW-3(config-if)# switchport port-security mac-address sticky
```

### **3. Dynamic ARP Inspection (DAI)**

Previene ataques ARP Spoofing que suelen acompañar al DHCP Spoofing:

```cisco
SW-1(config)# ip arp inspection vlan 10,20
SW-1(config)# interface GigabitEthernet0/1
SW-1(config-if)# ip arp inspection trust
```

### **4. IP Source Guard**

Evita que dispositivos usen IPs no asignadas por DHCP Snooping:

```cisco
SW-3(config)# interface GigabitEthernet0/5
SW-3(config-if)# ip verify source
```

### **5. Monitoreo y Alertas**

Configurar logging para detectar actividad sospechosa:

```cisco
Router(config)# logging buffered 16384 informational
Router(config)# logging console warnings
Router(config)# service timestamps log datetime msec

SW-1(config)# logging host 192.168.1.100
SW-1(config)# logging trap informational
```

### **6. Segmentación de Red (VLANs)**

Ya implementada en mi topología:
- VLAN 10 para usuarios Windows
- VLAN 20 para administradores/Kali Linux
- Evita que un atacante en VLAN 20 comprometa directamente VLAN 10 (aunque en este caso usé routing para demostrarlo)

---

## 🔬 Conclusión Final Técnica

El ataque **DHCP Rogue / DHCP Spoofing** es una técnica devastadora porque explota la falta de autenticación en el protocolo DHCP. Logré demostrar cómo un atacante puede:

✅ **Interceptar todo el tráfico** de una víctima redirigiendo su gateway  
✅ **Realizar ataques Man-in-the-Middle** sin necesidad de ARP Spoofing  
✅ **Capturar credenciales** en texto claro (HTTP, FTP, Telnet)  
✅ **Manipular el DNS** para redirigir a sitios maliciosos (phishing)  

Sin embargo, las defensas modernas como **DHCP Snooping**, **Port Security** y **Dynamic ARP Inspection** pueden mitigar completamente este ataque si se configuran correctamente.

Este laboratorio me permitió entender tanto la vulnerabilidad del protocolo DHCP como las mejores prácticas de seguridad en redes empresariales. La segmentación por VLANs y la configuración de switches con características de seguridad son fundamentales para prevenir estos ataques en entornos de producción.

**⚠️ Advertencia Legal:** Este script es exclusivamente para fines educativos y de prueba en entornos controlados. Realizar este ataque en redes sin autorización explícita es ilegal y puede resultar en sanciones penales.

---

**Autor:** Mariana  
**Fecha:** Febrero 2026  
**Laboratorio:** Seguridad en Redes - Ataques Layer 2  
**Repositorio:** [github.com/mariana121319/DHCP-Spoofing-Attack](https://github.com/mariana121319/DHCP-Spoofing-Attack)
