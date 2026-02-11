# Documentación sobre el ataque DHCP Rogue/Spoofing

## Topología

La topología de la red para el ataque DHCP Rogue/Spoofing se compone de las siguientes características:

- **VLANs:**
  - VLAN 10 (12.0.10.0/24)
  - VLAN 20 (12.0.20.0/24)

- **Dispositivos:**
  - **Kali Linux:** 12.0.20.2
  - **Windows (Víctima):** ubicado en VLAN 10
  - **Router vIOS:**
    - Gi0/0.10: 12.0.10.1
    - Gi0/0.20: 12.0.20.1

## Ejecución Paso a Paso

1. **Configuración del entorno:** Asegúrese de que todos los dispositivos están en las VLAN correctas según la topología.
2. **Initiar Kali Linux:** Arranque Kali y abra una terminal.
3. **Instalar y configurar `dnsmasq`:**  Utilize el siguiente comando para instalar:
   ```bash
   sudo apt-get install dnsmasq
   ```
   Luego, configure `dnsmasq` para que actúe como servidor DHCP.
4. **Ejecutar el ataque:** Utilice la configuración adecuada en `dnsmasq` para responder las solicitudes DHCP de los clientes en VLAN 10.
5. **Captura de tráfico:** Monitoree el tráfico con `Wireshark` para ver las solicitudes y respuestas DHCP.

## Medidas de Mitigación

- **DHCP Snooping:** Implementar DHCP Snooping en el switch para permitir solo respuestas DHCP confiables.
- **Port Security:** Configurar la seguridad en los puertos del switch para limitar el número de direcciones MAC aprendidas.
- **Dynamic ARP Inspection:** Usar ARP Inspection para verificar la validez de las solicitudes ARP.

## Conclusión Técnica

En resumen, los ataques de DHCP Rogue/Spoofing representan una seria amenaza en redes modernas. Es crucial implementar medidas de mitigación como DHCP Snooping, Port Security y Dynamic ARP Inspection para proteger la integridad de la red. Estos pasos ayudarán a garantizar que los dispositivos en la red estén seguros y que sus configuraciones de red no sean comprometidas por actores maliciosos. La educación continua sobre estas potenciales vulnerabilidades es vital para cualquier profesional de la red.