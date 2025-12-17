# Guía de Despliegue Automatizado - NICS | CyberLab

### Entorno de Laboratorio Automatizado (Versión Demo)

Este repositorio contiene la versión demo y experimental de **NICS | CyberLab**, un entorno de laboratorio automatizado diseñado para pruebas, formación y experimentación en ciberseguridad.
El proyecto permite desplegar rápidamente la infraestructura base del laboratorio mediante un único script de instalación y ejecutar módulos adicionales de prueba, como la PoC de **OpenStack + Snort 3**.

---

### Índice

- [Guía de Despliegue Automatizado - NICS | CyberLab](#guía-de-despliegue-automatizado---nics--cyberlab)
    - [Entorno de Laboratorio Automatizado (Versión Demo)](#entorno-de-laboratorio-automatizado-versión-demo)
    - [Índice](#índice)
  - [Introducción](#introducción)
  - [Estructura del repositorio](#estructura-del-repositorio)
    - [Requisitos previos](#requisitos-previos)
  - [🚀 Despliegue automático - `cyberlab.sh`](#-despliegue-automático---cyberlabsh)
    - [Ejecución:](#ejecución)
  - [Red virtual persistente - topología creada](#red-virtual-persistente---topología-creada)
    - [Módulo opcional: **OpenStack + Snort 3 (PoC)**](#módulo-opcional-openstack--snort-3-poc)
    - [Ejecución:](#ejecución-1)
  - [Notas resumen](#notas-resumen)
      - [Ejecutar manualmente el entorno](#ejecutar-manualmente-el-entorno)
      - [Acceder a OpenStack de forma manul](#acceder-a-openstack-de-forma-manul)
      - [Levantar la infraestructra de la red](#levantar-la-infraestructra-de-la-red)
    - [ℹ️ Buenas prácticas](#ℹ️-buenas-prácticas)
          - [© NICS LAB — NICS | CyberLab](#-nics-lab--nics--cyberlab)

---

## Introducción

La versión actual del proyecto simplifica por completo el despliegue del laboratorio.
Ahora **solo necesitas clonar el repositorio y ejecutar un único script**, que se encarga de:

* Instalar dependencias necesarias.
* Configurar servicios básicos del entorno.
* Preparar recursos utilizados internamente por el laboratorio.
* Validar puertos, rutas y configuraciones previas.

Además, se incluye una segunda utilidad opcional para probar la instalación automatizada de **OpenStack + Snort 3**, disponible como PoC dentro del propio repositorio.

---

## Estructura del repositorio

La raíz del proyecto contiene:

```
nics-cyberlab-A/
├── cyberlab.sh              → Instalador principal (entorno base)
├── op+snort.sh              → PoC opcional: OpenStack + Snort3
├── openstack-installer/     → Scripts auxiliares internos
├── static/                  → Recursos del Dashboard (demo)
├── scenario/                → Escenarios de ejemplo
├── app.py                   → Backend del Dashboard (modo demo)
├── *.log                    → Logs generados automáticamente
└── README.md                → Este documento
```

### Requisitos previos

* Ubuntu 22.04 / 24.04 (recomendado).
* 4 vCPU y 8 GB RAM (mínimo).
* 30 GB libres en disco.
* Acceso a Internet.
* Usuario con privilegios sudo.

---

## 🚀 Despliegue automático - `cyberlab.sh`

Este es el script principal del proyecto.
Realiza toda la preparación del laboratorio de forma completamente automatizada.

### Ejecución:

```bash
cd nics-cyberlab-A
chmod +x cyberlab.sh
./cyberlab.sh
```

El script realiza tareas como:

* Instalación y actualización de paquetes necesarios.
* Configuración básica del entorno.
* Preparación de directorios y dependencias del dashboard demo.
* Validaciones automáticas para evitar errores comunes.

Toda la salida del proceso se muestra en pantalla, y en caso de error se genera un log para depuración.

## Red virtual persistente - topología creada

Durante la instalación se configura una red virtual persistente utilizada por OpenStack como red de gestión y red externa.

```
                ┌────────────┐           ┌──────────────┐
                │   ens33    │◀────────▶│   Internet   │
                └────────────┘           └──────────────┘
                        │
                  [ NAT / iptables ]
                        │
                ┌──────────────────────┐
                │     uplinkbridge     │
                └──────────────────────┘
                        │
                   ┌────┴────┐
                   │         │
              ┌────────┐ ┌────────┐
              │ veth0  │ │ veth1  │
              └────────┘ └────────┘
```

- `ens33`: interfaz física principal.  
- `uplinkbridge`: puente virtual para comunicación externa.  
- `veth0 / veth1`: par de interfaces virtuales persistentes.  

---

### Módulo opcional: **OpenStack + Snort 3 (PoC)**

El repositorio incluye un script adicional que permite experimentar con una instalación automatizada de:

* **OpenStack** (despliegue básico de prueba)
* **Snort 3** (sensor de IDS/IPS)  

> ⚠️ Este módulo es experimental y está pensado únicamente para pruebas en fase demo.

### Ejecución:

```bash
chmod +x op+snort.sh
./op+snort.sh
```

El script se encargará del proceso de instalación y mostrará el estado de cada fase durante el despliegue.

---

## Notas resumen

Tras ejecutar `cyberlab.sh`, dentro del directorio **nics-cyberlab-A**:

#### Ejecutar manualmente el entorno

```bash
source openstack-installer/openstack_venv/bin/activate
source admin-openrc.sh
```

#### Acceder a OpenStack de forma manul

```bash
cat admin-openrc.sh # Fichero generado post ejecución de cyberlab.sh
```

- ``auth_url`` ➜ Contiene la dirreción con la que está configurado OpenStack, por ejemplo: "http://192.168.5.14".
- ``username`` ➜ **admin**.
- ``password`` ➜ Este campo contiene la contraseña generada post instalación, por ejemplo: _570vu8Q1jeZHyaLvVWopdNUBxO7ptYuBXImxLcfZ_

También se puede visualizar a través del directorio **/etc/kolla/clouds.yaml**.

```bash
cat /etc/kolla/clouds.yaml
```

#### Levantar la infraestructra de la red

```bash
sudo bash openstack-installer/setup-veth.sh
```

### ℹ️ Buenas prácticas

- Ejecuta siempre los scripts desde la raíz del repositorio.
- No modifiques rutas internas a menos que sepas exactamente lo que haces.
- Guarda los logs generados para depuración si ocurre algún error inesperado.
- Esta versión es experimental: algunas funcionalidades pueden cambiar en futuras actualizaciones.

---

###### © NICS LAB — NICS | CyberLab

Proyecto experimental para entornos de laboratorio y formación en ciberseguridad.
