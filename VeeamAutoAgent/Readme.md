# VeeamAgent
# Desde tu copia de trabajo (repo), importar el módulo temporalmente:
Import-Module "C:\Portfolio\Scripts\VeeamAutoAgent\VeeamAutoAgent.psd1" -Force

# 1) Instalar (copia el módulo a C:\scripts\VeeamAutoAgent y genera el runner)
Install-VeeamAutoAgent

# 2) Registrar la tarea programada (cada 5 minutos por defecto)
Register-VeeamAutoAgentTask -IntervalMinutes 5

# Re-registrar con otro intervalo (ej. cada 2 minutos)
Unregister-VeeamAutoAgentTask
Register-VeeamAutoAgentTask -IntervalMinutes 2

## Estado del proyecto

## Descripción

## Requisitos

## Instalación

## Configuración

## Uso

## Actualización

## Registro de cambios (Changelog)

## Roadmap

## Contribuir

## Seguridad

## Soporte

## Licencia

## Créditos