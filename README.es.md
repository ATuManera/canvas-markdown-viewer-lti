# canvas-markdown-viewer-lti

**Visor open source de archivos Markdown para Canvas LMS, construido con LTI 1.3.**

[![CI](https://github.com/ATuManera/canvas-markdown-viewer-lti/actions/workflows/ci.yml/badge.svg)](https://github.com/ATuManera/canvas-markdown-viewer-lti/actions/workflows/ci.yml)
[![Licencia: Apache 2.0](https://img.shields.io/badge/Licencia-Apache_2.0-blue.svg)](LICENSE)

> 🇬🇧 **[Read this in English](README.md)**

---

## El problema

Si subes un archivo `.md` a un curso de Canvas, Canvas te ofrece descargarlo. No lo muestra.
El alumnado recibe un archivo; el profesorado recibe una consulta.

Esta herramienta añade **Ver Markdown** al menú contextual del archivo. Al pulsarlo, el
documento se abre renderizado y legible dentro de Canvas.

Es una herramienta LTI 1.3 estándar. No modifica Canvas, no necesita un fork y no depende
del JavaScript del tema de Canvas.

**Author / Autor:** A Tu Manera Digital — Fernando Gallarday ([@fgallarday](https://github.com/fgallarday))

**AI Assistance / Asistencia de IA:** Developed with the support of GPT 5.6 Sol, Claude Opus 5, and Claude Sonnet 5.

**Version / Versión:** 0.1.0

## Qué aspecto tiene

Todavía no hay captura. Se añadirá aquí cuando la interfaz se haya asentado.

## Estado

**Publicado, v0.1.0.** El lanzamiento LTI 1.3, el consentimiento OAuth2 y el flujo completo
de lectura y renderizado se han ejercitado de extremo a extremo contra una instalación real
de Canvas autohospedada.

En concreto:

- ✅ Cada componente tiene pruebas automatizadas, incluidos los casos negativos de seguridad.
- ✅ El contenedor se construye y supera una prueba de humo.
- ✅ El lanzamiento LTI, el consentimiento OAuth2 y el comportamiento de los navegadores se
  han verificado contra un Canvas real.
- ✅ Las cadenas de los scopes se han confirmado contra una instalación real. Uno de los tres
  que se habían inferido no existía, y la descarga usa ahora la dirección que entrega el
  propio objeto File.

Ver [`CHANGELOG.md`](CHANGELOG.md) para lo publicado en cada versión.

## Cómo funciona

```
Menú de archivo   ──►  Lanzamiento LTI 1.3  ──►  esta herramienta  ──►  API REST de Canvas
  "Ver Markdown"           (firmado)                    │              (token del usuario)
                                                        ▼
                                          analizar → sanear → renderizar
```

1. Canvas lanza la herramienta desde el placement `file_menu` con un `id_token` firmado.
2. La herramienta valida el lanzamiento por completo: firma, emisor, audiencia, caducidad,
   `state` y `nonce` de un solo uso, identificador de despliegue y tipo de mensaje.
3. La persona autoriza una vez a la herramienta a leer archivos **en su propio nombre**,
   mediante el OAuth2 de Canvas. Nunca se usa un token administrativo ni compartido.
4. La herramienta lista los archivos Markdown que esa persona puede ver, descarga el elegido
   y lo renderiza tras dos barreras independientes contra XSS.

Las decisiones de arquitectura y el modelo de amenazas se mantienen en la documentación
interna del proyecto, no publicada en este repositorio.

### Algo que conviene saber antes de instalar

**Canvas no le dice a una herramienta LTI 1.3 desde qué archivo se abrió el menú.**

No es un descuido de este proyecto. El identificador del archivo solo existe en una URL
interna de Canvas y lo consume la ruta heredada de LTI 1.1; el lanzamiento 1.3 no lleva
ninguna referencia a él, y Canvas no expone ningún scope de LTI Advantage que permita leer
archivos de curso. Esto se confirmó leyendo directamente el código fuente de Canvas
correspondiente.

Por eso el flujo es: **Ver Markdown → elegir el archivo → leerlo.** El selector muestra
primero los Markdown, tiene búsqueda y explica por qué está ahí. Es un clic más, y la
herramienta lo dice en lugar de disimularlo.

Proponer una mejora a Canvas para resolverlo está en la hoja de ruta.

## Compatibilidad

|             |                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Canvas      | Autohospedado, verificado contra una instalación real. El Canvas de Instructure debería funcionar —la herramienta contempla el dominio de autenticación OIDC separado— pero **no está verificado**. |
| LTI         | Solo 1.3. LTI 1.1 no se admite ni se admitirá.                                                                                                                                                      |
| Node.js     | 24 LTS, si lo ejecutas sin el contenedor                                                                                                                                                            |
| PostgreSQL  | 12 o superior                                                                                                                                                                                       |
| Navegadores | Chrome, Safari, Firefox y navegadores móviles. Funciona con las cookies de terceros bloqueadas.                                                                                                     |

La versión concreta de Canvas probada no se hace pública aquí; considera cualquier Canvas
autohospedado reciente como objetivo.

## Puesta en marcha rápida

```bash
git clone https://github.com/ATuManera/canvas-markdown-viewer-lti.git
cd canvas-markdown-viewer-lti
cp .env.example .env

# Genera los secretos y luego edita .env
node -e "console.log('ENCRYPTION_KEYS=1:' + require('crypto').randomBytes(32).toString('base64'))"
node -e "console.log('STATE_SECRET=' + require('crypto').randomBytes(48).toString('base64url'))"
node -e "console.log('POSTGRES_PASSWORD=' + require('crypto').randomBytes(24).toString('base64url'))"

docker compose up -d --build
curl -s http://127.0.0.1:3000/healthz     # {"status":"ok"}
```

La herramienta no termina TLS. Pon delante un reverse proxy con un certificado válido.

## Instalación en Canvas

Este repositorio no publica una guía de instalación paso a paso completa. En corto: crea una
LTI Key a partir de
[`config/canvas-lti.example.json`](config/canvas-lti.example.json), crea una API Key con
_Enforce Scopes_ y dos scopes de solo lectura, instala la app por client id y pon el
identificador de despliegue en `.env`.

## Seguridad y privacidad

Ambas se sostienen con pruebas automatizadas, no solo se afirman. Lo que conviene saber
antes de instalar:

- **Canvas se lee como el usuario, nunca como administrador.** Canvas reevalúa sus permisos
  en cada petición; esta herramienta no los reimplementa.
- **Los refresh tokens se cifran** con AES-256-GCM y quedan ligados criptográficamente a su
  propietario, de modo que un registro copiado al de otra persona no se puede descifrar. Un
  volcado de la base de datos sin la clave no sirve de nada.
- **El contenido de los documentos no se almacena.** Ni en disco, ni en base de datos, ni en
  los registros.
- **Las imágenes externas se bloquean por defecto**, para que ningún servidor ajeno sepa
  quién está leyendo qué.
- **La credencial nunca cruza un cambio de origen.** Si la descarga redirige al
  almacenamiento de archivos, el token se descarta.
- **Los registros no contienen tokens, secretos, contenido, nombres ni correos**, y hay una
  prueba que falla si alguna vez aparecen.
- **Sin analítica, sin telemetría, sin llamadas a terceros, sin CDN.**

Para comunicar una vulnerabilidad en privado: [`SECURITY.md`](SECURITY.md).

## Limitaciones

Dichas con claridad, porque descubrirlas después de instalar es peor:

- **Hay que elegir el archivo en una lista.** Ver [más arriba](#algo-que-conviene-saber-antes-de-instalar).
- **Cada persona autoriza una vez**, en una pantalla de consentimiento de Canvas. No hay
  forma de evitarlo sin usar un token compartido, lo que rompería el modelo de permisos.
- **Hacen falta dos Developer Keys**, porque Canvas separa LTI del acceso a la API REST.
- **Se necesita PostgreSQL**, para los tokens cifrados y el estado de lanzamiento.
- **Pulsar el nombre del archivo sigue abriendo la vista previa de Canvas.** Esta herramienta
  añade una entrada de menú; no sustituye el comportamiento de Canvas.
- **No edita.** Es un visor, y no solicita ningún permiso de escritura.
- **Sin Mermaid, sin KaTeX, sin JavaScript procedente de los documentos.** Cada uno
  necesitaría su propia revisión de seguridad; están en la hoja de ruta, no en el producto.

## Hoja de ruta

Lo siguiente: un índice de contenidos navegable para documentos largos, enlaces permanentes
a secciones, y una propuesta a Canvas para que un lanzamiento desde `file_menu` pueda
identificar su archivo de forma segura. Sigue el avance en los
[issues](https://github.com/ATuManera/canvas-markdown-viewer-lti/issues) de este repositorio.

## Contribuir

[`CONTRIBUTING.md`](CONTRIBUTING.md). Abre una incidencia antes de escribir código para
cualquier cosa que no sea una errata; un cambio en el comportamiento de seguridad necesita
una prueba que falle sin él.

## Licencia

[Apache License 2.0](LICENSE). Dependencias de terceros y sus licencias:
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

---

Canvas LMS es una marca registrada de Instructure, Inc. Este proyecto independiente no está
afiliado a Instructure, ni patrocinado ni respaldado por ella.
