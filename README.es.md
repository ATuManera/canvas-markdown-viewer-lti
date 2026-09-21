# canvas-markdown-viewer-lti

**Visor open source de archivos Markdown para Canvas LMS, construido con LTI 1.3.**

[![CI](https://github.com/ATuManera/canvas-markdown-viewer-lti/actions/workflows/ci.yml/badge.svg)](https://github.com/ATuManera/canvas-markdown-viewer-lti/actions/workflows/ci.yml)
[![Licencia: Apache 2.0](https://img.shields.io/badge/Licencia-Apache_2.0-blue.svg)](LICENSE)

> 🇬🇧 **[Read this in English](README.md)** · 📘 **[Guía de instalación](docs/installation/canvas-self-hosted.md)**

---

## El problema

Si subes un archivo `.md` a un curso de Canvas, Canvas te ofrece descargarlo. No lo muestra.
El alumnado recibe un archivo; el profesorado recibe una consulta.

Esta herramienta añade **Ver Markdown** al menú contextual del archivo. Al pulsarlo, el
documento se abre renderizado y legible dentro de Canvas.

Es una herramienta LTI 1.3 estándar. No modifica Canvas, no necesita un fork y no depende
del JavaScript del tema de Canvas.

## Qué aspecto tiene

Todavía no hay captura. Este proyecto no se ha verificado contra una instalación real de
Canvas, así que no hay nada que enseñar que no fuera una escenificación. Se añadirá aquí
cuando se verifique, y esta frase desaparecerá.

Por lo mismo, no hay versión publicada. Ver [Estado](#estado).

## Estado

**Sin publicar todavía.** El código está completo y probado; no se ha ejecutado contra una
instalación real de Canvas. Hasta que eso ocurra, este proyecto no afirma que funcione en
producción, y no hay ninguna versión etiquetada.

En concreto:

- ✅ Cada componente tiene pruebas automatizadas, incluidos los casos negativos de seguridad.
- ✅ El contenedor se construye y supera una prueba de humo.
- ⏳ El lanzamiento LTI, el consentimiento OAuth2 y el comportamiento de los navegadores no
  se han ejercitado contra un Canvas real.
- ⏳ Las cadenas exactas de los scopes de la API de Canvas se derivaron del código fuente de
  Canvas y deben confirmarse contra la instalación de destino.

El avance está en [`docs/roadmap.md`](docs/roadmap.md).

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

Detalle completo: [`docs/architecture/architecture.md`](docs/architecture/architecture.md).

### Algo que conviene saber antes de instalar

**Canvas no le dice a una herramienta LTI 1.3 desde qué archivo se abrió el menú.**

No es un descuido de este proyecto. El identificador del archivo solo existe en una URL
interna de Canvas y lo consume la ruta heredada de LTI 1.1; el lanzamiento 1.3 no lleva
ninguna referencia a él, y Canvas no expone ningún scope de LTI Advantage que permita leer
archivos de curso. La evidencia, leída del código fuente de Canvas, está en
[`docs/research/canvas-lti-file-menu.md`](docs/research/canvas-lti-file-menu.md).

Por eso el flujo es: **Ver Markdown → elegir el archivo → leerlo.** El selector muestra
primero los Markdown, tiene búsqueda y explica por qué está ahí. Es un clic más, y la
herramienta lo dice en lugar de disimularlo.

Proponer una mejora a Canvas para resolverlo está en la hoja de ruta.

## Compatibilidad

|             |                                                                                                                                                             |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Canvas      | Autohospedado. El Canvas de Instructure debería funcionar —la herramienta contempla el dominio de autenticación OIDC separado— pero **no está verificado**. |
| LTI         | Solo 1.3. LTI 1.1 no se admite ni se admitirá.                                                                                                              |
| Node.js     | 24 LTS, si lo ejecutas sin el contenedor                                                                                                                    |
| PostgreSQL  | 12 o superior                                                                                                                                               |
| Navegadores | Chrome, Safari, Firefox y navegadores móviles. Funciona con las cookies de terceros bloqueadas.                                                             |

No se afirma haber probado ninguna versión concreta de Canvas, porque no se ha probado
ninguna.

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

El procedimiento completo —las dos Developer Keys y por qué hacen falta ambas, los scopes,
el identificador de despliegue, TLS en el origen, Cloudflare y cómo deshacerlo todo— está en
**[`docs/installation/canvas-self-hosted.md`](docs/installation/canvas-self-hosted.md)**.

En corto: crea una LTI Key a partir de
[`config/canvas-lti.example.json`](config/canvas-lti.example.json), crea una API Key con
_Enforce Scopes_ y tres scopes de solo lectura, instala la app por client id y pon el
identificador de despliegue en `.env`.

## Seguridad y privacidad

Ambas están documentadas, no afirmadas:
[`docs/security/threat-model.md`](docs/security/threat-model.md) enumera cada amenaza con el
control que la atiende y la prueba que lo demuestra;
[`docs/security/privacy.md`](docs/security/privacy.md) dice exactamente qué se guarda.

Lo que conviene saber antes de instalar:

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
- **Aún no verificado contra un Canvas real.** Ver [Estado](#estado).

## Hoja de ruta

[`docs/roadmap.md`](docs/roadmap.md). En resumen: completar la verificación contra un Canvas
real y, después, índice de contenidos, enlaces permanentes a secciones y una propuesta a
Canvas para que un lanzamiento desde `file_menu` pueda identificar su archivo de forma
segura.

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
