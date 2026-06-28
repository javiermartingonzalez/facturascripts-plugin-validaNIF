# ValidaNIF

ValidaNIF es un plugin para FacturaScripts que permite comprobar los NIF y CIF de clientes y proveedores con el Web Service de calidad de datos identificativos de la AEAT (VNifV2).

Su objetivo es ayudarte a detectar datos fiscales incorrectos antes de emitir documentos, presentar impuestos o mantener una ficha de cliente/proveedor con información poco fiable.

## Para qué sirve

Con ValidaNIF puedes validar si el NIF/CIF y el nombre o razón social introducidos en FacturaScripts coinciden con la información disponible en AEAT.

El plugin muestra el resultado de forma clara:

- **IDENTIFICADO**: los datos han sido verificados correctamente en el censo.
- **NO IDENTIFICADO**: AEAT no reconoce la combinación de NIF/CIF y nombre indicada.

Cuando la validación es correcta, ValidaNIF también muestra el nombre o razón social censal devuelto por AEAT.

Para empresas, basta con indicar un NIF/CIF válido para que AEAT devuelva el resultado con la razón social registrada en el censo de empresarios. Por otro lado, para personas físicas o autónomos, es necesaria la correcta combinación de NIF/DNI con nombre y apellidos (o una aproximación muy cercana) para que se devuelva la identificación censal de la persona.

## Funcionalidades

- Validación de NIF/CIF desde la ficha de cliente.
- Validación de NIF/CIF desde la ficha de proveedor.
- Página de configuración propia en el panel de administración para subida de certificados `.p12` y `.pfx` y prueba del servicio.

## Requisitos

- FacturaScripts 2026 o superior.
- Un certificado válido para consultar el servicio de identificación de AEAT.
- Servidor con las extensiones necesarias activadas (SOAP y OpenSSL).

La propia pantalla de configuración de ValidaNIF indica si falta algún requisito.

## Configuración

1. Instala y activa el plugin desde el administrador de FacturaScripts.
2. Entra en **Administrador > ValidaNIF**.
3. Sube el certificado digital a utilizar para la conexión con AEAT.
4. Usa la prueba de conexión para confirmar que el certificado se reconoce correctamente y que el servicio funciona.

Una vez configurado, podrás validar NIF/CIF directamente desde las páginas de clientes y proveedores.
