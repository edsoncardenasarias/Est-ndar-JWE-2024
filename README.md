# Ejemplo de JWE en Java

Este ejemplo encripta el texto plano "The true sign of intelligence is not knowledge but imagination." para un destinatario utilizando JSON Web Encryption (JWE) en Java.

## Descripción

El proceso implica la creación de un JSON Web Token (JWT) en formato JWE que cifra el texto plano utilizando un algoritmo de cifrado y una clave pública del destinatario.

### Pasos

1. **Encabezado Protegido JWE:**
   - Se declara el encabezado protegido JWE con características específicas.
   - Se codifica en BASE64URL(UTF8(JWE Protected Header)).

2. **Proceso de Encriptación:**
   - Generación de Content Encryption Key (CEK).
   - Encriptación del CEK con la clave pública del destinatario utilizando RSAES-OAEP.
   - Codificación en BASE64URL de la JWE Encrypted Key.
   - Generación de JWE Initialization Vector y codificación en BASE64URL.
   - Establecimiento de datos de cifrado adicionales y realización de un cifrado autenticado en el texto plano utilizando AES GCM.
   - Codificación en BASE64URL del texto cifrado y la etiqueta de autenticación.

### Representación Final del JWE

eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ==.qW6Riw7SOMNecXmkBsh9p8axRPp4yjj5CIP-Kb7ZqW3S1QNCncAgkdE8NFTQfAnypra3-Bmb2vzLJvxGk7rcvD8fJNLGAZyUMs9SpHj94YTRc8guE72PvmsZJvWjY5aEUVkVsHD7upFfjiC2u7KQLxmu2StqyJtx6KTrQGru55T4l3wigojdnXK-5RaQWN9sx2kh81KecLOXTiRY0si5nJzecRY9UEnpzUEUPWWc78tMDr0WFRBWkRU3myjWK-cmizf3hUKD3KKbMX09REqvaKQAi_0IoXytz6X6C32uFagc_5_bpcvxZ31g91fCrE4SvMigavoqL79STlzRtTRH1w==.908qZk8EvqjfCscG.GCcu2GihgfBz_YTlamSNS4j33YeDmmS9iClAe3wfEOxmNJ8TiuFs6WmHb5BtF1GjiwkJ1e9y4fGAtDq_AGSidYps4YwQnhFxg9O-1c3zszapRVGX2biosA==.908qZk8EvqjfCscG


Consulta la documentación adjunta para detalles completos sobre cómo generar este JWE en Java. Revisa el archivo de implementación en Java disponible en este repositorio para el código detallado.

Para más ejemplos y detalles, consulta la sección de ejemplos adicionales en la documentación.

---

**Nota:** El contenido de este README proporciona una descripción general del proceso. Se recomienda seguir la documentación y el código fuente en el repositorio para obtener instrucciones detalladas y precisas.
