package com.example.t01_jwe;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.util.Base64;

public class JWE_demo {
    public static void main(String[] args) throws Exception {
        // Generar un par de claves RSA (pública y privada)
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Tamaño de clave
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Obtener la clave pública RSA
        PublicKey publicKey = keyPair.getPublic();

        // Paso 2: Generar una clave de cifrado de contenido aleatoria (CEK)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey cek = keyGen.generateKey();

        // Paso 3: Cifrar la CEK con la clave pública RSA del destinatario
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedCEK = rsaCipher.doFinal(cek.getEncoded());

        // Paso 4: Codificar en Base64 la clave cifrada JWE
        String base64EncryptedCEK = Base64.getUrlEncoder().encodeToString(encryptedCEK);

        // Paso 5: Generar un vector de inicialización JWE aleatorio para AES-GCM
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12]; // Tamaño típico para AES-GCM
        random.nextBytes(iv);

        // Paso 6: Codificar en Base64 el vector de inicialización JWE
        String base64IV = Base64.getUrlEncoder().encodeToString(iv);

        // Paso 7: Definir el encabezado protegido JWE como se proporciona
        String jweProtectedHeader = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";

        // Paso 8: Codificar en Base64url el encabezado protegido JWE
        String base64ProtectedHeader = Base64.getUrlEncoder().encodeToString(jweProtectedHeader.getBytes());

        // Paso 9: Concatenar los valores para obtener la representación final del JWE
        String jwe = base64ProtectedHeader + "." + base64EncryptedCEK + "." + base64IV + ".";

        // Paso 10: Texto plano a cifrar
        String plainText = "El verdadero signo de inteligencia.";

        // Paso 11: Cifrado autenticado del texto plano con AES-GCM
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, cek, gcmParameterSpec);
        byte[] cipherText = aesCipher.doFinal(plainText.getBytes());

        // Paso 12: Codificar en Base64url el texto cifrado
        String base64CipherText = Base64.getUrlEncoder().encodeToString(cipherText);

        // Paso 13: Obtener la etiqueta de autenticación de AES-GCM
        byte[] authenticationTag = aesCipher.getParameters().getParameterSpec(GCMParameterSpec.class).getIV();

        // Paso 14: Codificar en Base64url la etiqueta de autenticación
        String base64AuthenticationTag = Base64.getUrlEncoder().encodeToString(authenticationTag);

        // Paso final: Concatenar texto cifrado y etiqueta de autenticación al JWE
        jwe += base64CipherText + "." + base64AuthenticationTag;

        // Imprimir el JWE resultante
        System.out.println("JWE resultante: " + jwe);
    }
}
