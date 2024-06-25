package com.example.t01_jwe;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class JWE_decifrado {
    public static void main(String[] args) throws Exception {
        // Generar un par de claves RSA (pública y privada)
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Tamaño de clave
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Obtener la clave pública y privada RSA
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

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
        String plainText = "El amor es una mentira";

        // Paso 11: Cifrado autenticado del texto plano con AES-GCM
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, cek, gcmParameterSpec);
        byte[] cipherTextWithTag = aesCipher.doFinal(plainText.getBytes());

        // Separar el texto cifrado y la etiqueta de autenticación
        int tagLength = 16; // Longitud típica de la etiqueta de autenticación en bytes
        byte[] cipherText = new byte[cipherTextWithTag.length - tagLength];
        byte[] authenticationTag = new byte[tagLength];
        System.arraycopy(cipherTextWithTag, 0, cipherText, 0, cipherText.length);
        System.arraycopy(cipherTextWithTag, cipherText.length, authenticationTag, 0, tagLength);

        // Paso 12: Codificar en Base64url el texto cifrado
        String base64CipherText = Base64.getUrlEncoder().encodeToString(cipherText);

        // Paso 14: Codificar en Base64url la etiqueta de autenticación
        String base64AuthenticationTag = Base64.getUrlEncoder().encodeToString(authenticationTag);

        // Paso final: Concatenar texto cifrado y etiqueta de autenticación al JWE
        jwe += base64CipherText + "." + base64AuthenticationTag;

        // Imprimir el JWE resultante
        System.out.println("JWE resultante: " + jwe);

        // ===== Descifrado =====

        // Separar los componentes del JWE
        String[] parts = jwe.split("\\.");
        String encCEK = parts[1];
        String encIV = parts[2];
        String encCipherText = parts[3];
        String encAuthTag = parts[4];

        // Decodificar Base64url
        byte[] decodedEncryptedCEK = Base64.getUrlDecoder().decode(encCEK);
        byte[] decodedIV = Base64.getUrlDecoder().decode(encIV);
        byte[] decodedCipherText = Base64.getUrlDecoder().decode(encCipherText);
        byte[] decodedAuthTag = Base64.getUrlDecoder().decode(encAuthTag);

        // Descifrar la CEK con la clave privada RSA
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedCEK = rsaCipher.doFinal(decodedEncryptedCEK);
        SecretKey originalCEK = new SecretKeySpec(decryptedCEK, 0, decryptedCEK.length, "AES");

        // Concatenar el texto cifrado y la etiqueta de autenticación
        byte[] ciphertextWithTagDecryption = new byte[decodedCipherText.length + decodedAuthTag.length];
        System.arraycopy(decodedCipherText, 0, ciphertextWithTagDecryption, 0, decodedCipherText.length);
        System.arraycopy(decodedAuthTag, 0, ciphertextWithTagDecryption, decodedCipherText.length, decodedAuthTag.length);

        // Descifrar el texto cifrado con AES-GCM
        aesCipher.init(Cipher.DECRYPT_MODE, originalCEK, new GCMParameterSpec(128, decodedIV));
        byte[] decryptedText = aesCipher.doFinal(ciphertextWithTagDecryption);

        // Convertir el texto descifrado a cadena
        String plainTextDecrypted = new String(decryptedText);

        // Imprimir el texto descifrado
        System.out.println("Texto descifrado: " + plainTextDecrypted);
    }
}
