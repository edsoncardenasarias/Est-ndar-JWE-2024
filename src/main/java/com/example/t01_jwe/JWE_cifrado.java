package com.example.t01_jwe;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.util.Base64;

public class JWE_cifrado {
    public static void main(String[] args) throws Exception {
        // Generar par de claves RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Generar clave simétrica AES
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey cek = keyGenerator.generateKey();

        // Cifrar la clave simétrica (CEK) con RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedCEK = rsaCipher.doFinal(cek.getEncoded());

        // Texto plano a cifrar
        String plainText = "Texto de ejemplo para cifrar con JWE";
        byte[] plainTextBytes = plainText.getBytes();

        // Generar IV (vector de inicialización) para AES-GCM
        byte[] iv = new byte[12];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        // Cifrar el texto plano utilizando AES-GCM
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, cek, gcmParameterSpec);
        aesCipher.updateAAD("".getBytes()); // Puede añadir AAD si se desea
        byte[] cipherText = aesCipher.doFinal(plainTextBytes);

        // Separar el texto cifrado y la etiqueta de autenticación
        byte[] cipherTextOnly = new byte[cipherText.length - 16];
        byte[] authenticationTag = new byte[16];
        System.arraycopy(cipherText, 0, cipherTextOnly, 0, cipherTextOnly.length);
        System.arraycopy(cipherText, cipherTextOnly.length, authenticationTag, 0, authenticationTag.length);

        // Codificar en Base64URL las partes del JWE
        String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}".getBytes());
        String encodedEncryptedCEK = Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedCEK);
        String encodedIV = Base64.getUrlEncoder().withoutPadding().encodeToString(iv);
        String encodedCipherText = Base64.getUrlEncoder().withoutPadding().encodeToString(cipherTextOnly);
        String encodedAuthTag = Base64.getUrlEncoder().withoutPadding().encodeToString(authenticationTag);

        // Construir el JWE
        String jwe = encodedHeader + "." + encodedEncryptedCEK + "." + encodedIV + "." + encodedCipherText + "." + encodedAuthTag;
        System.out.println("JWE generado: " + jwe);

        // Guardar claves para descifrado posterior
        System.out.println("Clave privada: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
    }
}
