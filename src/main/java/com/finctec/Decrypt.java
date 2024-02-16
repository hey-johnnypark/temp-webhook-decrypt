package com.finctec;

import java.io.File;
import java.io.FileReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemReader;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Decrypt {

    public static void main(String[] args) {
        try {
            // Load private key from file
            PrivateKey pKey = loadPrivateKey("webhook_encryption_private_key_RSPEC_ONLY.pem");

            // Load Webhook from File.
            String webhookPayload = Files.readString(Paths.get("encrypted_webhook.json"), Charset.defaultCharset());

            // Extract webhook values
            String[] splitWebhookPayload = webhookPayload.split("\\$");
            String encrypted_aes_key_base64 = splitWebhookPayload[0];
            String iv_base64 = splitWebhookPayload[1];
            String encrypted_payload_base64 = splitWebhookPayload[2];

            String decryptedAesKey = decrypt(pKey, encrypted_aes_key_base64);
            byte[] aesKeyBytes = Base64.getDecoder().decode(decryptedAesKey);

            byte[] ivBytes = Base64.getDecoder().decode(iv_base64);

            String decryptedPayload = decryptPayload(aesKeyBytes,ivBytes, encrypted_payload_base64);
            System.out.println("Decrypted Payload: " + decryptedPayload);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PrivateKey loadPrivateKey(String privateKeyFilePath) throws Exception {
        try (FileReader fileReader = new FileReader(privateKeyFilePath);
             PemReader pemReader = new PemReader(fileReader)) {

            PEMParser pemParser = new PEMParser(fileReader);
            Object pemObject = pemParser.readObject();

            if (pemObject instanceof PEMKeyPair) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                return converter.getPrivateKey(((PEMKeyPair) pemObject).getPrivateKeyInfo());
            } else {
                throw new IllegalArgumentException("Invalid PEM file format");
            }
        }
    }

    private static String decrypt(PrivateKey privateKey, String encryptedPayload) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedBytes = java.util.Base64.getDecoder().decode(encryptedPayload);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    private static String decryptPayload(byte[] secretKeyBytes, byte[] ivBytes, String encryptedPayload) throws Exception {

        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, "AES");

        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPayload);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
