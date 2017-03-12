package com.mavika.stenography;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Single interface to aes encryption and decryption
 */
public final class AESCrypt {

    /**
     * The IV used for encryption and decryption
     */
    private final IvParameterSpec ivParams;

    /**
     * Default constructor
     *
     * @throws Exception if any error occurs
     */
    public AESCrypt() throws Exception {
        // generate a random IV for encryption and decryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);
        ivParams = new IvParameterSpec(iv);
    }

    /**
     * Encrypt the message using the specified password
     *
     * @param messgae  the message to encrypt
     * @param password the password to use
     * @return the encrypted base64 message
     * @throws Exception if any error occurs
     */
    public String encrypt(String messgae, String password) throws Exception {
        // generate secret key from password
        byte[] key = password.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        // init the cipher
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParams);

        // encrypt and convert to base 64 string to be encoded in image
        byte[] encrypted = cipher.doFinal(messgae.getBytes());
        byte[] base64Byte = Base64.getEncoder().encode(encrypted);
        return new String(base64Byte, StandardCharsets.UTF_8);
    }

    /**
     * Decrypt the message using the specified password
     *
     * @param cypher   the cypher text
     * @param password the password
     * @return the decrypted message
     * @throws Exception if any error occurs
     */
    public String decrypt(String cypher, String password) throws Exception {
        byte[] cypherBase64Bytes = cypher.getBytes(StandardCharsets.UTF_8);
        byte[] normalCypherBytes = Base64.getDecoder().decode(cypherBase64Bytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        byte[] key = password.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParams);

        byte[] original = cipher.doFinal(normalCypherBytes);

        return new String(original);
    }
}
