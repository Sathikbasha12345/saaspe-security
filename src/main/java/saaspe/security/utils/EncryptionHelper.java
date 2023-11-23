package saaspe.security.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EncryptionHelper {

    private static byte[] salt = new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65,
            0x76 };

    public static String encrypt(String key, String clearText) {

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(key.toCharArray(), salt, 10000, 256);
            SecretKeySpec secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

            Key secretKey = factory.generateSecret(spec);
            byte[] keys = new byte[32];
            byte[] iv = new byte[16];
            System.arraycopy(secretKey.getEncoded(), 0, keys, 0, 32);
            System.arraycopy(secretKey.getEncoded(), 0, iv, 0, 16);
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);
            byte[] cipherText = cipher.doFinal(clearText.getBytes());
            return Base64.getEncoder().encodeToString(cipherText).replace("/", ":");
        } catch (Exception e) {
            return null;
        }
    }

    public static String decrypt(String key, String cipherText) {
        try {
            cipherText = cipherText.replace(":", "/").replace(" ", "+");
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(key.toCharArray(), salt, 10000, 256);
            SecretKeySpec secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

            Key secretKey = factory.generateSecret(spec);
            byte[] keys = new byte[32];
            byte[] iv = new byte[16];
            System.arraycopy(secretKey.getEncoded(), 0, keys, 0, 32);
            System.arraycopy(secretKey.getEncoded(), 0, iv, 0, 16);
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            return new String(plainText);
        } catch (Exception e) {
            return null;
        }
    }
}
