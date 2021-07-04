package symmetric;

import com.google.common.io.BaseEncoding;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SymmetricDemo {
    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        SymmetricDemo.symmetricEncryption("Batman");
    }

    private static void symmetricEncryption(String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

        // specific key length
        keyGenerator.init(192);

        final SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(keyGenerator.getAlgorithm());
        System.out.println(keyGenerator.getProvider());
        System.out.println("Key : " + BaseEncoding.base16().encode(secretKey.getEncoded()));

        // encryption
        final byte[] plainTextInBytes = plainText.repeat(8).getBytes(StandardCharsets.UTF_8);
        System.out.println("input : " + BaseEncoding.base16().encode(plainTextInBytes));

        final Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        final byte[] encryptedOutput = cipher.doFinal(plainTextInBytes);
        System.out.println(encryptedOutput.length);
        System.out.println("output : " + BaseEncoding.base16().encode(encryptedOutput));

        // decryption
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        final byte[] bytes = cipher.doFinal(encryptedOutput);
        System.out.println(new String(bytes));

    }
}
