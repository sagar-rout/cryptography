package symmetric;

import com.google.common.io.BaseEncoding;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

// Cipher block chaining
public class SymmetricCBCDemo {
    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        SymmetricCBCDemo.symmetricCBCEncryption("Batman");
    }

    private static void symmetricCBCEncryption(String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

        // specific key length
        keyGenerator.init(192);

        final SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(keyGenerator.getAlgorithm());
        System.out.println(keyGenerator.getProvider());
        System.out.println("Key : " + BaseEncoding.base16().encode(secretKey.getEncoded()));

        final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        final byte[] random = new byte[16];
        secureRandom.nextBytes(random);
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(random);
        System.out.println("ivParameterSpec : " + BaseEncoding.base16().encode(ivParameterSpec.getIV()));

        // encryption
        final byte[] plainTextInBytes = plainText.repeat(8).getBytes(StandardCharsets.UTF_8);
        System.out.println("input : " + BaseEncoding.base16().encode(plainTextInBytes));

        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        final byte[] encryptedOutput = cipher.doFinal(plainTextInBytes);
        System.out.println(encryptedOutput.length);
        System.out.println("output : " + BaseEncoding.base16().encode(encryptedOutput));

        // decryption
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        final byte[] bytes = cipher.doFinal(encryptedOutput);
        System.out.println(new String(bytes));

    }
}
