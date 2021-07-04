package asymmetric;

import com.google.common.io.BaseEncoding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class AsymmetricDemo {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        AsymmetricDemo.doEncryption("Batman");
    }

    private static void doEncryption(String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        final KeyPair keyPair = generator.generateKeyPair();
        final PrivateKey privateKey = keyPair.getPrivate();
        final PublicKey publicKey = keyPair.getPublic();

        System.out.println(new String(privateKey.getEncoded()));
        System.out.println("Private Key : " + BaseEncoding.base64().encode(privateKey.getEncoded()));
        System.out.println("Public Key : " + BaseEncoding.base64().encode(publicKey.getEncoded()));

        final byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);

        // encryption
        final Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        final byte[] encryptedText = cipher.doFinal(plainTextBytes);
        System.out.println("encrypted Text: " + BaseEncoding.base16().encode(encryptedText));
        System.out.println(encryptedText.length);

        // decryption
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        final byte[] unencryptedTextBytes = cipher.doFinal(encryptedText);
        System.out.println(new String(unencryptedTextBytes));
    }
}
