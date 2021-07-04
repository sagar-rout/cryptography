import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import org.apache.commons.io.IOUtils;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

public class EncryptionUtil {

    public static byte[] encrypt(String plainText) throws GeneralSecurityException, IOException {
        final Cipher cipher = Cipher.getInstance("RSA");
        final String publicKey = getContent("alice/alice.pub");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        final byte[] encryptedText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return encryptedText;
    }

    public static PublicKey getPublicKey(String content) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final byte[] publicKeyBytes = BaseEncoding.base64().decode(content);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static PrivateKey getPrivateKey(String privateKeyInBase64) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        final byte[] decode = BaseEncoding.base64().decode(privateKeyInBase64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decode);
        return kf.generatePrivate(keySpec);
    }

    public static String signature(String plainText) throws GeneralSecurityException, IOException {
        final Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(getPrivateKey(getContent("bob/bob_private")));
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        final byte[] signedData = signature.sign();
        return BaseEncoding.base64().encode(signedData);
    }

    public static String decrypt(String encryptedTextInBase64) throws GeneralSecurityException, IOException {
        final Cipher cipher = Cipher.getInstance("RSA");
        final String privateKey = getContent("alice/alice_private");
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        final byte[] decrypted = cipher.doFinal(BaseEncoding.base64().decode(encryptedTextInBase64));
        return new String(decrypted);
    }

    public static boolean isSignatureValid(String originalContent, String signatureInBase64Encoding) throws GeneralSecurityException, IOException {
        final Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(getPublicKey(getContent("bob/bob.pub")));
        signature.update(originalContent.getBytes(StandardCharsets.UTF_8));
        return signature.verify(BaseEncoding.base64().decode(signatureInBase64Encoding));
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {

        // encryption
        String plainText = new ObjectMapper().writeValueAsString(Map.of("name", "sagar"));
        final byte[] encryptedContent = encrypt(plainText);
        final String encode = BaseEncoding.base64().encode(encryptedContent);
        System.out.println("encryptedContentInBase64Encoding : " + encode);

        // signature
        final String signature = signature(plainText);
        System.out.println(signature);

        // decryption
        final String decrypt = decrypt(encode);
        System.out.println(decrypt);

        // verify signature
        System.out.println(isSignatureValid(plainText, signature));
    }

    public static String getContent(String path) throws IOException {
        ClassLoader classLoader = EncryptionUtil.class.getClassLoader();

        try (InputStream inputStream = classLoader.getResourceAsStream(path)) {

            String result = IOUtils.toString(inputStream, StandardCharsets.UTF_8);
            System.out.println(result);
            return result;
        } catch (IOException e) {
            throw new UnsupportedEncodingException("Unable to read the file");
        }
    }
}
