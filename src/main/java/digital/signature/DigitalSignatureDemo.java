package digital.signature;

import com.google.common.io.BaseEncoding;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class DigitalSignatureDemo {
    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        DigitalSignatureDemo.signRequest("My name is Sagar Rout");
    }

    private static void signRequest(String content) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096);
        final KeyPair keyPair = generator.generateKeyPair();

        System.out.println("Private Key : " + BaseEncoding.base16().encode(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key : " + BaseEncoding.base16().encode(keyPair.getPublic().getEncoded()));

        final Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(content.getBytes(StandardCharsets.UTF_8));
        final byte[] signedData = signature.sign();

        System.out.println(new String(signedData));
        signature.initVerify(keyPair.getPublic());
        signature.update(content.getBytes());
        final boolean isValid = signature.verify(signedData);
        System.out.println(isValid);


    }
}
