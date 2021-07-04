package hashing;

import com.google.common.io.BaseEncoding;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashingDemo {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        HashingDemo.getHash("My name is Sagar."); // one way only
        HashingDemo.getHash("My name is Sagar."); // deterministic means hash will generate same digest
        HashingDemo.getHash("My name is Sagar Rout."); // pseudo random, with minor change hash will change completely
        HashingDemo.getHash("My name is Sagar Rout and I am 28 years old."); // fixed length, no matter length of the input, digest length will be same.
    }

    private static byte[] getHash(String plainText) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        final byte[] plainTextBytes = plainText.getBytes();
        final byte[] digest = messageDigest.digest(plainTextBytes);
        System.out.println("plainText : " + plainText);
        System.out.println("Digest : " + BaseEncoding.base16().encode(digest));
        System.out.println("Digest length : " + digest.length + " bytes");
        return digest;
    }
}
