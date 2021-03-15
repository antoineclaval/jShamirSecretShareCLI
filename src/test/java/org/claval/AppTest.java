package org.claval;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import javax.crypto.Cipher;

import com.codahale.shamir.Scheme;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AppTest 
{

    private static final int LETTER_UP_TO_Z = 122;
    private static final int NUMERAL_ZERO = 48;

    Logger logger = LoggerFactory.getLogger(AppTest.class);


    private static String generateRandomAlphanum(int length){
        int leftLimit = NUMERAL_ZERO; 
        int rightLimit = LETTER_UP_TO_Z; 
        Random random = new Random();
    
        return random.ints(leftLimit, rightLimit + 1)
          .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
          .limit(length)
          .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
          .toString();
    }

    public static PrivateKey getPrivateKeyFromBytes(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException  {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return kf.generatePrivate(spec);
    }

    public static PublicKey getPublicKeyFromFile(String filename ) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException  {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
   
    @Test
    public void happyPathAndOfficialTestFormulation() throws Exception
    {
        // 1. Creates the RSA key pair with a Private Key broken into 5 shards.
        JSSS jsss = new JSSS(new Scheme(new SecureRandom(), 5, 2));
        jsss.shard();

        // 2. Encrypts a random plain text string using the RSA Public Key.
        String randomString = generateRandomAlphanum(23);
        logger.debug("Random string: " + randomString);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKeyFromFile("PUBLIC.txt"));
        byte [] encryptedByte = cipher.doFinal(randomString.getBytes());

        // 3. Reassembles the Private Key using shard 2 & 5 only. 
       byte [] reassembledKey = jsss.join("SHARD2.txt", "SHARD5.txt");

        // 4. Decrypts the cypher text back into the plain text using the reassembled Private Key.
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKeyFromBytes(reassembledKey));
        byte [] decryptedByte = cipher.doFinal(encryptedByte);
        String decryptedString = new String(decryptedByte);
        logger.debug("Decrypted string:" + decryptedString);

         // 5. Asserts the decrypted plain text is equal to the original random plain text in Step 2.
         assertEquals(randomString, decryptedString);
    }

}
