package org.claval;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import com.codahale.shamir.Scheme;


public class JSSS {

    private static final String RSA = "RSA";
    private final Scheme sss ;
    private final int KEYSIZE = 512;
    
    public JSSS(Scheme scheme) throws Exception{
       this.sss = scheme;
    }

    // Creates the RSA key pair with a Private Key broken into N shards. K of those shards will be needed to reassemble the private key. 
    public Entry<PublicKey,Map<Integer,byte[]>>shard() throws NoSuchAlgorithmException, IOException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
        keyGen.initialize(KEYSIZE);
        KeyPair keyPair = keyGen.genKeyPair();
        Map<Integer,byte[]> allPrivateKeyParts = sss.split(keyPair.getPrivate().getEncoded());

        for (Map.Entry<Integer,byte[]> entry : allPrivateKeyParts.entrySet()) {
            Files.write(Paths.get("SHARD"+entry.getKey()+".txt"), entry.getValue());
        }
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
        Files.write(Paths.get("PUBLIC.txt"), x509EncodedKeySpec.getEncoded());
        return new AbstractMap.SimpleEntry<PublicKey, Map<Integer,byte[]>>(keyPair.getPublic(), allPrivateKeyParts);
    }

    // Read the shards files and join them back in a byte [] private key.
    public byte [] join(String ... shardsFileName) throws IOException{
        Map<Integer, byte[]> shardToJoin = new HashMap<>();
        for (String fileName : shardsFileName) {
            shardToJoin.put(Integer.parseInt(fileName.replaceAll("[^\\d]", "")), Files.readAllBytes(Paths.get(fileName)));
        }
       byte[] privateKeyBytes = sss.join(shardToJoin);
       Files.write(Paths.get("PRIVATE.txt"), new PKCS8EncodedKeySpec(privateKeyBytes).getEncoded());
       return privateKeyBytes;
    }



}
