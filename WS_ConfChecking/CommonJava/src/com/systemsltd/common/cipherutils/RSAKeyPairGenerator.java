package com.systemsltd.common.cipherutils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSAKeyPairGenerator {
  private PrivateKey privateKey;
  
  private PublicKey publicKey;
  
  public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(1024);
    KeyPair pair = keyGen.generateKeyPair();
    this.privateKey = pair.getPrivate();
    this.publicKey = pair.getPublic();
  }
  
  public void writeToFile(String path, byte[] key) throws IOException {
    File f = new File(path);
    f.getParentFile().mkdirs();
    FileOutputStream fos = new FileOutputStream(f);
    fos.write(key);
    fos.flush();
    fos.close();
  }
  
  public PrivateKey getPrivateKey() {
    return this.privateKey;
  }
  
  public PublicKey getPublicKey() {
    return this.publicKey;
  }
  
  public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
    RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
    keyPairGenerator.writeToFile("RSA/publicKey", keyPairGenerator.getPublicKey().getEncoded());
    keyPairGenerator.writeToFile("RSA/privateKey", keyPairGenerator.getPrivateKey().getEncoded());
    System.out.println("Public Key : " + Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded()));
    System.out.println("Private Key : " + Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));
    String publicKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded());
    String privateKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded());
    System.out.println("Public Key length in bytes: " + (publicKey.getBytes()).length);
    System.out.println("Private Key length in bytes: " + (privateKey.getBytes()).length);
  }
}
