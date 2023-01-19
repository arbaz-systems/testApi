package com.systemsltd.common.cipherutils;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class RSAUtil {
  public static PublicKey getPublicKey(String base64PublicKey) {
    PublicKey publicKey = null;
    try {
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      publicKey = keyFactory.generatePublic(keySpec);
      return publicKey;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    } 
    return publicKey;
  }
  
  public static PrivateKey getPrivateKey(String base64PrivateKey) {
    PrivateKey privateKey = null;
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance("RSA");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } 
    try {
      privateKey = keyFactory.generatePrivate(keySpec);
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    } 
    return privateKey;
  }
  
  public static byte[] generateHash(byte[] bytesToHash, String algorithm) {
    byte[] hashedBytes = null;
    try {
      MessageDigest hash = MessageDigest.getInstance(algorithm);
      hashedBytes = hash.digest(bytesToHash);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } 
    return hashedBytes;
  }
  
  public static byte[] encrypt(byte[] bytesToEncrypt, String key, String algorithm) {
    byte[] encryptedBytes = null;
    SecretKeySpec secretKey = null;
    try {
      Cipher cipher = Cipher.getInstance(algorithm);
      String[] algo = algorithm.split("/");
      if (algo[0].equals("AES")) {
        byte[] decodedBytes = Base64.getDecoder().decode(key);
        secretKey = new SecretKeySpec(decodedBytes, algo[0]);
        cipher.init(1, secretKey);
      } else if (algo[0].equals("RSA")) {
        cipher.init(1, getPublicKey(key));
      } 
      encryptedBytes = cipher.doFinal(bytesToEncrypt);
    } catch (Exception e) {
      System.out.println("Error while encrypting " + e.toString());
    } 
    return encryptedBytes;
  }
  
  public static byte[] decrypt(byte[] encryptedBytes, String key, String algorithm) {
    byte[] decryptedBytes = null;
    try {
      Cipher cipher = Cipher.getInstance(algorithm);
      String[] algo = algorithm.split("/");
      if (algo[0].equals("AES")) {
        byte[] decodedBytes = Base64.getDecoder().decode(key);
        SecretKeySpec secretKey = new SecretKeySpec(decodedBytes, algo[0]);
        cipher.init(2, secretKey);
      } else if (algo[0].equals("RSA")) {
        cipher.init(2, getPrivateKey(key));
      } 
      decryptedBytes = cipher.doFinal(encryptedBytes);
    } catch (Exception e) {
      System.out.println("Error while decrypting " + e.toString());
    } 
    return decryptedBytes;
  }
}
