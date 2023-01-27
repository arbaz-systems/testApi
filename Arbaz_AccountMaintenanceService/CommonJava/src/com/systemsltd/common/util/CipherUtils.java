package com.systemsltd.common.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.Provider;
import java.security.Security;
import java.util.Base64;
import java.util.UUID;
import java.util.Arrays;
import java.io.UnsupportedEncodingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.xerces.impl.dv.util.HexBin;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.ibm.security.util.DerInputStream;
import com.ibm.security.util.DerValue;
import java.math.BigInteger;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.digests.SHA1Digest;


public class CipherUtils {
  public static final String ALGORITHM = "RSA";
  
  public static final String ENCODING = "UTF8";
  
  public static byte[] encrypt(byte[] data, String algorithm, byte[] key, byte[] iv) {
    byte[] encryptedBytes = null;
    try {
      String[] algo = algorithm.split("/");
      SecretKeySpec secretKey = new SecretKeySpec(key, algo[0]);
      Cipher cipher = Cipher.getInstance(algorithm);
      if (iv == null) {
        cipher.init(1, secretKey);
      } else {
        cipher.init(1, secretKey, new IvParameterSpec(iv));
      } 
      encryptedBytes = cipher.doFinal(data);
    } catch (Exception e) {
      e.printStackTrace();
    } 
    return encryptedBytes;
  }
  
  public static byte[] encryptAsymmetric(byte[] data, String algorithm, byte[] key) {
    byte[] encryptedBytes = null;
    try {
      String[] algo = algorithm.split("/");
      KeyFactory kf = KeyFactory.getInstance(algo[0]);
      PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(key));
      Cipher cipher = Cipher.getInstance(algorithm);
      cipher.init(1, pk);
      encryptedBytes = cipher.doFinal(data);
    } catch (Exception e) {
      e.printStackTrace();
    } 
    return encryptedBytes;
  }
  
  public static byte[] decrypt(byte[] encryptedData, String algorithm, byte[] key, byte[] iv) {
    byte[] decryptedBytes = null;
    try {
      String[] algo = algorithm.split("/");
      SecretKeySpec secretKey = new SecretKeySpec(key, algo[0]);
      Cipher cipher = Cipher.getInstance(algorithm);
      if (iv == null) {
        cipher.init(2, secretKey);
      } else {
        cipher.init(2, secretKey, new IvParameterSpec(iv));
      } 
      decryptedBytes = cipher.doFinal(encryptedData);
    } catch (Exception e) {
      e.printStackTrace();
    } 
    return decryptedBytes;
  }
  
  public static byte[] decryptAsymmetric(byte[] data, String algorithm, byte[] key) {
    byte[] decryptedBytes = null;
    try {
      String[] algo = algorithm.split("/");
      KeyFactory kf = KeyFactory.getInstance(algo[0]);
      PrivateKey pk = kf.generatePrivate(new PKCS8EncodedKeySpec(key));
      Cipher cipher = Cipher.getInstance(algorithm);
      cipher.init(2, pk);
      decryptedBytes = cipher.doFinal(data);
    } catch (Exception e) {
      e.printStackTrace();
    } 
    return decryptedBytes;
  }
  
  public static byte[] generateHash(byte[] data, String algorithm) {
    byte[] hashedBytes = null;
    try {
      MessageDigest hash = MessageDigest.getInstance(algorithm);
      hashedBytes = hash.digest(data);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } 
    return hashedBytes;
  }
  
  public static byte[] generateIV(Long size) {
    SecureRandom rand = new SecureRandom();
    byte[] iv = new byte[size.intValue()];
    rand.nextBytes(iv);
    return iv;
  }
  
  public static byte[] generateSymmetricKey(Long keySize, String keyAlgo) {
    byte[] generatedKey = null;
    try {
      KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgo);
      keyGen.init(keySize.intValue());
      generatedKey = keyGen.generateKey().getEncoded();
    } catch (Exception ex) {
      ex.printStackTrace();
    } 
    return generatedKey;
  }
  
  public static void main(String[] args) throws Exception {
    String publicKeyIvr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2QrEVzVvgMtw3KrRexKTBiy7+yW7KzBd+DjmTa2aQEqWyX8J0s+xImD+xTbnbyySmMryNG81IoYX1V/JOpmIKmP4vL4oSbQdB53+60zAsWkt4COw3rAs+37VTUrpWsnZctVj7LmvTaGZYurqKRd7mouzN2Eykx1HcRuoRiQn2WwIDAQAB";
    String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdXh2VbzkwRMDTwn7zM9NfOhTfmYREP5Pf5/Kj14bfhstRBF5Fz3YR97bPyGRxfzGIpEXybCQxm0USC3Ib8HIjDZM3VrW//c2P0R8EJaM9XxuOfXRnyi+ADKlSQQZ4md3PcLAToPwTQ2U9RabDjT/O3gdQp6ocaIAyXcgj8pmCuQIDAQAB";
    encryptTest("GNB123", publicKey, "GNB123");
    encryptTest("IVR123", publicKeyIvr, "IVR123");
  }
  
  private static void encryptTest(String text, String publicKey, String newPassword) {
    long keySize = 256L;
    String algorithm = "AES";
    UUID uuid = UUID.randomUUID();
    System.out.println("Raw Password: " + text);
    System.out.println("ReferenceId: " + uuid);
    String password = String.valueOf(text) + ":" + uuid;
    byte[] key = generateSymmetricKey(Long.valueOf(keySize), algorithm);
    byte[] encryptedPassword = encrypt(password.getBytes(), "AES/ECB/PKCS5Padding", key, null);
    System.out.println("Encrypted Password: " + Base64.getEncoder().encodeToString(encryptedPassword));
    byte[] encryptedKey = encryptAsymmetric(key, "RSA/ECB/PKCS1Padding", Base64.getDecoder().decode(publicKey));
    System.out.println("Encrypted RSA Key: " + Base64.getEncoder().encodeToString(encryptedKey));
    if (newPassword != null && newPassword.length() > 0) {
      byte[] encryptednewPassword = encrypt(newPassword.getBytes(), "AES/ECB/PKCS5Padding", key, null);
      System.out.println("Encrypted New Password: " + Base64.getEncoder().encodeToString(encryptednewPassword));
    } 
  }
  
  private static void decryptTest(String encAesKey, String encPassword, String privateKey) {
    byte[] decryptedKey = decryptAsymmetric(Base64.getDecoder().decode(encAesKey), "RSA/ECB/PKCS1Padding", Base64.getDecoder().decode(privateKey));
    byte[] decryptedPassword = decrypt(Base64.getDecoder().decode(encPassword), "AES/ECB/PKCS5Padding", decryptedKey, null);
    byte[] newPassword = decrypt(Base64.getDecoder().decode("mvri/1ce+EUYHoa/FFxG+Q=="), "AES/ECB/PKCS5Padding", decryptedKey, null);
    System.out.println("Decrypted Password: " + new String(decryptedPassword));
    System.out.println("New Password: " + new String(newPassword));
  }
  
  private static String encryptDataWithSymmetricKey(String data, byte[] secretKey, String symmPadding) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance(symmPadding);
    IvParameterSpec iv = new IvParameterSpec(new byte[8]);
    SecretKeySpec skeySpec = new SecretKeySpec(secretKey, "DESEDE");
    cipher.init(1, skeySpec, iv);
    byte[] encrypted = cipher.doFinal(data.getBytes());
    String encoded = HexBin.encode(encrypted);
    return new String(encoded);
  }
  public static String generateHmac(byte[] secretKey, String data, String algorithm, String encoding, Boolean hmacHexRequired) {
	    String signature = null;
	    try {
	      Mac mac = Mac.getInstance(algorithm);
	      SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, algorithm);
	      mac.init(secretKeySpec);
	      byte[] bytes = null;
	      if (encoding != null) {
	        bytes = mac.doFinal(data.getBytes(encoding));
	      } else {
	        bytes = mac.doFinal(data.getBytes());
	      } 
	      if (hmacHexRequired.booleanValue())
	        bytes = Hex.encodeHexString(bytes).getBytes(); 
	      signature = Base64.getEncoder().encodeToString(bytes);
	    } catch (InvalidKeyException|NoSuchAlgorithmException e) {
	      e.printStackTrace();
	    } catch (IllegalStateException e) {
	      e.printStackTrace();
	    } catch (UnsupportedEncodingException e) {
	      e.printStackTrace();
	    } 
	    return signature;
	  }
  public static String getHexString(byte[] b) {
	    String result = "";
	    for (int i = 0; i < b.length; i++)
	      result = String.valueOf(result) + Integer.toString((b[i] & 0xFF) + 256, 16).substring(1); 
	    return result;
	  }
//  	public static String encodeBase64(byte[] data) {
//		String encodedString = "";
//		try {
//			encodedString = Base64.getEncoder().encodeToString(data);
//		} catch (Exception exception) {
//		}
//		return encodedString;
//	}
  public static String encryptAsymmetricLMRAPublicKeyBouncyCastle(final byte[] data, final String key) {
      String encryptedString = null;
      try {
          Security.addProvider((Provider)new BouncyCastleProvider());
          final byte[] base64DecodeKey = Base64.getDecoder().decode(key);
          final DerInputStream derReader = new DerInputStream(base64DecodeKey);
          final DerValue[] seq = derReader.getSequence(0);
          final BigInteger modulus = seq[0].getBigInteger();
          final BigInteger publicExp = seq[1].getBigInteger();
          final OAEPEncoding cipher = new OAEPEncoding((AsymmetricBlockCipher)new RSAEngine(), (Digest)new SHA1Digest());
          final RSAKeyParameters keyParams = new RSAKeyParameters(false, modulus, publicExp);
          cipher.init(true, (CipherParameters)new ParametersWithRandom((CipherParameters)keyParams, SecureRandom.getInstance("SHA1PRNG")));
          final byte[] encryptedBytes = cipher.processBlock(data, 0, data.length);
          encryptedString = getHexString(encryptedBytes);
          
          
      }
      catch (Exception e) {
          e.printStackTrace();
      }
      return encryptedString;
  }
  public static byte[] encryptionWPS(final byte[] data, final String algorithm, final byte[] key, final byte[] iv) {
      byte[] encryptedBytes = null;
      String encryptedBytesStr = null;
      try {
          final String[] algo = algorithm.split("/");
          final SecretKeySpec secretKey = new SecretKeySpec(key, algo[0]);
          final Cipher cipher = Cipher.getInstance(algorithm);
          if (iv == null) {
              cipher.init(1, secretKey);
          }
          else {
              cipher.init(1, secretKey, new IvParameterSpec(iv));
          }
          encryptedBytes = cipher.doFinal(data);
          final String ivStr = getHexString(iv);
          encryptedBytesStr = getHexString(encryptedBytes);
          encryptedBytesStr = String.valueOf(ivStr) + "+" + encryptedBytesStr;
          encryptedBytes = encryptedBytesStr.getBytes();
      }
      catch (Exception e) {
          e.printStackTrace();
      }
      return encryptedBytes;
  }
  public static String decryptAESValue(final String key, final String pan, final String algorithm, final String hashAlgo, final byte[] iv) {
      final byte[] hashbytes = generateHash(key.getBytes(), hashAlgo);
      String decryptedPAN = null;
      try {
          final String[] algo = algorithm.split("/");
          final byte[] passwordKey = MessageDigest.getInstance(hashAlgo).digest(hashbytes);
          final byte[] passwordKey2 = Arrays.copyOfRange(passwordKey, 0, 16);
          final SecretKey secretKey = new SecretKeySpec(passwordKey2, algo[0]);
          final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
          final byte[] PAN = Base64.getDecoder().decode(pan);
          final Cipher aesCipher = Cipher.getInstance(algorithm);
          aesCipher.init(2, secretKey, ivParameterSpec);
          final byte[] decryptedData = aesCipher.doFinal(PAN);
          decryptedPAN = new String(decryptedData);
      }
      catch (Exception ex) {
          ex.printStackTrace();
      }
      return decryptedPAN;
  }
}
