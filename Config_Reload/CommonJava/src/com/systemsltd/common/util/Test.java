package com.systemsltd.common.util;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Test {

	public static void main(String[] args) {
		
		//replace below two with your password and public key
		String rawPassword = "GNB@2333";
		String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD9GO0DlxNj6kOoczjmE7FEuN979nASJaZKq1bF3a3hJtlsTZKfNAQVpGV5RJwZOizWWQe/3MvOed1VyT4YObEHkppo5vC0VCi2hcWiwqdZFXHLvwPNrb+U+CSbZ74SbfgDdm54YsOclEJwf9M6hL5MsYdGsfzy5j7nhikKiIPyLwIDAQAB";
		
		encryptTest(rawPassword, publicKey, null);
	}
	
	private static void encryptTest(String rawPassword, String publicKey, String newPassword) {
		long keySize = 256;
		String algorithm = "AES";
		UUID uuid = UUID.randomUUID();
//		System.out.println("Raw Password: "+text);
		System.out.println("************Start*********************************************");
		System.out.println("referenceId: "+uuid);
		String password = rawPassword+":" + uuid;
		
//		System.out.println("Raw Text:"+ password);
		byte[] key = generateSymmetricKey(keySize, algorithm);
//		System.out.println("Generated AES Key:"+ Base64.getEncoder().encodeToString(key));
//		System.out.println("Raw AES Key: " + new String(key));
		
		byte[] encryptedPassword = encrypt(password.getBytes(), "AES/ECB/PKCS5Padding", key, null);
		
		System.out.println("password: " + Base64.getEncoder().encodeToString(encryptedPassword));
		
		byte[] encryptedKey = encryptAsymmetric(key, "RSA/ECB/PKCS1Padding", Base64.getDecoder().decode(publicKey));
		System.out.println("authKey: " + Base64.getEncoder().encodeToString(encryptedKey));
		System.out.println("************end*********************************************");
//		if (newPassword != null && newPassword.length() > 0) {
//			byte[] encryptednewPassword = encrypt(newPassword.getBytes(), "AES/ECB/PKCS5Padding", key, null);
//			System.out.println("Encrypted New Password: " + Base64.getEncoder().encodeToString(encryptednewPassword));
//		}
	}
	
	
	/**
	 * Method to generate symmetric key based on provided algorithm and keySize. 
	 * 
	 * @param keyAlgo algorithm to be used for the key (e.g) AES etc.
	 * @param keySize size of the key in Bits (e.g) 128, 256.
	 * @return bytes of the newly generated key
	 */
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
	
	
	public static byte[] encrypt(byte[] data, String algorithm, byte[] key, byte[] iv) {
		byte[] encryptedBytes = null;
		
		try {
			String[] algo = algorithm.split("/");
			SecretKeySpec secretKey = new SecretKeySpec(key, algo[0]);
			Cipher cipher = Cipher.getInstance(algorithm);
			
			if (iv == null) {
				cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			} else {
				cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
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
			cipher.init(Cipher.ENCRYPT_MODE, pk);
			encryptedBytes = cipher.doFinal(data);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return encryptedBytes;
	}

}
