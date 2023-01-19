package com.systemsltd.common.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Base64;

import javax.crypto.SecretKey;

public class FileUtils {
  public static Boolean fileExists(String location) {
    File file = new File(location);
    return Boolean.valueOf(file.exists());
  }
  
  public static byte[] readFile(String location) {
    if (location == null || location.trim().equals(""))
      throw new IllegalArgumentException("File Location can't be empty"); 
    try {
      File file = new File(location);
      if (!file.exists())
        throw new FileNotFoundException("Unable to read File: " + location); 
      byte[] data = Files.readAllBytes(file.toPath());
      return data;
    } catch (IOException ioe) {
      throw new FileOperationFailureException("Unable to read File: " + location, ioe);
    } 
  }
  public static void generatefile(final String content, final String location) {
      if (location == null || location.trim().equals("")) {
          throw new IllegalArgumentException("File Location can't be empty");
      }
      try {
          final BufferedWriter writer = new BufferedWriter(new FileWriter(location));
          writer.write(content);
          writer.close();
      }
      catch (Exception ex) {
          throw new IllegalArgumentException(ex.getMessage());
      }
  }
  public static byte[] getSecretKey(String keystorePassword, String alias, String filepath) {
    byte[] key = null;
    try {
      char[] password = keystorePassword.toCharArray();
      KeyStore ks = KeyStore.getInstance("JCEKS");
      FileInputStream fis = new FileInputStream(filepath);
      ks.load(fis, password);
      SecretKey secretKey = (SecretKey)ks.getKey(alias, password);
      key = secretKey.getEncoded();
    } catch (Exception e) {
      System.out.println("Error while fetching key " + e.toString());
    } 
    return key;
  }
  
  public static void main(String[] arg) {
    byte[] key = getSecretKey("changeit", "soa-secret-key", "C:\\Users\\vendor.systemsltd2\\Desktop\\keystores\\secretKey.jck");
    String skey = Base64.getEncoder().encodeToString(key);
    System.out.println(skey);
  }
}
