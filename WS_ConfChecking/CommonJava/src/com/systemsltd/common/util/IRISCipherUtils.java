package com.systemsltd.common.util;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class IRISCipherUtils {
  static final String ALG_DES = "DES";
  
  static final String ALG_TRIPLE_DES = "DESede";
  
  static final String DES_MODE_ECB = "ECB";
  
  static final String DES_MODE_CBC = "CBC";
  
  static final String DES_NO_PADDING = "NoPadding";
  
  static final String[] hexStrings = new String[256];
  
  static final short LENGTH_DES = 64;
  
  static final short LENGTH_DES3_2KEY = 128;
  
  static final short LENGTH_DES3_3KEY = 192;
  
  static {
    for (int i = 0; i < 256; i++) {
      StringBuilder d = new StringBuilder(2);
      char ch = Character.forDigit((byte)i >> 4 & 0xF, 16);
      d.append(Character.toUpperCase(ch));
      ch = Character.forDigit((byte)i & 0xF, 16);
      d.append(Character.toUpperCase(ch));
      hexStrings[i] = d.toString();
    } 
  }
  
  public enum CipherMode {
    ECB, CBC, CFB8, CFB64, AES;
  }
  
  public static byte[] encryptData(byte[] data, String hexKey) {
    try {
      Key key = formDESKey(hexKey);
      data = doCryptStuff(data, key, 1);
    } catch (Exception e) {
      e.printStackTrace();
    } 
    return data;
  }
  
  public static Key formDESKey(String clearKeyHex) throws Exception {
    byte[] clearKeyBytes = hex2byte(clearKeyHex);
    int keyLength = clearKeyBytes.length * 8;
    return formDESKey(keyLength, clearKeyBytes);
  }
  
  static Key formDESKey(int keyLength, byte[] clearKeyBytes) throws Exception {
    Key key = null;
    switch (keyLength) {
      case 64:
        key = new SecretKeySpec(clearKeyBytes, "DES");
        break;
      case 128:
        clearKeyBytes = concat(clearKeyBytes, 0, getBytesLength((short)128), clearKeyBytes, 0, 
            getBytesLength((short)64));
      case 192:
        key = new SecretKeySpec(clearKeyBytes, "DESede");
        break;
    } 
    if (key == null)
      throw new Exception("Unsupported DES key length: " + keyLength + " bits"); 
    return key;
  }
  
  static byte[] doCryptStuff(byte[] data, Key key, int direction) throws Exception {
    return doCryptStuff(data, key, direction, CipherMode.ECB, null);
  }
  
  static byte[] doCryptStuff(byte[] data, Key key, int direction, CipherMode cipherMode, byte[] iv) throws Exception {
    byte[] result;
    String transformation = key.getAlgorithm();
    if (key.getAlgorithm().startsWith("DES"))
      transformation = String.valueOf(transformation) + "/" + cipherMode.name() + "/" + "NoPadding"; 
    AlgorithmParameterSpec aps = null;
    try {
      Cipher c1 = Cipher.getInstance(transformation);
      if (cipherMode != CipherMode.ECB)
        aps = new IvParameterSpec(iv); 
      c1.init(direction, key, aps);
      result = c1.doFinal(data);
      if (cipherMode != CipherMode.ECB)
        System.arraycopy(result, result.length - 8, iv, 0, iv.length); 
    } catch (Exception e) {
      throw new Exception(e);
    } 
    return result;
  }
  
  public static int getBytesLength(short keyLength) throws Exception {
    int bytesLength = 0;
    switch (keyLength) {
      case 64:
        bytesLength = 8;
        return bytesLength;
      case 128:
        bytesLength = 16;
        return bytesLength;
      case 192:
        bytesLength = 24;
        return bytesLength;
    } 
    throw new Exception("Unsupported key length: " + keyLength + " bits");
  }
  
  public static byte[] concat(byte[] array1, int beginIndex1, int length1, byte[] array2, int beginIndex2, int length2) {
    byte[] concatArray = new byte[length1 + length2];
    System.arraycopy(array1, beginIndex1, concatArray, 0, length1);
    System.arraycopy(array2, beginIndex2, concatArray, length1, length2);
    return concatArray;
  }
  
  public static byte[] hex2byte(String s) {
    if (s.length() % 2 == 0)
      return hex2byte(s.getBytes(), 0, s.length() >> 1); 
    return hex2byte("0" + s);
  }
  
  public static byte[] hex2byte(byte[] b, int offset, int len) {
    byte[] d = new byte[len];
    for (int i = 0; i < len * 2; i++) {
      int shift = (i % 2 == 1) ? 0 : 4;
      d[i >> 1] = (byte)(d[i >> 1] | Character.digit((char)b[offset + i], 16) << shift);
    } 
    return d;
  }
  
  public static String format0Encode(String pin, String pan) {
    try {
      String pinLenHead = String.valueOf(padleft(Integer.toString(pin.length()), 2, '0')) + pin;
      String pinData = padright(pinLenHead, 16, 'F');
      byte[] bPin = hex2byte(pinData);
      String panPart = extractPanAccountNumberPart(pan);
      String panData = padleft(panPart, 16, '0');
      byte[] bPan = hex2byte(panData);
      byte[] pinblock = new byte[8];
      for (int i = 0; i < 8; i++)
        pinblock[i] = (byte)(bPin[i] ^ bPan[i]); 
      return hexString(pinblock).toUpperCase();
    } catch (Exception e) {
      throw new RuntimeException("Util failed!", e);
    } 
  }
  
  public static String extractPanAccountNumberPart(String accountNumber) throws Exception {
    String accountNumberPart = null;
    accountNumberPart = takeLastN(accountNumber, 13);
    accountNumberPart = takeFirstN(accountNumberPart, 12);
    return accountNumberPart;
  }
  
  public static String padleft(String s, int len, char c) throws Exception {
    s = s.trim();
    if (s.length() > len)
      throw new Exception("invalid len " + s.length() + "/" + len); 
    StringBuilder d = new StringBuilder(len);
    int fill = len - s.length();
    while (fill-- > 0)
      d.append(c); 
    d.append(s);
    return d.toString();
  }
  
  public static String padright(String s, int len, char c) throws Exception {
    s = s.trim();
    if (s.length() > len)
      throw new Exception("invalid len " + s.length() + "/" + len); 
    StringBuilder d = new StringBuilder(len);
    int fill = len - s.length();
    d.append(s);
    while (fill-- > 0)
      d.append(c); 
    return d.toString();
  }
  
  public static String hexString(byte[] b) {
    StringBuilder d = new StringBuilder(b.length * 2);
    byte b1;
    int i;
    byte[] arrayOfByte;
    for (i = (arrayOfByte = b).length, b1 = 0; b1 < i; ) {
      byte aB = arrayOfByte[b1];
      d.append(hexStrings[aB & 0xFF]);
      b1++;
    } 
    return d.toString();
  }
  
  public static String takeLastN(String s, int n) throws Exception {
    if (s.length() > n)
      return s.substring(s.length() - n); 
    if (s.length() < n)
      return zeropad(s, n); 
    return s;
  }
  
  public static String takeFirstN(String s, int n) throws Exception {
    if (s.length() > n)
      return s.substring(0, n); 
    if (s.length() < n)
      return zeropad(s, n); 
    return s;
  }
  
  public static String zeropad(String s, int len) throws Exception {
    return padleft(s, len, '0');
  }
  
  public static void main(String[] args) throws Exception {
    String inPin = "1980";
    String inPan = "6180001004561";
    String pinblkhex = format0Encode(inPin, inPan);
    String desKey = "2315208C9110AD4015EA4CA20131C2FD";
    byte[] pinblk = hex2byte(pinblkhex);
    byte[] textEncrypted = encryptData(pinblk, desKey);
  }
}
