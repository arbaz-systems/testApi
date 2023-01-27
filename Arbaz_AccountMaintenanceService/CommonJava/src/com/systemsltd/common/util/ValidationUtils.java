package com.systemsltd.common.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ValidationUtils {
  public static Boolean isValidDate(String inDate, String format) {
    SimpleDateFormat dateFormat = new SimpleDateFormat(format);
    dateFormat.setLenient(false);
    try {
      dateFormat.parse(inDate.trim());
    } catch (ParseException pe) {
      return Boolean.valueOf(false);
    } 
    return Boolean.valueOf(true);
  }
  
  public static Boolean isValidFormat(String stringToValidate, String format) {
    Pattern pattern = Pattern.compile(format);
    Matcher matcher = pattern.matcher(stringToValidate);
    return Boolean.valueOf(matcher.matches());
  }
  
  public static Boolean isValidBase64(String StringToValidate) {
    try {
      byte[] arrayOfByte = Base64.getDecoder().decode(StringToValidate);
    } catch (Exception e) {
      return Boolean.valueOf(false);
    } 
    return Boolean.valueOf(true);
  }
  
  public static String encodeBase64(byte[] data) {
    String encodedString = "";
    try {
      encodedString = Base64.getEncoder().encodeToString(data);
    } catch (Exception exception) {}
    return encodedString;
  }
}
