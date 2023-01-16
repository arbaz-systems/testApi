package com.systemsltd.common.util;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class ConversionUtil {
  private static int DEFAULT_BUFFER_SIZE = 1000;
  
  public static Map<String, String> convertToMap(Properties props) {
    Map<String, String> map = new HashMap<>();
    if (props != null && !props.isEmpty())
      for (Object obj : props.keySet()) {
        if (obj instanceof String) {
          String key = (String)obj;
          map.put(key, props.getProperty(key));
        } 
      }  
    return map;
  }
  
  public static String join(String... values) {
    StringBuilder buffer = new StringBuilder(DEFAULT_BUFFER_SIZE);
    byte b;
    int i;
    String[] arrayOfString;
    for (i = (arrayOfString = values).length, b = 0; b < i; ) {
      String value = arrayOfString[b];
      buffer.append(value);
      b++;
    } 
    return buffer.toString();
  }
}
