package com.systemsltd.common.util;

import java.io.FileInputStream;
import java.util.Properties;

public class Utility {
  public static Properties properties = null;
  
  public static void loadProperties(String appName) throws Exception {
    properties = new Properties();
    FileInputStream fstream = null;
    try {
      fstream = new FileInputStream("/soa/soadir/config/Service.properties");
      properties.load(fstream);
    } catch (Exception e) {
      throw e;
    } finally {
      if (fstream != null)
        fstream.close(); 
    } 
  }
  
  public static String getProperty(String propertyName, String appName) {
    String propertyValue = null;
    try {
      if (properties == null)
        loadProperties(appName); 
      propertyValue = properties.getProperty(propertyName);
    } catch (Exception e) {
      e.printStackTrace();
    } 
    return propertyValue;
  }
}
