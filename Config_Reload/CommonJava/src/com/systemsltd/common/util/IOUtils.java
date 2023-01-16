package com.systemsltd.common.util;

public class IOUtils {
  public static void closeQuitely(AutoCloseable closable) {
    if (closable != null)
      try {
        closable.close();
      } catch (Exception exception) {} 
  }
}
