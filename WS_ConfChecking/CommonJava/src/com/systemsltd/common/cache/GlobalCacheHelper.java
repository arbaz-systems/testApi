package com.systemsltd.common.cache;

import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbGlobalMap;

public class GlobalCacheHelper {
  public static void insertInCache(String cacheName, String key, String value) {
    try {
      MbGlobalMap map = MbGlobalMap.getGlobalMap(cacheName);
      String test = (String)map.get(key);
      if (test == null) {
        map.put(key, value);
      } else {
        map.update(key, value);
      } 
    } catch (MbException e) {
      throw new CacheFailureException(cacheName, "Insert Entry", e);
    } 
  }
  
  public static void insertInCacheBLOB(String cacheName, String key, byte[] value) {
    try {
      System.out.println("cacheName:" + cacheName);
      System.out.println("cachekey:" + key);
      MbGlobalMap map = MbGlobalMap.getGlobalMap(cacheName);
      if (map.get(key) == null) {
        System.out.println("inside if:");
        map.put(key, value);
      } else {
        System.out.println("inside else:");
        map.update(key, value);
      } 
    } catch (MbException e) {
      throw new CacheFailureException(cacheName, "Insert BLOB", e);
    } 
  }
  
  public static String readFromCache(String cacheName, String key) {
    try {
      MbGlobalMap map = MbGlobalMap.getGlobalMap(cacheName);
      return (String)map.get(key);
    } catch (MbException e) {
      throw new CacheFailureException(cacheName, "Read Entry", e);
    } 
  }
  
  public static byte[] readFromCacheBLOB(String cacheName, String key) {
    try {
      MbGlobalMap map = MbGlobalMap.getGlobalMap(cacheName);
      return (byte[])map.get(key);
    } catch (MbException e) {
      throw new CacheFailureException(cacheName, "Read BLOB", e);
    } 
  }
  
  public static Boolean deleteFromCache(String cacheName, String key) {
    try {
      MbGlobalMap map = MbGlobalMap.getGlobalMap(cacheName);
      if (map.get(key) == null)
        return Boolean.valueOf(false); 
      map.remove(key);
    } catch (MbException e) {
      throw new CacheFailureException(cacheName, "Delete Entry", e);
    } 
    return Boolean.valueOf(true);
  }
  
  public static void insertAllInCache(String cacheName, MbElement element) {
    try {
      MbGlobalMap map = MbGlobalMap.getGlobalMap(cacheName);
      while (element != null) {
        MbElement keyElement = element.getFirstChild();
        MbElement valueElement = keyElement.getNextSibling();
        String key = keyElement.getValueAsString();
        if (map.containsKey(key)) {
          map.update(key, valueElement.getValue());
        } else {
          map.put(key, valueElement.getValue());
        } 
        element = element.getNextSibling();
      } 
    } catch (MbException mbe) {
      throw new CacheFailureException(cacheName, "Insert Entries", mbe);
    } 
  }
  
  public static MbElement getAllCacheKeys(String cacheName) {
    try {
      MbGlobalMap map = MbGlobalMap.getGlobalMap(cacheName);
      return (MbElement)map.get(cacheName);
    } catch (MbException mbe) {
      throw new CacheFailureException(cacheName, "Insert Entries", mbe);
    } 
  }
  
  public static void main(String[] args) throws Exception {
    MbElement mb = getAllCacheKeys("IRIS_CONNECTIONS");
  }
}
