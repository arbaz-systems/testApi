package com.systemsltd.common.cache;

public class CacheFailureException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  
  private static final String ERROR_MESSAGE = "Cache Operation %s Failed on %s";
  
  public CacheFailureException(String cacheName, String operation) {
    super(String.format("Cache Operation %s Failed on %s", new Object[] { operation, cacheName }));
  }
  
  public CacheFailureException(String cacheName, String operation, Throwable throwable) {
    super(String.format("Cache Operation %s Failed on %s", new Object[] { operation, cacheName }), throwable);
  }
}
