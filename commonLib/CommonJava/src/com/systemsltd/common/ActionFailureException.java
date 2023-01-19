package com.systemsltd.common;

public class ActionFailureException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  
  public ActionFailureException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
