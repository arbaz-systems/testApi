package com.systemsltd.common.util;

import com.systemsltd.common.ActionFailureException;

public class FileOperationFailureException extends ActionFailureException {
  private static final long serialVersionUID = 1L;
  
  public FileOperationFailureException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
