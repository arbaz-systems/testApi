package com.systemsltd.common;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class CommonMethods {
  public static Date convertStringToDate(String date, String format) {
    Date dateObj = null;
    SimpleDateFormat dateFormat = new SimpleDateFormat(format);
    dateFormat.setLenient(false);
    try {
      dateObj = dateFormat.parse(date.trim());
    } catch (ParseException pe) {
      pe.printStackTrace();
    } 
    return dateObj;
  }
  
  public static String convertDateToString(Date date, String format) {
    return (new SimpleDateFormat(format)).format(date);
  }
  
  public static String stringDateToString(String givenDateInStr, String srcFormat, String targetFormat) {
    String strDate = "";
    Date date = convertStringToDate(givenDateInStr, srcFormat);
    if (date != null)
      strDate = convertDateToString(date, targetFormat); 
    return strDate;
  }
  
  public static String getBrokerUUID() {
    InetAddress ip = null;
    try {
      ip = InetAddress.getLocalHost();
    } catch (UnknownHostException e) {
      e.printStackTrace();
    } 
    String hostname = ip.getHostAddress();
    return hostname;
  }
}
