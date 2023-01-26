package com.systemsltd.common.http.util;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class HttpRequestOverNTLM {
  public static String httpPostWithNTLM(String requestURL, String requestMsg, String soapAction, final String domain, final String userName, final String password) throws Exception {
    StringBuilder response = new StringBuilder();
    try {
      Authenticator.setDefault(new Authenticator() {
            public PasswordAuthentication getPasswordAuthentication() {
              return new PasswordAuthentication(String.valueOf(domain) + "\\" + userName, password.toCharArray());
            }
          });
      URL urlRequest = new URL(requestURL);
      HttpsURLConnection conn = (HttpsURLConnection)urlRequest.openConnection();
      conn.setDoOutput(true);
      conn.setDoInput(true);
      conn.setRequestMethod("POST");
      conn.setDoInput(true);
      conn.setDoOutput(true);
      conn.setUseCaches(false);
      conn.setRequestProperty("Content-Type", "text/xml");
      conn.setReadTimeout(120000);
      DataOutputStream out = new DataOutputStream(conn.getOutputStream());
      out.writeBytes(requestMsg);
      out.flush();
      out.close();
      InputStream stream = conn.getInputStream();
      BufferedReader in = new BufferedReader(new InputStreamReader(stream));
      String str = "";
      while ((str = in.readLine()) != null)
        response.append(str); 
      in.close();
    } catch (Exception ex) {
      throw new Exception(ex);
    } 
    return response.toString();
  }
}
