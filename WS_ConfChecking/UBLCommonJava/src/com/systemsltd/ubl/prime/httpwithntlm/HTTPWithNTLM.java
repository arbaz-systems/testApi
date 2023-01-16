package com.systemsltd.ubl.prime.httpwithntlm;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbUserException;
import com.systemsltd.common.cache.GlobalCacheHelper;
import com.systemsltd.common.http.util.HttpRequestOverNTLM;
import com.systemsltd.logging.LogHandler;

public class HTTPWithNTLM extends MbJavaComputeNode {
  private String loggerName;
  
  private String primeUrl;
  
  public void onInitialize() throws MbException {
    super.onInitialize();
    this.loggerName = (String)getUserDefinedAttribute("loggerName");
  }
  
  public void evaluate(MbMessageAssembly inAssembly) throws MbException {
    MbOutputTerminal out = getOutputTerminal("out");
    byte[] inMessage = inAssembly.getMessage().getBuffer();
    String serializedRequest = new String(inMessage);
    MbMessage outMessage = new MbMessage();
    MbElement outputRoot = outMessage.getRootElement();
    MbElement inputRoot = inAssembly.getMessage().getRootElement();
    outputRoot.addAsFirstChild(inputRoot.getFirstChild().copy());
    MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly, outMessage);
    LogHandler.logInfo(this.loggerName, "SOAP envelop added in request : " + serializedRequest);
    try {
      String domain = GlobalCacheHelper.readFromCache("ConfigCache", "PRIME_DOMAIN");
      String username = GlobalCacheHelper.readFromCache("ConfigCache", "PRIME_USERNAME");
      String password = GlobalCacheHelper.readFromCache("ConfigCache", "PRIME_PASSWORD");
      this.primeUrl = (String)getUserDefinedAttribute("PRIME_URL");
      String serializedResponse = HttpRequestOverNTLM.httpPostWithNTLM(this.primeUrl, 
          serializedRequest, "", domain, username, password);
      LogHandler.logInfo(this.loggerName, "Response received from Service : " + serializedResponse);
      outputRoot.createElementAsLastChildFromBitstream(serializedResponse.getBytes(), "XMLNSC", "", "", "", 0, 0, 0);
      out.propagate(outAssembly);
    } catch (Exception e) {
      throw new MbUserException(this, "evaluate()", "", "", e.toString(), null);
    } 
  }
}
