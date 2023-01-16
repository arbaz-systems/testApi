package com.systemsltd.ubl.ftbatch;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbNode;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbUserException;
import com.systemsltd.common.cache.GlobalCacheHelper;
import com.systemsltd.logging.LogHandler;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.SQLException;

public class CBSBatchDetailStatus extends MbJavaComputeNode {
  private String loggerName;
  
  private final Connection connection = null;
  
  public void onInitialize() throws MbException {
    super.onInitialize();
    this.loggerName = (String)getUserDefinedAttribute("loggerName");
  }
  
  public void evaluate(MbMessageAssembly inAssembly) throws MbException {
    MbOutputTerminal out = getOutputTerminal("out");
    byte[] inMessage = inAssembly.getMessage().getBuffer();
    String jsonString = new String(inMessage);
    MbMessage outMessage = new MbMessage();
    MbElement outputRoot = outMessage.getRootElement();
    MbElement inputRoot = inAssembly.getMessage().getRootElement();
    outputRoot.addAsFirstChild(inputRoot.getFirstChild().copy());
    MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly, outMessage);
    String cbsSchemaName = GlobalCacheHelper.readFromCache("ConfigCache", "CBS_SCHEMA_NAME");
    try {
      LogHandler.logInfo(this.loggerName, "Calling CBS Batch Detail Fund Transfer Stored Procedure");
      Connection conn = getCBSDBConnection("CBSJDBCConfigService");
      String sql = "call " + cbsSchemaName + ".TM_CBS_FINTRAN.PROCESS_BATCH(?,?)";
      CallableStatement cstmt = conn.prepareCall(sql);
      cstmt.registerOutParameter(2, 2005);
      Clob myClob = conn.createClob();
      myClob.setString(1L, jsonString);
      cstmt.setClob(1, myClob);
      cstmt.execute();
      Clob outClob = cstmt.getClob(2);
      cstmt.close();
      String outString = outClob.getSubString(1L, (int)outClob.length());
      LogHandler.logInfo(this.loggerName, "Response Received CBS Batch Detail Status: " + outString);
      outputRoot.createElementAsLastChildFromBitstream(outString.getBytes(), "XMLNSC", "", "", "", 0, 0, 0);
    } catch (SQLException e) {
      throw new MbUserException(this, "evaluate()", "", "", e.toString(), null);
    } 
    out.propagate(outAssembly);
  }
  
  private Connection getCBSDBConnection(String jdbcService) throws MbException {
    Connection conn = this.connection;
    if (conn == null)
      conn = getJDBCType4Connection(jdbcService, MbNode.JDBC_TransactionType.MB_TRANSACTION_AUTO); 
    return conn;
  }
}
