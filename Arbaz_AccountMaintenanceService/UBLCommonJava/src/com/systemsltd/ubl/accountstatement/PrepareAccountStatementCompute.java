package com.systemsltd.ubl.accountstatement;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbNode;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.systemsltd.logging.LogHandler;
import com.systemsltd.ubl.statementgenerator.datagenerator.StatementDataGeneratorBase;
import com.systemsltd.ubl.statementgenerator.dto.AccountStatementDto;
import com.systemsltd.ubl.statementgenerator.pdfgenerator.PDFGeneratorBase;
import java.sql.Connection;
import org.json.JSONObject;

public class PrepareAccountStatementCompute extends MbJavaComputeNode {
  private String loggerName;
  
  public void onInitialize() throws MbException {
    super.onInitialize();
    this.loggerName = (String)getUserDefinedAttribute("loggerName");
  }
  
  public void evaluate(MbMessageAssembly inAssembly) throws MbException {
    MbOutputTerminal out = getOutputTerminal("out");
    MbMessage env = inAssembly.getGlobalEnvironment();
    AccountStatementDto stmtDto = new AccountStatementDto();
    try {
      MbElement template = env.getRootElement().getFirstElementByPath("Variables").getFirstElementByPath("StatementPDFTemplate");
      String pdfTemplateName = template.getFirstElementByPath("PDF_TEMPLATE_NAME").getValueAsString();
      String dataGeneratorClass = template.getFirstElementByPath("DATA_GENERATOR_JAVA_CLASS").getValueAsString();
      String pdfGeneratorClass = template.getFirstElementByPath("PDF_GENERATOR_JAVA_CLASS").getValueAsString();
      String dataSource = template.getFirstElementByPath("DATA_SOURCE").getValueAsString();
      String resourcesPath = template.getFirstElementByPath("RESOURCES_PATH").getValueAsString();
      String jsonString = getJsonData(inAssembly.getMessage());
      JSONObject inRequest = new JSONObject(jsonString);
      String accountNumber = inRequest.getJSONObject("accountStatementInquiryRequest").getJSONObject("accountDetail")
        .getJSONObject("accountIdentifier").getString("accountNumber");
      Connection conn = getJDBCType4Connection(dataSource, MbNode.JDBC_TransactionType.MB_TRANSACTION_AUTO);
      StatementDataGeneratorBase dataGenerator = (StatementDataGeneratorBase)Class.forName(dataGeneratorClass).newInstance();
      dataGenerator.setLoggerName(this.loggerName);
      LogHandler.logInfo(this.loggerName, "Get customer email start");
      stmtDto = dataGenerator.getCustomerEmail(conn, accountNumber);
      LogHandler.logInfo(this.loggerName, "Get customer email end");
      String statementResponse = dataGenerator.getStatementData(conn, jsonString);
      stmtDto.setStatementResponse(statementResponse);
      stmtDto.setResourcesPath(resourcesPath);
      PDFGeneratorBase pdfGenerator = (PDFGeneratorBase)Class.forName(pdfGeneratorClass).newInstance();
      pdfGenerator.setLoggerName(this.loggerName);
      stmtDto = pdfGenerator.generatePDF(stmtDto);
      LogHandler.logInfo(this.loggerName, "PDF generated successfully at:" + stmtDto.getGeneratedPdfFilePath());
      env.getRootElement().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "responseHeader", "");
      env.getRootElement().getFirstChild().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "responseCode", "00");
      env.getRootElement().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "fileDetails", "");
      env.getRootElement().getFirstChild().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "fileName", stmtDto.getGeneratedPdfFileName());
      env.getRootElement().getFirstChild().getFirstChild().getFirstChild().createElementAsLastChild(50331648, "filePath", stmtDto.getGeneratedPdfFilePath());
      env.getRootElement().getFirstChild().getFirstChild().getFirstChild().createElementAsLastChild(50331648, "customerEmail", stmtDto.getCustomerEmailAddress());
    } catch (Exception e) {
      LogHandler.logException(this.loggerName, String.valueOf(stmtDto.getErrorDescription()) + " - " + e.getMessage(), e);
      env.getRootElement().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "responseHeader", "");
      env.getRootElement().getFirstChild().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "responseCode", "165");
    } 
    out.propagate(inAssembly);
  }
  
  public static String getJsonData(MbMessage inMessage) throws Exception {
    MbElement jsonElem = inMessage.getRootElement().getFirstElementByPath("JSON/Data");
    if (jsonElem == null)
      return null; 
    byte[] bs = jsonElem.toBitstream(null, null, null, 0, 1208, 0);
    if (bs == null)
      return null; 
    String inputJson = new String(bs, "UTF-8");
    return inputJson;
  }
}
