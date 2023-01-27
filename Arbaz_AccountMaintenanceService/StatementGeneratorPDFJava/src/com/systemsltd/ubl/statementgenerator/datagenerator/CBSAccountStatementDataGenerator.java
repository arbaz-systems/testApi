package com.systemsltd.ubl.statementgenerator.datagenerator;

import static com.systemsltd.common.cache.GlobalCacheHelper.readFromCache;
import static com.systemsltd.logging.LogHandler.logInfo;

import java.io.StringReader;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.json.JSONArray;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.systemsltd.common.CommonMethods;
import com.systemsltd.ubl.statementgenerator.dto.AccountStatementDto;

public class CBSAccountStatementDataGenerator extends
		StatementDataGeneratorBase {

	public String getStatementData(Connection conn, String jsonString) throws Exception {
		String respJson = "";
		JSONObject obj = new JSONObject(jsonString);
		JSONObject serviceHeader = obj.getJSONObject("serviceHeader");
		JSONObject transactionInfo = obj.getJSONObject("transactionInfo");
		JSONArray attributeList = transactionInfo.getJSONArray("attributeList");
		JSONObject stmtInqRequest = obj.getJSONObject("accountStatementInquiryRequest");
		
		String channel = serviceHeader.getString("channel");
		String referenceId = transactionInfo.getString("referenceId");
		String appCode = findInAttributeList(attributeList, "appCode");
		String workstation = findInAttributeList(attributeList, "workstation");
		String screenNo = findInAttributeList(attributeList, "screenNo");
		
		String accountNumber = stmtInqRequest.getJSONObject("accountDetail")
								.getJSONObject("accountIdentifier").getString("accountNumber");
		
		String fromDate = CommonMethods.stringDateToString(stmtInqRequest.getString("fromDate"), "yyyy-MM-dd", "dd.MM.yyyy");
		String toDate = CommonMethods.stringDateToString(stmtInqRequest.getString("toDate"), "yyyy-MM-dd", "dd.MM.yyyy");
		
		String cbsXmlRequest = "<REQUEST_IN><HEADER_IN><CORR_ID>"+referenceId+"</CORR_ID>"
				+ "<USER_NAME>CBS</USER_NAME><CHANNEL>"+channel+"</CHANNEL>"
				+ "<APPLICATION>"+appCode+"</APPLICATION><WORKSTATION>"+workstation+"</WORKSTATION>"
				+ "<SCREEN_NO>"+screenNo+"</SCREEN_NO><AUTH_KEY></AUTH_KEY></HEADER_IN>"
				+ "<DETAIL_IN><ACCT_NO>"+accountNumber+"</ACCT_NO><FROM_DATE>"+fromDate+"</FROM_DATE>"
						+ "<TO_DATE>"+toDate+"</TO_DATE></DETAIL_IN></REQUEST_IN>";
		
		
		String cbsSchemaName = readFromCache("ConfigCache", "CBS_SCHEMA_NAME");
		
		CallableStatement cstmt = null;
		try {
			logInfo(getLoggerName(), "CBS XML Request Prepared: "+cbsXmlRequest);
			
			logInfo(getLoggerName(), "Calling CBS Stored Procedure CBS.TM_CBS_SRV_WS.PROCESS_INQ");
			
			String sql = "call CBS.TM_CBS_SRV_WS.PROCESS_INQ(?,?)";
			
			cstmt = conn.prepareCall(sql);
			cstmt.registerOutParameter(2, Types.CLOB);

			Clob myClob = conn.createClob();
			myClob.setString(1, cbsXmlRequest);
			cstmt.setClob(1, myClob);

			cstmt.execute();

			Clob outClob = cstmt.getClob(2);
			cstmt.close();
			//conn.close();
			// Reader reader = outClob.getCharacterStream();

			String outString = outClob.getSubString(1, (int) outClob.length());
			logInfo(getLoggerName(), "Response Received From CBS : "+ outString);
			
			JSONObject resp = new JSONObject();
			resp.put("serviceHeader", obj.getJSONObject("serviceHeader"));
			resp.put("transactionInfo", obj.getJSONObject("transactionInfo"));
			
			outString = outString.replace("<![CDATA[", "").replace("]]>", "");
			Document cbsRespDoc = convertStringToXMLDocument(outString);
			String resultCode = cbsRespDoc.getElementsByTagName("RESULT_CODE").item(0).getTextContent();
			if (resultCode.equals("0")) {
				NodeList detailOutNodes = cbsRespDoc.getElementsByTagName("DETAIL_OUT").item(0).getChildNodes();
				
				for (int i=0; i<detailOutNodes.getLength(); i++) {
					Node n = detailOutNodes.item(i);
					String nodeName = n.getNodeName();
					System.out.println(nodeName);
					if (n.getNodeName().equals("ACCT_DET")) {
						Element eElement = (Element) n;
						
						JSONObject accountDetailFields = new JSONObject();
						JSONObject accIdentifier = new JSONObject().put("accountNumber", eElement.getElementsByTagName("ACCT_NO").item(0).getTextContent());
						accountDetailFields.put("accountIdentifier", accIdentifier);
						accountDetailFields.put("accountTitle", eElement.getElementsByTagName("ACCT_TITLE").item(0).getTextContent());
						accountDetailFields.put("accountBalance", eElement.getElementsByTagName("BALANCE").item(0).getTextContent());
						accountDetailFields.put("accountCurrency", eElement.getElementsByTagName("CURRENCY").item(0).getTextContent());
						accountDetailFields.put("depositType", eElement.getElementsByTagName("DEPOSIT_TYPE").item(0).getTextContent());
						accountDetailFields.put("accountAddress", eElement.getElementsByTagName("ACCT_ADDRESS").item(0).getTextContent());
						accountDetailFields.put("fromDate", eElement.getElementsByTagName("FROM_DATE").item(0).getTextContent());
						accountDetailFields.put("toDate", eElement.getElementsByTagName("TO_DATE").item(0).getTextContent());
						accountDetailFields.put("productType", eElement.getElementsByTagName("PRODUCT_TYPE").item(0).getTextContent());
						accountDetailFields.put("asOf", eElement.getElementsByTagName("AS_OF").item(0).getTextContent());
						accountDetailFields.put("cif", eElement.getElementsByTagName("CIF_NO").item(0).getTextContent());
						accountDetailFields.put("branchCode", eElement.getElementsByTagName("ACCT_BRANCH").item(0).getTextContent());
						accountDetailFields.put("branchName", eElement.getElementsByTagName("BRANCH_NAME").item(0).getTextContent());
						accountDetailFields.put("iban", eElement.getElementsByTagName("IBAN_CODE").item(0).getTextContent());
						accountDetailFields.put("cellNumber", eElement.getElementsByTagName("CELL_NO").item(0).getTextContent());
						accountDetailFields.put("birthDate", eElement.getElementsByTagName("BIRTH_DATE").item(0).getTextContent());
						accountDetailFields.put("openingBalance", eElement.getElementsByTagName("OPEN_BAL").item(0).getTextContent());
						
						JSONObject accountDetail = new JSONObject().put("accountDetail", accountDetailFields);
						resp.put("accountStatementInquiryResponse", accountDetail);
						
					} else if (n.getNodeName().equals("TRAN_HIST")) {
						JSONArray statementList = new JSONArray();
						NodeList tranHistory = n.getChildNodes();
						for (int j=0; j<tranHistory.getLength();j++) {
							Node record = tranHistory.item(j);
							Element eElement = (Element) record;
							JSONObject jsonRecord = new JSONObject();
							jsonRecord.put("seqNo", eElement.getElementsByTagName("SEQ_NO").item(0).getTextContent());
							jsonRecord.put("transactionDate", eElement.getElementsByTagName("TRAN_DATE").item(0).getTextContent());
							jsonRecord.put("particulars", eElement.getElementsByTagName("PARTICULARS").item(0).getTextContent());
							jsonRecord.put("instNo", eElement.getElementsByTagName("INST_NO").item(0).getTextContent());
							jsonRecord.put("transactionAmount", eElement.getElementsByTagName("TRAN_AMT").item(0).getTextContent());
							jsonRecord.put("crDr", eElement.getElementsByTagName("CR_DR").item(0).getTextContent());
							jsonRecord.put("runBal", eElement.getElementsByTagName("RUN_BAL").item(0).getTextContent());
							
							statementList.put(jsonRecord);
						}
						
						resp.getJSONObject("accountStatementInquiryResponse").put("statementItemList", statementList);
					}
				}
			}
			respJson = resp.toString();
			logInfo(getLoggerName(), "JSON prepared : "+ respJson);

		} catch (SQLException e) {
			throw new Exception(e);
		} catch (Exception e) {
			throw new Exception(e);
		} finally {
			cstmt.close();
		}
		return respJson;
	}
	
	private Document convertStringToXMLDocument(String xmlString) 
    {
        //Parser that produces DOM object trees from XML content
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
         
        //API to obtain DOM Document instance
        DocumentBuilder builder = null;
        try
        {
            //Create DocumentBuilder with default configuration
        	factory.setCoalescing(true);
            builder = factory.newDocumentBuilder();
             
            //Parse the content to Document object
            Document doc = builder.parse(new InputSource(new StringReader(xmlString)));
            return doc;
        } 
        catch (Exception e) 
        {
            e.printStackTrace();
        }
        return null;
    }

	@Override
	public AccountStatementDto getCustomerEmail(Connection conn, String accountNumber) throws Exception {
		AccountStatementDto dto = new AccountStatementDto();
		dto.setIsError(false);
		
		String query = "SELECT details.* FROM CBS.TM_ACCT_ESTATEMENT_V details "
				+ "WHERE details.CUSTNO = "+accountNumber+" AND details.ISACTIVE = 'Y' "
						+ "AND details.STMT_HANDLING = 'CO'";
		String custEmail1 = "", custEmail2 = "", custEmail="";
		
		Statement stmt = null;
		ResultSet rs = null;
		try {
			stmt = conn.createStatement();
			rs = stmt.executeQuery(query);
			
			while(rs.next()){
		         custEmail1 = rs.getString("CUSTEMAIL1");
		         custEmail2 = rs.getString("CUSTEMAIL2");
			}
		} catch (SQLException e) {
//			e.printStackTrace();
			throw new Exception(e);
		} finally {
			if (rs != null) rs.close();
			if (stmt != null) stmt.close();
		}
		
		if (custEmail1 != null && custEmail1.length() > 0) {
			custEmail = custEmail1;
		} else if (custEmail2 != null && custEmail2.length() > 0) {
			custEmail = custEmail2;
		} else {
			//customer email not found
			dto.setIsError(true);
			dto.setErrorDescription("customer email address not found");
			throw new Exception(dto.getErrorDescription());
		}
		
		dto.setCustomerEmailAddress(custEmail);
		return dto;
	}
}
