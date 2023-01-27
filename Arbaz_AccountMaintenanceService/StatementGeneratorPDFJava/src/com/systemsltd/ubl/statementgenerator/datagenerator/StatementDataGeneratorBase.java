package com.systemsltd.ubl.statementgenerator.datagenerator;

import java.sql.Connection;

import org.json.JSONArray;
import org.json.JSONObject;

import com.systemsltd.ubl.statementgenerator.dto.AccountStatementDto;

public abstract class StatementDataGeneratorBase {
	
	private String loggerName;
	
	public abstract String getStatementData(Connection conn, String data) throws Exception;
	public abstract AccountStatementDto getCustomerEmail(Connection conn, String accountNumber) throws Exception;
	

	public String findInAttributeList(JSONArray attributeList, String attributeKey) {
		String attributeValue = "";
		for (int i = 0; i < attributeList.length(); i++) {
			JSONObject attributeObj = attributeList.getJSONObject(i);
			String key = attributeObj.getString("attributeKey");
			if (attributeObj.getString("attributeKey").equals(attributeKey)) {
				attributeValue = attributeObj.getString("attributeValue");
				break;
			}
		}
		return attributeValue;
	}
	public String getLoggerName() {
		return loggerName;
	}
	public void setLoggerName(String loggerName) {
		this.loggerName = loggerName;
	}
}
