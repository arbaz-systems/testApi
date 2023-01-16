package com.systemsltd.ubl.statementgenerator.pdfgenerator;

import com.systemsltd.ubl.statementgenerator.dto.AccountStatementDto;

public abstract class PDFGeneratorBase {

	private String loggerName;
	
	public abstract AccountStatementDto generatePDF(AccountStatementDto statementData) throws Exception;

	public String getLoggerName() {
		return loggerName;
	}

	public void setLoggerName(String loggerName) {
		this.loggerName = loggerName;
	}
	
	public String addOrRemoveNegativeSign(String amount) {
		if (amount != null && amount.length() > 0) {
			if (amount.contains("-")) {
				amount = amount.replace("-", "");
	    	} else {
	    		amount = "-"+amount;
	    	}
		}
		return amount;
	}
}
