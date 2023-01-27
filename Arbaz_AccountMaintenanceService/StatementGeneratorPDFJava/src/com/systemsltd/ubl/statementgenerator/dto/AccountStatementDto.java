package com.systemsltd.ubl.statementgenerator.dto;

public class AccountStatementDto {

	private String resourcesPath;
	private String statementRequest;
	private String statementResponse;
	private String generatedPdfFileName;
	private String generatedPdfFilePath;
	private String customerEmailAddress;
	private Boolean isError = false;
	private String errorDescription;
	
	public String getResourcesPath() {
		return resourcesPath;
	}
	
	public void setResourcesPath(String resourcesPath) {
		this.resourcesPath = resourcesPath;
	}

	public Boolean getIsError() {
		return isError;
	}

	public void setIsError(Boolean isError) {
		this.isError = isError;
	}

	public String getErrorDescription() {
		return errorDescription;
	}

	public void setErrorDescription(String errorDescription) {
		this.errorDescription = errorDescription;
	}

	public String getCustomerEmailAddress() {
		return customerEmailAddress;
	}

	public void setCustomerEmailAddress(String customerEmailAddress) {
		this.customerEmailAddress = customerEmailAddress;
	}

	public String getStatementRequest() {
		return statementRequest;
	}

	public void setStatementRequest(String statementRequest) {
		this.statementRequest = statementRequest;
	}

	public String getStatementResponse() {
		return statementResponse;
	}

	public void setStatementResponse(String statementResponse) {
		this.statementResponse = statementResponse;
	}

	public String getGeneratedPdfFilePath() {
		return generatedPdfFilePath;
	}

	public void setGeneratedPdfFilePath(String generatedPdfFilePath) {
		this.generatedPdfFilePath = generatedPdfFilePath;
	}

	public String getGeneratedPdfFileName() {
		return generatedPdfFileName;
	}

	public void setGeneratedPdfFileName(String generatedPdfFileName) {
		this.generatedPdfFileName = generatedPdfFileName;
	}
}
