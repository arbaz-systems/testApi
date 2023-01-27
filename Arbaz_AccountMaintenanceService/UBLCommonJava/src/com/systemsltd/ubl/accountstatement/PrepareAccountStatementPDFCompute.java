package com.systemsltd.ubl.accountstatement;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.borders.Border;
import com.itextpdf.layout.borders.DashedBorder;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.IBlockElement;
import com.itextpdf.layout.element.Image;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.property.TextAlignment;
import com.systemsltd.common.cache.GlobalCacheHelper;
import com.systemsltd.logging.LogHandler;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.json.JSONArray;
import org.json.JSONObject;

public class PrepareAccountStatementPDFCompute extends MbJavaComputeNode {
  private String loggerName;
  
  private String imageURL;
  
  private String filePath;
  
  public void onInitialize() throws MbException {
    super.onInitialize();
    this.loggerName = (String)getUserDefinedAttribute("loggerName");
  }
  
  public void evaluate(MbMessageAssembly inAssembly) throws MbException {
    MbOutputTerminal out = getOutputTerminal("out");
    byte[] inMessage = inAssembly.getMessage().getBuffer();
    String jsonString = new String(inMessage);
    JSONObject obj = new JSONObject(jsonString);
    MbMessage env = inAssembly.getGlobalEnvironment();
    try {
      if (obj.has("accountStatementInquiryResponse") && obj.getJSONObject("accountStatementInquiryResponse").has("statementItemList")) {
        JSONArray arrStatementList = obj.getJSONObject("accountStatementInquiryResponse").getJSONArray("statementItemList");
        JSONObject accountDetail = null;
        if (obj.getJSONObject("accountStatementInquiryResponse").has("accountDetail"))
          accountDetail = obj.getJSONObject("accountStatementInquiryResponse").getJSONObject("accountDetail"); 
        String fromDate = "";
        if (accountDetail.has("accountAttributeList")) {
          fromDate = accountDetail.getJSONArray("accountAttributeList").getJSONObject(0).getString("attributeValue");
        } else if (accountDetail.has("fromDate")) {
          fromDate = accountDetail.getString("fromDate");
        } 
        String toDate = "";
        if (accountDetail.has("accountAttributeList")) {
          toDate = accountDetail.getJSONArray("accountAttributeList").getJSONObject(1).getString("attributeValue");
        } else if (accountDetail.has("toDate")) {
          toDate = accountDetail.getString("toDate");
        } 
        this.filePath = GlobalCacheHelper.readFromCache("ConfigCache", "FILE_PATH");
        LogHandler.logInfo(this.loggerName, "Writing PDF file to path: " + this.filePath);
        String fileName = String.valueOf((new SimpleDateFormat("ddMMyyyyHHmmssSSS")).format(new Date())) + ".pdf";
        String outputFileName = String.valueOf(this.filePath) + fileName;
        PdfWriter writer = new PdfWriter(outputFileName);
        PdfDocument pdf = new PdfDocument(writer);
        Document doc = new Document(pdf);
        try {
          this.imageURL = GlobalCacheHelper.readFromCache("ConfigCache", "IMAGE_PATH");
          ImageData data = ImageDataFactory.create(this.imageURL);
          LogHandler.logInfo(this.loggerName, "Writing image: " + this.imageURL + "to pdf" + outputFileName);
          Image image = new Image(data);
          image.setFixedPosition(0.0F, 790.0F);
          doc.add(image);
        } catch (Exception ex) {
          LogHandler.logException(this.loggerName, "Image not found", ex);
        } 
        doc.add((IBlockElement)new Paragraph("\n"));
        if (accountDetail.has("accountTitle"))
          doc.add((IBlockElement)new Paragraph(accountDetail.getString("accountTitle"))); 
        float[] pointColumnWidth = { 100.0F, 100.0F, 100.0F, 100.0F, 200.0F };
        Table topTable = new Table(pointColumnWidth);
        Cell cellNoField = new Cell();
        cellNoField.add((IBlockElement)new Paragraph("Reg cell No."));
        cellNoField.setFontSize(10.0F);
        removeBorders(cellNoField, true, true, true, true);
        topTable.addCell(cellNoField);
        Cell cellNoValue = new Cell();
        cellNoValue.add((IBlockElement)new Paragraph(""));
        cellNoValue.setFontSize(10.0F);
        removeBorders(cellNoValue, true, true, true, true);
        topTable.addCell(cellNoValue);
        Cell emptyCell = new Cell();
        emptyCell.add((IBlockElement)new Paragraph(""));
        removeBorders(emptyCell, true, true, false, false);
        topTable.addCell(emptyCell);
        Cell pageNoField = new Cell();
        pageNoField.add((IBlockElement)new Paragraph("Page No:"));
        pageNoField.setFontSize(8.0F);
        removeBorders(pageNoField, false, true, false, true);
        topTable.addCell(pageNoField);
        Cell pageNoValue = new Cell();
        pageNoValue.add((IBlockElement)new Paragraph("1"));
        removeBorders(pageNoValue, false, true, true, false);
        pageNoValue.setFontSize(8.0F);
        topTable.addCell(pageNoValue);
        Cell ibanField = new Cell();
        ibanField.add((IBlockElement)new Paragraph("IBAN No."));
        ibanField.setFontSize(10.0F);
        removeBorders(ibanField, true, true, true, true);
        topTable.addCell(ibanField);
        Cell ibanValue = new Cell();
        if (accountDetail.has("accountIdentifier") && accountDetail.getJSONObject("accountIdentifier").has("iban")) {
          ibanValue.add((IBlockElement)new Paragraph(accountDetail.getJSONObject("accountIdentifier").getString("iban")));
        } else {
          ibanValue.add((IBlockElement)new Paragraph(""));
        } 
        ibanValue.setFontSize(10.0F);
        removeBorders(ibanValue, true, true, true, true);
        topTable.addCell(ibanValue);
        topTable.addCell(emptyCell);
        Cell statementField = new Cell();
        statementField.add((IBlockElement)new Paragraph("Statement Period:"));
        statementField.setFontSize(8.0F);
        removeBorders(statementField, false, true, false, true);
        topTable.addCell(statementField);
        Cell statementValue = new Cell();
        statementValue.add((IBlockElement)new Paragraph("From " + fromDate + " To " + toDate));
        removeBorders(statementValue, false, true, true, false);
        statementValue.setFontSize(8.0F);
        topTable.addCell(statementValue);
        removeBorders(emptyCell, true, true, true, true);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        Cell branchField = new Cell();
        branchField.add((IBlockElement)new Paragraph("Branch:"));
        branchField.setFontSize(8.0F);
        removeBorders(branchField, false, true, false, true);
        topTable.addCell(branchField);
        Cell branchValue = new Cell();
        if (accountDetail != null && accountDetail.has("branchInfo") && 
          accountDetail.getJSONObject("branchInfo").has("branchAddress") && 
          accountDetail.getJSONObject("branchInfo").getJSONObject("branchAddress").has("addressLine")) {
          branchValue.add((IBlockElement)new Paragraph(accountDetail.getJSONObject("branchInfo").getJSONObject("branchAddress").getString("addressLine")));
        } else {
          branchValue.add((IBlockElement)new Paragraph(""));
        } 
        removeBorders(branchValue, false, true, true, false);
        branchValue.setFontSize(8.0F);
        topTable.addCell(branchValue);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        Cell accountNoField = new Cell();
        accountNoField.add((IBlockElement)new Paragraph("Account No.:"));
        accountNoField.setFontSize(8.0F);
        removeBorders(accountNoField, false, true, false, true);
        topTable.addCell(accountNoField);
        Cell accountNoValue = new Cell();
        if (accountDetail.has("accountIdentifier") && accountDetail.getJSONObject("accountIdentifier").has("accountNumber")) {
          accountNoValue.add((IBlockElement)new Paragraph(accountDetail.getJSONObject("accountIdentifier").getString("accountNumber")));
        } else {
          accountNoValue.add((IBlockElement)new Paragraph(""));
        } 
        removeBorders(accountNoValue, false, true, true, false);
        accountNoValue.setFontSize(8.0F);
        topTable.addCell(accountNoValue);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        Cell accountTypeField = new Cell();
        accountTypeField.add((IBlockElement)new Paragraph("Account type:"));
        accountTypeField.setFontSize(8.0F);
        removeBorders(accountTypeField, false, true, false, true);
        topTable.addCell(accountTypeField);
        Cell accountTypeValue = new Cell();
        if (accountDetail.has("accountType")) {
          accountTypeValue.add((IBlockElement)new Paragraph(accountDetail.getString("accountType")));
        } else {
          accountTypeValue.add((IBlockElement)new Paragraph(""));
        } 
        removeBorders(accountTypeValue, false, true, true, false);
        accountTypeValue.setFontSize(8.0F);
        topTable.addCell(accountTypeValue);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        Cell accountStatusField = new Cell();
        accountStatusField.add((IBlockElement)new Paragraph("Account status:"));
        accountStatusField.setFontSize(8.0F);
        removeBorders(accountStatusField, false, true, false, true);
        topTable.addCell(accountStatusField);
        Cell accountStatusValue = new Cell();
        accountStatusValue.add((IBlockElement)new Paragraph(""));
        removeBorders(accountStatusValue, false, true, true, false);
        accountStatusValue.setFontSize(8.0F);
        topTable.addCell(accountStatusValue);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        Cell currencyField = new Cell();
        currencyField.add((IBlockElement)new Paragraph("Currency:"));
        currencyField.setFontSize(8.0F);
        removeBorders(currencyField, false, true, false, true);
        topTable.addCell(currencyField);
        Cell currencyValue = new Cell();
        if (accountDetail.has("accountCurrency")) {
          currencyValue.add((IBlockElement)new Paragraph(accountDetail.getString("accountCurrency")));
        } else {
          currencyValue.add((IBlockElement)new Paragraph(""));
        } 
        removeBorders(currencyValue, false, true, true, false);
        currencyValue.setFontSize(8.0F);
        topTable.addCell(currencyValue);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        Cell balanceField = new Cell();
        balanceField.add((IBlockElement)new Paragraph("Balance:"));
        balanceField.setFontSize(8.0F);
        removeBorders(balanceField, false, true, false, true);
        topTable.addCell(balanceField);
        Cell balanceValue = new Cell();
        if (accountDetail.has("accountBalance")) {
          balanceValue.add((IBlockElement)new Paragraph(accountDetail.getString("accountBalance")));
        } else {
          balanceValue.add((IBlockElement)new Paragraph(""));
        } 
        removeBorders(balanceValue, false, true, true, false);
        balanceValue.setFontSize(8.0F);
        topTable.addCell(balanceValue);
        topTable.addCell(emptyCell);
        topTable.addCell(emptyCell);
        Cell cell = new Cell();
        removeBorders(cell, true, true, false, false);
        topTable.addCell(cell);
        Cell generatedOnField = new Cell();
        generatedOnField.add((IBlockElement)new Paragraph("Generated On:"));
        generatedOnField.setFontSize(8.0F);
        removeBorders(generatedOnField, true, false, false, true);
        topTable.addCell(generatedOnField);
        Cell generatedOnValue = new Cell();
        generatedOnValue.add((IBlockElement)new Paragraph((new SimpleDateFormat("dd-MM-yyyy")).format(new Date())));
        removeBorders(generatedOnValue, true, false, true, false);
        generatedOnValue.setFontSize(8.0F);
        topTable.addCell(generatedOnValue);
        doc.add((IBlockElement)topTable);
        doc.add((IBlockElement)new Paragraph("\n"));
        float[] pointColumnWidths = { 80.0F, 200.0F, 100.0F, 80.0F, 80.0F, 80.0F };
        Table statementTable = new Table(pointColumnWidths);
        Cell dateField = new Cell();
        dateField.add((IBlockElement)new Paragraph("Date"));
        dateField.setFontSize(12.0F);
        dateField.setBackgroundColor(ColorConstants.BLUE);
        dateField.setFontColor(ColorConstants.WHITE);
        dateField.setTextAlignment(TextAlignment.CENTER);
        statementTable.addCell(dateField);
        Cell particularsField = new Cell();
        particularsField.add((IBlockElement)new Paragraph("Particulars"));
        particularsField.setFontSize(12.0F);
        particularsField.setBackgroundColor(ColorConstants.BLUE);
        particularsField.setFontColor(ColorConstants.WHITE);
        particularsField.setTextAlignment(TextAlignment.CENTER);
        statementTable.addCell(particularsField);
        Cell instField = new Cell();
        instField.add((IBlockElement)new Paragraph("Inst No."));
        instField.setFontSize(12.0F);
        instField.setBackgroundColor(ColorConstants.BLUE);
        instField.setFontColor(ColorConstants.WHITE);
        instField.setTextAlignment(TextAlignment.CENTER);
        statementTable.addCell(instField);
        Cell debitField = new Cell();
        debitField.add((IBlockElement)new Paragraph("Debit"));
        debitField.setFontSize(12.0F);
        debitField.setBackgroundColor(ColorConstants.BLUE);
        debitField.setFontColor(ColorConstants.WHITE);
        debitField.setTextAlignment(TextAlignment.CENTER);
        statementTable.addCell(debitField);
        Cell creditField = new Cell();
        creditField.add((IBlockElement)new Paragraph("Credit"));
        creditField.setFontSize(12.0F);
        creditField.setBackgroundColor(ColorConstants.BLUE);
        creditField.setFontColor(ColorConstants.WHITE);
        creditField.setTextAlignment(TextAlignment.CENTER);
        statementTable.addCell(creditField);
        Cell accountbalanceField = new Cell();
        accountbalanceField.add((IBlockElement)new Paragraph("Balance"));
        accountbalanceField.setFontSize(12.0F);
        accountbalanceField.setBackgroundColor(ColorConstants.BLUE);
        accountbalanceField.setFontColor(ColorConstants.WHITE);
        accountbalanceField.setTextAlignment(TextAlignment.CENTER);
        statementTable.addCell(accountbalanceField);
        Cell openingDate = new Cell();
        openingDate.add((IBlockElement)new Paragraph(fromDate));
        openingDate.setFontSize(10.0F);
        statementTable.addCell(openingDate);
        Cell openingBalance = new Cell();
        openingBalance.add((IBlockElement)new Paragraph("** OPENING BALANCE **"));
        openingBalance.setFontSize(10.0F);
        statementTable.addCell(openingBalance);
        statementTable.addCell("");
        statementTable.addCell("");
        statementTable.addCell("");
        statementTable.addCell("");
        Double debitAmount = Double.valueOf(0.0D), creditAmount = Double.valueOf(0.0D), credit = Double.valueOf(0.0D), debit = Double.valueOf(0.0D);
        for (int i = 0; i < arrStatementList.length(); i++) {
          Integer j = Integer.valueOf(0);
          if (arrStatementList.getJSONObject(i).has("payment")) {
            JSONObject payment = arrStatementList.getJSONObject(i).getJSONObject("payment");
            Cell dateValue = new Cell();
            dateValue.setFontSize(9.0F);
            Cell particularsValue = new Cell();
            particularsValue.setFontSize(9.0F);
            Cell instValue = new Cell();
            instValue.setFontSize(9.0F);
            Cell debitValue = new Cell();
            debitValue.setFontSize(9.0F);
            Cell creditValue = new Cell();
            creditValue.setFontSize(9.0F);
            Cell accountBalanceValue = new Cell();
            accountBalanceValue.setFontSize(9.0F);
            if (payment.has("transactionInfo") && payment.getJSONObject("transactionInfo").has("transactionDate")) {
              dateValue.add((IBlockElement)new Paragraph(payment.getJSONObject("transactionInfo").getString("transactionDate")));
            } else {
              dateValue.add((IBlockElement)new Paragraph(""));
            } 
            statementTable.addCell(dateValue);
            if (payment.has("transactionInfo") && payment.getJSONObject("transactionInfo").has("attributeList") && 
              payment.getJSONObject("transactionInfo").getJSONArray("attributeList").getJSONObject(j.intValue()).getString("attributeKey").equals("PARTICULARS")) {
              particularsValue.add((IBlockElement)new Paragraph(payment.getJSONObject("transactionInfo").getJSONArray("attributeList").getJSONObject(j.intValue()).getString("attributeValue")));
              statementTable.addCell(particularsValue);
              instValue.add((IBlockElement)new Paragraph((payment.getJSONObject("transactionInfo").getJSONArray("attributeList").length() == 2) ? 
                    payment.getJSONObject("transactionInfo").getJSONArray("attributeList").getJSONObject(1).getString("attributeValue") : ""));
              statementTable.addCell(instValue);
              if (payment.has("amount") && arrStatementList.getJSONObject(i).has("transactionNature")) {
                if (arrStatementList.getJSONObject(i).getString("transactionNature").equals("Debit")) {
                  debitValue.add((IBlockElement)new Paragraph(payment.getString("amount")));
                  statementTable.addCell(debitValue);
                  statementTable.addCell("");
                  debitAmount = Double.valueOf(debitAmount.doubleValue() + Double.parseDouble(payment.getString("amount")));
                  debit = Double.valueOf(debit.doubleValue() + 1.0D);
                } else {
                  statementTable.addCell("");
                  creditValue.add((IBlockElement)new Paragraph(payment.has("amount") ? payment.getString("amount") : " "));
                  statementTable.addCell(creditValue);
                  creditAmount = Double.valueOf(creditAmount.doubleValue() + Double.parseDouble(payment.getString("amount")));
                  credit = Double.valueOf(credit.doubleValue() + 1.0D);
                } 
              } else {
                statementTable.addCell("");
                statementTable.addCell("");
              } 
              accountBalanceValue.add((IBlockElement)new Paragraph(arrStatementList.getJSONObject(i).has("currentBalance") ? 
                    arrStatementList.getJSONObject(i).getString("currentBalance") : " "));
              statementTable.addCell(accountBalanceValue);
            } else {
              statementTable.addCell("");
              statementTable.addCell("");
              if (payment.has("amount") && arrStatementList.getJSONObject(i).has("transactionNature")) {
                if (arrStatementList.getJSONObject(i).getString("transactionNature").equals("Debit")) {
                  debitValue.add((IBlockElement)new Paragraph(String.valueOf(payment.getDouble("amount"))));
                  statementTable.addCell(debitValue);
                  debitAmount = Double.valueOf(debitAmount.doubleValue() + payment.getDouble("amount"));
                  debit = Double.valueOf(debit.doubleValue() + 1.0D);
                  statementTable.addCell("");
                } else {
                  statementTable.addCell("");
                  creditValue.add((IBlockElement)new Paragraph(String.valueOf(payment.getDouble("amount"))));
                  statementTable.addCell(creditValue);
                  creditAmount = Double.valueOf(creditAmount.doubleValue() + payment.getDouble("amount"));
                  credit = Double.valueOf(credit.doubleValue() + 1.0D);
                } 
              } else {
                statementTable.addCell("");
                statementTable.addCell("");
              } 
              accountBalanceValue.add((IBlockElement)new Paragraph(arrStatementList.getJSONObject(i).has("currentBalance") ? 
                    String.valueOf(arrStatementList.getJSONObject(i).getDouble("currentBalance")) : " "));
              statementTable.addCell(accountBalanceValue);
            } 
          } 
        } 
        Cell closingDateValue = new Cell();
        closingDateValue.add((IBlockElement)new Paragraph(toDate));
        closingDateValue.setFontSize(10.0F);
        statementTable.addCell(closingDateValue);
        Cell closingParticularsValue = new Cell();
        closingParticularsValue.add((IBlockElement)new Paragraph("** CLOSING BALANCE **"));
        closingParticularsValue.setFontSize(10.0F);
        statementTable.addCell(closingParticularsValue);
        Cell closingInstValue = new Cell();
        closingInstValue.add((IBlockElement)new Paragraph(""));
        statementTable.addCell(closingInstValue);
        Cell closingDebitValue = new Cell();
        closingDebitValue.add((IBlockElement)new Paragraph(""));
        statementTable.addCell(closingDebitValue);
        Cell closingCreditValue = new Cell();
        closingCreditValue.add((IBlockElement)new Paragraph(""));
        statementTable.addCell(closingCreditValue);
        Cell closingAccountBalanceValue = new Cell();
        closingAccountBalanceValue.add((IBlockElement)new Paragraph(accountDetail.has("accountBalance") ? accountDetail.getString("accountBalance") : " "));
        closingAccountBalanceValue.setFontSize(10.0F);
        statementTable.addCell(closingAccountBalanceValue);
        doc.add((IBlockElement)statementTable);
        float[] totalTransactionsColumnWidths = { 280.0F, 100.0F, 80.0F, 80.0F, 80.0F };
        Table totalTransactionsTable = new Table(totalTransactionsColumnWidths);
        Cell label = new Cell();
        label.add((IBlockElement)new Paragraph("**TOTAL WITHDRAWALS & DEPOSITS**"));
        label.setFontSize(10.0F);
        label.setTextAlignment(TextAlignment.CENTER);
        removeBorders(label, false, false, false, true);
        totalTransactionsTable.addCell(label);
        Cell empty = new Cell();
        empty.add((IBlockElement)new Paragraph(""));
        removeBorders(empty, false, false, true, true);
        totalTransactionsTable.addCell(empty);
        Cell totalDebit = new Cell();
        totalDebit.add((IBlockElement)new Paragraph(String.valueOf(debitAmount)));
        totalDebit.setFontSize(10.0F);
        totalDebit.setTextAlignment(TextAlignment.CENTER);
        removeBorders(totalDebit, false, false, true, true);
        totalTransactionsTable.addCell(totalDebit);
        Cell totalCredit = new Cell();
        totalCredit.add((IBlockElement)new Paragraph(String.valueOf(creditAmount)));
        totalCredit.setFontSize(10.0F);
        totalCredit.setTextAlignment(TextAlignment.CENTER);
        removeBorders(totalCredit, false, false, true, true);
        totalTransactionsTable.addCell(totalCredit);
        totalTransactionsTable.addCell("");
        doc.add((IBlockElement)totalTransactionsTable);
        float[] totalNoOfTransactionsColumnWidths = { 280.0F, 100.0F, 80.0F, 80.0F, 80.0F };
        Table totalNoOfTransactionsTable = new Table(totalNoOfTransactionsColumnWidths);
        Cell totalTransactions = new Cell();
        totalTransactions.add((IBlockElement)new Paragraph("**TOTAL NUMBER OF TRANSACTIONS**"));
        totalTransactions.setFontSize(10.0F);
        totalTransactions.setTextAlignment(TextAlignment.CENTER);
        removeBorders(totalTransactions, false, false, false, true);
        totalNoOfTransactionsTable.addCell(totalTransactions);
        Cell instEmptyCell = new Cell();
        instEmptyCell.add((IBlockElement)new Paragraph(""));
        removeBorders(instEmptyCell, false, false, true, true);
        totalNoOfTransactionsTable.addCell(instEmptyCell);
        Cell totalNoOfDebit = new Cell();
        totalNoOfDebit.add((IBlockElement)new Paragraph(String.valueOf(debit)));
        totalNoOfDebit.setFontSize(10.0F);
        totalNoOfDebit.setTextAlignment(TextAlignment.CENTER);
        removeBorders(totalNoOfDebit, false, false, true, true);
        totalNoOfTransactionsTable.addCell(totalNoOfDebit);
        Cell totalNoOfCredit = new Cell();
        totalNoOfCredit.add((IBlockElement)new Paragraph(String.valueOf(credit)));
        totalNoOfCredit.setFontSize(10.0F);
        totalNoOfCredit.setTextAlignment(TextAlignment.CENTER);
        removeBorders(totalNoOfCredit, false, false, true, true);
        totalNoOfTransactionsTable.addCell(totalNoOfCredit);
        totalNoOfTransactionsTable.addCell("");
        doc.add((IBlockElement)totalNoOfTransactionsTable);
        doc.add((IBlockElement)new Paragraph("\n"));
        Paragraph p = new Paragraph();
        p.add("This is system generated Account Statement. Serial No:" + 
            obj.getJSONObject("transactionInfo").getString("referenceId"));
        p.setFontSize(10.0F);
        doc.add((IBlockElement)p);
        doc.close();
        LogHandler.logInfo(this.loggerName, "PDF generated successfully at:" + outputFileName);
        env.getRootElement().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "responseHeader", "");
        env.getRootElement().getFirstChild().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "responseCode", "00");
        env.getRootElement().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "fileDetails", "");
        env.getRootElement().getFirstChild().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "fileName", fileName);
        env.getRootElement().getFirstChild().getFirstChild().getFirstChild().createElementAsLastChild(50331648, "filePath", outputFileName);
      } 
    } catch (Exception ex) {
      LogHandler.logException(this.loggerName, "Exception occured in writing to PDF", ex);
      env.getRootElement().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "responseHeader", "");
      env.getRootElement().getFirstChild().getFirstChild().getFirstChild().createElementAsFirstChild(50331648, "responseCode", "01");
    } 
    out.propagate(inAssembly);
  }
  
  private void removeBorders(Cell cell, boolean top, boolean bottom, boolean left, boolean right) {
    DashedBorder dashedBorder = new DashedBorder(ColorConstants.WHITE, 3.0F);
    if (bottom)
      cell.setBorderBottom((Border)dashedBorder); 
    if (right)
      cell.setBorderRight((Border)dashedBorder); 
    if (left)
      cell.setBorderLeft((Border)dashedBorder); 
    if (top)
      cell.setBorderTop((Border)dashedBorder); 
  }
}
