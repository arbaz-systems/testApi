package com.systemsltd.ubl.statementgenerator.pdfgenerator;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.json.JSONArray;
import org.json.JSONObject;

import com.itextpdf.io.font.constants.StandardFonts;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.colors.WebColors;
import com.itextpdf.kernel.events.Event;
import com.itextpdf.kernel.events.IEventHandler;
import com.itextpdf.kernel.events.PdfDocumentEvent;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.PageSize;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfPage;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.borders.Border;
import com.itextpdf.layout.borders.SolidBorder;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.IBlockElement;
import com.itextpdf.layout.element.Image;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.property.TextAlignment;
import com.systemsltd.common.CommonMethods;
import com.systemsltd.ubl.statementgenerator.dto.AccountStatementDto;
//import static com.systemsltd.logging.LogHandler.logException;

public class CBSPDFGenerator extends PDFGeneratorBase {
	
	protected PdfFormXObject template;

	@SuppressWarnings("resource")
	@Override
	public AccountStatementDto generatePDF(AccountStatementDto dto) throws Exception {
	
		JSONObject obj = new JSONObject(dto.getStatementResponse());
		
		try {
			  if (obj.has("accountStatementInquiryResponse") && obj.getJSONObject("accountStatementInquiryResponse").has("statementItemList")) {
				    JSONArray arrStatementList = obj.getJSONObject("accountStatementInquiryResponse").getJSONArray("statementItemList");
				    JSONObject accountDetail = null;
				    if (obj.getJSONObject("accountStatementInquiryResponse").has("accountDetail")) {
				     accountDetail = obj.getJSONObject("accountStatementInquiryResponse").getJSONObject("accountDetail");
				    }
				    String fromDate = accountDetail.getString("fromDate");
//				    if (accountDetail.has("accountAttributeList")) {
//				    	fromDate = accountDetail.getJSONArray("accountAttributeList").getJSONObject(0).getString("attributeValue");
//				    }
//				    else if (accountDetail.has("fromDate")) {
//					    fromDate = accountDetail.getString("fromDate");
//					 }

				    String toDate = accountDetail.getString("toDate");
//				    if (accountDetail.has("accountAttributeList")) {
//				    	toDate = accountDetail.getJSONArray("accountAttributeList").getJSONObject(1).getString("attributeValue");
//				    }
//				    else if (accountDetail.has("toDate")) {
//					    toDate = accountDetail.getString("toDate");
//					}

//				    filePath = readFromCache("ConfigCache", "FILE_PATH");
//				    String filePath = "D:\\IIBDevlepment\\UBL\\vm\\";
				    String filePath = dto.getResourcesPath() + "pdfs/";
//				    logInfo("", "Writing PDF file to path: " + filePath);
				    String fileName = new SimpleDateFormat("ddMMyyyyHHmmssSSS").format(new Date()) + ".pdf";
				    String outputFileName = filePath + fileName;
				    
				    dto.setGeneratedPdfFileName(fileName);
				    dto.setGeneratedPdfFilePath(outputFileName);
				    
				    // Creating a PdfWriter       
				    PdfWriter writer = new PdfWriter(outputFileName); 
				    
			       //Creating a PdfDocument       
				    PdfDocument pdfDocument = new PdfDocument(writer);              
				   
				    Document doc = new Document(pdfDocument);
				    
				    template = new PdfFormXObject(new Rectangle(553, 735, 30, 30));
				    
				    
				    Canvas canvas = new Canvas(template, pdfDocument);
			        
			        doc.setMargins(100, 0, 100, 0);
				    
				    float [] headerTableColumnWidth = {300F, 400F};
			        Table headerTable = new Table(headerTableColumnWidth);
			        DeviceRgb myColor = WebColors.getRGBColor("#007dc5");
			        headerTable.setBackgroundColor(myColor);
			        
			        Cell logoCell = new Cell();
			        logoCell.add(new Paragraph());
			        logoCell.setHeight(76);
			        logoCell.setBorder(Border.NO_BORDER);
				    String imagesPath = dto.getResourcesPath()+"images/";
				    try {
				    	String imageURL = imagesPath+"ubl-logo.PNG";
					    ImageData data = ImageDataFactory.create(imageURL);
//					    logInfo("", "Writing image: " + imageURL + "to pdf" + outputFileName);
				        Image image = new Image(data);
				        image.setWidth(110);image.setHeight(66);
				        image.setMarginTop(5);image.setMarginLeft(9);
				        logoCell.add(image);
				    } catch (Exception ex) {
//				   		logException(getLoggerName(), "Image not found", ex);
				    }
			        headerTable.addCell(logoCell);
			        
			        Cell headerRightCell = new Cell();
			        headerRightCell.add(new Paragraph());
			        headerRightCell.setHeight(76);
			        headerRightCell.setBorder(Border.NO_BORDER);
			        
			        Paragraph p1 = new Paragraph("Account Statement");
			        p1.setPaddingTop(25);
			        p1.setPaddingRight(30);
				    p1.setFontSize(15);
				    p1.setFontColor(ColorConstants.WHITE);
			        p1.setTextAlignment(TextAlignment.RIGHT);
				    headerRightCell.add(p1);
				    
				    Paragraph p2 = new Paragraph("Printed on "+new SimpleDateFormat("MMMM dd, yyyy").format(new Date()));
//				    p2.setPaddingTop(35);
				    p2.setPaddingRight(30);
				    p2.setFontSize(8);
				    p2.setFontColor(ColorConstants.WHITE);
				    p2.setTextAlignment(TextAlignment.RIGHT);
				    headerRightCell.add(p2);
				    
			        headerTable.addCell(headerRightCell);
			        
			        headerTable.setBorder(Border.NO_BORDER);
			        
//			        doc.add(headerTable);
			        PdfFont helvetica = PdfFontFactory.createFont(StandardFonts.HELVETICA);
			        PdfFont helveticaBold = PdfFontFactory.createFont(StandardFonts.HELVETICA_BOLD);
			        PdfFont zapFdingBats = PdfFontFactory.createFont(StandardFonts.ZAPFDINGBATS);
			        
			        
			        Table headerTable2 = new Table(new float[] {325F, 70F, 70F, 10F, 115F, 10F, 90F});
			        DeviceRgb header2Color = WebColors.getRGBColor("#e6e7e9");
			        headerTable2.setBackgroundColor(header2Color);
			        headerTable2.setHeight(22);
			        
			        headerTable2.addCell(new Cell().setBorder(Border.NO_BORDER));
			        
			        headerTable2.addCell(new Cell().add(new Paragraph("Account Number: ")).setBorder(Border.NO_BORDER)
			        		.setFontSize(7).setPaddingTop(5).setPaddingLeft(8).setFont(helvetica)
			        		.setTextAlignment(TextAlignment.JUSTIFIED));
			        
			        String accountNumber = accountDetail.getJSONObject("accountIdentifier").getString("accountNumber");
//			        String fromDate = accountDetail.getString("fromDate");
//				    String toDate = accountDetail.getString("toDate");
			        String lst_acct = accountNumber.substring(accountNumber.length()-6);
                    String account_num = accountNumber .substring(0,5)+ lst_acct.substring(0, 0) + "****" +lst_acct.substring(4,6);
                    headerTable2.addCell((Cell)((Cell)((Cell)((Cell)((Cell)((Cell)(new Cell()).add((IBlockElement)new Paragraph(account_num)).setBorder(Border.NO_BORDER))
                            .setFontSize(7.0F)).setPaddingTop(5.0F)).setPaddingLeft(-1.0F)).setFont(helveticaBold))
                            .setTextAlignment(TextAlignment.JUSTIFIED));
			       /* headerTable2.addCell(new Cell().add(new Paragraph(accountNumber)).setBorder(Border.NO_BORDER)
			        		.setFontSize(7).setPaddingTop(5).setPaddingLeft(-1).setFont(helveticaBold)
			        		.setTextAlignment(TextAlignment.JUSTIFIED));*/
			        
			        Paragraph bullet = new Paragraph(String.valueOf((char)110)).setFont(zapFdingBats).setFontSize(5)
			        		.setPaddingTop(5);
			        
			        Paragraph dateRange = new Paragraph(fromDate+" - "+toDate).setFont(helvetica).setFontSize(7)
			        		.setPaddingTop(5);

			        
			        headerTable2.addCell(new Cell().add(bullet).setBorder(Border.NO_BORDER));
			        
			        headerTable2.addCell(new Cell().add(dateRange).setBorder(Border.NO_BORDER));
			        
			        
			        headerTable2.addCell(new Cell().add(bullet).setBorder(Border.NO_BORDER));
			        headerTable2.addCell(new Cell().add(new Paragraph("")).setBorder(Border.NO_BORDER)
			        		.setFont(helvetica).setFontSize(7).setPaddingTop(5));
			        
//			        doc.add(headerTable2);
			        
			        Table footerTable = new Table(new float[] {50F, 50F, 50F, 50F, 50F, 50F, 50F, 50F, 50F, 50F, 200F});
			        footerTable.setBackgroundColor(header2Color).setHeight(76);
			        
			        try {
				    	String imageURL = imagesPath+"fb.png";
					    ImageData data = ImageDataFactory.create(imageURL);
				        Image image = new Image(data);
				        image.setWidth(15);image.setHeight(15);
				        
				        footerTable.addCell(new Cell().add(image).setPaddingLeft(30).setPaddingTop(40).setBorder(Border.NO_BORDER));
				        footerTable.addCell(new Cell().add(
				        		new Paragraph("UBLUnitedBankLtd").setFont(helvetica).setFontSize(7)
				        		.setPaddingTop(41).setPaddingLeft(-5)
				        		).setBorder(Border.NO_BORDER));
				        
				        imageURL = imagesPath+"twitter.png";
					    data = ImageDataFactory.create(imageURL);
				        image = new Image(data);
				        image.setWidth(15);image.setHeight(15);
				        
				        footerTable.addCell(new Cell().add(image).setPaddingTop(40).setPaddingLeft(12).setBorder(Border.NO_BORDER));
				        footerTable.addCell(new Cell().add(
				        		new Paragraph("ubldigital").setFont(helvetica).setFontSize(7)
				        		.setPaddingTop(41).setPaddingLeft(-19)
				        		).setBorder(Border.NO_BORDER));
				        
				        imageURL = imagesPath+"insta.png";
					    data = ImageDataFactory.create(imageURL);
				        image = new Image(data);
				        image.setWidth(15);image.setHeight(15);
				        
				        footerTable.addCell(new Cell().add(image).setPaddingTop(40).setPaddingLeft(-12).setBorder(Border.NO_BORDER));
				        footerTable.addCell(new Cell().add(
				        		new Paragraph("ubldigital").setFont(helvetica).setFontSize(7)
				        		.setPaddingTop(41).setPaddingLeft(-35)
				        		).setBorder(Border.NO_BORDER));
				        
				        imageURL = imagesPath+"linkedin.png";
					    data = ImageDataFactory.create(imageURL);
				        image = new Image(data);
				        image.setWidth(12);image.setHeight(12);
				        
				        footerTable.addCell(new Cell().add(image).setPaddingTop(42).setPaddingLeft(-25).setBorder(Border.NO_BORDER));
				        footerTable.addCell(new Cell().add(
				        		new Paragraph("United-Bank-Limited").setFont(helvetica).setFontSize(7)
				        		.setPaddingTop(41).setPaddingLeft(-47)
				        		).setBorder(Border.NO_BORDER));
				        
				        
				        imageURL = imagesPath+"youtube.png";
					    data = ImageDataFactory.create(imageURL);
				        image = new Image(data);
				        image.setWidth(12);image.setHeight(12);
				        
				        footerTable.addCell(new Cell().add(image).setPaddingTop(42).setPaddingLeft(-5).setBorder(Border.NO_BORDER));
				        footerTable.addCell(new Cell().add(
				        		new Paragraph("ubldigital").setFont(helvetica).setFontSize(7)
				        		.setPaddingTop(41).setPaddingLeft(-34)
				        		).setBorder(Border.NO_BORDER));
				        
				        footerTable.addCell(new Cell().setBorder(Border.NO_BORDER));
				        
				        
				    } catch (Exception ex) {
//				   		logException(getLoggerName(), "Image not found", ex);
				    }
			        
			        
			        pdfDocument.addEventHandler(PdfDocumentEvent.END_PAGE, new HeaderEventHandler(headerTable, headerTable2, footerTable, helvetica));
			        
				    
			        doc.add(new Paragraph("\n"));
			        if (accountDetail.has("accountTitle")) {
			        	doc.add(new Paragraph(accountDetail.getString("accountTitle"))
				        .setPaddingLeft(30).setFont(helveticaBold).setTextAlignment(TextAlignment.JUSTIFIED)
				        .setFontSize(10));
			        }
			        
			        //Account Detail tables
			        float [] accountDetailColumnWidth = {470F, 230F};
			        Table accountDetailTable = new Table(accountDetailColumnWidth);
			        accountDetailTable.setBorder(Border.NO_BORDER);
			        
			        //Account Details Left table start
			        float [] pointColumnWidth = {150F, 50F};
			        Table topTableLeft = new Table(pointColumnWidth);
			        topTableLeft.setMarginLeft(26);
			        topTableLeft.setBorder(Border.NO_BORDER);

			        //row 1
			        if (accountDetail.has("accountAddress")) {
				        topTableLeft.addCell(new Cell().add(new Paragraph(accountDetail.getString("accountAddress"))).setBorder(Border.NO_BORDER)
				        		.setFont(helvetica).setTextAlignment(TextAlignment.LEFT).setFontSize(10));
			        } else {
			        	topTableLeft.addCell(new Cell().setBorder(Border.NO_BORDER));
			        }
			        topTableLeft.addCell(new Cell().setBorder(Border.NO_BORDER));
			        
			        //Account Details Left table end
			        
			        //Account Details Left table start
			        float [] pointColumnWidthRight = {150F, 50F};
			        Table topTableRight = new Table(pointColumnWidthRight);
			        topTableRight.setBorder(Border.NO_BORDER);
			        topTableRight.setMarginRight(30);
			        
//			        row 1
			        topTableRight.addCell(new Cell().add(new Paragraph("Balance: ")).setFont(helvetica).setBorder(Border.NO_BORDER)
			        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingTop(-10));
			        
			        if (accountDetail.has("accountBalance")) {
				        topTableRight.addCell(new Cell().add(new Paragraph(addOrRemoveNegativeSign(accountDetail.getString("accountBalance")))).setBorder(Border.NO_BORDER)
				        		.setFont(helveticaBold)
				        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingLeft(-88).setPaddingTop(-10));
			        } else {
			        	topTableRight.addCell(new Cell().add(new Paragraph("")).setBorder(Border.NO_BORDER));
			        }
			       
//			        row 2
			        topTableRight.addCell(new Cell().add(new Paragraph("As of: ")).setBorder(Border.NO_BORDER).setFont(helvetica)
			        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingTop(1));
			        
			        if (accountDetail.has("asOf")) {
				        String asOf = accountDetail.getString("asOf");
				        asOf = CommonMethods.stringDateToString(asOf, "dd-MMM-yy", "dd MMMM, yyyy");
				        
				        topTableRight.addCell(new Cell().add(new Paragraph(asOf)).setBorder(Border.NO_BORDER).setFont(helveticaBold)
				        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingLeft(-100).setPaddingTop(1));
			        } else {
			        	topTableRight.addCell(new Cell().add(new Paragraph("")).setBorder(Border.NO_BORDER));
			        }
//			        row 3
			        topTableRight.addCell(new Cell().add(new Paragraph("Account type: ")).setBorder(Border.NO_BORDER).setFont(helvetica)
			        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingTop(0));
			        
			        if (accountDetail.has("productType")) {
			        	topTableRight.addCell(new Cell().add(new Paragraph(accountDetail.getString("productType"))).setBorder(Border.NO_BORDER)
			        			.setFont(helveticaBold)
				        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingLeft(-70).setPaddingTop(0));
			        } else {
			        	topTableRight.addCell(new Cell().add(new Paragraph("")).setBorder(Border.NO_BORDER));
			        }
			        
//			        row 4
			        topTableRight.addCell(new Cell().add(new Paragraph("Currency: ")).setBorder(Border.NO_BORDER).setFont(helvetica)
			        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingTop(0));
			        
			        if (accountDetail.has("accountCurrency")) {
			        	topTableRight.addCell(new Cell().add(new Paragraph(accountDetail.getString("accountCurrency"))).setBorder(Border.NO_BORDER)
			        			.setFont(helveticaBold)
				        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingLeft(-85).setPaddingTop(0));
			        }
			        else {
			        	topTableRight.addCell(new Cell().add(new Paragraph("")).setBorder(Border.NO_BORDER));
			        }
			        
//			        row 5
			        topTableRight.addCell(new Cell().add(new Paragraph("Reg. Cell No: ")).setBorder(Border.NO_BORDER).setFont(helvetica)
			        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingTop(10));
			        
			        if (accountDetail.has("cellNumber")) {
				        topTableRight.addCell(new Cell().add(new Paragraph(accountDetail.getString("cellNumber"))).setBorder(Border.NO_BORDER)
				        		.setFont(helveticaBold)
				        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingLeft(-70).setPaddingTop(10));
			        } else {
			        	topTableRight.addCell(new Cell().add(new Paragraph("")).setBorder(Border.NO_BORDER));
			        }
//			        row 6
			        topTableRight.addCell(new Cell().add(new Paragraph("IBAN No: ")).setFont(helvetica).setBorder(Border.NO_BORDER)
			        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingTop(0));
			        
			        if (accountDetail.has("iban")) {
			        	String iban = accountDetail.getString("iban");
			            topTableRight.addCell((Cell)((Cell)((Cell)((Cell)((Cell)((Cell)(new Cell()).add((IBlockElement)new Paragraph(iban.substring(0, 9) + "**" + iban.substring(12, 18) + "****" + iban.substring(22, 24))).setBorder(Border.NO_BORDER))
			                .setFont(helveticaBold))
			                .setTextAlignment(TextAlignment.LEFT)).setFontSize(8.0F)).setPaddingLeft(-85.0F)).setPaddingTop(0.0F));
				        /*topTableRight.addCell(new Cell().add(new Paragraph(accountDetail.getString("iban"))).setBorder(Border.NO_BORDER)
				        		.setFont(helveticaBold)
				        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingLeft(-85).setPaddingTop(0));*/
			        } else {
			        	topTableRight.addCell(new Cell().add(new Paragraph("")).setBorder(Border.NO_BORDER));
			        }
//			        row 7
			        /*topTableRight.addCell(new Cell().add(new Paragraph("CIF: ")).setBorder(Border.NO_BORDER).setFont(helvetica)
			        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingTop(0));*/
			        
			        if (accountDetail.has("cif")) {
				        /*topTableRight.addCell(new Cell().add(new Paragraph(accountDetail.getString("cif"))).setBorder(Border.NO_BORDER)
				        		.setFont(helveticaBold)
				        		.setTextAlignment(TextAlignment.LEFT).setPaddingLeft(-102).setFontSize(8).setPaddingTop(0));*/
			        } else {
			        	topTableRight.addCell(new Cell().add(new Paragraph("")).setBorder(Border.NO_BORDER));
			        }
//			        row 8
			        topTableRight.addCell(new Cell().add(new Paragraph("Branch: ")).setBorder(Border.NO_BORDER).setFont(helvetica)
			        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingTop(0));
			        
			        if (accountDetail.has("branchName")) {
				        topTableRight.addCell(new Cell().add(new Paragraph(accountDetail.getString("branchName"))).setBorder(Border.NO_BORDER)
				        		.setFont(helveticaBold)
				        		.setTextAlignment(TextAlignment.LEFT).setPaddingLeft(-90).setFontSize(8).setPaddingTop(0));
			        } else {
			        	topTableRight.addCell(new Cell().add(new Paragraph("")).setBorder(Border.NO_BORDER));
			        }
			        
//			        row 9
			        topTableRight.addCell(new Cell().add(new Paragraph("Branch Code: ")).setBorder(Border.NO_BORDER).setFont(helvetica)
			        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingTop(0));
			        
			        if (accountDetail.has("branchCode")) {
				        topTableRight.addCell(new Cell().add(new Paragraph(accountDetail.getString("branchCode"))).setBorder(Border.NO_BORDER)
				        		.setFont(helveticaBold)
				        		.setTextAlignment(TextAlignment.LEFT).setFontSize(8).setPaddingLeft(-70).setPaddingTop(0));
			        } else {
			        	topTableRight.addCell(new Cell().add(new Paragraph("")).setBorder(Border.NO_BORDER));
			        }
			        
			        accountDetailTable.addCell(new Cell().add(topTableLeft).setBorder(Border.NO_BORDER));
			        accountDetailTable.addCell(new Cell().add(topTableRight).setBorder(Border.NO_BORDER));
			        
			        doc.add(accountDetailTable);
			        
			        // accountDetailTable end

			        doc.add(new Paragraph("\n"));

			        doc.add(new Paragraph("Activity Summary")
			        .setPaddingLeft(30).setFont(helveticaBold).setTextAlignment(TextAlignment.JUSTIFIED)
			        .setFontSize(13));
			        //Statement table
			        float [] pointColumnWidths = {80F, 200F, 100F, 80F, 80F, 80F};
			        Table statementTable = new Table(pointColumnWidths);
			        statementTable.setMarginLeft(30).setMarginRight(30).setMarginBottom(60);

			        //Adding cell headings
			        statementTable.addCell(new Cell().add(new Paragraph("DATE")).setFont(helveticaBold).setFontSize(10)
			        		.setBorderTop(new SolidBorder(new Float(1)))
			        		.setBorderLeft(Border.NO_BORDER)
			        		.setBorderRight(Border.NO_BORDER));
			        
			        statementTable.addCell(new Cell().add(new Paragraph("PARTICULARS")).setFont(helveticaBold).setFontSize(10)
			        		.setBorderTop(new SolidBorder(new Float(1)))
			        		.setBorderLeft(Border.NO_BORDER)
			        		.setBorderRight(Border.NO_BORDER));
			        
			        statementTable.addCell(new Cell().add(new Paragraph("INST. NO.")).setFont(helveticaBold).setFontSize(10)
			        		.setBorderTop(new SolidBorder(new Float(1)))
			        		.setBorderLeft(Border.NO_BORDER)
			        		.setBorderRight(Border.NO_BORDER));
			        
			        statementTable.addCell(new Cell().add(new Paragraph("DEBIT")).setFont(helveticaBold).setFontSize(10)
			        		.setBorderTop(new SolidBorder(new Float(1)))
			        		.setBorderLeft(Border.NO_BORDER)
			        		.setBorderRight(Border.NO_BORDER));
			        
			        statementTable.addCell(new Cell().add(new Paragraph("CREDIT")).setFont(helveticaBold).setFontSize(10)
			        		.setBorderTop(new SolidBorder(new Float(1)))
			        		.setBorderLeft(Border.NO_BORDER)
			        		.setBorderRight(Border.NO_BORDER));
			        
			        statementTable.addCell(new Cell().add(new Paragraph("BALANCE")).setFont(helveticaBold).setFontSize(10)
			        		.setBorderTop(new SolidBorder(new Float(1)))
			        		.setBorderLeft(Border.NO_BORDER)
			        		.setBorderRight(Border.NO_BORDER));
			        
			        
			        //opening balance line
			        fromDate = CommonMethods.stringDateToString(fromDate, "dd-MMM-yy", "dd-MMM-yyyy");
			        statementTable.addCell(new Cell().add(new Paragraph(fromDate)).setFont(helvetica).setFontSize(8)
			        		.setBorder(Border.NO_BORDER).setPaddingTop(10).setPaddingBottom(10));
			        
			        statementTable.addCell(new Cell().add(new Paragraph("** Opening Balance")).setFont(helvetica).setFontSize(8)
			        		.setBorder(Border.NO_BORDER).setPaddingTop(10).setPaddingBottom(10));
			        
			        statementTable.addCell(new Cell().setBorder(Border.NO_BORDER).setPaddingTop(10).setPaddingBottom(10));
			        statementTable.addCell(new Cell().setBorder(Border.NO_BORDER).setPaddingTop(10).setPaddingBottom(10));
			        statementTable.addCell(new Cell().setBorder(Border.NO_BORDER).setPaddingTop(10).setPaddingBottom(10));
			        
			        if (accountDetail.has("openingBalance")) {
			        	String openingBalance = accountDetail.getString("openingBalance");
			        	openingBalance = addOrRemoveNegativeSign(openingBalance);
			        	statementTable.addCell(new Cell().add(new Paragraph(openingBalance)).setFont(helvetica).setFontSize(8)
				        		.setBorder(Border.NO_BORDER).setPaddingTop(10).setPaddingBottom(10));
	            	} else {
	            		 statementTable.addCell(new Cell().setBorder(Border.NO_BORDER).setPaddingTop(10).setPaddingBottom(10));
	            	}
			        
			        
			        for (int i = 0; i < arrStatementList.length(); i++) {
		            	JSONObject payment = arrStatementList.getJSONObject(i);
		            	String transactionDate = "", particulars = "", instNo = "", transactionAmount = "", 
		            			crDr = "", remainingBalance = "";
		            	
		            	if (payment.has("transactionDate")) {
		            		transactionDate = payment.getString("transactionDate");
		            		transactionDate = CommonMethods.stringDateToString(transactionDate, "dd-MMM-yy", "dd-MMM-yyyy");
		            	}
		            	
		            	if (payment.has("particulars")) {
		            		particulars = payment.getString("particulars");
		            	}
		            	
		            	if (payment.has("instNo")) {
		            		instNo = payment.getString("instNo");
		            	}
		            	
		            	if (payment.has("transactionAmount")) {
		            		transactionAmount = payment.getString("transactionAmount");
		            	}
		            	
		            	if (payment.has("crDr")) {
		            		crDr = payment.getString("crDr");
		            	}
		            	
		            	if (payment.has("runBal")) {
		            		remainingBalance = addOrRemoveNegativeSign(payment.getString("runBal"));
		            	}
		            	
		            	DeviceRgb rowBackground = WebColors.getRGBColor("#ffffff");
		            	if ((i+1)%2 == 1) {
		            		rowBackground = WebColors.getRGBColor("#e6e7e9");
		            	}
		            	
		            	//Adding cells to the table
		            	statementTable.addCell(new Cell().add(new Paragraph(transactionDate)).setFont(helvetica).setFontSize(8)
					        		.setBorder(Border.NO_BORDER).setBackgroundColor(rowBackground)
					        		.setPaddingTop(10).setPaddingBottom(10));
		            	
		            	statementTable.addCell(new Cell().add(new Paragraph(particulars)).setFont(helvetica).setFontSize(8)
				        		.setPaddingRight(30).setBorder(Border.NO_BORDER).setBackgroundColor(rowBackground)
				        		.setPaddingTop(10).setPaddingBottom(10));

		            	statementTable.addCell(new Cell().add(new Paragraph(instNo)).setFont(helvetica).setFontSize(8)
				        		.setBorder(Border.NO_BORDER).setBackgroundColor(rowBackground)
				        		.setPaddingTop(10).setPaddingBottom(10));
		            	
		            	
		            	Cell debitValue = new Cell().add(new Paragraph("")).setFont(helvetica).setFontSize(8)
		        		.setBorder(Border.NO_BORDER).setBackgroundColor(rowBackground);
		            	
		            	Cell creditValue = new Cell().add(new Paragraph("")).setFont(helvetica).setFontSize(8)
				        		.setBorder(Border.NO_BORDER).setBackgroundColor(rowBackground);
		            	
		            	if (crDr.equals("D")) {
		            		debitValue.add(new Paragraph(transactionAmount).setPaddingTop(10).setPaddingBottom(10));
		            	} else if (crDr.equals("C")) {
		            		creditValue.add(new Paragraph(transactionAmount).setPaddingTop(10).setPaddingBottom(10));
		            	}
		            	
		            	statementTable.addCell(debitValue);
		            	statementTable.addCell(creditValue);
		            	
		            	statementTable.addCell(new Cell().add(new Paragraph(remainingBalance)).setFont(helvetica).setFontSize(8)
				        		.setBorder(Border.NO_BORDER).setBackgroundColor(rowBackground)
				        		.setPaddingTop(10).setPaddingBottom(10));
			             		            
			        }
			        // Adding Statement Table to document
			        doc.add(statementTable);
			        
			        canvas.add(new Paragraph(String.valueOf(pdfDocument.getNumberOfPages()))
			        		.setFont(helvetica).setFontSize(7)).close();
			        
			        doc.close(); 
		  } 
		  }
		  catch (Exception ex) {
//			  logException(getLoggerName(), "Exception occured in writing to PDF", ex);
			  throw new Exception(ex);
		   }
		return dto;
	}
	
	private class HeaderEventHandler implements IEventHandler {
        protected Table headerTable1;
        protected Table headerTable2, footerTable;
        protected PdfFont helveticaFont;

        public HeaderEventHandler(Table headerTable1, Table headerTable2, Table footerTable, PdfFont helveticaFont) {
            this.headerTable1 = headerTable1;
            this.headerTable2 = headerTable2;
            this.footerTable = footerTable;
            this.helveticaFont = helveticaFont;
        }

        @SuppressWarnings("resource")
		@Override
        public void handleEvent(Event currentEvent) {
            PdfDocumentEvent docEvent = (PdfDocumentEvent) currentEvent;
            PdfDocument pdfDoc = docEvent.getDocument();
            PdfPage page = docEvent.getPage();
            int pageNum = pdfDoc.getPageNumber(page);
            
            PdfCanvas canvas = new PdfCanvas(page.newContentStreamBefore(), page.getResources(), pdfDoc);
            PageSize pageSize = pdfDoc.getDefaultPageSize();
//            float coordX = pageSize.getX() + doc.getLeftMargin();
//            System.out.println("pageSize.getX() " + pageSize.getX() + " doc.getLeftMargin() "+ doc.getLeftMargin());
//            float coordY = pageSize.getTop() - doc.getTopMargin();
            
            float coordX = 0;
            float coordY = 766;
            float width = pageSize.getWidth();
            float height = 76;
            Rectangle rect = new Rectangle(coordX, coordY, width, height);

            new Canvas(canvas, rect).add(headerTable1).close();
            
            coordX = 0;
            coordY = 745;
            width = pageSize.getWidth();
            height = 22;
            rect = new Rectangle(coordX, coordY, width, height);
            
			new Canvas(page, rect).add(headerTable2).close();
			
			coordX = 0;
            coordY = 0;
            width = pageSize.getWidth();
            height = 76;
            rect = new Rectangle(coordX, coordY, width, height);
            
			new Canvas(page, rect).add(footerTable).close();
			
			coordX = 0;
            coordY = 0;
            width = 210;
            height = 76;
            rect = new Rectangle(coordX, coordY, width, height);
            
			new Canvas(page, rect).add(
					new Paragraph("For latest schedule of charges, kindly visit your branch or UBL website www.ubldigital.com")
					.setFont(helveticaFont).setFontSize(7)
					.setPaddingLeft(30).setPaddingTop(10)).close();
			
			coordX = 480;
            coordY = 0;
            width = 100;
            height = 76;
            rect = new Rectangle(coordX, coordY, width, height);
            
            new Canvas(page, rect).add(
					new Paragraph("www.ubldigital.com 111-825-888")
					.setFont(helveticaFont).setFontSize(7).setTextAlignment(TextAlignment.RIGHT)
					.setPaddingLeft(30).setPaddingTop(15)).close();
            
			
			PdfCanvas canvas1 = new PdfCanvas(page);

            // Creates header text content
			canvas1.beginText();
			canvas1.setFontAndSize(helveticaFont, 7);
			canvas1.beginMarkedContent(PdfName.Artifact);
			canvas1.moveText(520, 754);
			canvas1.showText(String.format("Page %d of", pageNum));
			canvas1.endText();
			canvas1.stroke();
			canvas1.addXObject(template, 0, 0);
			canvas1.endMarkedContent();
			canvas1.release();
        }
    }
}
