package com.systemsltd.common.util;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import javax.jms.Destination;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.QueueBrowser;
import javax.jms.QueueConnection;
import javax.jms.QueueConnectionFactory;
import javax.jms.QueueSession;
import javax.jms.TextMessage;
import javax.sql.DataSource;
import oracle.AQ.AQQueueTable;
import oracle.AQ.AQQueueTableProperty;
import oracle.jdbc.pool.OracleDataSource;
import oracle.jms.AQjmsDestinationProperty;
import oracle.jms.AQjmsFactory;
import oracle.jms.AQjmsSession;

public class OracleAQClient {
  public static QueueConnection getConnection(String jdbcURL, String userName, String password) {
    QueueConnectionFactory QFac = null;
    QueueConnection QCon = null;
    try {
      OracleDataSource dataSource = new OracleDataSource();
      dataSource.setUser(userName);
      dataSource.setPassword(password);
      dataSource.setURL(jdbcURL);
      QFac = AQjmsFactory.getQueueConnectionFactory((DataSource)dataSource);
      QCon = QFac.createQueueConnection(userName, password);
    } catch (Exception e) {
      e.printStackTrace();
    } 
    return QCon;
  }
  
  public static List<String> consumeMessages(String user, String queueName, String jdbcURL, String userName, String password) throws Exception {
    List<String> messages = new ArrayList<>();
    try {
      QueueConnection QCon = getConnection(jdbcURL, userName, password);
      QueueSession queueSession = QCon.createQueueSession(false, 2);
      QCon.start();
      Queue queue = ((AQjmsSession)queueSession).getQueue(user, queueName);
      QueueBrowser browser = queueSession.createBrowser(queue);
      MessageConsumer consumer = queueSession.createConsumer((Destination)queue);
      Enumeration enu = browser.getEnumeration();
      while (enu.hasMoreElements()) {
        TextMessage msg = (TextMessage)consumer.receive();
        messages.add(msg.getText());
        msg.acknowledge();
        enu.nextElement();
      } 
      browser.close();
      consumer.close();
      queueSession.close();
      QCon.close();
    } catch (JMSException e) {
      throw new Exception(e);
    } 
    return messages;
  }
  
  public static void createQueue(String user, String qTable, String queueName) {
    try {
      System.out.println("Creating Queue Table...");
      QueueConnection QCon = getConnection("jdbc:oracle:thin:@10.224.110.185:1521/dbbah", "CBS", "CBSBAH");
      QueueSession queueSession = QCon.createQueueSession(false, 2);
      AQQueueTable q_table = null;
      Queue queue = null;
      AQQueueTableProperty qt_prop = new AQQueueTableProperty("SYS.AQ$_JMS_TEXT_MESSAGE");
      q_table = ((AQjmsSession)queueSession).createQueueTable(user, qTable, qt_prop);
      System.out.println("Qtable created");
      AQjmsDestinationProperty dest_prop = new AQjmsDestinationProperty();
      queue = ((AQjmsSession)queueSession).createQueue(q_table, queueName, dest_prop);
      System.out.println("Queue created");
    } catch (Exception e) {
      e.printStackTrace();
      return;
    } 
  }
  
  public static void sendMessage(String user, String queueName, String message) {
    try {
      QueueConnection QCon = getConnection("jdbc:oracle:thin:@10.224.110.185:1521/dbqat", "cbs", "cbsqat");
      QueueSession queueSession = QCon.createQueueSession(false, 1);
      QCon.start();
      Queue queue = ((AQjmsSession)queueSession).getQueue(user, queueName);
      MessageProducer producer = queueSession.createProducer((Destination)queue);
      TextMessage tMsg = queueSession.createTextMessage(message);
      producer.send((Message)tMsg);
      System.out.println("Sent message = " + tMsg.getText());
      queueSession.close();
      producer.close();
      QCon.close();
    } catch (JMSException e) {
      e.printStackTrace();
      return;
    } 
  }
  
  public static void browseMessage(String user, String queueName) {
    try {
      QueueConnection QCon = getConnection("jdbc:oracle:thin:@10.224.110.185:1521/dbqat", "cbssoa", "cbssoa");
      QueueSession queueSession = QCon.createQueueSession(false, 2);
      QCon.start();
      Queue queue = ((AQjmsSession)queueSession).getQueue(user, queueName);
      QueueBrowser browser = queueSession.createBrowser(queue);
      Enumeration<TextMessage> enu = browser.getEnumeration();
      List<String> list = new ArrayList();
      while (enu.hasMoreElements()) {
        TextMessage message = enu.nextElement();
        list.add(message.getText());
      } 
      for (int i = 0; i < list.size(); i++)
        System.out.println("Browsed msg " + list.get(i)); 
      browser.close();
      queueSession.close();
      QCon.close();
    } catch (JMSException e) {
      e.printStackTrace();
    } 
  }
  
  public static void consumeMessage(String user, String queueName) {
    try {
      QueueConnection QCon = getConnection("jdbc:oracle:thin:@10.224.110.185:1521/dbbah", "CBS", "CBSBAH");
      QueueSession queueSession = QCon.createQueueSession(false, 2);
      QCon.start();
      Queue queue = ((AQjmsSession)queueSession).getQueue(user, queueName);
      MessageConsumer consumer = queueSession.createConsumer((Destination)queue);
      TextMessage msg = (TextMessage)consumer.receive();
      System.out.println("MESSAGE RECEIVED " + msg.getText());
      consumer.close();
      queueSession.close();
      QCon.close();
    } catch (JMSException e) {
      e.printStackTrace();
    } 
  }
  
  public static void main(String[] args) {
    String userName = "CBS";
    String queue = "JMS_TEZ_QUE_IIB";
    browseMessage(userName, queue);
  }
}
