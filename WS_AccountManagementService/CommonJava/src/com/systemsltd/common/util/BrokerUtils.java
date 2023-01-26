package com.systemsltd.common.util;

import com.ibm.broker.config.proxy.BrokerProxy;
//import com.ibm.broker.config.proxy.ConfigurableService;
import com.systemsltd.common.ActionFailureException;
import java.util.Properties;

public class BrokerUtils {
  private static int PROXY_WAIT_COUNT = 10;
  
  public static BrokerProxy getBrokerProxy() {
    int tryCount = 0;
    BrokerProxy brokerProxy = null;
    try {
      brokerProxy = BrokerProxy.getLocalInstance();
      while (!brokerProxy.hasBeenPopulatedByBroker() && tryCount < PROXY_WAIT_COUNT) {
        tryCount++;
        Thread.sleep(1000L);
      } 
    } catch (Exception ex) {
      throw new ActionFailureException("Unable to load broker proxy", ex);
    } 
    return brokerProxy;
  }
  
/*  public static Properties getServiceProperties(String serviceType, String serviceName) {
    BrokerProxy brokerProxy = getBrokerProxy();
    try {
      ConfigurableService cs = brokerProxy.getConfigurableService(serviceType, serviceName);
      if (cs == null)
        throw new IllegalStateException("UserDefined configurable service ConfigProperties not found"); 
      return cs.getProperties();
    } catch (Exception ex) {
      throw new ActionFailureException("Unable to read broker configurable service properties", ex);
    } finally {
      brokerProxy.disconnect();
    } 
  }
  
  public static void updateServiceProperties(String serviceType, String serviceName, Properties props) {
    BrokerProxy brokerProxy = getBrokerProxy();
    try {
      ConfigurableService cs = brokerProxy.getConfigurableService(serviceType, serviceName);
      if (cs == null)
        throw new IllegalStateException("UserDefined configurable service ConfigProperties not found"); 
      cs.setProperties(props);
    } catch (Exception ex) {
      throw new ActionFailureException("Unable to read broker configurable service properties", ex);
    } finally {
      brokerProxy.disconnect();
    } 
  }
  
  public static String getServiceProperty(String serviceType, String serviceName, String propertyName) {
    Properties props = getServiceProperties(serviceType, serviceName);
    return props.getProperty(propertyName);
  }
  
  public static void updateServiceProperty(String serviceType, String serviceName, String propertyName, String propertyValue) {
    BrokerProxy brokerProxy = getBrokerProxy();
    try {
      ConfigurableService cs = brokerProxy.getConfigurableService(serviceType, serviceName);
      Properties props = cs.getProperties();
      props.setProperty(propertyName, propertyValue);
      cs.setProperties(props);
    } catch (Exception ex) {
      throw new ActionFailureException("Unable to update broker configurable service properties", ex);
    } finally {
      brokerProxy.disconnect();
    } 
  } */
}
