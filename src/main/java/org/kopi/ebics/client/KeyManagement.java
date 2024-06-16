/*
 * Copyright (c) 1990-2012 kopiLeft Development SARL, Bizerte, Tunisia
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * $Id$
 */

package org.kopi.ebics.client;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.kopi.ebics.certificate.KeyStoreManager;
import org.kopi.ebics.certificate.KeyUtil;
import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.interfaces.ContentFactory;
import org.kopi.ebics.io.ByteArrayContentFactory;
import org.kopi.ebics.session.EbicsSession;
import org.kopi.ebics.utils.Utils;
import org.kopi.ebics.xml.HIARequest;
import org.kopi.ebics.xml.HPBRequestElement;
import org.kopi.ebics.xml.HPBResponseOrderDataElement;
import org.kopi.ebics.xml.INIRequestElement;
import org.kopi.ebics.xml.KeyManagementResponseElement;
import org.kopi.ebics.xml.SPRRequestElement;
import org.kopi.ebics.xml.SPRResponseElement;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;


/**
 * Everything that has to do with key handling.
 * If you have a totally new account use <code>sendINI()</code> and <code>sendHIA()</code> to send you newly created keys to the bank.
 * Then wait until the bank activated your keys.
 * If you are migrating from FTAM. Just send HPB, your EBICS account should be usable without delay.
 *
 * @author Hachani
 *
 */
public class KeyManagement {

  /**
   * Constructs a new <code>KeyManagement</code> instance
   * with a given ebics session
   * @param session the ebics session
   */
  public KeyManagement(EbicsSession session) {
    this.session = session;
  }

  /**
   * Sends the user's signature key (A005) to the bank.
   * After successful operation the user is in state "initialized".
   * @throws EbicsException server generated error message
   * @throws IOException communication error
   */
  public void sendINI() throws EbicsException, IOException {
    INIRequestElement			request;
    KeyManagementResponseElement	response;
    HttpRequestSender			sender;
    int					httpCode;

    sender = new HttpRequestSender(session);
    request = new INIRequestElement(session);
    request.build();
    request.validate();
    session.getConfiguration().getTraceManager().trace(request);
    byte[] content = request.prettyPrint();
    System.out.println(new String(content));
    if (0==0) throw new RuntimeException();
    httpCode = sender.send(new ByteArrayContentFactory(content));
    Utils.checkHttpCode(httpCode);
    response = new KeyManagementResponseElement(sender.getResponseBody(), "INIResponse");
    response.build();
    session.getConfiguration().getTraceManager().trace(response);
    response.report();
  }

  /**
   * Sends the public part of the protocol keys to the bank.
   * @param orderId the order ID. Let it null to generate a random one.
   * @throws IOException communication error
   * @throws EbicsException server generated error message
   */
  public void sendHIA(String orderId) throws IOException, EbicsException {
    HIARequest request;
    KeyManagementResponseElement	response;
    HttpRequestSender			sender;
    int					httpCode;

    sender = new HttpRequestSender(session);
    request = new HIARequest(session, orderId);
    request.build();
    request.validate();
    session.getConfiguration().getTraceManager().trace(request);
    byte[] content = request.prettyPrint();
    System.out.println(new String(content));
    if (0==0) throw new RuntimeException();
    httpCode = sender.send(new ByteArrayContentFactory(content));
    Utils.checkHttpCode(httpCode);
    response = new KeyManagementResponseElement(sender.getResponseBody(), "HIAResponse");
    response.build();
    session.getConfiguration().getTraceManager().trace(response);
    response.report();
  }

  /**
   * Sends encryption and authentication keys to the bank.
   * This order is only allowed for a new user at the bank side that has been created by copying the A005 key.
   * The keys will be activated immediately after successful completion of the transfer.
   * @throws IOException communication error
   * @throws GeneralSecurityException data decryption error
   * @throws EbicsException server generated error message
   */
  public void sendHPB() throws IOException, GeneralSecurityException, EbicsException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, SAXException {
    HPBRequestElement			request;
    KeyManagementResponseElement	response;
    HttpRequestSender			sender;
    HPBResponseOrderDataElement		orderData;
    ContentFactory			factory;
    KeyStoreManager			keystoreManager;
    String				path;
    RSAPublicKey			e002PubKey;
    RSAPublicKey			x002PubKey;
    int					httpCode;

    sender = new HttpRequestSender(session);
    request = new HPBRequestElement(session);
    request.build();
    request.validate();
    session.getConfiguration().getTraceManager().trace(request);
    byte[] content = request.prettyPrint();
    String s = new String(Utils.canonize(content));
    System.out.println(s);
    request.verify(content);
    Canonicalizer canonicalizer = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
    request.verify(canonicalizer.canonicalize(content));
    httpCode = sender.send(new ByteArrayContentFactory(content));
    Utils.checkHttpCode(httpCode);
    response = new KeyManagementResponseElement(sender.getResponseBody(), "HBPResponse");
    response.build();
    session.getConfiguration().getTraceManager().trace(response);
    response.report();
    factory = new ByteArrayContentFactory(Utils.unzip(session.getUser().decrypt(response.getOrderData(), response.getTransactionKey())));
    orderData = new HPBResponseOrderDataElement(factory);
    orderData.build();
    session.getConfiguration().getTraceManager().trace(orderData);
    keystoreManager = new KeyStoreManager();
    path = session.getConfiguration().getKeystoreDirectory(session.getUser());
    keystoreManager.load("" , session.getUser().getPasswordCallback().getPassword());

    if (session.getUser().getPartner().getBank().useCertificate())
    {
        e002PubKey = keystoreManager.getPublicKey(new ByteArrayInputStream(orderData.getBankE002Certificate()));
        x002PubKey = keystoreManager.getPublicKey(new ByteArrayInputStream(orderData.getBankX002Certificate()));
        session.getUser().getPartner().getBank().setBankKeys(e002PubKey, x002PubKey);
        keystoreManager.setCertificateEntry(session.getBankID() + "-E002", new ByteArrayInputStream(orderData.getBankE002Certificate()));
        keystoreManager.setCertificateEntry(session.getBankID() + "-X002", new ByteArrayInputStream(orderData.getBankX002Certificate()));
        keystoreManager.save(new FileOutputStream(path + File.separator + session.getBankID() + ".p12"));
    }
    else
    {
        e002PubKey = keystoreManager.getPublicKey(new BigInteger(1, orderData.getBankE002PublicKeyExponent()), new BigInteger(1, orderData.getBankE002PublicKeyModulus()));
        x002PubKey = keystoreManager.getPublicKey(new BigInteger(1, orderData.getBankX002PublicKeyExponent()), new BigInteger(1, orderData.getBankX002PublicKeyModulus()));
        session.getUser().getPartner().getBank().setBankKeys(e002PubKey, x002PubKey);
        //keystoreManager.setCertificateEntry(session.getBankID() + "-E002", new ByteArrayInputStream(orderData.getBankE002Certificate()));
        //keystoreManager.setCertificateEntry(session.getBankID() + "-X002", new ByteArrayInputStream(orderData.getBankX002Certificate()));
        keystoreManager.save(new FileOutputStream(path + File.separator + session.getBankID() + ".p12"));
    }
  }

  /**
   * Sends the SPR order to the bank.
   * After that you have to start over with sending INI and HIA.
   * @throws IOException Communication exception
   * @throws EbicsException Error message generated by the bank.
   */
  public void lockAccess() throws IOException, EbicsException {
    HttpRequestSender			sender;
    SPRRequestElement			request;
    SPRResponseElement			response;
    int					httpCode;

    sender = new HttpRequestSender(session);
    request = new SPRRequestElement(session);
    request.build();
    request.validate();
    session.getConfiguration().getTraceManager().trace(request);
    httpCode = sender.send(new ByteArrayContentFactory(request.prettyPrint()));
    Utils.checkHttpCode(httpCode);
    response = new SPRResponseElement(sender.getResponseBody());
    response.build();
    session.getConfiguration().getTraceManager().trace(response);
    response.report();
  }

  // --------------------------------------------------------------------
  // DATA MEMBERS
  // --------------------------------------------------------------------

  private EbicsSession 				session;
}
