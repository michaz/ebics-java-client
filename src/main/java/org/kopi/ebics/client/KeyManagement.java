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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.codec.binary.Hex;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.HexEncoder;
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

  public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
    String m = "B2 90 65 AC 01 05 D7 8A 6D F0 5D 21 8A D5 A7 A6 6E F7 19 7D C7 65 83 16 D1 F3 28 39 D1 AE 89 C7\n" +
            "3E 18 64 82 BD 30 6D BB 02 8C EB BC FC 9B 60 4E D8 75 EE CE B6 CB AF 63 DB 34 E6 C8 F6 5F 93 1A\n" +
            "80 44 40 62 40 5B BF 6F 50 32 1B 05 43 AC 9D 2C 15 44 90 47 68 99 85 3D 28 78 57 8A 87 07 E4 AE\n" +
            "71 35 D6 14 8A 69 5F 4F 66 F6 6C F8 3D 7A 0E 00 26 D1 1C E9 18 E2 7A 78 DE 12 0E 49 C2 61 DF B8\n" +
            "D5 98 53 87 A3 56 1E 2D 69 6B 03 D9 59 8A 80 A3 B1 0E 9F AC 99 1F A3 1F 73 4C EB 5A E9 A6 64 FD\n" +
            "47 BB F3 F5 C0 8E EB 55 43 BB DA D5 60 D8 5A 4D 87 CA 52 97 7A FB 23 D7 28 7C 06 29 10 0E EF 38\n" +
            "DF B4 DD 5B 1B 26 38 07 3B 62 54 B9 53 69 30 12 A0 70 62 9C 08 98 9A 33 60 5F EB 6B B3 ED A8 74\n" +
            "3D 62 1D F6 44 A2 66 E0 A1 53 96 B1 40 F1 C8 24 64 FD 01 FE 02 BF BA 00 4A EA CD 8B C6 7F 50 F7";
    String e = "1 00 01";
    String hexEncodedPublicKeyInfo = e.replaceAll("\\s", "").toLowerCase() + " " + m.replaceAll("\\s", "").toLowerCase();
    System.out.println(hexEncodedPublicKeyInfo);
    byte[] digest = MessageDigest.getInstance("SHA-256", new BouncyCastleProvider()).digest(hexEncodedPublicKeyInfo.getBytes(StandardCharsets.US_ASCII));
    String actual = new String(Hex.encodeHex(digest, false));
    String fingerprint = "90 B7 8F 15 D6 28 19 81 3F C7 96 D5 CA CF D4 DD\n" +
            "E6 1A 5A A8 59 A4 39 8A 38 B8 36 C4 A0 D7 DD 48\n";
    String expected = fingerprint.replaceAll("\\s", "");
    if (!expected.equals(actual)) {
      throw new RuntimeException(actual + " " + expected);
    }
  }
}
