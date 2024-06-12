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
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xmlbeans.XmlException;
import org.kopi.ebics.certificate.KeyStoreManager;
import org.kopi.ebics.certificate.KeyUtil;
import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.interfaces.ContentFactory;
import org.kopi.ebics.io.ByteArrayContentFactory;
import org.kopi.ebics.session.EbicsSession;
import org.kopi.ebics.utils.Utils;
import org.kopi.ebics.xml.*;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;


public class KeyManagement {

  private EbicsSession session;

    public KeyManagement(EbicsSession session) {
        this.session = session;
    }

    public void sendINI(String orderId) throws EbicsException, IOException {
        INIRequestElement request;
        KeyManagementResponseElement response;
        HttpRequestSender sender;
        int httpCode;

        sender = new HttpRequestSender(session);
        request = new INIRequestElement(session, orderId);
        request.build();
        request.validate();
        session.getConfiguration().getTraceManager().trace(request);
        httpCode = sender.send(new ByteArrayContentFactory(request.toByteArray()));
        Utils.checkHttpCode(httpCode);
        response = new KeyManagementResponseElement(sender.getResponseBody(), "INIResponse");
        response.build();
        session.getConfiguration().getTraceManager().trace(response);
        response.report();
    }

    public void sendHIA(String orderId) throws IOException, EbicsException {
        HIARequestElement request;
        KeyManagementResponseElement response;
        HttpRequestSender sender;
        int httpCode;

        sender = new HttpRequestSender(session);
        request = new HIARequestElement(session, orderId);
        request.build();
        request.validate();
        session.getConfiguration().getTraceManager().trace(request);
        httpCode = sender.send(new ByteArrayContentFactory(request.toByteArray()));
        Utils.checkHttpCode(httpCode);
        response = new KeyManagementResponseElement(sender.getResponseBody(), "HIAResponse");
        response.build();
        session.getConfiguration().getTraceManager().trace(response);
        response.report();
    }

    public void sendHPB() throws IOException, GeneralSecurityException, EbicsException, XmlException, ParserConfigurationException, SAXException, XPathExpressionException, XMLSecurityException {
        HttpRequestSender sender = new HttpRequestSender(session);
        Document request = NoPubKeyDigestsRequestDocumentForHPB.create(session);
        String requestString = nodeToString(request);
        System.out.println(requestString);
        int httpCode = sender.send(new ByteArrayContentFactory(requestString.getBytes()));
        Utils.checkHttpCode(httpCode);
        KeyManagementResponseElement response = new KeyManagementResponseElement(sender.getResponseBody(), "HPBResponse");
        response.build();
        session.getConfiguration().getTraceManager().trace(response);
        response.report();
        ContentFactory factory = new ByteArrayContentFactory(Utils.unzip(session.getUser().decrypt(response.getOrderData(), response.getTransactionKey())));
        HPBResponseOrderDataElement orderData = new HPBResponseOrderDataElement(factory);
        orderData.build();
        session.getConfiguration().getTraceManager().trace(orderData);
        KeyStoreManager keystoreManager = new KeyStoreManager();
        String path = session.getConfiguration().getKeystoreDirectory(session.getUser());
        keystoreManager.load("", session.getUser().getPasswordCallback().getPassword());

        RSAPublicKey e002PubKey;
        RSAPublicKey x002PubKey;
        if (session.getUser().getPartner().getBank().useCertificate()) {
            e002PubKey = keystoreManager.getPublicKey(new ByteArrayInputStream(orderData.getBankE002Certificate()));
            x002PubKey = keystoreManager.getPublicKey(new ByteArrayInputStream(orderData.getBankX002Certificate()));
            session.getUser().getPartner().getBank().setBankKeys(e002PubKey, x002PubKey);
            session.getUser().getPartner().getBank().setDigests(KeyUtil.getKeyDigest(e002PubKey), KeyUtil.getKeyDigest(x002PubKey));
            keystoreManager.setCertificateEntry(session.getBankID() + "-E002", new ByteArrayInputStream(orderData.getBankE002Certificate()));
            keystoreManager.setCertificateEntry(session.getBankID() + "-X002", new ByteArrayInputStream(orderData.getBankX002Certificate()));
            keystoreManager.save(new FileOutputStream(path + File.separator + session.getBankID() + ".p12"));
        } else {
            e002PubKey = keystoreManager.getPublicKey(new BigInteger(orderData.getBankE002PublicKeyExponent()), new BigInteger(orderData.getBankE002PublicKeyModulus()));
            x002PubKey = keystoreManager.getPublicKey(new BigInteger(orderData.getBankX002PublicKeyExponent()), new BigInteger(orderData.getBankX002PublicKeyModulus()));
            session.getUser().getPartner().getBank().setBankKeys(e002PubKey, x002PubKey);
            session.getUser().getPartner().getBank().setDigests(KeyUtil.getKeyDigest(e002PubKey), KeyUtil.getKeyDigest(x002PubKey));
            keystoreManager.save(new FileOutputStream(path + File.separator + session.getBankID() + ".p12"));
        }
    }

    private static String nodeToString(org.w3c.dom.Node node) {
        try {
            javax.xml.transform.Transformer transformer = javax.xml.transform.TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(javax.xml.transform.OutputKeys.OMIT_XML_DECLARATION, "yes");
            javax.xml.transform.dom.DOMSource source = new javax.xml.transform.dom.DOMSource(node);
            java.io.StringWriter sw = new java.io.StringWriter();
            javax.xml.transform.stream.StreamResult result = new javax.xml.transform.stream.StreamResult(sw);
            transformer.transform(source, result);
            return sw.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void sendSPR() throws IOException, EbicsException {
        HttpRequestSender sender;
        SPRRequestElement request;
        SPRResponseElement response;
        int httpCode;

        sender = new HttpRequestSender(session);
        request = new SPRRequestElement(session);
        request.build();
        request.validate();
        session.getConfiguration().getTraceManager().trace(request);
        httpCode = sender.send(new ByteArrayContentFactory(request.toByteArray()));
        Utils.checkHttpCode(httpCode);
        response = new SPRResponseElement(sender.getResponseBody());
        response.build();
        session.getConfiguration().getTraceManager().trace(response);
        response.report();
    }

}
