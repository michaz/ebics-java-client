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

package org.kopi.ebics.xml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.*;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlOptions;
import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.schema.h004.*;
import org.kopi.ebics.schema.h004.EbicsNoPubKeyDigestsRequestDocument.EbicsNoPubKeyDigestsRequest;
import org.kopi.ebics.schema.h004.EbicsNoPubKeyDigestsRequestDocument.EbicsNoPubKeyDigestsRequest.Header;
import org.kopi.ebics.schema.xmldsig.*;
import org.kopi.ebics.schema.xmldsig.SignatureType;
import org.kopi.ebics.session.EbicsSession;
import org.kopi.ebics.utils.Utils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;

/**
 * The <code>NoPubKeyDigestsRequestElement</code> is the root element
 * for a HPB ebics server request.
 *
 * @author hachani
 *
 */
public class NoPubKeyDigestsRequestDocumentForHPB extends DefaultEbicsRootElement {

  /**
   * Construct a new No Public Key Digests Request element.
   * @param session the current ebics session.
   */
  public NoPubKeyDigestsRequestDocumentForHPB(EbicsSession session) {
    super(session);
  }

  public static Document create(EbicsSession session) throws XmlException, IOException, ParserConfigurationException, SAXException, XPathExpressionException, XMLSecurityException {
    System.out.println("===create");
    EbicsNoPubKeyDigestsRequestDocument newEbicsNoPubKeyDigestsRequestDocument = createShit(session);

    System.out.println("===dump XMLBeans before signing");
    var suggestedPrefixes = new HashMap<String, String>();
    suggestedPrefixes.put("urn:org:ebics:H004", "ebics");
    suggestedPrefixes.put("http://www.w3.org/2000/09/xmldsig#", "ds");
    XmlOptions opts = new XmlOptions().setUseDefaultNamespace().setSavePrettyPrint().setSaveAggressiveNamespaces();
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    newEbicsNoPubKeyDigestsRequestDocument.save(byteArrayOutputStream, opts);
    byteArrayOutputStream.writeTo(System.out);
    System.out.println();
    System.out.println();

    System.out.println("===reconstructing DOM, namespace aware");
    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setNamespaceAware(true);
    DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
    Document document = documentBuilder.parse(new ByteArrayInputStream(byteArrayOutputStream.toString(StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8)));

    System.out.println("===operate on it");
    XMLSignature xmlSignature = new XMLSignature(document, "", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
    Transforms trans = new Transforms(document);
    trans.addTransform(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
    xmlSignature.addDocument("#xpointer(//*[@authenticate='true'])", trans, "http://www.w3.org/2001/04/xmlenc#sha256", "", "");
    xmlSignature.addResourceResolver(new ResourceResolverSpi() {
      @Override
      public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
        if (context.uriToResolve.equals("#xpointer(//*[@authenticate='true'])")) {
          Node headerNode = document.getElementsByTagNameNS("urn:org:ebics:H004", "header").item(0);
          XMLSignatureNodeInput header = new XMLSignatureNodeInput(headerNode);
          header.setSourceURI("#xpointer(//*[@authenticate='true'])");
          return header;
        } else {
          throw new RuntimeException();
        }
      }

      @Override
      public boolean engineCanResolveURI(ResourceResolverContext context) {
        return context.uriToResolve.equals("#xpointer(//*[@authenticate='true'])");
      }
    });

    xmlSignature.sign(session.getUser().getX002PrivateKey());
    Node rootNode = document.getElementsByTagNameNS("urn:org:ebics:H004", "AuthSignature").item(0);
    rootNode.appendChild(xmlSignature.getSignedInfo().getElement());
    Node signatureValue = xmlSignature.getElement().getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignatureValue").item(0);
    String wurst = signatureValue.getTextContent().replaceAll("\r\n", "");
    String replacedText = wurst.substring(1, wurst.length()-1);
    System.out.println(replacedText);
    signatureValue.setTextContent(replacedText);
    rootNode.appendChild(signatureValue);
    return document;
  }

  private static EbicsNoPubKeyDigestsRequestDocument createShit(EbicsSession session) {
    EbicsNoPubKeyDigestsRequestDocument newEbicsNoPubKeyDigestsRequestDocument = EbicsNoPubKeyDigestsRequestDocument.Factory.newInstance();
    EbicsNoPubKeyDigestsRequest document = newEbicsNoPubKeyDigestsRequestDocument.addNewEbicsNoPubKeyDigestsRequest();
    document.setRevision(session.getConfiguration().getRevision());
    document.setVersion(session.getConfiguration().getVersion());
    Header newHeader = document.addNewHeader();
    newHeader.setAuthenticate(true);
    NoPubKeyDigestsRequestStaticHeaderType staticHeader = newHeader.addNewStatic();
    staticHeader.setHostID(session.getBankID());
    staticHeader.setNonce(Utils.generateNonce());
    staticHeader.setTimestamp(Calendar.getInstance());
    staticHeader.setPartnerID(session.getUser().getPartner().getPartnerId());
    staticHeader.setSystemID(session.getUser().getUserId());
    staticHeader.setUserID(session.getUser().getUserId());
    ProductElementType product = staticHeader.addNewProduct();
    product.setLanguage(session.getProduct().getLanguage());
    product.setStringValue(session.getProduct().getName());
    OrderDetailsType orderDetails = staticHeader.addNewOrderDetails();
    orderDetails.setOrderAttribute("DZHNN");
    orderDetails.setOrderType("HPB");
    staticHeader.setSecurityMedium(session.getUser().getSecurityMedium());
    newHeader.addNewMutable();
    document.addNewBody();
    document.addNewAuthSignature();
//    SignatureType authSignature1 = document.addNewAuthSignature();
//    SignedInfoType signedInfo = authSignature1.addNewSignedInfo();
//    signedInfo.addNewSignatureMethod().setAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
//    signedInfo.addNewCanonicalizationMethod().setAlgorithm(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
//    ReferenceType reference = signedInfo.addNewReference();
//    reference.setURI("#xpointer(//*[@authenticate='true'])");
//    reference.addNewTransforms().addNewTransform().setAlgorithm(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
//    reference.addNewDigestMethod().setAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");
//    authSignature1.addNewSignatureValue();
    return newEbicsNoPubKeyDigestsRequestDocument;
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

  public void setAuthSignature(Signature authSignature) {
    ((EbicsNoPubKeyDigestsRequestDocument) xmlObject).getEbicsNoPubKeyDigestsRequest().setAuthSignature(authSignature.getSignatureType());
  }

  @Override
  public byte[] toByteArray() {
    return super.toByteArray();
  }

  @Override
  public String getName() {
    return "NoPubKeyDigestsRequest.xml";
  }

  // --------------------------------------------------------------------
  // DATA MEMBERS
  // --------------------------------------------------------------------

  private static final long		serialVersionUID = 3177047145408329472L;
}
