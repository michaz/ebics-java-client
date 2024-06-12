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

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xmlbeans.XmlObject;
import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.interfaces.EbicsUser;
import org.kopi.ebics.schema.xmldsig.*;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


/**
 * A representation of the SignedInfo element
 * performing signature for signed ebics requests
 *
 * @author hachani
 *
 */
public class Signature extends DefaultEbicsRootElement {

  /**
   * Constructs a new <code>SignedInfo</code> element
   * @param digest the digest value
   */
  public Signature(EbicsUser user, byte[] digest) {
    this.user = user;
    this.digest = digest;
  }

  public void build() throws EbicsException {
    SignedInfoType signedInfoType = SignedInfoType.Factory.newInstance();
    SignatureMethodType signatureMethodType = SignatureMethodType.Factory.newInstance();
    signatureMethodType.setAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    signedInfoType.setSignatureMethod(signatureMethodType);
    CanonicalizationMethodType newCanonicalizationMethodType = CanonicalizationMethodType.Factory.newInstance();
    newCanonicalizationMethodType.setAlgorithm(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
    signedInfoType.setCanonicalizationMethod(newCanonicalizationMethodType);
    DigestMethodType newDigestMethodType = DigestMethodType.Factory.newInstance();
    newDigestMethodType.setAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");

    TransformType newTransformType = TransformType.Factory.newInstance();
    newTransformType.setAlgorithm(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);

    TransformsType newTransformsType = TransformsType.Factory.newInstance();
    newTransformsType.setTransformArray(new TransformType[] {newTransformType});

    ReferenceType newReferenceType = ReferenceType.Factory.newInstance();
    newReferenceType.setURI("#xpointer(//*[@authenticate='true'])");
    newReferenceType.setTransforms(newTransformsType);
    newReferenceType.setDigestMethod(newDigestMethodType);
    newReferenceType.setDigestValue(digest);

    signedInfoType.setReferenceArray(new ReferenceType[] {newReferenceType});

    SignatureType newSignatureType = SignatureType.Factory.newInstance();
    newSignatureType.setSignedInfo(signedInfoType);
    xmlObject = newSignatureType;
  }

  /**
   * Returns the signed info element as an <code>XmlObject</code>
   * @return he signed info element
   */
  public SignatureType getSignatureType() {
    return (SignatureType) xmlObject;
  }

  public static void main(String[] args) throws InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, IOException, SAXException, TransformerException, XPathExpressionException {
    org.apache.xml.security.Init.init();
    Canonicalizer canonicalizer = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
    String xml = """
            <Dildo xmlns="wurst:blubb:kotz" xmlns:blubb="affe:eimer:ommo">
            <Wurst authenticate="true">
            rtgrtgrtg
            </Wurst>
            <Worst authenticate="true">
            rtgrtgrtg
            </Worst>
            <blubb:Knork>
            rtgrtgrtg
            </blubb:Knork>
            </Dildo>
            """;
    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setNamespaceAware(true);

    HashMap<String, String> prefMap = new HashMap<String, String>() {{
      put("blubb", "affe:eimer:ommo");
    }};


    DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
    Document document = documentBuilder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    XPath xpath = XPathFactory.newInstance().newXPath();
    xpath.setNamespaceContext(new NamespaceContext() {
      @Override
      public String getNamespaceURI(String prefix) {
        return prefMap.get(prefix);
      }

      @Override
      public String getPrefix(String namespaceURI) {
        throw new RuntimeException();
      }

      @Override
      public Iterator<String> getPrefixes(String namespaceURI) {
        throw new RuntimeException();
      }
    });

    // Compile an XPath expression
    XPathExpression expr = xpath.compile("//*[@authenticate='true']");
    System.out.println("===!!!!!!!");
    // Evaluate the XPath expression on the document
    NodeList nodeList = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
    Set<Node> nodeSet = new HashSet<>(nodeList.getLength());
    for (int i = 0; i < nodeList.getLength(); i++) {
      Node node = nodeList.item(i);
      nodeSet.add(node);
    }
    canonicalizer.canonicalizeXPathNodeSet(nodeSet, System.out);



  }

  // Utility method to convert a Node and its children to a String
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


  public byte[] sign(XmlObject context) throws EbicsException {
    try {
      Canonicalizer canonicalizer = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
      System.out.println("============");
      System.out.println("============");
      System.out.println("============");
      context.save(System.out);
      System.out.println("============");
      System.out.println("===PUUUUUUUPS=========");
      System.out.println("============");

      XPath xpath = XPathFactory.newInstance().newXPath();

      // Compile an XPath expression
      XPathExpression expr = xpath.compile("//ds:SignedInfo");

      // Evaluate the XPath expression on the document
      NodeList nodeList = (NodeList) expr.evaluate(context.getDomNode(), XPathConstants.NODESET);
      Set<Node> nodeSet = new HashSet<>(nodeList.getLength());
      for (int i = 0; i < nodeList.getLength(); i++) {
        Node node = nodeList.item(i);
        nodeSet.add(node);
      }
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      canonicalizer.canonicalizeXPathNodeSet(nodeSet, out);
      byte[] canonicalizedSignedInfo = out.toByteArray();
      System.out.println("CANONICALIZED THING I AM SIGNING:");
      System.out.println(new String(canonicalizedSignedInfo));
      byte[] signedDigestedCanonicalizedSignedInfo = user.authenticate(canonicalizedSignedInfo);
      SignatureValueType signatureValue = SignatureValueType.Factory.newInstance();
      signatureValue.setByteArrayValue(signedDigestedCanonicalizedSignedInfo);
      getSignatureType().setSignatureValue(signatureValue);
      System.out.println(getSignatureType());
      System.out.println("============");
      System.out.println("============");
      System.out.println("============");

      return signedDigestedCanonicalizedSignedInfo;
    } catch(Exception e) {
      throw new EbicsException(e);
    }
  }

  @Override
  public String getName() {
    return "SignedInfo.xml";
  }

  // --------------------------------------------------------------------
  // DATA MEMBERS
  // --------------------------------------------------------------------

  private byte[]			digest;
  private EbicsUser 			user;
  private static final long 		serialVersionUID = 4194924578678778580L;
}
