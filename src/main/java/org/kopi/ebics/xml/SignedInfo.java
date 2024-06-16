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
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.utils.IgnoreAllErrorHandler;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.interfaces.EbicsUser;
import org.kopi.ebics.schema.xmldsig.CanonicalizationMethodType;
import org.kopi.ebics.schema.xmldsig.DigestMethodType;
import org.kopi.ebics.schema.xmldsig.ReferenceType;
import org.kopi.ebics.schema.xmldsig.SignatureMethodType;
import org.kopi.ebics.schema.xmldsig.SignatureType;
import org.kopi.ebics.schema.xmldsig.SignedInfoType;
import org.kopi.ebics.schema.xmldsig.TransformType;
import org.kopi.ebics.schema.xmldsig.TransformsType;
import org.kopi.ebics.utils.Utils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;


/**
 * A representation of the SignedInfo element
 * performing signature for signed ebics requests
 *
 * @author hachani
 *
 */
public class SignedInfo extends DefaultEbicsRootElement {

  /**
   * Constructs a new <code>SignedInfo</code> element
   * @param digest the digest value
   */
  public SignedInfo(EbicsUser user, byte[] digest) {
    this.user = user;
    this.digest = digest;
  }

  @Override
  public void build() throws EbicsException {
    CanonicalizationMethodType 	canonicalizationMethod;
    SignatureMethodType 	signatureMethod;
    ReferenceType 		reference;
    TransformsType 		transforms;
    DigestMethodType 		digestMethod;
    TransformType 		transform;
    SignedInfoType		signedInfo;

    if (digest == null) {
      throw new EbicsException("digest value cannot be null");
    }

    transform = EbicsXmlFactory.createTransformType(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
    digestMethod = EbicsXmlFactory.createDigestMethodType("http://www.w3.org/2001/04/xmlenc#sha256");
    transforms = EbicsXmlFactory.createTransformsType(new TransformType[] {transform});
    reference = EbicsXmlFactory.createReferenceType("#xpointer(//*[@authenticate='true'])",
	                                            transforms,
	                                            digestMethod,
	                                            digest);
    signatureMethod = EbicsXmlFactory.createSignatureMethodType("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    canonicalizationMethod = EbicsXmlFactory.createCanonicalizationMethodType(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
    signedInfo = EbicsXmlFactory.createSignedInfoType(canonicalizationMethod,
	                                              signatureMethod,
	                                              new ReferenceType[] {reference});

    document = EbicsXmlFactory.createSignatureType(signedInfo);
  }

  /**
   * Returns the digest value.
   * @return the digest value.
   */
  public byte[] getDigest() {
    return digest;
  }

  /**
   * Returns the signed info element as an <code>XmlObject</code>
   * @return he signed info element
   */
  public SignatureType getSignatureType() {
    return ((SignatureType)document);
  }

  /**
   * Canonizes and signs a given input with the authentication private key.
   * of the EBICS user.
   * 
   * <p>The given input to be signed is first Canonized using the 
   * http://www.w3.org/TR/2001/REC-xml-c14n-20010315 algorithm.
   * 
   * <p>The element to be canonized is only the SignedInfo element that should be
   * contained in the request to be signed. Otherwise, a {@link TransformationException}
   * is thrown.
   * 
   * <p> The namespace of the SignedInfo element should be named <b>ds</b> as specified in
   * the EBICS specification for common namespaces nomination.
   * 
   * <p> The signature is ensured using the user X002 private key. This step is done in
   * {@link EbicsUser#authenticate(byte[]) authenticate}.
   * 
   * @param toSign the input to sign
   * @return the signed input
   * @throws EbicsException signature fails.
   */
  public byte[] sign(byte[] toSign) throws EbicsException {
    try {
      DocumentBuilderFactory 		factory;
      DocumentBuilder			builder;
      Document				document;
      Node 				node;
      Canonicalizer 			canonicalizer;

      factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setValidating(true);
      builder = factory.newDocumentBuilder();
      builder.setErrorHandler(new IgnoreAllErrorHandler());
      document = builder.parse(new ByteArrayInputStream(toSign));
      node = XPathAPI.selectSingleNode(document, "//ds:SignedInfo");
      canonicalizer = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
      System.out.println("sign");
      byte[] data = canonicalizer.canonicalizeSubtree(node);
      System.out.println(new String(data));
      return user.authenticate(data);
    } catch(Exception e) {
      throw new EbicsException(e.getMessage());
    }
  }

  public void verify(byte[] toVerify) throws EbicsException {
    try {
      DocumentBuilderFactory 		factory;
      DocumentBuilder			builder;
      Document				document;
      Node 				node;
      Canonicalizer 			canonicalizer;

      factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setValidating(true);
      builder = factory.newDocumentBuilder();
      builder.setErrorHandler(new IgnoreAllErrorHandler());
      document = builder.parse(new ByteArrayInputStream(toVerify));
      String actualDigest = XPathAPI.selectSingleNode(document, "//ds:DigestValue").getTextContent();
      String expectedDigest = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256", "BC").digest(Utils.canonize(toVerify)));
      if (!actualDigest.equals(expectedDigest)) {
        throw new EbicsException("Digest does not match");
      }
      node = XPathAPI.selectSingleNode(document, "//ds:SignedInfo");
      String sig = XPathAPI.selectSingleNode(document, "//ds:SignatureValue").getTextContent();
      canonicalizer = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
      Signature signature = Signature.getInstance("SHA256WithRSA", BouncyCastleProvider.PROVIDER_NAME);
      signature.initVerify(user.getX002PublicKey());
      System.out.println("verify");
      byte[] data = canonicalizer.canonicalizeSubtree(node);
      System.out.println(new String(data));
      signature.update(data);
      boolean verify = signature.verify(Base64.getDecoder().decode(sig));
      if (!verify) {
        throw new RuntimeException();
      }
    } catch(Exception e) {
      throw new EbicsException(e.getMessage());
    }
  }

  @Override
  public byte[] toByteArray() {
    addNamespaceDecl("", "urn:org:ebics:H004");
    setPrefixes("http://www.w3.org/2000/09/xmldsig#", "ds");

    return super.toByteArray();
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
