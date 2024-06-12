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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Calendar;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.schema.h004.*;
import org.kopi.ebics.schema.h004.EbicsNoPubKeyDigestsRequestDocument.EbicsNoPubKeyDigestsRequest;
import org.kopi.ebics.schema.h004.EbicsNoPubKeyDigestsRequestDocument.EbicsNoPubKeyDigestsRequest.Body;
import org.kopi.ebics.schema.h004.EbicsNoPubKeyDigestsRequestDocument.EbicsNoPubKeyDigestsRequest.Header;
import org.kopi.ebics.session.EbicsSession;
import org.kopi.ebics.utils.Utils;

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

  /**
   * Returns the digest value of the authenticated XML portions.
   * @return  the digest value.
   * @throws EbicsException Failed to retrieve the digest value.
   */
  public byte[] getDigest() throws EbicsException {
    try {
      return MessageDigest.getInstance("SHA-256", "BC").digest(Utils.canonize(xmlObject.getDomNode()));
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new EbicsException(e.getMessage());
    }
  }

  /**
   * Sets the authentication signature of the <code>NoPubKeyDigestsRequestElement</code>
   * @param authSignature the the authentication signature.
   */
  public void setAuthSignature(Signature authSignature) {
    ((EbicsNoPubKeyDigestsRequestDocument) xmlObject).getEbicsNoPubKeyDigestsRequest().setAuthSignature(authSignature.getSignatureType());
  }

  public void build() throws EbicsException, XmlException, IOException {
    NoPubKeyDigestsRequestStaticHeaderType newNoPubKeyDigestsRequestStaticHeaderType = NoPubKeyDigestsRequestStaticHeaderType.Factory.newInstance();
    newNoPubKeyDigestsRequestStaticHeaderType.setHostID(session.getBankID());
    newNoPubKeyDigestsRequestStaticHeaderType.setNonce(Utils.generateNonce());
    newNoPubKeyDigestsRequestStaticHeaderType.setTimestamp(Calendar.getInstance());
    newNoPubKeyDigestsRequestStaticHeaderType.setPartnerID(session.getUser().getPartner().getPartnerId());
    newNoPubKeyDigestsRequestStaticHeaderType.setUserID(session.getUser().getUserId());
    ProductElementType newProductElementType = ProductElementType.Factory.newInstance();
    newProductElementType.setLanguage(session.getProduct().getLanguage());
    newProductElementType.setStringValue(session.getProduct().getName());

    newNoPubKeyDigestsRequestStaticHeaderType.setProduct(newProductElementType);
    OrderDetailsType newOrderDetailsType = OrderDetailsType.Factory.newInstance();
    newOrderDetailsType.setOrderAttribute("DZHNN");
    newOrderDetailsType.setOrderType("HPB");

    newNoPubKeyDigestsRequestStaticHeaderType.setOrderDetails(newOrderDetailsType);
    newNoPubKeyDigestsRequestStaticHeaderType.setSecurityMedium(session.getUser().getSecurityMedium());

    Header newHeader = Header.Factory.newInstance();
    newHeader.setAuthenticate(true);

    newHeader.setMutable(EmptyMutableHeaderType.Factory.newInstance());
    newHeader.setStatic(newNoPubKeyDigestsRequestStaticHeaderType);


    EbicsNoPubKeyDigestsRequestDocument newEbicsNoPubKeyDigestsRequestDocument = EbicsNoPubKeyDigestsRequestDocument.Factory.parse(
"""
  <ebics:ebicsNoPubKeyDigestsRequest xmlns:ebics="urn:org:ebics:H004" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>
""");
    System.out.println("pupsaffe");
    System.out.println("pupsaffe");
    newEbicsNoPubKeyDigestsRequestDocument.save(System.out);
    EbicsNoPubKeyDigestsRequest newEbicsNoPubKeyDigestsRequest = newEbicsNoPubKeyDigestsRequestDocument.getEbicsNoPubKeyDigestsRequest();
    newEbicsNoPubKeyDigestsRequest.setRevision(session.getConfiguration().getRevision());
    newEbicsNoPubKeyDigestsRequest.setVersion(session.getConfiguration().getVersion());
    newEbicsNoPubKeyDigestsRequest.setHeader(newHeader);
    newEbicsNoPubKeyDigestsRequest.setBody(Body.Factory.newInstance());

    newEbicsNoPubKeyDigestsRequestDocument.setEbicsNoPubKeyDigestsRequest(newEbicsNoPubKeyDigestsRequest);
    System.out.println("pupsaffe");
    System.out.println("pupsaffe");
    newEbicsNoPubKeyDigestsRequestDocument.save(System.out);
    System.out.println("dildo");
    System.out.println("dildo");
    xmlObject = newEbicsNoPubKeyDigestsRequestDocument;
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
