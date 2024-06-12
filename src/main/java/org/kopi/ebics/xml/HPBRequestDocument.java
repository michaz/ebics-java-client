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

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.session.EbicsSession;

import java.io.IOException;

/**
 * The <code>HPBRequestElement</code> is the element to be sent when
 * a HPB request is needed to retrieve the bank public keys
 *
 * @author hachani
 *
 */
public class HPBRequestDocument extends DefaultEbicsRootElement {

  /**
   * Constructs a new HPB Request element.
   * @param session the current ebics session.
   */
  public HPBRequestDocument(EbicsSession session) {
    super(session);
  }

  @Override
  public String getName() {
    return "HPBRequest.xml";
  }

  public void build() throws EbicsException, XmlException, IOException {
    noPubKeyDigestsRequestDocumentForHPB = new NoPubKeyDigestsRequestDocumentForHPB(session);
    noPubKeyDigestsRequestDocumentForHPB.build();
    Signature authSignature = new Signature(session.getUser(), noPubKeyDigestsRequestDocumentForHPB.getDigest());
    authSignature.build();
    noPubKeyDigestsRequestDocumentForHPB.setAuthSignature(authSignature);
    noPubKeyDigestsRequestDocumentForHPB.xmlObject.save(System.out);
    authSignature.sign(noPubKeyDigestsRequestDocumentForHPB.xmlObject);
    noPubKeyDigestsRequestDocumentForHPB.setAuthSignature(authSignature);

    System.out.println(noPubKeyDigestsRequestDocumentForHPB.xmlObject);
    System.out.println(new String(noPubKeyDigestsRequestDocumentForHPB.toByteArray()));
    xmlObject = noPubKeyDigestsRequestDocumentForHPB.xmlObject;
  }

  @Override
  public byte[] toByteArray() {
    return noPubKeyDigestsRequestDocumentForHPB.toByteArray();
  }

  public void validate() throws EbicsException {
    noPubKeyDigestsRequestDocumentForHPB.validate();
  }

  public XmlObject getMotherfuckingDocument() {
    return xmlObject;
  }

  // --------------------------------------------------------------------
  // DATA MEMBERS
  // --------------------------------------------------------------------

  private NoPubKeyDigestsRequestDocumentForHPB noPubKeyDigestsRequestDocumentForHPB;
  private static final long 			serialVersionUID = -5565390370996751973L;
}
