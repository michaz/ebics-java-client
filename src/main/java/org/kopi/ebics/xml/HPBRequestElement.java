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

import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.session.EbicsSession;

/**
 * The <code>HPBRequestElement</code> is the element to be sent when
 * a HPB request is needed to retrieve the bank public keys
 *
 * @author hachani
 *
 */
public class HPBRequestElement extends DefaultEbicsRootElement {

  private SignedInfo signedInfo;

  /**
   * Constructs a new HPB Request element.
   * @param session the current ebics session.
   */
  public HPBRequestElement(EbicsSession session) {
    super(session);
  }

  @Override
  public String getName() {
    return "HPBRequest.xml";
  }

  @Override
  public void build() throws EbicsException {
    noPubKeyDigestsRequest = new NoPubKeyDigestsRequestElement(session);
    noPubKeyDigestsRequest.build();
    signedInfo = new SignedInfo(session.getUser(), noPubKeyDigestsRequest.getDigest());
    signedInfo.build();
    noPubKeyDigestsRequest.setAuthSignature(signedInfo.getSignatureType());
    noPubKeyDigestsRequest.setSignatureValue(signedInfo.sign(noPubKeyDigestsRequest.toByteArray()));
  }

  @Override
  public byte[] toByteArray() {
    return noPubKeyDigestsRequest.toByteArray();
  }

  @Override
  public void validate() throws EbicsException {
    noPubKeyDigestsRequest.validate();
  }

  public void verify(byte[] toVerify) throws EbicsException {
    signedInfo.verify(toVerify);
  }

  // --------------------------------------------------------------------
  // DATA MEMBERS
  // --------------------------------------------------------------------

  private NoPubKeyDigestsRequestElement		noPubKeyDigestsRequest;
  private static final long 			serialVersionUID = -5565390370996751973L;
}
