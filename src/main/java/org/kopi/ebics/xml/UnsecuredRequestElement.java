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
import org.kopi.ebics.interfaces.EbicsOrderType;
import org.kopi.ebics.schema.h004.*;
import org.kopi.ebics.session.EbicsSession;

/**
 * The <code>UnsecuredRequestElement</code> is the common element
 * used for key management requests.
 *
 * @author hachani
 *
 */
public class UnsecuredRequestElement extends DefaultEbicsRootElement {

  /**
   * Constructs a Unsecured Request Element.
   * @param session the ebics session.
   * @param orderType the order type (INI | HIA).
   * @param orderId the order id, if null a random one is generated.
   */
  public UnsecuredRequestElement(EbicsSession session,
                                 EbicsOrderType orderType,
                                 String orderId,
                                 byte[] orderData)
  {
    super(session);
    this.orderType = orderType;
    this.orderId = orderId;
    this.orderData = orderData;
  }

  public void build() throws EbicsException {

      EbicsUnsecuredRequestDocument newEbicsUnsecuredRequestDocument = EbicsUnsecuredRequestDocument.Factory.newInstance();
      EbicsUnsecuredRequestDocument.EbicsUnsecuredRequest.Header newHeader = EbicsUnsecuredRequestDocument.EbicsUnsecuredRequest.Header.Factory.newInstance();
      newHeader.setAuthenticate(true);
      newHeader.setMutable(EmptyMutableHeaderType.Factory.newInstance());
      ProductElementType newProductElementType = ProductElementType.Factory.newInstance();
      newProductElementType.setLanguage(session.getProduct().getLanguage());
      newProductElementType.setStringValue(session.getProduct().getName());

      if (orderId == null) {
          session.getUser().getPartner().nextOrderId();
      }
      OrderDetailsType newOrderDetailsType = OrderDetailsType.Factory.newInstance();
      newOrderDetailsType.setOrderAttribute("DZNNN");
      newOrderDetailsType.setOrderType(orderType.getCode());

      UnsecuredRequestStaticHeaderType newUnsecuredRequestStaticHeaderType = UnsecuredRequestStaticHeaderType.Factory.newInstance();
      newUnsecuredRequestStaticHeaderType.setHostID(session.getBankID());
      newUnsecuredRequestStaticHeaderType.setPartnerID(session.getUser().getPartner().getPartnerId());
      newUnsecuredRequestStaticHeaderType.setUserID(session.getUser().getUserId());
      newUnsecuredRequestStaticHeaderType.setProduct(newProductElementType);
      newUnsecuredRequestStaticHeaderType.setOrderDetails(newOrderDetailsType);
      newUnsecuredRequestStaticHeaderType.setSecurityMedium(session.getUser().getSecurityMedium());

      newHeader.setStatic(newUnsecuredRequestStaticHeaderType);

      EbicsUnsecuredRequestDocument.EbicsUnsecuredRequest newEbicsUnsecuredRequest = EbicsUnsecuredRequestDocument.EbicsUnsecuredRequest.Factory.newInstance();
      newEbicsUnsecuredRequest.setHeader(newHeader);
      EbicsUnsecuredRequestDocument.EbicsUnsecuredRequest.Body newBody = EbicsUnsecuredRequestDocument.EbicsUnsecuredRequest.Body.Factory.newInstance();
      newBody.setDataTransfer(EbicsXmlFactory.createDataTransfer(EbicsXmlFactory.createOrderData(this.orderData)));

      newEbicsUnsecuredRequest.setBody(newBody);
      newEbicsUnsecuredRequest.setRevision(session.getConfiguration().getRevision());
      newEbicsUnsecuredRequest.setVersion(session.getConfiguration().getVersion());

      newEbicsUnsecuredRequestDocument.setEbicsUnsecuredRequest(newEbicsUnsecuredRequest);

      xmlObject = newEbicsUnsecuredRequestDocument;
  }

  @Override
  public String getName() {
    return "UnsecuredRequest.xml";
  }

  // --------------------------------------------------------------------
  // DATA MEMBERS
  // --------------------------------------------------------------------

  private EbicsOrderType orderType;
  private String			orderId;
  private byte[]			orderData;
  private static final long 		serialVersionUID = -3548730114599886711L;
}
