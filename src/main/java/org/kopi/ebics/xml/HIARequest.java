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
import org.kopi.ebics.session.OrderType;
import org.kopi.ebics.utils.Utils;

public class HIARequest extends DefaultEbicsRootElement {

  /**
   * Constructs a new HIA Request root element
   * @param session the current ebics session
   * @param orderId the order id, if null a random one is generated.
   */
  public HIARequest(EbicsSession session, String orderId) {
    super(session);
    this.orderId = orderId;
  }

  @Override
  public String getName() {
    return "HIARequest.xml";
  }

  @Override
  public void build() throws EbicsException {
    HIARequestOrderData requestOrderData = new HIARequestOrderData(session);
    requestOrderData.build();
    byte[] toZip = requestOrderData.prettyPrint();
    System.out.println(new String(toZip));
    ebicsUnsecuredRequest = new EbicsUnsecuredRequest(session, OrderType.HIA, Utils.zip(toZip));
    ebicsUnsecuredRequest.build();
  }

  @Override
  public byte[] toByteArray() {
    setPrefixes("http://www.ebics.org/H003", "");

    return ebicsUnsecuredRequest.toByteArray();
  }

  @Override
  public void validate() throws EbicsException {
    ebicsUnsecuredRequest.validate();
  }

  // --------------------------------------------------------------------
  // DATA MEMBERS
  // --------------------------------------------------------------------

  private String			orderId;
  private EbicsUnsecuredRequest ebicsUnsecuredRequest;
  private static final long 		serialVersionUID = 1130436605993828777L;
}
