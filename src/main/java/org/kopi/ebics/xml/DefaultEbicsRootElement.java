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
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.xmlbeans.XmlError;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;
import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.interfaces.EbicsOrderType;
import org.kopi.ebics.interfaces.EbicsRootElement;
import org.kopi.ebics.session.EbicsSession;
import org.kopi.ebics.utils.Utils;

public abstract class DefaultEbicsRootElement implements EbicsRootElement {

  /**
   * Constructs a new default <code>EbicsRootElement</code>
   * @param session the current ebics session
   */
  public DefaultEbicsRootElement(EbicsSession session) {
    this.session = session;
  }

  /**
   *  Constructs a new default <code>EbicsRootElement</code>
   */
  public DefaultEbicsRootElement() {
    this(null);
  }

  /**
   * Generates a random file name with a prefix.
   * @param type the order type.
   * @return the generated file name.
   */
  public static String generateName(EbicsOrderType type) {
    return type.getCode() + new BigInteger(130, Utils.secureRandom).toString(32);
  }
  
  /**
   * Generates a random file name with a prefix.
   * @param prefix the prefix to use.
   * @return the generated file name.
   */
  public static String generateName(String prefix) {
    return prefix + new BigInteger(130, Utils.secureRandom).toString(32);
  }

  @Override
  public String toString() {
    return new String(toByteArray());
  }

  @Override
  public byte[] toByteArray() {
    XmlOptions		options;

    options = new XmlOptions();
    options.setSavePrettyPrint();
    return xmlObject.xmlText(options).getBytes();
  }

  public void validate() throws EbicsException {
    ArrayList<XmlError> validationMessages = new ArrayList<XmlError>();
    boolean isValid = xmlObject.validate(new XmlOptions().setErrorListener(validationMessages));

    if (!isValid) {
      Iterator<XmlError> iter = validationMessages.iterator();
      StringBuilder message = new StringBuilder();
      while (iter.hasNext()) {
        if (!message.toString().equals("")) {
          message.append(";");
        }
        message.append(iter.next().getMessage());
      }

      throw new EbicsException(message.toString());
    }
  }

  @Override
  public void save(OutputStream out) throws EbicsException {
    try {
      byte[]		element;

      element = toByteArray();
      out.write(element);
      out.flush();
      out.close();
    } catch (IOException e) {
      throw new EbicsException(e.getMessage());
    }
  }

  // --------------------------------------------------------------------
  // DATA MEMBERS
  // --------------------------------------------------------------------

  protected XmlObject xmlObject;
  protected EbicsSession 		session;
  private static final long 		serialVersionUID = -3928957097145095177L;
}
