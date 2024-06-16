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

package org.kopi.ebics.certificate;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.BigIntegers;
import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.utils.Utils;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;

/**
 * Some key utilities
 *
 * @author hachani
 *
 */
public class KeyUtil {

    private KeyUtil() {
    }

  /**
   * Generates a <code>KeyPair</code> in RSA format.
   *
   * @param keyLen - key size
   * @return KeyPair the key pair
   * @throws NoSuchAlgorithmException
   */
  public static KeyPair makeKeyPair(int keyLen) throws NoSuchAlgorithmException {
    KeyPairGenerator 		keyGen;

    keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keyLen, Utils.secureRandom);

    return keyGen.generateKeyPair();

  }

  /**
   * Returns the digest value of a given public key.
   *
   *
   * <p>In Version “H003” of the EBICS protocol the ES of the financial:
   *
   * <p>The SHA-256 hash values of the financial institution's public keys for X002 and E002 are
   * composed by concatenating the exponent with a blank character and the modulus in hexadecimal
   * representation (using lower case letters) without leading zero (as to the hexadecimal
   * representation). The resulting string has to be converted into a byte array based on US ASCII
   * code.
   *
   * @param publicKey the public key
   * @return the digest value
   * @throws EbicsException
   */
  public static byte[] getKeyDigest(RSAPublicKey publicKey) throws EbicsException {
    String exponent = Hex.encodeHexString(BigIntegers.asUnsignedByteArray(publicKey.getPublicExponent()));
    String modulus = Hex.encodeHexString(BigIntegers.asUnsignedByteArray(publicKey.getModulus()));
    String hexEncodedPublicKeyInfo = exponent + " " + modulus;
    String hexEncodedPublicKeyInfoWithoutLeadingZeros = hexEncodedPublicKeyInfo.replaceFirst("^0+(?!$)", "");

    try {
      return MessageDigest.getInstance("SHA-256", "BC").digest(hexEncodedPublicKeyInfoWithoutLeadingZeros.getBytes(StandardCharsets.US_ASCII));
    } catch (GeneralSecurityException e) {
      throw new EbicsException(e.getMessage());
    }
  }

}
