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

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.schema.xmldsig.SignatureValueType;
import org.kopi.ebics.utils.Utils;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

/**
 * Key store loader. This class loads a key store from
 * a given path and allow to get private keys and certificates
 * for a given alias.
 * The PKCS12 key store type is recommended to be used
 *
 * @author hachani
 *
 */
public class KeyStoreManager {

  /**
   * Loads a certificate for a given alias
   *
   * @param alias the certificate alias
   * @return the certificate
   * @throws KeyStoreException
   */
  public final X509Certificate getCertificate(String alias) throws KeyStoreException {
    X509Certificate cert;

    cert = (X509Certificate) keyStore.getCertificate(alias);

    if (cert == null) {
      throw new IllegalArgumentException("alias " + alias + " not found in the KeyStore");
    }

    return cert;
  }

  /**
   * Loads a private key for a given alias
   *
   * @param alias the certificate alias
   * @return the private key
   * @throws GeneralSecurityException
   */
  public final PrivateKey getPrivateKey(String alias) throws GeneralSecurityException {
    PrivateKey key;

    key = (PrivateKey) keyStore.getKey(alias, password);
    if (key == null) {
      throw new IllegalArgumentException("private key not found for alias " + alias);
    }

    return key;
  }

  /**
   * Loads a key store from a given path and password
   *
   * @param path     the key store path
   * @param password the key store password
   * @throws GeneralSecurityException
   * @throws IOException
   */
  public void load(String path, char[] password)
          throws GeneralSecurityException, IOException {
    keyStore = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
    this.password = password;
    load(path);
  }

  /**
   * Loads a key store and cache the loaded one
   *
   * @param path the key store path.
   * @throws GeneralSecurityException
   * @throws IOException
   */
  private void load(String path) throws GeneralSecurityException, IOException {
    if (path.equals("")) {
      this.keyStore.load(null, null);
    } else {
      this.keyStore.load(new FileInputStream(path), password);
      this.certs = read(this.keyStore);
    }
  }

  /**
   * Reads a certificate from an input stream for a given provider
   *
   * @param input    the input stream
   * @param provider the certificate provider
   * @return the certificate
   * @throws CertificateException
   * @throws IOException
   */
  public X509Certificate read(InputStream input, Provider provider)
          throws CertificateException, IOException {
    X509Certificate certificate;

    certificate = (X509Certificate) CertificateFactory.getInstance("X.509", provider).generateCertificate(input);

    if (certificate == null) {
      certificate = (X509Certificate) (new PEMReader(new InputStreamReader(input))).readObject();
    }

    return certificate;
  }

  /**
   * Returns the public key of a given certificate.
   *
   * @param input the given certificate
   * @return The RSA public key of the given certificate
   * @throws GeneralSecurityException
   * @throws IOException
   */
  public RSAPublicKey getPublicKey(InputStream input)
          throws GeneralSecurityException, IOException {
    X509Certificate cert;

    cert = read(input, keyStore.getProvider());
    return (RSAPublicKey) cert.getPublicKey();
  }

  public RSAPublicKey getPublicKey(BigInteger publicExponent, BigInteger modulus) {
    try {
      return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
      Logger.getLogger(KeyStoreManager.class.getName()).log(Level.SEVERE, null, ex);
      return null;
    }
  }

  /**
   * Writes the given certificate into the key store.
   *
   * @param alias the certificate alias
   * @param input the given certificate.
   * @throws GeneralSecurityException
   * @throws IOException
   */
  public void setCertificateEntry(String alias, InputStream input)
          throws GeneralSecurityException, IOException {
    keyStore.setCertificateEntry(alias, read(input, keyStore.getProvider()));
  }

  /**
   * Saves the key store to a given output stream.
   *
   * @param output the output stream.
   */
  public void save(OutputStream output)
          throws GeneralSecurityException, IOException {
    keyStore.store(output, password);
  }

  /**
   * Returns the certificates contained in the key store.
   *
   * @return the certificates contained in the key store.
   */
  public Map<String, X509Certificate> getCertificates() {
    return certs;
  }

  /**
   * Reads all certificate existing in a given key store
   *
   * @param keyStore the key store
   * @return A <code>Map</code> of certificate,
   * the key of the map is the certificate alias
   * @throws KeyStoreException
   */
  public Map<String, X509Certificate> read(KeyStore keyStore)
          throws KeyStoreException {
    Map<String, X509Certificate> certificates;
    Enumeration<String> enumeration;

    certificates = new HashMap<String, X509Certificate>();
    enumeration = keyStore.aliases();
    while (enumeration.hasMoreElements()) {
      String alias;

      alias = enumeration.nextElement();
      certificates.put(alias, (X509Certificate) keyStore.getCertificate(alias));
    }

    return certificates;
  }

  // --------------------------------------------------------------------
  // DATA MEMBERS
  // --------------------------------------------------------------------

  private KeyStore keyStore;
  private char[] password;
  private Map<String, X509Certificate> certs;

  public static void main(String[] args) throws GeneralSecurityException, IOException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, SAXException, TransformerException, EbicsException {
    KeyStoreManager keyStoreManager = new KeyStoreManager();
    keyStoreManager.load("/Users/michaelzilske/ebics/client/users/F001B235/keystore/F001B235.p12", "pupsaffe123".toCharArray());
    keyStoreManager.certs.forEach((alias, key) -> {
      System.out.println(alias);
      System.out.println(key);
    });
    X509Certificate certificate = keyStoreManager.getCertificate("F001B235-X002");

//    char[] chars = Hex.encodeHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()), false);
//    System.out.println(chars);

    RSAPublicKey publicKey = ((RSAPublicKey) certificate.getPublicKey());
    String exponent = Hex.encodeHexString(publicKey.getPublicExponent().toByteArray());
    String modulus = Hex.encodeHexString(removeFirstByte(publicKey.getModulus().toByteArray()));
    String message = exponent + " " + modulus;

    if (message.charAt(0) == '0') {
      message = message.substring(1);
    }
    System.out.println(message);
    System.out.println(Hex.encodeHex(MessageDigest.getInstance("SHA-256", new BouncyCastleProvider()).digest(message.getBytes("US-ASCII")), false));

    System.out.println();

    String goodExponent = "10001";
    String goodModulus = "B1 98 A6 95 AB FF 35 1E 32 3E EE 3E E6 B2 F9 79 C6 22 22 41 8E 21 0E 85 EE D4 C2 26 0E 9E ED 43" +
            " D0 40 4F 7A DE 24 86 23 DA 83 91 5C 68 78 B7 94 EA 44 26 8F 27 B5 32 33 3A DB A0 7F 6D 05 A9 82" +
            " 10 2F DD 8F 22 79 4B 18 E5 11 51 41 7F B7 60 CC 25 D0 65 64 FA 83 AE BB EB 98 74 3A 74 66 C2 98" +
            " 18 29 9A 03 3F 0C EF 48 7B 47 BB CA BA 39 03 02 B7 0B AA 47 33 21 A4 DF 93 AB 14 F9 2F 40 7C C3" +
            " 46 A8 35 1C 3B F7 03 F1 9D 6F 65 90 FE 96 6C 1C 0F 4D 28 1F BD 5D 1F 36 31 5D 9F 9C B4 EE 66 4A" +
            " B6 1C 80 6F 89 33 38 51 F9 83 80 28 5F F8 71 8A 49 D5 F4 B5 87 B1 9D 45 BF CF FA 61 31 12 6B 90" +
            " B9 8E B8 99 16 AE 8A E5 FD B0 D9 C3 6B 28 12 6B E6 A8 4A 86 33 4C D3 92 9D 31 65 EE 71 BE F5 C8" +
            " 29 0E DB 27 59 33 CA 67 0F 11 74 8F 4D 21 BB ED 10 8F CE E8 E2 82 77 5A 81 CC C6 FE 99 64 1B 7B";

    goodModulus = goodModulus.toLowerCase().replaceAll(" ", "");
    String oldMessage = goodExponent + " " + goodModulus;
    System.out.println(oldMessage);
    System.out.println(Hex.encodeHex(MessageDigest.getInstance("SHA-256", new BouncyCastleProvider()).digest(oldMessage.getBytes("US-ASCII")), false));

    String requestString =
            """
<?xml version="1.0" encoding="UTF-8"?>
 <urn:ebicsNoPubKeyDigestsRequest xmlns:urn="urn:org:ebics:H004" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Revision="1" Version="H004">
  <urn:header authenticate="true">
    <urn:static>
      <urn:HostID>D86-ELKO</urn:HostID>
      <urn:Nonce>4A0A26059F067D918E9ABCDD070D07C1</urn:Nonce>
      <urn:Timestamp>2024-06-11T10:10:35.484+02:00</urn:Timestamp>
      <urn:PartnerID>K0013706</urn:PartnerID>
      <urn:UserID>F001B235</urn:UserID>
      <urn:Product Language="de">EBICS Java Kernel 1.1-graphhopper-SNAPSHOT</urn:Product>
      <urn:OrderDetails>
        <urn:OrderType>HPB</urn:OrderType>
        <urn:OrderAttribute>DZHNN</urn:OrderAttribute>
      </urn:OrderDetails>
      <urn:SecurityMedium>0000</urn:SecurityMedium>
    </urn:static>
    <urn:mutable />
  </urn:header>
  <urn:AuthSignature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
      <ds:Reference URI="#xpointer(//*[@authenticate='true'])">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
        <ds:DigestValue>/3wXvPw1mfno2CgiLVUxcLzVfuFV4IdLCTTxK/hqbas=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>VJuq1dro1YIt9t5kBFSnIwWY20rC6FNZrit/mDcx75e0Ww7F+2XPcuTtu4HWgqfAHipNEALKobOzKEl/P3HHKfjLZUeFxrDYE7M6b+rJv+x59l51Sfw0QufD4p6Uhtmtjd/bLHYvIyy7KSWt7KUFcseQvlOi1qPQGfh59OokDv6X+oBXjEVvTO2agEoY1uGO+fEAppo53C5D6Y69gAtkXpAJ41Bjn93GaGASW7eiBluUbbP2YsAhMOEJP0/7MnfPJgNtBcKzEGXA9lcWjlFsYAg3MNnSf12JERLUR7wnaNgUnUFFCg5sBeq0LFJBU9a77JkB5drt6L3BBKjiNkpqxg==</ds:SignatureValue>
  </urn:AuthSignature>
  <urn:body />
</urn:ebicsNoPubKeyDigestsRequest>
            """;

    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    factory.setValidating(true);
    DocumentBuilder builder = factory.newDocumentBuilder();
    Node document = builder.parse(new ByteArrayInputStream(requestString.getBytes()));
    Node node = XPathAPI.selectSingleNode(document, "//ds:SignedInfo");

    org.apache.xml.security.Init.init();
    Canonicalizer canonicalizer = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
    byte[] canonicalized = canonicalizer.canonicalizeSubtree(node);

    PrivateKey x002PrivateKey = keyStoreManager.getPrivateKey("F001B235-X002");
    Signature signature = Signature.getInstance("SHA256WithRSA", new BouncyCastleProvider());
    signature.initSign(x002PrivateKey);
    signature.update(canonicalized);
    byte[] signatureValue = signature.sign();

    SignatureValueType newSignatureValueType = SignatureValueType.Factory.newInstance();
    newSignatureValueType.setByteArrayValue(signatureValue);
    System.out.println(newSignatureValueType.getStringValue());

    byte[] canonized = Utils.canonize(requestString.getBytes());
    System.out.println(new String(canonized));
  }

  private static byte[] removeFirstByte(byte[] byteArray) {
    byte[] b = new byte[byteArray.length - 1];
    System.arraycopy(byteArray, 1, b, 0, b.length);
    return b;
  }


}
