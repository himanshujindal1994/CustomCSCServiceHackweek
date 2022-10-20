package com.javatpoint.utils;

import com.cavium.key.*;
import com.cavium.key.parameter.*;
import java.io.*;
import java.math.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.KeyGenerator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.jcajce.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
//import org.faceless.pdf2.*;

public class SignatureUtil {

    public static void genKey() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, OperatorCreationException {
        String keyStoreFile = "testkeystore";   // Name of new KeyStore file to generate
        String alias = "testkey";           // alias of key in that keystore
        char[] password = "secret".toCharArray();   // password to use
        String dn = "CN=Test Tester, C=GB"; // DN for the identity you're creating
        int bits = 2048;                    // Number of bits
        String alg = "SHA256WithRSA";       // Certificate signature algorithm
        boolean extractable = false;        // This key will not be extractable

        Provider provider = new com.cavium.provider.CaviumProvider();
        Security.addProvider(provider);
        KeyStore keyStore = KeyStore.getInstance("CloudHSM");
        keyStore.load(null, null);

        // 1. Generate KeyPair with a non-extractable key
        System.err.println("Generating Key");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
        kpg.initialize(new CaviumRSAKeyGenParameterSpec(bits, new BigInteger("65537"), alias + ":public", alias, extractable, false));
        KeyPair pair = kpg.generateKeyPair();
        // Is it really non-extractable?
        System.err.println("Generated: extractable = " + ((CaviumRSAPrivateKey)pair.getPrivate()).isExtractable());

        // 2. Generate a self-signed certificate to go with the key.
        System.err.println("Generating Certificate");
        Date startDate = new Date();
        Date endDate = new Date(System.currentTimeMillis() + 365*24*60*60*1000l);
        BigInteger serial = new BigInteger(32, new SecureRandom());
        X500Name name = new X500Name(dn);
        ContentSigner signer = new JcaContentSignerBuilder(alg).build(pair.getPrivate());
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(name, serial, startDate, endDate, name, pair.getPublic());
        byte[] encoded = certBuilder.build(signer).getEncoded();

        // 3. Store the certificate and the key into the KeyStore
        System.err.println("Storing key and Certificate");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(encoded));
        KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(pair.getPrivate(), new Certificate[] { cert });
        keyStore.setEntry(alias, entry, new KeyStore.PasswordProtection(password));

        FileOutputStream out = new FileOutputStream(keyStoreFile);
        keyStore.store(out, password);
        out.close();

        // 4. Generate a CSR from the newly-generated PrivateKey and PublicKey
        System.err.println("Generating CSR");
        JcaPKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(name, pair.getPublic());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        StringWriter w = new StringWriter();
        JcaPEMWriter ww = new JcaPEMWriter(w);
        ww.writeObject(csr);
        ww.close();
        System.out.println(w);
    }

    public static void importGenKey() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        String keyStoreFile = "testkeystore";
        String alias = "testkey";
        char[] password = "secret".toCharArray();
        String certFile = "testkey.crt";

        Provider provider = new com.cavium.provider.CaviumProvider();
        Security.addProvider(provider);
        KeyStore keyStore = KeyStore.getInstance("CloudHSM");
        keyStore.load(new FileInputStream(keyStoreFile), password);

        Key key = keyStore.getKey(alias, password);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate cert = factory.generateCertificate(new FileInputStream(certFile));
        keyStore.setKeyEntry(alias, key, password, new Certificate[] { cert });
        FileOutputStream out = new FileOutputStream(keyStoreFile);
        keyStore.store(out, password);
        out.close();
    }

    public static void signPDF(String filename) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {           // The PDF to sign
        String keyStoreFile = "testkeystore";    // The name of our keystore file
        String alias = "testkey";              // The alias into that keystore
        char[] password = "secret".toCharArray(); // The password for that keystore

        Provider provider = new com.cavium.provider.CaviumProvider();
        Security.addProvider(provider);
        KeyStore keyStore = KeyStore.getInstance("CloudHSM");
        keyStore.load(new FileInputStream(keyStoreFile), password);
/*
        PDF pdf = new PDF(new PDFReader(new File(args[0])));
        AcrobatSignatureHandlerFactory factory = new AcrobatSignatureHandlerFactory();
        factory.setProvider(provider);
        FormSignature sig = new FormSignature();
        pdf.getForm().getElements().put("Sig1", sig);
        sig.sign(keyStore, alias, password, factory);

        OutputStream out = new FileOutputStream("Sign.pdf");
        pdf.render(out);
        out.close();

 */
    }
}
