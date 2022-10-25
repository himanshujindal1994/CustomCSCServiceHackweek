package com.javatpoint.utils;

import com.javatpoint.service.KeyUtilitiesRunner;
import com.javatpoint.service.RSAWrappingRunner;

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
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.jcajce.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.operator.ContentSigner;

public class SignUtil {


    public static void step1() throws Exception {
        Key nonextractableKey = RSAWrappingRunner.generateNonExtractableKey(256, "himanshu1", false);


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

        CaviumKey key = KeyUtilitiesRunner.getKeyByHandle(7);
        KeyUtilitiesRunner.displayKeyInfo(key);

        KeyUtilitiesRunner.displayKeyInfo((CaviumKey) nonextractableKey);

    }
}
