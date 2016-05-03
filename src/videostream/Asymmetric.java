package videostream;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import static javax.xml.bind.DatatypeConverter.printHexBinary;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

//test
import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.*;
import java.security.*;
import java.nio.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Asymmetric {
//test values
/*
     * Enables logging of the SSLEngine operations.
     */
    private static boolean logging = true;

    /*
     * Enables the JSSE system debugging system property:
     *
     *     -Djavax.net.debug=all
     *
     * This gives a lot of low-level information about operations underway,
     * including specific handshake messages, and might be best examined
     * after gaining some familiarity with this application.
     */
    private SSLContext sslc;

    private SSLEngine clientEngine;     // client Engine
    private ByteBuffer clientOut;       // write side of clientEngine
    private ByteBuffer clientIn;        // read side of clientEngine

    private SSLEngine serverEngine;     // server Engine
    private ByteBuffer serverOut;       // write side of serverEngine
    private ByteBuffer serverIn;        // read side of serverEngine

    /*
     * For data transport, this example uses local ByteBuffers.  This
     * isn't really useful, but the purpose of this example is to show
     * SSLEngine concepts, not how to do network transport.
     */
    private ByteBuffer cTOs;            // "reliable" transport client->server
    private ByteBuffer sTOc;            // "reliable" transport server->client

    /*
     * The following is to set up the keystores.
     */
    private static String keyStoreFile = "testkeys";
    private static String trustStoreFile = "testkeys";
    private static String passwd = "passphrase";
    //end test variables

    /**
     * Two party key agreement using Diffie-Hellman
     */
    private static BigInteger g512 = new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
            + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
            + "410b7a0f12ca1cb9a428cc", 16);
    private static BigInteger p512 = new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
            + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
            + "f0573bf047a3aca98cdf3b", 16);

    public void DH() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        DHParameterSpec dhParams = new DHParameterSpec(p512, g512);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        SecureRandom sr = SecureRandom.getInstanceStrong();
        keyGen.initialize(dhParams, sr);

        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair bPair = keyGen.generateKeyPair();

        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);
        // generate the key bytes
        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());

        System.out.println(printHexBinary(aShared));
        System.out.println(printHexBinary(bShared));
    }

    public void ECDH() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        EllipticCurve curve = new EllipticCurve(
                new ECFieldFp(new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16)), // p
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)); // b

        ECParameterSpec ecSpec = new ECParameterSpec(
                curve,
                new ECPoint(
                        new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
                        new BigInteger("f8e6d46a003725879cefee1294db32298c06885ee186b7ee", 16)), // G
                new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16), // order
                1); // h

        SecureRandom sr = SecureRandom.getInstanceStrong();
        keyGen.initialize(ecSpec, sr);

        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair bPair = keyGen.generateKeyPair();

        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        // generate the key bytes
        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());

        System.out.println(printHexBinary(aShared));
        System.out.println(printHexBinary(bShared));

    }

    public void DHE() throws Exception {
        //party 1
        DHBasicKeyPairGenerator aliceKeyGen = new DHBasicKeyPairGenerator();
        DHParametersGenerator aliceGenerator = new DHParametersGenerator();
        aliceGenerator.init(512, 30, new SecureRandom());
        DHParameters aliceParameters = aliceGenerator.generateParameters();

        KeyGenerationParameters aliceKGP = new DHKeyGenerationParameters(new SecureRandom(), aliceParameters);
        aliceKeyGen.init(aliceKGP);

        AsymmetricCipherKeyPair aliceKeyPair = aliceKeyGen.generateKeyPair();
        DHBasicAgreement aliceKeyAgree = new DHBasicAgreement();
        aliceKeyAgree.init(aliceKeyPair.getPrivate());
        //end party 1

        //transmit req data to party 2
        //party 2 
        DHBasicKeyPairGenerator bobKeyGen = new DHBasicKeyPairGenerator();
        DHParameters bobParameters = aliceParameters;//new DHParameters(aliceParameters.getP(),aliceParameters.getG(),aliceParameters.getQ());

        KeyGenerationParameters bobKGP = new DHKeyGenerationParameters(new SecureRandom(), bobParameters);
        bobKeyGen.init(bobKGP);

        AsymmetricCipherKeyPair bobKeyPair = bobKeyGen.generateKeyPair();
        DHBasicAgreement bobKeyAgree = new DHBasicAgreement();
        bobKeyAgree.init(bobKeyPair.getPrivate());
        //END SETUP BOB

        // generate the key bytes
        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aliceKeyAgree.calculateAgreement(bobKeyPair.getPublic()).toByteArray());
        byte[] bShared = hash.digest(bobKeyAgree.calculateAgreement(aliceKeyPair.getPublic()).toByteArray());

        System.out.println(printHexBinary(aShared));
        System.out.println(printHexBinary(bShared));
    }

    public void ECDHE() throws Exception {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
        g.initialize(ecSpec, new SecureRandom());

        KeyPair aPair = g.generateKeyPair();
        KeyPair bPair = g.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");

        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        // generate the key bytes
        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());

        System.out.println(printHexBinary(aShared));
        System.out.println(printHexBinary(bShared));
    }
}
