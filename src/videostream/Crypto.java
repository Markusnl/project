package videostream;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import static javax.xml.bind.DatatypeConverter.printHexBinary;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

//test
import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.*;
import java.security.*;
import java.nio.*;
import sun.util.logging.resources.logging;

public class Crypto {

    //cipher enum
    public final static int AES_128_GCM = 0;
    public final static int AES_256_GCM = 1;
    public final static int CHACHA20_HMAC = 2;
    public final static int CHACHA12_HMAC = 3;
    public final static int CHACHA20_POLY = 4;
    public final static int AES_256_CTR_HMAC = 5;

    //default AES_256_GCM
    private int NONCE_SIZE = 12;
    private int HMAC_SIZE = 0;
    private int KEY_SIZE = 32;
    private int CRYPTO_HEADER_SIZE = NONCE_SIZE + HMAC_SIZE;
    private int MESSAGE_FORMAT = 1;
    private int CHACHA_ROUNDS = 20;

    //debug option
    private final boolean debug = false;

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
     * Returns the Message Authentication Code from the input. By default it
     * returns the first 32 byte as SHA256 describes.
     *
     * @param input The data from which to extract the Message Authentication
     * Code
     * @return The 32 byte SHA256 Message Authentication Code
     */
    public byte[] getMac(byte[] input) {
        byte mac[] = new byte[HMAC_SIZE];
        System.arraycopy(input, 0, mac, 0, HMAC_SIZE);
        return mac;
    }

    /**
     * Returns the Nonce from the input. By default it returns the first 8 byte
     * as ChaCha20 describes.
     *
     * @param input The data from which to extract the Nonce
     * @return The 8 byte ChaCha20 describes
     */
    public byte[] getNonce(byte[] input) {
        byte nonce[] = new byte[NONCE_SIZE];
        System.arraycopy(input, HMAC_SIZE, nonce, 0, NONCE_SIZE);
        return nonce;
    }

    /**
     * Returns the inputted data without the crypto header By default it returns
     * input - 32 byte HMAC - 8 byte Nonce.
     *
     * @param input The data from which to extract the Message Authentication
     * Code
     * @return The inputted data without crypto header
     */
    public byte[] getData(byte[] input) {
        byte data[] = new byte[input.length - CRYPTO_HEADER_SIZE];
        System.arraycopy(input, CRYPTO_HEADER_SIZE, data, 0, data.length);
        return data;
    }

    /**
     * Prepends the given Message Authentication Code to the Data
     *
     * @param mac The Message Authentication code to prepend
     * @param input The data to which the Message Authentication code should be
     * prepended
     * @return Message Authentication Code prepended to data
     */
    public byte[] prependMac(byte[] mac, byte[] input) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(mac);
            outputStream.write(input);
        } catch (IOException ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return outputStream.toByteArray();
    }

    /**
     * Prepends the given nonce to the Data
     *
     * @param nonce The Message Authentication code to prepend
     * @param input The data to which the nonce should be prepended
     * @return nonce prepended to data
     */
    public byte[] prependNonce(byte[] nonce, byte[] input) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(nonce);
            outputStream.write(input);
        } catch (IOException ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return outputStream.toByteArray();
    }

    /**
     * Method to verify whether the given Message Authentication code is equal
     * to the Message authentication code calculated from the inputted data. If
     * this method returns true no tampering has occurred given the synchronous
     * key is only known by both sending and receiving party.
     *
     * @param key The synchronous key
     * @param input The data from which to compute a Message Authentication Code
     * @param mac The Message Authentication code to compare with the computed
     * one
     * @param headerPresent Boolean whether the given input still has a Message
     * Authentication Code prepended that has to be removed before calculation
     * @return True is Message Authentications are equal, False is they are not
     */
    public boolean verifyMac(byte[] key, byte[] input, byte[] mac, boolean headerPresent) {
        //initialize MAC
        Digest digest = new SHA256Digest();
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(key));

        //MAC still prepended to message, remove it first to calculate validity
        if (headerPresent) {
            input = removeMac(input);
        }

        //Calculate MAC
        hmac.update(input, 0, input.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        hmac.doFinal(resBuf, 0);

        //debug prints to manually verify MAC's
        if (debug) {
            System.out.println("computed mac: " + printHexBinary(resBuf));
            System.out.println("given mac: " + printHexBinary(mac));
        }

        return Arrays.equals(resBuf, mac);
    }

    /**
     * Generate a Hashed Message Authentication Code with SHA256 from the
     * inputted data and the given synchronous key
     *
     * @param key The synchronous key
     * @param input The data from which to calculate a Message Authentication
     * Code
     * @return The Message authentication code calculated from the input with
     * the given synchronous key
     */
    public byte[] generateHMac(byte[] key, byte[] input) {
        //initialize MAC
        Digest digest = new SHA256Digest();
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(key));

        //calculate MAC
        hmac.update(input, 0, input.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        hmac.doFinal(resBuf, 0);

        return resBuf;
    }

    /**
     * Encrypt or decrypt inputted data using given nonce and synchronous key.
     * ChaCha20 is a stream cipher based on the XOR operation, encryption and
     * decryption is the same process. This function does not have awareness of
     * the data, if a wrong key is used it is still able to "decrypt", use
     * verifyMac() function to validate messages first!
     *
     * @param key The synchronous key
     * @param nonce The nonce used in the encryption
     * @param input The data to be encrypted
     * @return The encrypted or decrypted data
     */
    private byte[] encryptWithChaChaHmac(byte[] key, byte[] nonce, byte[] input) {
        //create chacha engine with key and nonce
        CipherParameters cp = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(cp, nonce);
        StreamCipher engine = new ChaChaEngine(CHACHA_ROUNDS);
        engine.init(true, params);

        //encrypt/decrypt and return output
        byte ciphertxt[] = new byte[input.length];
        engine.processBytes(input, 0, input.length, ciphertxt, 0);

        byte out[] = prependNonce(nonce, ciphertxt);
        return prependMac(generateHMac(key, out), out);
    }

    private byte[] decryptWithChaChaPoly(byte[] key, byte[] input) {
        ChaChaEngine engine = new ChaChaEngine();
        Poly1305 mac = new Poly1305();
        engine.init(true, new ParametersWithIV(new KeyParameter(key), getNonce(input)));

        byte[] computedMac = new byte[16];
        byte[] receivedMac = new byte[16];

        //initMAC(cipher); -- entire function       
        byte[] firstBlock = new byte[64];
        engine.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0);
        // NOTE: The BC implementation puts 'r' after 'k'
        System.arraycopy(firstBlock, 0, firstBlock, 32, 16);
        KeyParameter macKey = new KeyParameter(firstBlock, 16, 32);
        Poly1305KeyGenerator.clamp(macKey.getKey());
        mac.init(macKey);
        //end function

        System.arraycopy(input, 0, receivedMac, 0, mac.getMacSize());

        byte out[] = new byte[input.length - CRYPTO_HEADER_SIZE];
        byte data[] = getData(input);

        //update mac with data and decrypt data
        mac.update(data, 0, data.length);
        engine.processBytes(data, 0, data.length, out, 0);

        // check if the two MACs match
        mac.doFinal(computedMac, 0);
        if (Arrays.equals(receivedMac, computedMac)) {
            return out;
        } else {
            return null;
        }
    }

    //key, getNonce(data), getData(data));
    private byte[] encryptWithChaChaPoly(byte[] key, byte[] nonce, byte[] input) {
        ChaChaEngine engine = new ChaChaEngine();
        Poly1305 mac = new Poly1305();
        engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] ciphertextMac = new byte[16];

        //initMAC(cipher); -- entire function       
        byte[] firstBlock = new byte[64];
        engine.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0);
        // NOTE: The BC implementation puts 'r' after 'k'
        System.arraycopy(firstBlock, 0, firstBlock, 32, 16);
        KeyParameter macKey = new KeyParameter(firstBlock, 16, 32);
        Poly1305KeyGenerator.clamp(macKey.getKey());
        mac.init(macKey);
        //end function

        byte out[] = new byte[input.length];
        engine.processBytes(input, 0, input.length, out, 0);
        mac.update(out, 0, out.length);
        mac.doFinal(ciphertextMac, 0);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ciphertextMac);
            outputStream.write(nonce);
            outputStream.write(out);
        } catch (IOException ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return outputStream.toByteArray();
    }

    /**
     * Function that enables crypto class to secure random numbers
     *
     * @param length The length of the desired random number
     * @return A sequence of random numbers with the provided length
     */
    public byte[] createRandom(int length) {
        //create secure random key and nonce
        byte random[] = new byte[length];
        SecureRandom sr = null;
        try {
            sr = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        sr.nextBytes(random);
        return random;
    }

    /**
     * Method for creating a KEY_SIZE-bit secure random key for usage as Message
     * authentication key and data encryption key
     *
     * @return A 256-bit key
     */
    public byte[] createKey() {
        return createRandom(KEY_SIZE);
    }

    /**
     * Method that start the reKeying process between sending en receiving
     * clients
     *
     * @return The new synchronous key between clients
     */
    public byte[] reKey() {
        //additional reKeying operations
        return createKey();
    }

    /**
     * Method for creating a NONCE_SIZE-bit secure random Nonce
     *
     * @return A 64-bit nonce
     */
    public byte[] createNonce() {
        return createRandom(NONCE_SIZE);
    }

    /**
     * Function to remove prepended MAC from input
     *
     * @param input Data from with prepended HMAC should be removed
     * @return input with MAC removed
     */
    private byte[] removeMac(byte[] input) {
        byte data[] = new byte[input.length - HMAC_SIZE];
        System.arraycopy(input, HMAC_SIZE, data, 0, data.length);
        return data;
    }

    /**
     *
     * @param key
     * @param nonce 12 bit nonce!
     * @param data
     * @return
     */
    public byte[] encryptWithAESGCM(byte[] key, byte[] nonce, byte[] data) {
        // encrypt
        AEADParameters parameters = new AEADParameters(new KeyParameter(key), 128, nonce);//, aad);
        GCMBlockCipher gcmEngine = new GCMBlockCipher(new AESFastEngine());
        gcmEngine.init(true, parameters);

        byte[] encMsg = new byte[gcmEngine.getOutputSize(data.length)];
        int encLen = gcmEngine.processBytes(data, 0, data.length, encMsg, 0);

        try {
            encLen += gcmEngine.doFinal(encMsg, encLen);
        } catch (IllegalStateException | InvalidCipherTextException ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }

        return prependNonce(nonce, encMsg);
    }

    /**
     * 12 bit nonce!
     *
     * @param key
     * @param data
     * @param nonce
     * @return
     */
    public byte[] decryptWithAESGCM(byte[] key, byte[] nonce, byte[] data) {
        AEADParameters parameters = new AEADParameters(
                new KeyParameter(key), 128, nonce);//, aad);
        GCMBlockCipher gcmEngine = new GCMBlockCipher(new AESFastEngine());
        gcmEngine.init(false, parameters);

        byte[] decMsg = new byte[gcmEngine.getOutputSize(data.length)];
        int decLen = gcmEngine.processBytes(data, 0, data.length,
                decMsg, 0);
        try {
            decLen += gcmEngine.doFinal(decMsg, decLen);
        } catch (IllegalStateException | InvalidCipherTextException ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return decMsg;
    }

    public void setCipher(int cipher) {
        switch (cipher) {
            case 0:
                NONCE_SIZE = 12;
                HMAC_SIZE = 0;
                KEY_SIZE = 16;
                CRYPTO_HEADER_SIZE = NONCE_SIZE + HMAC_SIZE;
                MESSAGE_FORMAT = 0;
                break;

            case 1:
                NONCE_SIZE = 12;
                HMAC_SIZE = 0;
                KEY_SIZE = 32;
                CRYPTO_HEADER_SIZE = NONCE_SIZE + HMAC_SIZE;
                MESSAGE_FORMAT = 1;
                break;

            case 2:
                NONCE_SIZE = 8;
                HMAC_SIZE = 32;
                KEY_SIZE = 32;
                CRYPTO_HEADER_SIZE = NONCE_SIZE + HMAC_SIZE;
                CHACHA_ROUNDS = 20;
                MESSAGE_FORMAT = 2;
                break;

            case 3:
                NONCE_SIZE = 8;
                HMAC_SIZE = 32;
                KEY_SIZE = 32;
                CRYPTO_HEADER_SIZE = NONCE_SIZE + HMAC_SIZE;
                CHACHA_ROUNDS = 12;
                MESSAGE_FORMAT = 3;
                break;

            case 4:
                NONCE_SIZE = 8;
                HMAC_SIZE = 16;
                KEY_SIZE = 32;
                CRYPTO_HEADER_SIZE = NONCE_SIZE + HMAC_SIZE;
                CHACHA_ROUNDS = 20;
                MESSAGE_FORMAT = 4;
                break;

            case 5:
                NONCE_SIZE = 16;
                HMAC_SIZE = 32;
                KEY_SIZE = 32;
                CRYPTO_HEADER_SIZE = NONCE_SIZE + HMAC_SIZE;
                MESSAGE_FORMAT = 5;
                break;

            default:
                System.out.println("invalid cipher choice");
                break;
        }
    }

    public byte[] encryptMessage(byte[] key, byte[] data) {
        byte[] nonce = createNonce();
        switch (MESSAGE_FORMAT) {
            case 0:
                return encryptWithAESGCM(key, nonce, data);

            case 1:
                return encryptWithAESGCM(key, nonce, data);

            case 2:
                return encryptWithChaChaHmac(key, nonce, data);

            case 3:
                return encryptWithChaChaHmac(key, nonce, data);

            case 4:
                return encryptWithChaChaPoly(key, nonce, data);

            case 5:
                return encryptWithAESCTR(key, nonce, data);

            default:
                System.out.println("wrong message format");
                System.exit(1);

        }
        return null;
    }

    public byte[] decryptMessage(byte[] key, byte[] data) {
        switch (MESSAGE_FORMAT) {
            //AES_126_GCM
            case 0:
                return decryptWithAESGCM(key, getNonce(data), getData(data));

            //AES_256_GCM
            case 1:
                return decryptWithAESGCM(key, getNonce(data), getData(data));

            //CHACHA20/20_HMAC
            case 2:
                if (verifyMac(key, data, getMac(data), true)) {
                    return encryptWithChaChaHmac(key, getNonce(data), getData(data));
                } else {
                    System.out.println("Mac verification failed");
                    return null;
                }

            //CHACHA20/20_HMAC
            case 3:
                if (verifyMac(key, data, getMac(data), true)) {
                    return encryptWithChaChaHmac(key, getNonce(data), getData(data));
                } else {
                    System.out.println("Mac verification failed");
                    return null;
                }

            case 4:
                return decryptWithChaChaPoly(key, data);

            case 5:
                if (verifyMac(key, data, getMac(data), true)) {
                    return decryptWithAESCTR(key, getNonce(data), getData(data));
                } else {
                    System.out.println("Mac verification failed");
                    return null;
                }

            default:
                System.out.println("wrong message format");
                System.exit(1);

        }
        return null;
    }

    private byte[] encryptWithAESCTR(byte[] key, byte[] nonce, byte[] data) {
        SICBlockCipher ctrEngine = new SICBlockCipher(new AESFastEngine());
        ctrEngine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] ciphertxt = new byte[data.length];
        ctrEngine.processBytes(data, 0, data.length, ciphertxt, 0);

        byte out[] = prependNonce(nonce, ciphertxt);
        return prependMac(generateHMac(key, out), out);
    }

    private byte[] decryptWithAESCTR(byte[] key, byte[] nonce, byte[] data) {
        SICBlockCipher ctrEngine = new SICBlockCipher(new AESFastEngine());
        ctrEngine.init(false, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] out = new byte[data.length];
        ctrEngine.processBytes(data, 0, data.length, out, 0);
        return out;
    }

    public void TLSJCA() {
        try {
            runDemo();
        } catch (Exception ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * Run the demo.
     *
     * Sit in a tight loop, both engines calling wrap/unwrap regardless
     * of whether data is available or not.  We do this until both engines
     * report back they are closed.
     *
     * The main loop handles all of the I/O phases of the SSLEngine's
     * lifetime:
     *
     *     initial handshaking
     *     application data transfer
     *     engine closing
     *
     * One could easily separate these phases into separate
     * sections of code.
     */
    public void runDemo() throws Exception {
        //constructor
        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore ts = KeyStore.getInstance("JKS");

        char[] passphrase = "passphrase".toCharArray();

        ks.load(new FileInputStream(keyStoreFile), passphrase);
        ts.load(new FileInputStream(trustStoreFile), passphrase);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, passphrase);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext sslCtx = SSLContext.getInstance("TLS");

        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        sslc = sslCtx;
        //end constructor

        boolean dataDone = false;

        createSSLEngines();
        createBuffers();

        SSLEngineResult clientResult;   // results from client's last operation
        SSLEngineResult serverResult;   // results from server's last operation

        /*
         * Examining the SSLEngineResults could be much more involved,
         * and may alter the overall flow of the application.
         *
         * For example, if we received a BUFFER_OVERFLOW when trying
         * to write to the output pipe, we could reallocate a larger
         * pipe, but instead we wait for the peer to drain it.
         */
        while (!isEngineClosed(clientEngine)
                || !isEngineClosed(serverEngine)) {

            log("================");

            clientResult = clientEngine.wrap(clientOut, cTOs);
            log("client wrap: ", clientResult);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.wrap(serverOut, sTOc);
            log("server wrap: ", serverResult);
            runDelegatedTasks(serverResult, serverEngine);

            cTOs.flip();
            sTOc.flip();

            log("----");

            clientResult = clientEngine.unwrap(sTOc, clientIn);
            log("client unwrap: ", clientResult);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.unwrap(cTOs, serverIn);
            log("server unwrap: ", serverResult);
            runDelegatedTasks(serverResult, serverEngine);

            cTOs.compact();
            sTOc.compact();

            /*
             * After we've transfered all application data between the client
             * and server, we close the clientEngine's outbound stream.
             * This generates a close_notify handshake message, which the
             * server engine receives and responds by closing itself.
             *
             * In normal operation, each SSLEngine should call
             * closeOutbound().  To protect against truncation attacks,
             * SSLEngine.closeInbound() should be called whenever it has
             * determined that no more input data will ever be
             * available (say a closed input stream).
             */
            if (!dataDone && (clientOut.limit() == serverIn.position())
                    && (serverOut.limit() == clientIn.position())) {

                /*
                 * A sanity check to ensure we got what was sent.
                 */
                checkTransfer(serverOut, clientIn);
                checkTransfer(clientOut, serverIn);

                log("\tClosing clientEngine's *OUTBOUND*...");
                clientEngine.closeOutbound();
                // serverEngine.closeOutbound();
                dataDone = true;
            }
        }
    }

    /*
     * Using the SSLContext created during object creation,
     * create/configure the SSLEngines we'll use for this demo.
     */
    private void createSSLEngines() throws Exception {
        /*
         * Configure the serverEngine to act as a server in the SSL/TLS
         * handshake.  Also, require SSL client authentication.
         */
        serverEngine = sslc.createSSLEngine();
        serverEngine.setUseClientMode(false);
        serverEngine.setNeedClientAuth(true);

        /*
         * Similar to above, but using client mode instead.
         */
        clientEngine = sslc.createSSLEngine("client", 80);
        clientEngine.setUseClientMode(true);
    }

    /*
     * Create and size the buffers appropriately.
     */
    private void createBuffers() {

        /*
         * We'll assume the buffer sizes are the same
         * between client and server.
         */
        SSLSession session = clientEngine.getSession();
        int appBufferMax = session.getApplicationBufferSize();
        int netBufferMax = session.getPacketBufferSize();

        /*
         * We'll make the input buffers a bit bigger than the max needed
         * size, so that unwrap()s following a successful data transfer
         * won't generate BUFFER_OVERFLOWS.
         *
         * We'll use a mix of direct and indirect ByteBuffers for
         * tutorial purposes only.  In reality, only use direct
         * ByteBuffers when they give a clear performance enhancement.
         */
        clientIn = ByteBuffer.allocate(appBufferMax + 50);
        serverIn = ByteBuffer.allocate(appBufferMax + 50);

        cTOs = ByteBuffer.allocateDirect(netBufferMax);
        sTOc = ByteBuffer.allocateDirect(netBufferMax);

        clientOut = ByteBuffer.wrap("Hi Server, I'm Client".getBytes());
        serverOut = ByteBuffer.wrap("Hello Client, I'm Server".getBytes());
    }

    /*
     * If the result indicates that we have outstanding tasks to do,
     * go ahead and run them in this thread.
     */
    private static void runDelegatedTasks(SSLEngineResult result,
            SSLEngine engine) throws Exception {

        if (result.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                log("\trunning delegated task...");
                runnable.run();
            }
            HandshakeStatus hsStatus = engine.getHandshakeStatus();
            if (hsStatus == HandshakeStatus.NEED_TASK) {
                throw new Exception(
                        "handshake shouldn't need additional tasks");
            }
            log("\tnew HandshakeStatus: " + hsStatus);
        }
    }

    private static boolean isEngineClosed(SSLEngine engine) {
        return (engine.isOutboundDone() && engine.isInboundDone());
    }

    /*
     * Simple check to make sure everything came across as expected.
     */
    private static void checkTransfer(ByteBuffer a, ByteBuffer b)
            throws Exception {
        a.flip();
        b.flip();

        if (!a.equals(b)) {
            throw new Exception("Data didn't transfer cleanly");
        } else {
            log("\tData transferred cleanly");
        }

        a.position(a.limit());
        b.position(b.limit());
        a.limit(a.capacity());
        b.limit(b.capacity());
    }

    /*
     * Logging code
     */
    private static boolean resultOnce = true;

    private static void log(String str, SSLEngineResult result) {
        if (!logging) {
            return;
        }
        if (resultOnce) {
            resultOnce = false;
            System.out.println("The format of the SSLEngineResult is: \n"
                    + "\t\"getStatus() / getHandshakeStatus()\" +\n"
                    + "\t\"bytesConsumed() / bytesProduced()\"\n");
        }
        HandshakeStatus hsStatus = result.getHandshakeStatus();
        log(str
                + result.getStatus() + "/" + hsStatus + ", "
                + result.bytesConsumed() + "/" + result.bytesProduced()
                + " bytes");
        if (hsStatus == HandshakeStatus.FINISHED) {
            log("\t...ready for application data");
        }
    }

    private static void log(String str) {
        if (logging) {
            System.out.println(str);
        }
    }
}
