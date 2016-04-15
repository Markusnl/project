package videostream;

import java.io.ByteArrayOutputStream;
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
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class Crypto {

    //cipher enum
    public final static int AES_128_GCM = 0;
    public final static int AES_256_GCM = 1;
    public final static int CHACHA20_HMAC = 2;
    public final static int CHACHA12_HMAC = 3;
    public final static int CHACHA20_POLY = 4;

    //default AES_256_GCM
    private int NONCE_SIZE = 12;
    private int HMAC_SIZE = 0;
    private int KEY_SIZE = 32;
    private int CRYPTO_HEADER_SIZE = NONCE_SIZE + HMAC_SIZE;
    private int MESSAGE_FORMAT = 1;
    private int CHACHA_ROUNDS = 20;

    //debug option
    private final boolean debug = false;

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
    private byte[] encryptWithChaCha(byte[] key, byte[] nonce, byte[] input) {
        //create chacha engine with key and nonce
        CipherParameters cp = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(cp, nonce);
        StreamCipher engine = new ChaChaEngine(CHACHA_ROUNDS);
        engine.init(true, params);

        //encrypt/decrypt and return output
        byte ciphertxt[] = new byte[input.length];
        engine.processBytes(input, 0, input.length, ciphertxt, 0);

        byte out[]=prependNonce(nonce,ciphertxt);
        return prependMac(generateHMac(key,out),out);
    }

    public byte[] decryptWithChaChaPoly(byte[] key, byte[] input) {
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

        byte out[] = new byte[input.length-CRYPTO_HEADER_SIZE];
        byte data []= getData(input);

        
        //update mac with data and decrypt data
        mac.update(data,0,data.length);
        engine.processBytes(data, 0,data.length, out, 0);

        // check if the two MACs match
        mac.doFinal(computedMac, 0);
        if(Arrays.equals(receivedMac, computedMac))
            return out;
        else
            return null;
    }

    //key, getNonce(data), getData(data));
    public byte[] encryptWithChaChaPoly(byte[] key, byte[] nonce, byte[] input) {
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
    private byte[] encryptWithAESGCM(byte[] key, byte[] nonce, byte[] data) {
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
    private byte[] decryptWithAESGCM(byte[] key, byte[] nonce, byte[] data) {
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
                return encryptWithChaCha(key, nonce, data);


            case 3:
                return encryptWithChaCha(key, nonce, data);
                              
             case 4:
                return encryptWithChaChaPoly(key, nonce, data);              

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
                    return encryptWithChaCha(key, getNonce(data), getData(data));
                } else {
                    System.out.println("Mac verification failed");
                    return null;
                }

            //CHACHA20/20_HMAC
            case 3:
                if (verifyMac(key, data, getMac(data), true)) {
                    return encryptWithChaCha(key, getNonce(data), getData(data));
                } else {
                    System.out.println("Mac verification failed");
                    return null;
                }
                
            case 4:
                return decryptWithChaChaPoly(key,data);

            default:
                System.out.println("wrong message format");
                System.exit(1);

        }
        return null;
    }
}
