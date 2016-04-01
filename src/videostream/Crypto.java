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
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class Crypto {

    private final int NONCE_SIZE = 8;
    private final int HMAC_SIZE = 32;
    private final int KEY_SIZE = 32;
    private final int CRYPTO_HEADER_SIZE = NONCE_SIZE + HMAC_SIZE;
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
     * Generate a Message Authentication Code from the inputted data and the
     * given synchronous key
     *
     * @param key The synchronous key
     * @param input The data from which to calculate a Message Authentication
     * Code
     * @return The Message authentication code calculated from the input with
     * the given synchronous key
     */
    public byte[] generateMac(byte[] key, byte[] input) {
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
    public byte[] encryptWithChaCha(byte[] key, byte[] nonce, byte[] input) {
        //create chacha engine with key and nonce
        CipherParameters cp = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(cp, nonce);
        StreamCipher engine = new ChaChaEngine();
        engine.init(true, params);

        //encrypt/decrypt and return output
        byte out[] = new byte[input.length];
        engine.processBytes(input, 0, input.length, out, 0);
        return out;
    }

    /**
     * Function that enables crypto class to secure random numbers
     * @param length The length of the desired random number
     * @return A sequence of random numbers with the provided length
     */
    private byte[] createRandom(int length) {
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
     * Method for creating a 256-bit secure random key for usage as Message authentication key and data encryption key
     * @return A 256-bit key
     */
    public byte[] createKey() {
        return createRandom(KEY_SIZE);
    }

    /**
     * Method that start the reKeying process between sending en receiving clients
     * @return The new synchronous key between clients
     */
    public byte[] reKey() {
        //additional reKeying operations
        return createKey();
    }

    /**
     * Method for creating a 64-bit secure random Nonce
     * @return A 64-bit nonce
     */
    public byte[] createNonce() {
        return createRandom(NONCE_SIZE);
    }

    /**
     * Function to remove prepended MAC from input
     * @param input Data from with prepended MACH should be removed
     * @return input with MAC removed
     */
    private byte[] removeMac(byte[] input) {
        byte data[] = new byte[input.length - HMAC_SIZE];
        System.arraycopy(input, HMAC_SIZE, data, 0, data.length);
        return data;
    }

}
