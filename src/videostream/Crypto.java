package videostream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class Crypto {

    public byte[] addMac(byte[] key, byte[] data) throws NoSuchAlgorithmException, IOException {
        Digest digest = new SHA256Digest();
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        hmac.doFinal(resBuf, 0);
        String resStr = new String(Hex.encode(resBuf)); // Contains final usable value
        
        //append mac to data
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(resBuf);
        outputStream.write(data);
        byte out[] = outputStream.toByteArray();
        
        return out;
    }

    public byte[] ChaCha(byte[] key, byte[] nonce, byte[] in, boolean encrypt) {
        //create chacha engine with key and IV
        CipherParameters cp = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(cp, nonce);
        StreamCipher engine = new ChaChaEngine();
        engine.init(encrypt, params);

        //encrypt/decrypt and return output
        byte out[] = new byte[in.length];
        engine.processBytes(in, 0, in.length, out, 0);
        return out;
    }

    public byte[] createRandom(int length) {
        //create secure random key and nonce
        byte random[] = new byte[length];
        SecureRandom sr = null;
        try {
            sr = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Security provider not available");
        }
        sr.nextBytes(random);
        return random;
    }

}
