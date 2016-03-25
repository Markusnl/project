package videostream;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Crypto {

    public static void main(String[] args) throws UnknownHostException, IOException, KeyManagementException, NoSuchAlgorithmException
    {   
       // Security.addProvider(new BouncyCastleProvider());

        //BC is the ID for the Bouncy Castle provider;
        if (Security.getProvider("BC") == null){
            System.out.println("Bouncy Castle provider is NOT available");
        }
        else{
            System.out.println("Bouncy Castle provider is available");
        }

        SSLSocketFactoryEx factory = new SSLSocketFactoryEx();
        String[] cipherSuites = factory.GetCipherList();
        System.out.println(Arrays.toString(cipherSuites));

    } //end main
}