package videostream;

import java.io.IOException;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.opencv.core.*;
import org.opencv.videoio.*;
import static java.lang.Thread.sleep;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class Videostream {

    //debugging variable for program
    public static final boolean debug = false;

    //Crypto object for class
    private Crypto crypt = new Crypto();

    //server address
    public static final String IP_ADDRESS = "130.161.177.84";//"145.24.226.170";//"192.168.50.100";"
    public static final int PORT = 5000;

    //camera login
    public static final String username = "admin";
    public static final String password = "12345";

    // Load the native OpenCV library
    static {
        System.loadLibrary(Core.NATIVE_LIBRARY_NAME);
    }

    /**
     * Entrypoint of the project, specification whether a streaming client or
     * receiving client should be started
     */
    public static void main(String[] args) {
        Videostream stream = new Videostream();
        stream.streamClient("rtsp://wowzaec2demo.streamlock.net/vod/mp4:BigBuckBunny_115k.mov");
        //stream.receiveClient();

        //Example URLS
        /*  
            "http://i.istockimg.com/video_passthrough/71680603/153/71680603.mp4"
            "rtsp://wowzaec2demo.streamlock.net/vod/mp4:BigBuckBunny_115k.mov"
            "http://administrator:thales@192.168.50.253/cgi-bin/nphcontinuousserverpush"
            "http://ak7.picdn.net/shutterstock/videos/2487797/preview/stock-footage-digital-countdown-timer-in-blue-color-over-black-background.mp4"
            "http://administrator:thales@192.168.50.253/cgi-bin/nphcontinuousserverpush"
            "C:\\Libs\\opencv\\sources\\samples\\cpp\\tutorial_code\\HighGUI\\video-input-psnr-ssim\\video\\Megamind.avi"
            "68.228.0.35:8082"
            "192.168.50.10"
         */
    }

    /**
     * Stream Client, sets up the stream and has the option to change the used
     * symmetric cryptographic algorithm and the parties who are allowed to
     * watch the stream.
     *
     * @param mediaUrl the url that should be streamed
     */
    public void streamClient(String mediaUrl) {
        crypt.setCipher(Crypto.CHACHA20_POLY);
        String[] allowed = {"cf947f00247538718d32ec1d093ca8ddcfcaf8aa", "30", "892eb30a57bb487ee7e5c5335b877db2884f4e1d", "3600"};
        crypt.exchangeKeyServer(allowed);
        System.out.println("Symmetric crypto key: " + printHexBinary(crypt.getKey()));
        //get smallest required rekey time
        int smallestTime = Integer.MAX_VALUE;
        for (int i = 1; i < allowed.length; i += 2) {
            if (smallestTime > Integer.valueOf(allowed[i])) {
                smallestTime = Integer.valueOf(allowed[i]);
            }
        }
        //do not allow more time than 30 minutes though
        smallestTime = smallestTime > 1800 ? 1800 : smallestTime;
        System.out.println("Rekeying interval set at " + Math.round(smallestTime / 60) + " minutes " + smallestTime % 60 + " seconds");
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                crypt.reKey();
                System.out.println("require rekey, new symmetric crypto key: " + printHexBinary(crypt.getKey()));
            }
        }, smallestTime * 1000, smallestTime * 1000);

        Vector<String> profiles = null;
        if (validIP(mediaUrl)) {
            OnvifControl onvifcamera = new OnvifControl();
            try {
                System.out.println("Attempting ONVIF autoconnect");
                profiles = onvifcamera.getProfiles(mediaUrl);
            } catch (IOException ex) {
                System.out.println("autoconnect failed");
            }
        }
        //No onvif profile was created
        if (profiles == null || profiles.isEmpty()) {
            displayVideo(mediaUrl);
        } else {
            mediaUrl = "rtsp://" + username + ":" + password + "@" + mediaUrl + "/ONVIF/MediaInput?profile=" + profiles.elementAt(1);
            System.out.println("Trying to connect to: " + mediaUrl);
            displayVideo(mediaUrl);
        }

    }

    /**
     * The receiving client. Receives and plays the stream if he added on the
     * list of allowed clients in the streaming client.
     */
    public void receiveClient() {
        try {
            crypt.exchangeKeyClient(IP_ADDRESS);
            System.out.println("Symmetric crypto key: " + printHexBinary(crypt.getKey()));
        } catch (Exception ex) {
            Logger.getLogger(Videostream.class.getName()).log(Level.SEVERE, null, ex);
        }
        Receiver receiver = new Receiver();
        receiver.receiveImages("224.1.1.1", 4446);
    }

    /**
     * Starts the video capture and the multicast server. Will encrypt data
     * according to the specified algorithm in the streaming client Will also
     * show the captured stream to the streaming client
     *
     * @param location the location of the video
     */
    public void displayVideo(String location) {
        //use ANY to capture video location
        VideoCapture cap = new VideoCapture(location, Videoio.CAP_ANY);
        //Try to start multicast server
        MulticastServer server = new MulticastServer(5000);
        new Thread(server).start();

        // Check if video capturing is enabled
        if (!cap.isOpened()) {
            System.out.println("Unable to open stream");
            System.exit(-1);
        }

        // Matrix for storing image
        Mat image = new Mat();
        // Frame for displaying image
        MyFrame frame = new MyFrame("captured stream");
        frame.setVisible(true);

        //get smallest time frame for rekey
        while (cap.read(image)) {
            //server renders to send image as well
            server.setImage(image);
            //System.out.println(Math.round(cap.get(Videoio.CAP_PROP_FPS)));
            //own render without additional processing
            frame.render(image);

            //manage video fps
            if (cap.get(Videoio.CAP_PROP_FPS) != 0 && !Double.isNaN(cap.get(Videoio.CAP_PROP_FPS))) {
                try {
                    sleep(1000 / (int) Math.round((cap.get(Videoio.CAP_PROP_FPS))));
                } catch (InterruptedException ex) {
                    System.out.println("Error managing fps");
                }
            }
        }

    }

    /**
     * Method used to determine whether a string can be used as an IP-address
     *
     * @param ip The string representation of a possible IP-address
     * @return True is the presented string can be used as an IP-address, false
     * otherwise
     */
    public static boolean validIP(String ip) {
        try {
            if (ip == null || ip.isEmpty()) {
                return false;
            }

            String[] parts = ip.split("\\.");

            //break port of last string section
            if (parts[3].contains(":")) {
                String[] port = parts[3].split("\\:");
                parts[3] = port[0];
                //check if port is valid
                int i = Integer.parseInt(port[1]);
                if (i < 0 || i > 65535) {
                    return false;
                }
            }

            if (parts.length != 4) {
                return false;
            }

            for (String s : parts) {
                int i = Integer.parseInt(s);
                if ((i < 0) || (i > 255)) {
                    return false;
                }
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Method that will encrypt and decrypt messages, used for performance
     * measurements and sanity checks
     */
    public void testCrypto() {
        Random r = new Random();
        byte key[];
        double samples = 10000;
        double avglength = 0;
        long runTime0 = 0;
        long runTime1 = 0;
        long runTime2 = 0;
        long runTime3 = 0;
        long runTime4 = 0;
        long runTime5 = 0;
        crypt.reKey();
        for (int i = 0; i < samples; i++) {
            try {
                //generate random data of random size to test
                byte[] data = crypt.createRandom(10000);//r.nextInt(MulticastServer.DATAGRAM_MAX_SIZE));
                avglength += data.length;

                //start ChaCha20poly performance test
                crypt.setCipher(Crypto.CHACHA20_POLY);
                long startTime4 = System.nanoTime();
                byte[] ciphertxt4 = crypt.encryptMessage(data);
                key = crypt.getKey();
                crypt.decryptMessage(key, ciphertxt4);
                runTime4 += System.nanoTime() - startTime4;

                //start AES GCM performance test
                crypt.setCipher(Crypto.AES_128_GCM);
                long startTime0 = System.nanoTime();
                byte[] ciphertxt0 = crypt.encryptMessage(data);
                key = crypt.getKey();
                crypt.decryptMessage(key, ciphertxt0);
                runTime0 += System.nanoTime() - startTime0;

                //start AES GCM performance test
                crypt.setCipher(Crypto.AES_256_GCM);
                long startTime1 = System.nanoTime();
                byte[] ciphertxt1 = crypt.encryptMessage(data);
                key = crypt.getKey();
                crypt.decryptMessage(key, ciphertxt1);
                runTime1 += System.nanoTime() - startTime1;

                //start Chacha20/20 performance test
                crypt.setCipher(Crypto.CHACHA20_HMAC);
                long startTime2 = System.nanoTime();
                byte[] ciphertxt2 = crypt.encryptMessage(data);
                key = crypt.getKey();
                crypt.decryptMessage(key, ciphertxt2);
                runTime2 += System.nanoTime() - startTime2;

                //start ChaCha20/12 performance test
                crypt.setCipher(Crypto.CHACHA12_HMAC);
                long startTime3 = System.nanoTime();
                byte[] ciphertxt3 = crypt.encryptMessage(data);
                key = crypt.getKey();
                crypt.decryptMessage(key, ciphertxt3);
                runTime3 += System.nanoTime() - startTime3;

                crypt.setCipher(Crypto.AES_256_CTR_HMAC);
                long startTime5 = System.nanoTime();
                byte[] ciphertxt5 = crypt.encryptMessage(data);
                key = crypt.getKey();
                crypt.decryptMessage(key, ciphertxt5);
                runTime5 += System.nanoTime() - startTime5;
            } catch (IOException ex) {
                Logger.getLogger(Videostream.class.getName()).log(Level.SEVERE, null, ex);
            }

        }
        System.out.println("avg message length: " + avglength / samples);
        System.out.println("AVG time AES128GCM: " + TimeUnit.NANOSECONDS.toMillis(runTime0) / samples + " ms");
        System.out.println("AVG time AES256GCM: " + TimeUnit.NANOSECONDS.toMillis(runTime1) / samples + " ms");
        System.out.println("AVG time CHA20/20HMAC: " + TimeUnit.NANOSECONDS.toMillis(runTime2) / samples + " ms");
        System.out.println("AVG time CHA20/12HMAC: " + TimeUnit.NANOSECONDS.toMillis(runTime3) / samples + " ms");
        System.out.println("AVG time CHA20/20POLY: " + TimeUnit.NANOSECONDS.toMillis(runTime4) / samples + " ms");
        System.out.println("AVG time AES256CTRHMAC: " + TimeUnit.NANOSECONDS.toMillis(runTime5) / samples + " ms");
        System.out.println("Cha20/20HMAC is " + ((TimeUnit.NANOSECONDS.toMillis(runTime1) - TimeUnit.NANOSECONDS.toMillis(runTime2)) / (double) TimeUnit.NANOSECONDS.toMillis(runTime2) * 100) + " % faster than AES256GCM");
        System.out.println("Cha20/12HMAC is " + ((TimeUnit.NANOSECONDS.toMillis(runTime0) - TimeUnit.NANOSECONDS.toMillis(runTime3)) / (double) TimeUnit.NANOSECONDS.toMillis(runTime3) * 100) + " % faster than AES128GCM");
        System.out.println("Cha20/12HMAC is " + ((TimeUnit.NANOSECONDS.toMillis(runTime2) - TimeUnit.NANOSECONDS.toMillis(runTime3)) / (double) TimeUnit.NANOSECONDS.toMillis(runTime3) * 100) + " % faster than ChaCha20/20");
        System.out.println("Cha20/20POLY is " + ((TimeUnit.NANOSECONDS.toMillis(runTime1) - TimeUnit.NANOSECONDS.toMillis(runTime4)) / (double) TimeUnit.NANOSECONDS.toMillis(runTime4) * 100) + " % faster than AES256GCM");

    }
}
