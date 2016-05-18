package videostream;

import java.io.IOException;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.opencv.core.*;
import org.opencv.videoio.*;
import static java.lang.Thread.sleep;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;
import java.util.logging.Logger;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class Videostream {

    //debug option
    public static final boolean debug = false;
    private Crypto crypt = new Crypto();

    static {
        // Load the native OpenCV library
        System.loadLibrary(Core.NATIVE_LIBRARY_NAME);
    }

    public static void main(String[] args) {
        Videostream stream = new Videostream();
        //stream.streamClient();
        stream.receiveClient();

        /*onvifControl onvifcamera = new onvifControl();
            try {
            System.out.println("Attempting autoconnect on IP:PORT");
            onvifcamera.getSystemDateAndTime("68.228.0.35:8082");
            onvifcamera.getSystemDeviceInformation("68.228.0.35:8082");
            onvifcamera.getCapabilities("68.228.0.35:8082");
            } catch (IOException ex) {
            Logger.getLogger(Videostream.class.getName()).log(Level.SEVERE, null, ex);
            }*/
        //stream.displayVideo("C:\\Libs\\opencv\\sources\\samples\\cpp\\tutorial_code\\HighGUI\\video-input-psnr-ssim\\video\\Megamind.avi");
        //stream.displayVideo("admin:admin@http://85.173.183.13/image1");
        //stream.displayVideo("http://d3macfshcnzosd.cloudfront.net/047802938_main_xxl.mp4");
        //stream.displayVideo("http://ak7.picdn.net/shutterstock/videos/2487797/preview/stock-footage-digital-countdown-timer-in-blue-color-over-black-background.mp4");
        //stream.displayVideo("http://administrator:thales@192.168.50.253/cgi-bin/nphcontinuousserverpush");
        /* TEST URLS
            "rtsp://wowzaec2demo.streamlock.net/vod/mp4:BigBuckBunny_115k.mov"
            "http://administrator:thales@192.168.50.253/cgi-bin/nphcontinuousserverpush"
            http://ak7.picdn.net/shutterstock/videos/2487797/preview/stock-footage-digital-countdown-timer-in-blue-color-over-black-background.mp4
         */
        //stream.displayVideo("http://85.173.183.13/image1");
        //stream.displayVideo("http://d3macfshcnzosd.cloudfront.net/047802938_main_xxl.mp4");
        //stream.displayVideo("http://ak7.picdn.net/shutterstock/videos/2487797/preview/stock-footage-digital-countdown-timer-in-blue-color-over-black-background.mp4");
        //stream.displayVideo("http://administrator:thales@192.168.50.253/cgi-bin/nphcontinuousserverpush");
    }

    public void streamClient() {
        crypt.setCipher(Crypto.CHACHA20_POLY);
        String[] allowed = {"130.161.177.182", "20", "130.161.177.92", "3600","130.161.177.117","40"};
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
        smallestTime = smallestTime>1800 ? 1800 : smallestTime;
        System.out.println("Rekeying interval set at "+Math.round(smallestTime/60)+" minutes "+ smallestTime%60+" seconds");
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                crypt.reKey();
                System.out.println("require rekey, new symmetric crypto key: " + printHexBinary(crypt.getKey()));
            }
        }, smallestTime * 1000, smallestTime * 1000);

        displayVideo("rtsp://wowzaec2demo.streamlock.net/vod/mp4:BigBuckBunny_115k.mov");

    }

    public void receiveClient() {
        //initial key exchange to start
        try {
            crypt.exchangeKeyClient("130.161.177.117");
            System.out.println("Symmetric crypto key: " + printHexBinary(crypt.getKey()));
        }
        catch (Exception ex) {
            Logger.getLogger(Videostream.class.getName()).log(Level.SEVERE, null, ex);
        } 
        Receiver receiver = new Receiver();
        receiver.receiveImages("224.1.1.1", 4446);
    }

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

    public void testCrypto() {
        Crypto crypt = new Crypto();
        Random r = new Random();
        byte key[];
        //byte key[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes();
        double samples = 100;
        double avglength = 0;
        long runTime0 = 0;
        long runTime1 = 0;
        long runTime2 = 0;
        long runTime3 = 0;
        long runTime4 = 0;
        long runTime5 = 0;

        for (int i = 0; i < samples; i++) {
            try {
                //generate random data of random size to test
                byte[] data = crypt.createRandom(10000);//r.nextInt(MulticastServer.DATAGRAM_MAX_SIZE));
                avglength += data.length;
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
                
                //start ChaCha20/12 performance test
                crypt.setCipher(Crypto.CHACHA20_POLY);
                long startTime4 = System.nanoTime();
                byte[] ciphertxt4 = crypt.encryptMessage(data);
                key = crypt.getKey();
                crypt.decryptMessage(key, ciphertxt4);
                runTime4 += System.nanoTime() - startTime4;
                
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
