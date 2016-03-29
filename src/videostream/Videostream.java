package videostream;

import java.io.IOException;
import static java.lang.Thread.sleep;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.opencv.core.*;
import org.opencv.videoio.*;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class Videostream {

    static {
        // Load the native OpenCV library
        System.loadLibrary(Core.NATIVE_LIBRARY_NAME);
    }

    public static void main(String[] args){
        Videostream stream = new Videostream();
        Crypto crypt = new Crypto();            
        
        byte key[] = crypt.createRandom(32);
        byte nonce[] = crypt.createRandom(8);
        
        //encrypt test string with key and nonce
        String test = "oke oke oke";
        byte out[]=new byte[test.length()];
        out=crypt.ChaCha(key,nonce,(byte[])test.getBytes(),true);
        System.out.println("Ciphertext: "+printHexBinary(out));
        
        try {
            out=crypt.addMac(key, out);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Videostream.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Videostream.class.getName()).log(Level.SEVERE, null, ex);
        }
        //decrypt test string with same key and nonce
        //System.out.println(new String(crypt.ChaCha(key,nonce,out,true)));
        //out=crypt.ChaCha(key,nonce,out,true);
        
        //split array
        byte[] source = new byte[out.length];
        byte[] part1 = new byte[32];
        byte[] part2 = new byte[out.length-part1.length];

        System.arraycopy(out, 0, part1, 0, part1.length);
        System.arraycopy(out, part1.length, part2, 0, part2.length);
        
        System.out.println("SHA256:" +printHexBinary(part1));
        System.out.println("Decoded PLAINTEXT:"+new String(crypt.ChaCha(key,nonce,part2,true)));

       
        
        onvifControl onvifcamera = new onvifControl();
        try {
            System.out.println("Attempting autoconnect on IP:PORT");
            onvifcamera.getSystemDateAndTime("68.228.0.35:8082");
            onvifcamera.getSystemDeviceInformation("68.228.0.35:8082");
            onvifcamera.getCapabilities("68.228.0.35:8082");
        } catch (IOException ex) {
            Logger.getLogger(Videostream.class.getName()).log(Level.SEVERE, null, ex);     
        }
         
        //stream.displayVideo("http://85.173.183.13/image1");
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
            /* TEST URLS
            "rtsp://wowzaec2demo.streamlock.net/vod/mp4:BigBuckBunny_115k.mov"
            "http://administrator:thales@192.168.50.253/cgi-bin/nphcontinuousserverpush"
            http://ak7.picdn.net/shutterstock/videos/2487797/preview/stock-footage-digital-countdown-timer-in-blue-color-over-black-background.mp4
            */     
       
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
}
