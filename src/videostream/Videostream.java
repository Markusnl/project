package videostream;

import java.io.IOException;
import static java.lang.Thread.sleep;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.soap.SOAPException;
import org.opencv.core.*;
import org.opencv.videoio.*;

public class Videostream {

    static {
        // Load the native OpenCV library
        System.loadLibrary(Core.NATIVE_LIBRARY_NAME);
    }

    public static void main(String[] args) {
        Videostream stream = new Videostream();
        //stream.displayVideo("http://85.173.183.13/image1");
        //stream.displayVideo("http://d3macfshcnzosd.cloudfront.net/047802938_main_xxl.mp4");
        //stream.displayVideo("http://ak7.picdn.net/shutterstock/videos/2487797/preview/stock-footage-digital-countdown-timer-in-blue-color-over-black-background.mp4");
        //stream.displayVideo("http://administrator:thales@192.168.50.253/cgi-bin/nphcontinuousserverpush");
        /* TEST URLS
            "rtsp://wowzaec2demo.streamlock.net/vod/mp4:BigBuckBunny_115k.mov"  
            "http://administrator:thales@192.168.50.253/cgi-bin/nphcontinuousserverpush"
        http://ak7.picdn.net/shutterstock/videos/2487797/preview/stock-footage-digital-countdown-timer-in-blue-color-over-black-background.mp4  
         */
        onvifControl onvifcamera = new onvifControl();
        try {
            System.out.println("Attempting autoconnect on IP:PORT");
            onvifcamera.getSystemDateAndTime("68.228.0.35:8082");
            onvifcamera.getSysemDeviceInformation("68.228.0.35:8082");  
            onvifcamera.getCapabilities("68.228.0.35:8082");
        } catch (SOAPException e) {
            Logger.getLogger(onvifControl.class.getName()).log(Level.SEVERE, null, e);
        } catch (IOException ex) {
            Logger.getLogger(Videostream.class.getName()).log(Level.SEVERE, null, ex);     
        }
        
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