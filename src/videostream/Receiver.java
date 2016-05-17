package videostream;

import com.sun.security.ntlm.Client;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JWindow;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

/**
 * Multicast Image Receiver Version: 0.1
 *
 * @author Jochen Luell
 *
 */
public class Receiver implements Runnable {

    /* Flags and sizes */
    public static int HEADER_SIZE = 8;

    public static int SESSION_START = 128;

    public static int SESSION_END = 64;
    public boolean debug = false;

    /*
     * The absolute maximum datagram packet size is 65507, The maximum IP packet
     * size of 65535 minus 20 bytes for the IP header and 8 bytes for the UDP
     * header.
     */
    private static int DATAGRAM_MAX_SIZE = 65507;

    /* Default values */
    //public static String IP_ADDRESS = "225.4.5.6";
    //public static int PORT = 4444;
    JFrame frame;

    boolean fullscreen = false;

    JWindow fullscreenWindow = null;

    Crypto crypt = new Crypto();
    String multicastAddress;
    int port;

    /**
     * Revceive method
     *
     * @param multicastAddress IP multicast adress
     * @param port Port
     */
    public void receiveImages(String multicastAddress, int port) {
        this.multicastAddress = multicastAddress;
        this.port = port;
        new Thread(this).start();
    }
    /*crypt.setCipher(Crypto.CHACHA20_POLY);
     InetAddress ia = null;
     MulticastSocket ms = null;

     //Constuct frame
     JLabel labelImage = new JLabel();
     JLabel windowImage = new JLabel();

     frame = new JFrame("Multicast Image Receiver");
     frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
     frame.getContentPane().add(labelImage);
     frame.setSize(300, 10);
     frame.setVisible(true);

     //Construct full screen window
     fullscreenWindow = new JWindow();
     fullscreenWindow.getContentPane().add(windowImage);

     try {
     // Get address
     ia = InetAddress.getByName(multicastAddress);

     // Setup socket and join group
     ms = new MulticastSocket(port);
     ms.joinGroup(ia);

     int currentSession = -1;
     int slicesStored = 0;
     int[] slicesCol = null;
     byte[] imageData = null;
     boolean sessionAvailable = false;

     // Setup byte array to store data received
     byte[] buffer = new byte[DATAGRAM_MAX_SIZE];
     // Receiving loop

     } catch (IOException e) {
     e.printStackTrace();
     } finally {
     if (ms != null) {
     try {
     //Leave group and close socket
     ms.leaveGroup(ia);
     ms.close();
     } catch (IOException e) {
     }
     }
     }
     }*/

    @Override
    public void run() {
        crypt.setCipher(Crypto.CHACHA20_POLY);
        InetAddress ia = null;
        MulticastSocket ms = null;

        /* Constuct frame */
        JLabel labelImage = new JLabel();
        JLabel windowImage = new JLabel();

        frame = new JFrame("Multicast Image Receiver");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().add(labelImage);
        frame.setSize(300, 10);
        frame.setVisible(true);

        /* Construct full screen window */
        fullscreenWindow = new JWindow();
        fullscreenWindow.getContentPane().add(windowImage);

        try {
            /* Get address */
            ia = InetAddress.getByName(multicastAddress);

            /* Setup socket and join group */
            ms = new MulticastSocket(port);
            ms.joinGroup(ia);

            int currentSession = -1;
            int slicesStored = 0;
            int[] slicesCol = null;
            byte[] imageData = null;
            boolean sessionAvailable = false;

            /* Setup byte array to store data received */
            byte[] buffer = new byte[DATAGRAM_MAX_SIZE];
            /* Receiving loop */

            while (true) {
                /* Receive a UDP packet */
                DatagramPacket dp = new DatagramPacket(buffer, buffer.length);
                ms.receive(dp);
                byte[] data = new byte[dp.getLength()];
                System.arraycopy(dp.getData(), 0, data, 0, dp.getLength());
                byte[] data1 = crypt.decryptMessage(crypt.getKey(), data);

                if (data1 != null) {
                    // Read header infomation
                    short session = (short) (data1[1] & 0xff);
                    short slices = (short) (data1[2] & 0xff);
                    int maxPacketSize = (int) ((data1[3] & 0xff) << 8 | (data1[4] & 0xff)); // mask
                    // the
                    // sign
                    // bit
                    short slice = (short) (data1[5] & 0xff);
                    int size = (int) ((data1[6] & 0xff) << 8 | (data1[7] & 0xff)); // mask
                    // the
                    // sign
                    // bit

                    if (debug) {
                        System.out.println("------------- PACKET -------------");
                        System.out.println("SESSION_START = "
                                + ((data1[0] & SESSION_START) == SESSION_START));
                        System.out.println("SSESSION_END = "
                                + ((data1[0] & SESSION_END) == SESSION_END));
                        System.out.println("SESSION NR = " + session);
                        System.out.println("SLICES = " + slices);
                        System.out.println("MAX PACKET SIZE = " + maxPacketSize);
                        System.out.println("SLICE NR = " + slice);
                        System.out.println("SIZE = " + size);
                        System.out.println("------------- PACKET -------------\n");
                    }

                    // If SESSION_START falg is set, setup start values
                    if ((data1[0] & SESSION_START) == SESSION_START) {
                        if (session != currentSession) {
                            currentSession = session;
                            slicesStored = 0;
                            // Consturct a appropreately sized byte array
                            imageData = new byte[slices * maxPacketSize];
                            slicesCol = new int[slices];
                            sessionAvailable = true;
                        }
                    }

                    // If package belogs to current session //
                    if (sessionAvailable && session == currentSession) {
                        if (slicesCol != null && slicesCol[slice] == 0) {
                            slicesCol[slice] = 1;
                            System.arraycopy(data1, HEADER_SIZE, imageData, slice
                                    * maxPacketSize, size);
                            slicesStored++;
                        }
                    }

                    // If image is complete dispay it //
                    if (slicesStored == slices) {
                        ByteArrayInputStream bis = new ByteArrayInputStream(
                                imageData);
                        BufferedImage image = ImageIO.read(bis);
                        labelImage.setIcon(new ImageIcon(image));
                        windowImage.setIcon(new ImageIcon(image));

                        frame.pack();
                    }

                    if (debug) {
                        System.out.println("STORED SLICES: " + slicesStored);
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (ms != null) {
                try {
                    /* Leave group and close socket */
                    ms.leaveGroup(ia);
                    ms.close();
                } catch (IOException e) {
                }
            }
        }
    }
}