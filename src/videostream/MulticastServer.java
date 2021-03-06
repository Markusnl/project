/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package videostream;

import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.UnknownHostException;
import java.util.Iterator;
import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import org.opencv.core.Mat;


class MulticastServer implements Runnable {

    /* Flags and sizes */
    public static float quality = 0.75f;
    public static int HEADER_SIZE = 8;
    public static int MAX_PACKETS = 255;
    public static int SESSION_START = 128;
    public static int SESSION_END = 64;
    public static int CRYPTO_HEADER = 40;
    public static int DATAGRAM_MAX_SIZE = 65507 - HEADER_SIZE - CRYPTO_HEADER;
    public static int MAX_SESSION_NUMBER = 255;
    public static String OUTPUT_FORMAT = "jpg";

    protected DatagramSocket socket = null;
    protected boolean running = true;
    private Mat toSend = null;

    //constructor
    public MulticastServer(int port) {
    }

    @Override
    public synchronized void run() {
        int sessionNumber = 0;
        Crypto crypt = new Crypto();

        while (true) {
            try {
                wait();
                /* Get image or screenshot */
                byte[] imageByteArray = matToByteArray(toSend, OUTPUT_FORMAT);
                int packets = (int) Math.ceil(imageByteArray.length / (float) DATAGRAM_MAX_SIZE);

                /* If image has more than MAX_PACKETS slices -> error */
                if (packets > MAX_PACKETS) {
                    System.out.println("Image is too large to be transmitted!");
                    System.exit(-1);
                }

                /* Loop through slices */
                for (int i = 0; i <= packets; i++) {
                    int flags = 0;
                    flags = i == 0 ? flags | SESSION_START : flags;
                    flags = (i + 1) * DATAGRAM_MAX_SIZE > imageByteArray.length ? flags | SESSION_END : flags;

                    int size = (flags & SESSION_END) != SESSION_END ? DATAGRAM_MAX_SIZE : imageByteArray.length - i * DATAGRAM_MAX_SIZE;

                    /* Set additional header */
                    byte[] data = new byte[HEADER_SIZE + size];
                    data[0] = (byte) flags;
                    data[1] = (byte) sessionNumber;
                    data[2] = (byte) packets;
                    data[3] = (byte) (DATAGRAM_MAX_SIZE >> 8);
                    data[4] = (byte) DATAGRAM_MAX_SIZE;
                    data[5] = (byte) i;
                    data[6] = (byte) (size >> 8);
                    data[7] = (byte) size;

                    /* Copy current slice to byte array */
                    System.arraycopy(imageByteArray, i * DATAGRAM_MAX_SIZE, data, HEADER_SIZE, size);

                    crypt.setCipher(Crypto.CHACHA20_POLY);
                    byte[] ciphertext = crypt.encryptMessage(data);

                    //send data
                    sendImage(ciphertext, "224.1.1.1", 4446);

                    /* Leave loop if last slice has been sent */
                    if ((flags & SESSION_END) == SESSION_END) {
                        break;
                    }
                }
                /* Increase session number */
                sessionNumber = sessionNumber < MAX_SESSION_NUMBER ? ++sessionNumber : 0;

            } catch (NullPointerException e) {
                System.out.println("No image to send");
            } catch (InterruptedException ex) {
                System.out.println("Threading error");
            } catch (IOException ex) {
                System.out.println("Image conversion error ");
            }
        }
    }

    //image to send
    public synchronized void setImage(Mat m) {
        toSend = m;
        notifyAll();
    }

    /**
     * Transforms an OpenCV mat to a byte array
     * @param m The mat to transform
     * @param format The desired format
     * @return The mat transformed to a byte array
     * @throws IOException 
     */
    public byte[] matToByteArray(Mat m, String format) throws IOException {
        // Check if image is grayscale or color
        int type = BufferedImage.TYPE_BYTE_GRAY;
        if (m.channels() > 1) {
            type = BufferedImage.TYPE_3BYTE_BGR;
        }
        // Transfer bytes from Mat to BufferedImage
        int bufferSize = m.channels() * m.cols() * m.rows();
        byte[] b = new byte[bufferSize];
        m.get(0, 0, b); // get all the pixels
        BufferedImage image = new BufferedImage(m.cols(), m.rows(), type);
        final byte[] targetPixels = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
        System.arraycopy(b, 0, targetPixels, 0, b.length);

        Iterator iter = ImageIO.getImageWritersByFormatName("jpeg");
        ImageWriter writer = (ImageWriter) iter.next();
        ImageWriteParam iwp = writer.getDefaultWriteParam();

        iwp.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
        iwp.setCompressionQuality(quality);

        ByteArrayOutputStream baos1 = new ByteArrayOutputStream();
        ImageOutputStream ios = ImageIO.createImageOutputStream(baos1);
        writer.setOutput(ios);
        IIOImage Iimage = new IIOImage(image, null, null);
        writer.write(null, Iimage, iwp);
        writer.dispose();
        
        return baos1.toByteArray();

    }

    /**
     * Sends the image in byte array to the multicast group
     * @param imageData The frame to send
     * @param multicastAddress The desired multicast group
     * @param port The desired port
     * @return True is sending was succesfull, fail otherwise.
     */
    private boolean sendImage(byte[] imageData, String multicastAddress, int port) {
        InetAddress ia;
        boolean ret = false;
        int ttl = 2;

        try {
            ia = InetAddress.getByName(multicastAddress);
        } catch (UnknownHostException e) {
            System.out.println("Unable to reach host");
            return ret;
        }

        MulticastSocket ms = null;
        try {
            ms = new MulticastSocket();
            ms.setTimeToLive(ttl);
            DatagramPacket dp = new DatagramPacket(imageData, imageData.length, ia, port);
            ms.send(dp);
            ret = true;
        } catch (IOException e) {
            e.printStackTrace();
            ret = false;
        } finally {
            if (ms != null) {
                ms.close();
            }
        }

        return ret;
    }

}
