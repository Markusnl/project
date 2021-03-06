package videostream;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

public class NioSslClient extends NioSslPeer {

    /**
     * The remote address of the server this client is configured to connect to.
     */
    private String remoteAddress;

    /**
     * The port of the server this client is configured to connect to.
     */
    private int port;

    /**
     * The engine that will be used to encrypt/decrypt data between this client
     * and the server.
     */
    private SSLEngine engine;

    /**
     * The socket channel that will be used as the transport link between this
     * client and the server.
     */
    private SocketChannel socketChannel;

    /**
     * Initiates the engine to run as a client using peer information, and
     * allocates space for the buffers that will be used by the engine.
     *
     * @param protocol The SSL/TLS protocol to be used. Java 1.6 will only run
     * with up to TLSv1 protocol. Java 1.7 or higher also supports TLSv1.1 and
     * TLSv1.2 protocols.
     * @param remoteAddress The IP address of the peer.
     * @param port The peer's port that will be used.
     * @throws Exception
     */
    public NioSslClient(String protocol, String remoteAddress, int port) throws Exception {
        this.remoteAddress = remoteAddress;
        this.port = port;

        SSLContext context = SSLContext.getInstance(protocol);
        context.init(createKeyManagers("certs/EC256/Client/Clientkey2.jks", "thales", "thales"), createTrustManagers("certs/EC256/Trusted.jks", "thales"), new SecureRandom());
        engine = context.createSSLEngine(remoteAddress, port);
        engine.setEnabledCipherSuites(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"});
        engine.setUseClientMode(true);

        SSLSession session = engine.getSession();
        myAppData = ByteBuffer.allocate(1024);
        myNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        peerAppData = ByteBuffer.allocate(1024);
        peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
    }

    /**
     * Opens a socket channel to communicate with the configured server and
     * tries to complete the handshake protocol.
     *
     * @return True if client established a connection with the server, false
     * otherwise.
     * @throws Exception
     */
    public boolean connect() throws Exception {
        socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(false);
        socketChannel.connect(new InetSocketAddress(remoteAddress, port));
        while (!socketChannel.finishConnect()) {
            // can do something here...
        }

        engine.beginHandshake();
        return doHandshake(socketChannel, engine);
    }

    /**
     * Public method to send a message to the server.
     *
     * @param message - message to be sent to the server.
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    public void write(byte[] message) throws IOException {
        write(socketChannel, engine, message);
    }

    /**
     * Implements the write method that sends a message to the server the client
     * is connected to, but should not be called by the user, since socket
     * channel and engine are inner class' variables.
     * {@link NioSslClient#write(String)} should be called instead.
     *
     * @param message - message to be sent to the server.
     * @param engine - the engine used for encryption/decryption of the data
     * exchanged between the two peers.
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    @Override
    protected void write(SocketChannel socketChannel, SSLEngine engine, byte[] message) throws IOException {

        //System.out.println("About to write to the server...");
        myAppData.clear();
        myAppData.put(message);
        myAppData.flip();
        while (myAppData.hasRemaining()) {
            // The loop has a meaning for (outgoing) messages larger than 16KB.
            // Every wrap call will remove 16KB from the original message and send it to the remote peer.
            myNetData.clear();
            SSLEngineResult result = engine.wrap(myAppData, myNetData);
            switch (result.getStatus()) {
                case OK:
                    myNetData.flip();
                    while (myNetData.hasRemaining()) {
                        socketChannel.write(myNetData);
                    }
                    //   System.out.println("Message sent to the server: " + printHexBinary(message));
                    break;
                case BUFFER_OVERFLOW:
                    myNetData = enlargePacketBuffer(engine, myNetData);
                    break;
                case BUFFER_UNDERFLOW:
                    throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
                case CLOSED:
                    closeConnection(socketChannel, engine);
                    return;
                default:
                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
            }
        }

    }

    /**
     * Public method to try to read from the server.
     *
     * @throws Exception
     */
    public void read() throws Exception {
        read(socketChannel, engine);
    }

    /**
     * Will wait for response from the remote peer, until it actually gets
     * something. Uses {@link SocketChannel#read(ByteBuffer)}, which is
     * non-blocking, and if it gets nothing from the peer, waits for
     * {@code waitToReadMillis} and tries again.
     * <p/>
     * Just like {@link NioSslClient#read(SocketChannel, SSLEngine)} it uses
     * inner class' socket channel and engine and should not be used by the
     * client. {@link NioSslClient#read()} should be called instead.
     *
     * @param message - message to be sent to the server.
     * @param engine - the engine used for encryption/decryption of the data
     * exchanged between the two peers.
     * @throws Exception
     */
    @Override
    protected void read(SocketChannel socketChannel, SSLEngine engine) throws Exception {

        //  System.out.println("About to read from the server...");
        peerNetData.clear();
        int waitToReadMillis = 50;
        boolean exitReadLoop = false;
        while (!exitReadLoop) {
            int bytesRead = socketChannel.read(peerNetData);
            if (bytesRead > 0) {
                peerNetData.flip();
                while (peerNetData.hasRemaining()) {
                    peerAppData.clear();
                    SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
                    switch (result.getStatus()) {
                        case OK:
                            peerAppData.flip();
                            //System.out.println("Server response: " + new String(peerAppData.array()));
                            parseMessage(peerAppData.array());
                            exitReadLoop = true;
                            break;
                        case BUFFER_OVERFLOW:
                            peerAppData = enlargeApplicationBuffer(engine, peerAppData);
                            break;
                        case BUFFER_UNDERFLOW:
                            peerNetData = handleBufferUnderflow(engine, peerNetData);
                            break;
                        case CLOSED:
                            closeConnection(socketChannel, engine);
                            return;
                        default:
                            throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                    }
                }
            } else if (bytesRead < 0) {
                handleEndOfStream(socketChannel, engine);
                return;
            }
            Thread.sleep(waitToReadMillis);
        }
    }

    /**
     * Should be called when the client wants to explicitly close the connection
     * to the server.
     *
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    public void shutdown() throws IOException {
        closeConnection(socketChannel, engine);
        executor.shutdown();
    }

    /**
     * Method that will parse the received message from the server and set the key accordingly
     * @param array The message returned
     */
    private void parseMessage(byte[] array) {
        String message = null;
        byte[] key = null;
        int cipher = -1;
        try {
            message = new String(array, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(NioSslClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        //AES_128_GCM = 0;
        if (message.startsWith("0:")) {
            key = new byte[16];
            System.arraycopy(array, 2, key, 0, key.length);
            cipher = 0;
        }
        //AES_256_GCM = 1;
        if (message.startsWith("1:")) {
            key = new byte[32];
            System.arraycopy(array, 2, key, 0, key.length);
            cipher = 1;
        }
        //CHACHA20_HMAC = 2;
        if (message.startsWith("2:")) {
            key = new byte[32];
            System.arraycopy(array, 2, key, 0, key.length);
            cipher = 2;
        }
        //CHACHA12_HMAC = 3;
        if (message.startsWith("3:")) {
            key = new byte[32];
            System.arraycopy(array, 2, key, 0, key.length);
            cipher = 3;
        }
        //CHACHA20_POLY = 4;
        if (message.startsWith("4:")) {
            key = new byte[32];
            System.arraycopy(array, 2, key, 0, key.length);
            cipher = 4;
        }
        //AES_256_CTR_HMAC = 5;
        if (message.startsWith("5:")) {
            key = new byte[32];
            System.arraycopy(array, 2, key, 0, key.length);
            cipher = 5;
        }
        Crypto.setKey(key);
    }

}
