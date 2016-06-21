package videostream;

public class ServerRunnable implements Runnable {

    NioSslServer server;

    /**
     * Thread starting the TLS engine
     *
     * @param ip The IP address the TLS engine will bind to
     * @param port The port the TLS engine will bind to
     */
    public ServerRunnable(String ip, int port) {
        try {
            server = new NioSslServer("TLSv1.2", ip, port);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public void run() {
        try {
            server.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Should be called in order to gracefully stop the server.
     */
    public void stop() {
        server.stop();
    }

    /**
     * Sets the response that should be returned after the TLS handshake
     *
     * @param response The response that should be given after a successfull TLS
     * handshake
     */
    public void setResponse(byte[] response) {
        server.setResponse(response);
    }

    /**
     * Passes the list of allowed parties and their corresponding times to the
     * SSL engine
     *
     * @param allowed The list of allowed parties and their time conform
     * ("party1","time1","party2","time2") etc..
     */
    public void setAllowedPartyTime(String[] allowed) {
        server.setAllowedPartyTime(allowed);
    }

}
