package videostream;

public class ServerRunnable implements Runnable {

    NioSslServer server;

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

    public void setResponse(byte[] response) {
        server.setResponse(response);
    }

}
