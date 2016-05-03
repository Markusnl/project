package videostream;

public class ServerRunnable implements Runnable {

	NioSslServer server;
	
	@Override
	public void run() {
		try {
			server = new NioSslServer("TLSv1.2", "localhost", 9222);
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
        
        public byte[] getKey(){
            return server.getKey();
        }
	
}