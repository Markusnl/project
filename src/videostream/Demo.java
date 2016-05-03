package videostream;

public class Demo {
	
	ServerRunnable serverRunnable;
	
	public Demo() {
		serverRunnable = new ServerRunnable();
		Thread server = new Thread(serverRunnable);
		server.start();
	}
	
	public void runDemo() throws Exception {
		
		// System.setProperty("javax.net.debug", "all");
		
		NioSslClient client = new NioSslClient("TLSv1.2", "localhost", 9222);
		client.connect();
		client.write("Hello! I am a client!");
		client.read();
		client.shutdown();
		serverRunnable.stop();
	}
	
	public static void main(String[] args) throws Exception {
		Demo demo = new Demo();
		Thread.sleep(1000);	// Give the server some time to start.
		demo.runDemo();
	}
	
}