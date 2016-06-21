package videostream;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.w3c.dom.NodeList;
import java.util.Base64;
import java.util.Vector;

public class OnvifControl {

    /**
     * Create a SOAP message end
     * @return SOAP message end
     */
    private String envelopeMessageEnd() {
        return "</soap:Envelope>";
    }
    /**
     * Create a SOAP message start including relevant namespaces
     * @return SOAP message start
     */
    private String envelopeMessageStart() {
        return "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"  xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">";
    }

    /**
     * Creates an authentication header
     * @return a usable header for authentication on ONVIF compliant devices
     * @throws IOException 
     */
    private String wsUsernameToken() throws IOException {
        String encodednonce = "";
        String encodeddigest = "";

        //generate nonce
        SecureRandom random = new SecureRandom();
        byte nonce[] = new byte[20];
        random.nextBytes(nonce);
        String time = getCurrentTimeStamp();

        //encode nonce
        encodednonce = Base64.getEncoder().encodeToString(nonce);

        //create hashengine
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(OnvifControl.class.getName()).log(Level.SEVERE, null, ex);
        }

        //concatenate nonce + time + password
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(nonce);
        outputStream.write(time.getBytes());
        outputStream.write(Videostream.password.getBytes());
        byte out[] = outputStream.toByteArray();

        //create hash
        encodeddigest = Base64.getEncoder().encodeToString(md.digest(out));
        String header = ""
                + "<soap:Header>"
                + "<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                + "<wsse:UsernameToken>"
                + "<wsse:Username>" + Videostream.username + "</wsse:Username>"
                + "<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + encodeddigest + "</wsse:Password>"
                + "<wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + encodednonce + "</wsse:Nonce>"
                + "<wsu:Created>" + time + "</wsu:Created>"
                + "</wsse:UsernameToken>"
                + "</wsse:Security>"
                + "</soap:Header>";

        return header;
    }

    /**
     * Query the given IP-address with the getCapabilities function, outputs to console
     * @param ip The IP-address of the device
     * @throws IOException 
     */
    public void getCapabilities(String ip) throws IOException {
        String message = envelopeMessageStart() + wsUsernameToken()
                + "<soap:Body>"
                + "<tds:GetCapabilities>"
                + "<tds:Category>Media</tds:Category>"
                + "</tds:GetCapabilities>"
                + "</soap:Body>"
                + envelopeMessageEnd();

        try {
            parseXML(sendOnvif(message, ip), "*");
        } catch (NullPointerException ex) {
            System.out.println(" - Messaging failed");
        } catch (ParserConfigurationException | SAXException ex) {
            Logger.getLogger(OnvifControl.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Query the given IP-address with the getSystemDeviceInformation function, outputs to console
     * @param ip The IP-address of the device
     * @throws IOException 
     */
    public void getSystemDeviceInformation(String ip) throws IOException {
        String message = envelopeMessageStart() + wsUsernameToken()
                + "<soap:Body>"
                + "<tds:GetDeviceInformation>"
                + "</tds:GetDeviceInformation>"
                + "</soap:Body>"
                + envelopeMessageEnd();

        try {
            parseXML(sendOnvif(message, ip), "tds:Manufacturer");
        } catch (ParserConfigurationException | SAXException | NullPointerException ex) {
            System.out.println(" - Messaging failed");
        }
    }

    /**
     * Query the given IP-address with the getSystemDateAndTime function, outputs to console
     * @param ip The IP-address of the device
     * @throws IOException 
     */
    public void getSystemDateAndTime(String ip) throws IOException {
        String message = envelopeMessageStart() + wsUsernameToken()
                + "<soap:Body>"
                + "<tds:GetSystemDateAndTime>"
                + "</tds:GetSystemDateAndTime>"
                + "</soap:Body>"
                + envelopeMessageEnd();

        try {
            parseXML(sendOnvif(message, ip), "tt:Date");
        } catch (ParserConfigurationException | SAXException | NullPointerException ex) {
            System.out.println(" - Messaging failed");
        }
    }
    
    /**
     * Query the given IP-address with the getProfiles function
     * @param ip The IP-address of the device
     * @return a vector<string> containing viable profiles to create a media ulr
     * @throws IOException 
     */
    public Vector<String> getProfiles(String ip) throws IOException {
        String message = envelopeMessageStart() + wsUsernameToken()
                + "<soap:Body>"
                + "<trt:GetProfiles/>"
                + "</soap:Body>"
                + envelopeMessageEnd();
        try {
            return parseProfiles(sendOnvif(message, ip), "trt:Profiles");
        } catch (NullPointerException | ParserConfigurationException | SAXException ex) {
            System.out.println(" - Messaging failed");
        }
        return null;
    }

    /**
     * Sends the created query to the device
     * @param message The query generated
     * @param ip The IP-address of the device
     * @return The response of the device as String
     * @throws IOException 
     */
    private String sendOnvif(String message, String ip) throws IOException {
        String url = "http://" + ip + "/onvif/device_service";
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();

        //add reqeust header
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "text/xml charset=utf-8");

        // Send post request
        con.setDoOutput(true);
        DataOutputStream wr = new DataOutputStream(con.getOutputStream());

        wr.write(message.getBytes());
        wr.flush();
        wr.close();

        int responseCode = con.getResponseCode();
        System.out.println("Response Code : " + responseCode);

        //succesfull request
        if (responseCode == 200) {
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            return response.toString();
        }
        return null;
    }

    /**
     * Parses the String response to more human readable and usable information, prints to console
     * @param message The message to parse
     * @param tagname The desired information tag
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException 
     */
    private void parseXML(String message, String tagname) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setIgnoringElementContentWhitespace(true);

        Document doc = null;
        try {
            DocumentBuilder builder = dbf.newDocumentBuilder();
            doc = builder.parse(new InputSource(new StringReader(message)));
        } catch (ParserConfigurationException e) {
            System.err.println(e);
            System.exit(1);
        }
        NodeList list = doc.getElementsByTagName(tagname);
        for (int i = 0; i < list.getLength(); i++) {
            System.out.println(list.item(i).getNodeName() + " : " + list.item(i).getTextContent());

        }
    }

    /**
     * Parses the String response to more human readable and usable information
     * @param message The message to parse
     * @param tagname The desired information tag
     * @return a vector<string> containing viable profiles parsed to be used
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException 
     */
    private Vector<String> parseProfiles(String message, String tagname) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setIgnoringElementContentWhitespace(true);

        Document doc = null;
        try {
            DocumentBuilder builder = dbf.newDocumentBuilder();
            doc = builder.parse(new InputSource(new StringReader(message)));
        } catch (ParserConfigurationException e) {
            System.err.println(e);
            System.exit(1);
        }
        NodeList list = doc.getElementsByTagName(tagname);
        Vector<String> profiles = new Vector();
        for (int i = 0; i < list.getLength(); i++) {
            profiles.add(list.item(i).getAttributes().getNamedItem("token").getNodeValue());
        }

        if (Videostream.debug) {
            System.out.println("Available profiles: ");
            for (int i = 0; i < profiles.size(); i++) {
                System.out.println(profiles.elementAt(i));
            }
        }
        return profiles;
    }

    /**
     * Create timestamp conform requirements ONVIF header
     * @return ONVIF header conform timestamp
     */
    private String getCurrentTimeStamp() {
        SimpleDateFormat dDate = new SimpleDateFormat("yyyy-MM-dd");//dd/MM/yyyy
        SimpleDateFormat tDate = new SimpleDateFormat("HH:mm:ss");//dd/MM/yyyy
        Date now = new Date();
        String strdDate = dDate.format(now);
        String strtDate = tDate.format(now);
        return strdDate + "T" + strtDate + "Z";
    }
}
