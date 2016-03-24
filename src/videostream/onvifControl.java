package videostream;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.soap.*;
import javax.xml.parsers.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.w3c.dom.NodeList;

public class onvifControl {

    public void getCapabilities(String ip) throws SOAPException, IOException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();

        // SOAP Envelope
        SOAPEnvelope envelope = soapPart.getEnvelope();
        envelope.addNamespaceDeclaration("tds", "http://www.onvif.org/ver10/device/wsdl");
        envelope.addNamespaceDeclaration("tt", "http://www.onvif.org/ver10/schema");

        // SOAP Body
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem = soapBody.addChildElement("GetCapabilities", "tds");
        soapBodyElem.addChildElement("Category", "tds").addTextNode("Media");
        soapMessage.saveChanges();

        sendOnvif(ip, soapMessage);
    }

    public void getSysemDeviceInformation(String ip) throws SOAPException, IOException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();

        // SOAP Envelope
        SOAPEnvelope envelope = soapPart.getEnvelope();
        envelope.addNamespaceDeclaration("tds", "http://www.onvif.org/ver10/device/wsdl");

        // SOAP Body
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem = soapBody.addChildElement("GetDeviceInformation", "tds");
        soapMessage.saveChanges();

        sendOnvif(ip, soapMessage);
    }

    public void getSystemDateAndTime(String ip) throws SOAPException, IOException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();

        // SOAP Envelope
        SOAPEnvelope envelope = soapPart.getEnvelope();
        envelope.addNamespaceDeclaration("tds", "http://www.onvif.org/ver10/device/wsdl");

        // SOAP Body
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem = soapBody.addChildElement("GetSystemDateAndTime", "tds");
        soapMessage.saveChanges();

        sendOnvif(ip, soapMessage);
    }

    private int sendOnvif(String ip, SOAPMessage message) throws IOException {
        String url = "http://" + ip + "/onvif/device_service";
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();

        //add reqeust header
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "text/xml charset=utf-8");

        // Send post request
        con.setDoOutput(true);
        DataOutputStream wr = new DataOutputStream(con.getOutputStream());

        try {
            message.writeTo(wr);
        } catch (SOAPException ex) {
            Logger.getLogger(onvifControl.class.getName()).log(Level.SEVERE, null, ex);
        }
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

            try {
                parseXML(response.toString());
            } catch (ParserConfigurationException | SAXException ex) {
                Logger.getLogger(onvifControl.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return responseCode;
    }

    private void parseXML(String message) throws ParserConfigurationException, IOException, SAXException {
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
        NodeList list = doc.getElementsByTagName(/*"http://www.onvif.org/ver10/device/wsdl"*/"*"); //* for all
        //doc.getElementsByTagNameNS(message, message)
        for (int i = 0; i < list.getLength(); i++) {
            System.out.println(list.item(i).getNodeName() + " : " + list.item(i).getTextContent());

        }

    }
}
