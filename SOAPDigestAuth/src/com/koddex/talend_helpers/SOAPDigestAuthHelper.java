package com.koddex.talend_helpers;

import javax.xml.soap.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Created by igordla on 3/22/17.
 */
public class SOAPDigestAuthHelper {

    public SOAPDigestAuthHelper() {}

    /**
     * Web Service Security (WSS)
     * https://www.oasis-open.org/committees/download.php/13392/wss-v1.1-spec-pr-UsernameTokenProfile-01.htm#_Toc104276210
     * From the spec: Password_Digest = Base64 ( SHA-1 ( nonce + created + password ) )
     */
    public static String createSOAPMessage(String usernameStr, String passwordStr, String messageStr) {
        try {
            // Make the nonce
            SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
            rand.setSeed(System.currentTimeMillis());
            byte[] nonceBytes = new byte[16];
            rand.nextBytes(nonceBytes);

            // Make the created date
            DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            df.setTimeZone(TimeZone.getTimeZone("UTC"));
            String createdDate = df.format(Calendar.getInstance().getTime());
            byte[] createdDateBytes = createdDate.getBytes(StandardCharsets.UTF_8);

            // Make the password
            byte[] passwordBytes = passwordStr.getBytes(StandardCharsets.UTF_8);

            // SHA-1 hash the bunch of it.
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(nonceBytes);
            baos.write(createdDateBytes);
            baos.write(passwordBytes);
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digestedPassword = md.digest(baos.toByteArray());

            // Encode the password and nonce for sending
            String passwordB64 = Base64.getEncoder().encodeToString(digestedPassword);
            String nonceB64 = Base64.getEncoder().encodeToString(nonceBytes);

            MessageFactory messageFactory = MessageFactory.newInstance();
            InputStream is = new ByteArrayInputStream(messageStr.getBytes(StandardCharsets.UTF_8));
            SOAPMessage soapMessage = messageFactory.createMessage(null, is);

            // Retrieve different parts
            SOAPEnvelope envelope = soapMessage.getSOAPPart().getEnvelope();

            // Now create the header with all the appropriate elements
            SOAPHeader header = envelope.getHeader() != null ? envelope.getHeader() : envelope.addHeader();

            SOAPElement security = header.addChildElement("Security", "wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            security.setAttribute("soapenv:mustUnderstand","1");
            security.addNamespaceDeclaration("wsu","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

            SOAPElement usernameToken = security.addChildElement("UsernameToken", "wsse");

            SOAPElement username = usernameToken.addChildElement("Username", "wsse");
            username.addTextNode(usernameStr);

            SOAPElement password = usernameToken.addChildElement("Password", "wsse");
            password.setAttribute("Type", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest");
            password.addTextNode(passwordB64);

            SOAPElement nonce = usernameToken.addChildElement("Nonce", "wsse");
            nonce.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
            nonce.addTextNode(nonceB64);

            SOAPElement created = usernameToken.addChildElement("Created", "wsu");
            created.addTextNode(createdDate);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            soapMessage.writeTo(out);

            return new String(out.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {}
}
