package net.sf.kraken.protocols.xmpp.mechanisms;

import java.io.IOException;

import net.sf.jmyspaceiml.log.Log;

import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.util.Base64;

/**
 * OAuth 2.0 - based authentication mechanism for GTalk.
 * <p>
 * Treats password as OAuth access token.
 * 
 * @see <a href = "https://developers.google.com/talk/jep_extensions/oauth">OAuth 2.0 Authorization</a>
 */
public class GTalkOAuth2Mechanism extends SASLMechanism {
    private String username;
    private String accessToken;
    
    public GTalkOAuth2Mechanism(SASLAuthentication saslAuthentication) {
        super(saslAuthentication);
    }
    
    @Override
    public void authenticate(String username, String host, String password)
            throws IOException, XMPPException {
        Log.info("OAuth: " + username + " " + password);
        this.username = username;
        this.accessToken = password;
        super.authenticate(username, host, password);
    }
    
    @Override
    protected void authenticate() throws IOException, XMPPException {
        byte[] auth = ("\0" + username + "\0" + accessToken).getBytes("UTF-8");
        
        final StringBuilder stanza = new StringBuilder();
        stanza.append("<auth xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\" ");
        stanza.append("mechanism=\"X-OAUTH2\" ");
        stanza.append("auth:service=\"oauth2\" ");
        stanza.append("xmlns:auth=\"http://www.google.com/talk/protocol/auth\">");
        stanza.append(Base64.encodeBytes(auth, Base64.DONT_BREAK_LINES));
        stanza.append("</auth>");
        
        getSASLAuthentication().send(new Packet() {
            @Override
            public String toXML() {
                return stanza.toString();
            }
        });        
    }

    @Override
    protected String getName() {
        return "X-OAUTH2";
    }
}
