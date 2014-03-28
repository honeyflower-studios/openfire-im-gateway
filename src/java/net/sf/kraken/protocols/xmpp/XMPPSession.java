/**
 * $Revision$
 * $Date$
 *
 * Copyright 2006-2010 Daniel Henninger.  All rights reserved.
 *
 * This software is published under the terms of the GNU Public License (GPL),
 * a copy of which is included in this distribution.
 */

package net.sf.kraken.protocols.xmpp;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicReference;

import net.sf.kraken.BaseTransport;
import net.sf.kraken.avatars.Avatar;
import net.sf.kraken.protocols.xmpp.mechanisms.FacebookConnectSASLMechanism;
import net.sf.kraken.protocols.xmpp.mechanisms.GTalkOAuth2Mechanism;
import net.sf.kraken.protocols.xmpp.mechanisms.MySASLDigestMD5Mechanism;
import net.sf.kraken.protocols.xmpp.packet.BuzzExtension;
import net.sf.kraken.protocols.xmpp.packet.GoogleMailBoxPacket;
import net.sf.kraken.protocols.xmpp.packet.GoogleMailNotifyExtension;
import net.sf.kraken.protocols.xmpp.packet.GoogleNewMailExtension;
import net.sf.kraken.protocols.xmpp.packet.GoogleUserSettingExtension;
import net.sf.kraken.protocols.xmpp.packet.IQWithPacketExtension;
import net.sf.kraken.protocols.xmpp.packet.ProbePacket;
import net.sf.kraken.protocols.xmpp.packet.VCardUpdateExtension;
import net.sf.kraken.registration.Registration;
import net.sf.kraken.registration.RegistrationHandler;
import net.sf.kraken.session.TransportSession;
import net.sf.kraken.type.ChatStateType;
import net.sf.kraken.type.ConnectionFailureReason;
import net.sf.kraken.type.PresenceType;
import net.sf.kraken.type.SupportedFeature;
import net.sf.kraken.type.TransportLoginStatus;
import net.sf.kraken.type.TransportType;

import org.apache.log4j.Logger;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.session.ClientSession;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.smack.Chat;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.Roster;
import org.jivesoftware.smack.Roster.SubscriptionMode;
import org.jivesoftware.smack.RosterEntry;
import org.jivesoftware.smack.RosterGroup;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.filter.OrFilter;
import org.jivesoftware.smack.filter.PacketExtensionFilter;
import org.jivesoftware.smack.filter.PacketTypeFilter;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.Presence.Type;
import org.jivesoftware.smack.provider.ProviderManager;
import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smackx.ChatState;
import org.jivesoftware.smackx.packet.ChatStateExtension;
import org.jivesoftware.smackx.packet.VCard;
import org.jivesoftware.util.Base64;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.LocaleUtils;
import org.jivesoftware.util.NotFoundException;
import org.xmpp.packet.JID;

/**
 * Handles XMPP transport session.
 *
 * @author Daniel Henninger
 * @author Mehmet Ecevit
 */
public class XMPPSession extends TransportSession<XMPPBuddy> {
    /**
     * Usernames of GTalk users authenticated by OAuth should have this prefix 
     * to distinguish them from normal users
     */
    private static final String OAUTH_PREFIX = "oauth:";

    static Logger Log = Logger.getLogger(XMPPSession.class);
    
    /**
     * Create an XMPP Session instance.
     *
     * @param registration Registration information used for logging in.
     * @param jid JID associated with this session.
     * @param transport Transport instance associated with this session.
     * @param priority Priority of this session.
     */
    public XMPPSession(Registration registration, JID jid, XMPPTransport transport, Integer priority) {
        super(registration, jid, transport, priority);
        setSupportedFeature(SupportedFeature.attention);
        setSupportedFeature(SupportedFeature.chatstates);

        Log.debug("Creating "+getTransport().getType()+" session for " + registration.getUsername());
        String connecthost;
        Integer connectport;
        String domain;

        connecthost = JiveGlobals.getProperty("plugin.gateway."+getTransport().getType()+".connecthost", (getTransport().getType().equals(TransportType.gtalk) ? "talk.google.com" : getTransport().getType().equals(TransportType.facebook) ? "chat.facebook.com" : "jabber.org"));
        connectport = JiveGlobals.getIntProperty("plugin.gateway."+getTransport().getType()+".connectport", 5222);

        if (getTransport().getType().equals(TransportType.gtalk)) {
            domain = "gmail.com";
        }
        else if (getTransport().getType().equals(TransportType.facebook)) {
            //if (connecthost.equals("www.facebook.com")) {
                connecthost = "chat.facebook.com";
            //}
            //if (connectport.equals(80)) {
                connectport = 5222;
            //}
            domain = "chat.facebook.com";
        }
        else if (getTransport().getType().equals(TransportType.renren)) {
            connecthost = "talk.renren.com";
            connectport = 5222;
            domain = "renren.com";
        }
        else {
            domain = connecthost;
        }

        // For different domains other than 'gmail.com', which is given with Google Application services
        if (registration.getUsername().indexOf("@") > -1) {
            domain = registration.getUsername().substring( registration.getUsername().indexOf("@")+1 );
        }

        // If administrator specified "*" for domain, allow user to connect to anything.
        if (connecthost.equals("*")) {
            connecthost = domain;
        }

        config = new ConnectionConfiguration(connecthost, connectport, domain);
        config.setCompressionEnabled(JiveGlobals.getBooleanProperty("plugin.gateway."+getTransport().getType()+".usecompression", false));

        if (getTransport().getType().equals(TransportType.facebook)) {
            //SASLAuthentication.supportSASLMechanism("PLAIN", 0);
            //config.setSASLAuthenticationEnabled(false);
            //config.setSecurityMode(ConnectionConfiguration.SecurityMode.enabled);
        }

        // instead, send the initial presence right after logging in. This
        // allows us to use a different presence mode than the plain old
        // 'available' as initial presence.
        config.setSendPresence(false); 

        if (getTransport().getType().equals(TransportType.gtalk) && JiveGlobals.getBooleanProperty("plugin.gateway.gtalk.mailnotifications", true)) {
            ProviderManager.getInstance().addIQProvider(GoogleMailBoxPacket.MAILBOX_ELEMENT, GoogleMailBoxPacket.MAILBOX_NAMESPACE, new GoogleMailBoxPacket.Provider());
            ProviderManager.getInstance().addExtensionProvider(GoogleNewMailExtension.ELEMENT_NAME, GoogleNewMailExtension.NAMESPACE, new GoogleNewMailExtension.Provider());
        }
    }
    
    /*
     * XMPP connection configuration
     */
    private final ConnectionConfiguration config;
    
    /**
     * Active connection.
     */
    class ActiveConnection {    
        /*
         * XMPP connection
         */
        private XMPPConnection conn = null;
        
        /**
         * XMPP listener
         */
        private XMPPListener listener = null;
    
        /**
         * Run thread.
         */
        private Thread runThread = null;
    
    	/**
    	 * Instance that will handle all presence stanzas sent from the legacy
    	 * domain
    	 */
    	private XMPPPresenceHandler presenceHandler = null;
        
    
        /**
         * Timer to check for online status.
         */
        private Timer timer = new Timer();
    
        /**
         * Interval at which status is checked.
         */
        private int timerInterval = 60000; // 1 minute
    
        /**
         * Mail checker
         */
        private MailCheck mailCheck;
        
        private final AtomicReference<ConnectionState> state = 
                new AtomicReference<ConnectionState>(ConnectionState.NEW);
        
        public void logIn(final org.jivesoftware.smack.packet.Presence presence) {
            log("logIn()");
            listener = new XMPPListener(this);
            presenceHandler = new XMPPPresenceHandler(this);
            runThread = new Thread() {
                @Override
                public void run() {
                    doLogIn(presence);
                }
            };
            runThread.start();
        }
        
        private void doLogIn(org.jivesoftware.smack.packet.Presence presence) {
            if (!state.compareAndSet(ConnectionState.NEW, ConnectionState.LOGGING_IN)) {
                log("NEW -> LOGGING_IN failed: closed before connecting");
                cleanup();
                noReconnect(null);
                return;
            }
            
            log("NEW -> LOGGING_IN: logging in");
            
            String userName = generateUsername(registration.getUsername());
            conn = new XMPPConnection(config);
            try {
                conn.getSASLAuthentication().registerSASLMechanism("DIGEST-MD5", MySASLDigestMD5Mechanism.class);
                if (getTransport().getType().equals(TransportType.facebook) && registration.getUsername().equals("{PLATFORM}")) {
                    conn.getSASLAuthentication().registerSASLMechanism("X-FACEBOOK-PLATFORM", FacebookConnectSASLMechanism.class);
                    conn.getSASLAuthentication().supportSASLMechanism("X-FACEBOOK-PLATFORM", 0);
                } else if (getTransport().getType().equals(TransportType.gtalk) && isOAuth(registration.getUsername())) {
                    // Use OAuth mechanism for GTalk accounts whose username is prefixed with "oauth:"
                    conn.getSASLAuthentication().registerSASLMechanism("X-OAUTH2", GTalkOAuth2Mechanism.class);
                    conn.getSASLAuthentication().supportSASLMechanism("X-OAUTH2", 0);
                }

                Roster.setDefaultSubscriptionMode(SubscriptionMode.manual);
                conn.connect();
                
                if (state.get() == ConnectionState.CLOSED) {
                    log("Closed while connecting");
                    cleanup();
                    noReconnect(null);
                    return;
                }
                
                //log("Connected");
                
                conn.addConnectionListener(listener);
                try {
                    conn.addPacketListener(presenceHandler, new PacketTypeFilter(org.jivesoftware.smack.packet.Presence.class));
                    // Use this to filter out anything we don't care about
                    conn.addPacketListener(listener, new OrFilter(
                            new PacketTypeFilter(GoogleMailBoxPacket.class),
                            new PacketExtensionFilter(GoogleNewMailExtension.ELEMENT_NAME, GoogleNewMailExtension.NAMESPACE)
                    ));
                    conn.login(userName, registration.getPassword(), xmppResource);
                    
                    if (state.get() == ConnectionState.CLOSED) {
                        log("Closed while logging in");
                        cleanup();
                        return;
                    }
                    
                    log("Logged in");
                    
                    conn.sendPacket(presence); // send initial presence.
                    conn.getChatManager().addChatListener(listener);
                    conn.getRoster().addRosterListener(listener);

                    if (JiveGlobals.getBooleanProperty("plugin.gateway."+getTransport().getType()+".avatars", !TransportType.facebook.equals(getTransport().getType())) && getAvatar() != null) {
                        new Thread() {
                            @Override
                            public void run() {
                                Avatar avatar = getAvatar();

                                VCard vCard = new VCard();
                                try {
                                    vCard.load(conn);
                                    vCard.setAvatar(Base64.decode(avatar.getImageData()), avatar.getMimeType());
                                    vCard.save(conn);
                                }
                                catch (XMPPException e) {
                                    Log.debug("XMPP: Error while updating vcard for avatar change.", e);
                                }
                                catch (NotFoundException e) {
                                    Log.debug("XMPP: Unable to find avatar while setting initial.", e);
                                }
                            }
                        }.start();
                    }

                    setLoginStatus(TransportLoginStatus.LOGGED_IN);
                    syncUsers();

                    if (getTransport().getType().equals(TransportType.gtalk) && JiveGlobals.getBooleanProperty("plugin.gateway.gtalk.mailnotifications", true)) {
                        conn.sendPacket(new IQWithPacketExtension(generateFullJID(getRegistration().getUsername()), new GoogleUserSettingExtension(null, true, null), IQ.Type.SET));
                        conn.sendPacket(new IQWithPacketExtension(generateFullJID(getRegistration().getUsername()), new GoogleMailNotifyExtension()));
                        mailCheck = new MailCheck();
                        timer.schedule(mailCheck, timerInterval, timerInterval);
                    }
                    
                    if (!state.compareAndSet(ConnectionState.LOGGING_IN, ConnectionState.LOGGED_IN)) {
                        log("LOGGING_IN -> LOGGED_IN failed: Closed while initializing");
                        cleanup();
                        noReconnect(null);
                        return;
                    }
                    
                    //log("LOGGING_IN -> LOGGED_IN: Initialized");
                }
                catch (XMPPException e) {                            
                    log("Error when logging in: " + e);
                    Log.debug(getTransport().getType()+" user's login/password does not appear to be correct: "+getRegistration().getUsername(), e);
                    
                    disconnected(
                            LocaleUtils.getLocalizedString("gateway.xmpp.passwordincorrect", "kraken"), 
                            ConnectionFailureReason.USERNAME_OR_PASSWORD_INCORRECT, 
                            false, true);
                    
                    //setFailureStatus(ConnectionFailureReason.USERNAME_OR_PASSWORD_INCORRECT);
                    //sessionDisconnectedNoReconnect();
                }
            }
            catch (XMPPException  e) {
                log("Error when connecting: " + e);
                Log.debug(getTransport().getType()+" user is not able to connect: "+getRegistration().getUsername(), e);

                disconnected(
                        LocaleUtils.getLocalizedString("gateway.xmpp.connectionfailed", "kraken"), 
                        ConnectionFailureReason.CAN_NOT_CONNECT, 
                        true, true);
                
                //setFailureStatus(ConnectionFailureReason.CAN_NOT_CONNECT);                        
                //sessionDisconnected(LocaleUtils.getLocalizedString("gateway.xmpp.connectionfailed", "kraken"));
            }
        }
        
        public void logOut() {
            log("logOut()");
            ConnectionState oldState = state.getAndSet(ConnectionState.CLOSED);
            if (oldState == ConnectionState.LOGGED_IN) {
                log("LOGGED_IN -> CLOSED, cleaning up");
                cleanup();
                noReconnect(null);
            } else {
                log("!LOGGED_IN -> CLOSED, will clean up later");
            }
        }
        
        private boolean cleanup() {
            log("cleanup()");
            boolean wasActive = inactivate();
            
            if (timer != null) {
                try {
                    timer.cancel();
                }
                catch (Exception e) {
                    // Ignore
                }
                timer = null;
            }
            if (mailCheck != null) {
                try {
                    mailCheck.cancel();
                }
                catch (Exception e) {
                    // Ignore
                }
                mailCheck = null;
            }
            if (conn != null) {
                try {
                    conn.removeConnectionListener(listener);
                }
                catch (Exception e) {
                    // Ignore
                }
                
                try {
                    conn.removePacketListener(listener);
                }
                catch (Exception e) {
                    // Ignore
                }
                try {
                    conn.removePacketListener(presenceHandler);
                } catch (Exception e) {
                    // Ignore
                }
                try {
                    conn.getChatManager().removeChatListener(listener);
                }
                catch (Exception e) {
                    // Ignore
                }
                try {
                    conn.getRoster().removeRosterListener(listener);
                }
                catch (Exception e) {
                    // Ignore
                }
                try {
                    conn.disconnect();
                }
                catch (Exception e) {
                    // Ignore
                }
            }
            conn = null;
            listener = null;
            presenceHandler = null;
            if (runThread != null) {
                try {
                    runThread.interrupt();
                }
                catch (Exception e) {
                    // Ignore
                }
                runThread = null;
            }
            
            return wasActive;
        }
        
        public void disconnected(
                String errorMessage, ConnectionFailureReason reason, 
                boolean mayReconnect) {
            disconnected(errorMessage, reason, mayReconnect, false);
        }
        
        private void disconnected(
                String errorMessage, ConnectionFailureReason reason, 
                boolean mayReconnect, boolean loginError) {
            boolean wasActive = false;
            boolean wasLoggedIn = state.getAndSet(ConnectionState.CLOSED) == ConnectionState.LOGGED_IN;
            if (wasLoggedIn || loginError) {
                wasActive = cleanup();
            } else {
                log("No need to clean up, just inactivate");
                wasActive = inactivate();
            }
            
            boolean shouldReconnect = mayReconnect &&
                    !(getRegistrationPacket() != null || 
                    !JiveGlobals.getBooleanProperty("plugin.gateway."+getTransport().getType()+"reconnect", true) || 
                    (++reconnectionAttempts > JiveGlobals.getIntProperty("plugin.gateway."+getTransport().getType()+"reconnectattempts", 3)));
            
            if (shouldReconnect) {
                reconnect(errorMessage);
            } else {
                noReconnect(errorMessage);
            }
        }
        
        private boolean inactivate() {
            return activeConnection.compareAndSet(this, null);
        }

        public void execute(ConnectionCommand command) {
            ConnectionState currentState = state.get();
            /*if (currentState != ConnectionState.LOGGED_IN) {
                throw new IllegalStateException("Not logged in: " + currentState);
            } else*/ if (activeConnection.get() == this) {
                command.execute(XMPPSession.this, conn, listener);
            } else {
                log("Attempt to execute a command on inactive connection: " + command);
            }
        }
        
        /**
         * MailCheck.
         */
        private class MailCheck extends TimerTask {
            /**
             * Check GMail for new mail.
             */
            @Override
            public void run() {
                if (getTransport().getType().equals(TransportType.gtalk) && JiveGlobals.getBooleanProperty("plugin.gateway.gtalk.mailnotifications", true)) {
                    GoogleMailNotifyExtension gmne = new GoogleMailNotifyExtension();
                    gmne.setNewerThanTime(listener.getLastGMailThreadDate());
                    gmne.setNewerThanTid(listener.getLastGMailThreadId());
                    conn.sendPacket(new IQWithPacketExtension(generateFullJID(getRegistration().getUsername()), gmne));
                }
            }
        }
        
        private void log(String message) {
            XMPPSession.this.log("[" + hashCode() + "] " + message);
        }
    }
    
    /**
     * Possible state of active connection.
     */
    private static enum ConnectionState {
        NEW, LOGGING_IN, LOGGED_IN, CLOSED;
    }
    
    private final AtomicReference<ActiveConnection> activeConnection = new AtomicReference<ActiveConnection>();

    /**
     * XMPP Resource - the resource we are using (randomly generated)
     */
    public String xmppResource = StringUtils.randomString(10);

     
    /**
     * Returns a full JID based off of a username passed in.
     *
     * If it already looks like a JID, returns what was passed in.
     *
     * @param username Username to turn into a JID.
     * @return Converted username.
     */
    public String generateFullJID(String username) {
        username = stripOAuth(username);
        
        if (username.indexOf("@") > -1) {
            return username;
        }

        if (getTransport().getType().equals(TransportType.gtalk)) {
            return username+"@"+"gmail.com";
        }
        else if (getTransport().getType().equals(TransportType.facebook)) {
            return username+"@"+"chat.facebook.com";
        }
        else if (getTransport().getType().equals(TransportType.renren)) {
            return username+"@"+"renren.com";
        }
        else if (getTransport().getType().equals(TransportType.livejournal)) {
            return username+"@"+"livejournal.com";
        }
        else {
            String connecthost = JiveGlobals.getProperty("plugin.gateway."+getTransport().getType()+".connecthost", (getTransport().getType().equals(TransportType.gtalk) ? "talk.google.com" : getTransport().getType().equals(TransportType.facebook) ? "chat.facebook.com" : "jabber.org"));
            return username+"@"+connecthost;
        }
    }
    
    /**
     * Returns a username based off of a registered name (possible JID) passed in.
     *
     * If it already looks like a username, returns what was passed in.
     *
     * @param regName Registered name to turn into a username.
     * @return Converted registered name.
     */
    public String generateUsername(String regName) {
        regName = stripOAuth(regName);
        
        if (regName.equals("{PLATFORM}")) {
            return JiveGlobals.getProperty("plugin.gateway.facebook.platform.apikey")+"|"+JiveGlobals.getProperty("plugin.gateway.facebook.platform.apisecret");
        }
        else if (regName.indexOf("@") > -1) {
            if (getTransport().getType().equals(TransportType.gtalk)) {
                return regName;
            }
            else {
                return regName.substring(0, regName.indexOf("@"));
            }
        }
        else {
            if (getTransport().getType().equals(TransportType.gtalk)) {
                return regName+"@gmail.com";
            }
            else {
                return regName;
            }
        }
    }
    
    private boolean isOAuth(String username) {
        return username != null && username.startsWith(OAUTH_PREFIX);
    }
    
    private String stripOAuth(String username) {
        if (isOAuth(username)) {
            return username.substring(OAUTH_PREFIX.length());
        } else {
            return username;
        }
    }

    /**
     * @see net.sf.kraken.session.TransportSession#logIn(net.sf.kraken.type.PresenceType, String)
     */
    @Override
    public void logIn(PresenceType presenceType, String verboseStatus) {
        final org.jivesoftware.smack.packet.Presence presence = new org.jivesoftware.smack.packet.Presence(org.jivesoftware.smack.packet.Presence.Type.available);
        if (JiveGlobals.getBooleanProperty("plugin.gateway."+getTransport().getType()+".avatars", true) && getAvatar() != null) {
            Avatar avatar = getAvatar();
            // Same thing in this case, so lets go ahead and set them.
            avatar.setLegacyIdentifier(avatar.getXmppHash());
            VCardUpdateExtension ext = new VCardUpdateExtension();
            ext.setPhotoHash(avatar.getLegacyIdentifier());
            presence.addExtension(ext);
        }
        final Presence.Mode pMode = ((XMPPTransport) getTransport())
                .convertGatewayStatusToXMPP(presenceType);
        if (pMode != null) {
            presence.setMode(pMode);
        }
        if (verboseStatus != null && verboseStatus.trim().length() > 0) {
            presence.setStatus(verboseStatus);
        }
        setPendingPresenceAndStatus(presenceType, verboseStatus);
        
        ActiveConnection c = new ActiveConnection();
        if (activeConnection.compareAndSet(null, c)) {
            log("Created active connection");
            c.logIn(presence);
        } else {
            log("logIn() ignored: connection already active");
        }
    }

    /**
     * @see net.sf.kraken.session.TransportSession#logOut()
     */
    @Override
    public void logOut() {
        ActiveConnection c = activeConnection.getAndSet(null);
        if (c != null) {
            c.logOut();
        } else {
            log("logOut() ignored: no active connection");
        }
    }
    
    public void reconnect(String errorMessage) {
        if (activeConnection.get() != null) return;
        
        setLoginStatus(TransportLoginStatus.RECONNECTING);
        ClientSession session = XMPPServer.getInstance().getSessionManager().getSession(getJIDWithHighestPriority());
        if (session != null) {
            log("Reconnecting...");
            logIn(getTransport().getPresenceType(session.getPresence()), null);
        }
        else {
            noReconnect(errorMessage);
        }
    }
    
    public void noReconnect(String errorMessage) {
        if (activeConnection.get() != null) return;
        
        log("No reconnect");
        
        setLoginStatus(TransportLoginStatus.LOGGED_OUT);
        if (getRegistrationPacket() != null) {
            new RegistrationHandler(getTransport()).completeRegistration(this);
        }
        else {
            org.xmpp.packet.Presence p = new org.xmpp.packet.Presence(org.xmpp.packet.Presence.Type.unavailable);
            p.setTo(getJID());
            p.setFrom(getTransport().getJID());
            getTransport().sendPacket(p);
            if (errorMessage != null) {
                getTransport().sendMessage(
                        getJIDWithHighestPriority(),
                        getTransport().getJID(),
                        errorMessage,
                        org.xmpp.packet.Message.Type.error
                );
            }
            getBuddyManager().sendOfflineForAllAvailablePresences(getJID());
        }
        buddyManager.resetBuddies();
        getTransport().getSessionManager().removeSession(getJID(), this);
    }

    /**
     * @see net.sf.kraken.session.TransportSession#cleanUp()
     */
    @Override
    public void cleanUp() {
        throw new UnsupportedOperationException();
    }

    /**
     * @see net.sf.kraken.session.TransportSession#updateStatus(net.sf.kraken.type.PresenceType, String)
     */
    @Override
    public void updateStatus(final PresenceType presenceType, final String verboseStatus) {
        execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                setPresenceAndStatus(presenceType, verboseStatus);
                final org.jivesoftware.smack.packet.Presence presence = constructCurrentLegacyPresencePacket();

                try {
                    conn.sendPacket(presence);
                }
                catch (IllegalStateException e) {
                    Log.debug("XMPP: Not connected while trying to change status.");
                }
            }
        });
    }

    /**
     * @see net.sf.kraken.session.TransportSession#addContact(org.xmpp.packet.JID, String, java.util.ArrayList)
     */
    @Override
    public void addContact(final JID jid, final String nickname, final ArrayList<String> groups) {
        execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                String mail = getTransport().convertJIDToID(jid);
                try {
                    conn.getRoster().createEntry(mail, nickname, groups.toArray(new String[groups.size()]));
                    RosterEntry entry = conn.getRoster().getEntry(mail);

                    getBuddyManager().storeBuddy(new XMPPBuddy(getBuddyManager(), mail, nickname, entry.getGroups(), entry));
                }
                catch (XMPPException ex) {
                    Log.debug("XMPP: unable to add:"+ mail);
                }
            }
        });
    }

    /**
     * @see net.sf.kraken.session.TransportSession#removeContact(net.sf.kraken.roster.TransportBuddy)
     */
    @Override
    public void removeContact(final XMPPBuddy contact) {
        execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                RosterEntry user2remove;
                String mail = getTransport().convertJIDToID(contact.getJID());
                user2remove =  conn.getRoster().getEntry(mail);
                try {
                    conn.getRoster().removeEntry(user2remove);
                }
                catch (XMPPException ex) {
                    Log.debug("XMPP: unable to remove:"+ mail);
                }
            }
        });
    }

    /**
     * @see net.sf.kraken.session.TransportSession#updateContact(net.sf.kraken.roster.TransportBuddy)
     */
    @Override
    public void updateContact(final XMPPBuddy contact) {
        execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                RosterEntry user2Update;
                String mail = getTransport().convertJIDToID(contact.getJID());
                user2Update =  conn.getRoster().getEntry(mail);
                user2Update.setName(contact.getNickname());
                Collection<String> newgroups = contact.getGroups();
                if (newgroups == null) {
                    newgroups = new ArrayList<String>();
                }
                for (RosterGroup group : conn.getRoster().getGroups()) {
                    if (newgroups.contains(group.getName())) {
                        if (!group.contains(user2Update)) {
                            try {
                                group.addEntry(user2Update);
                            }
                            catch (XMPPException e) {
                                Log.debug("XMPP: Unable to add roster item to group.");
                            }
                        }
                        newgroups.remove(group.getName());
                    }
                    else {
                        if (group.contains(user2Update)) {
                            try {
                                group.removeEntry(user2Update);
                            }
                            catch (XMPPException e) {
                                Log.debug("XMPP: Unable to delete roster item from group.");
                            }
                        }
                    }
                }
                for (String group : newgroups) {
                    RosterGroup newgroup = conn.getRoster().createGroup(group);
                    try {
                        newgroup.addEntry(user2Update);
                    }
                    catch (XMPPException e) {
                        Log.debug("XMPP: Unable to add roster item to new group.");
                    }
                }
            }
        });
    }
    
    /**
     * @see net.sf.kraken.session.TransportSession#acceptAddContact(JID)
     */
    @Override
    public void acceptAddContact(final JID jid) {
        execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                final String userID = getTransport().convertJIDToID(jid);
                Log.debug("XMPP: accept-add contact: " + userID);
                
                final Presence accept = new Presence(Type.subscribed);
                accept.setTo(userID);
                conn.sendPacket(accept);
            }
        });        
    }
    
    /**
     * @see net.sf.kraken.session.TransportSession#sendMessage(org.xmpp.packet.JID, String)
     */
    @Override
    public void sendMessage(final JID jid, final String message) {
        execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                Chat chat = conn.getChatManager().createChat(getTransport().convertJIDToID(jid), listener);
                try {
                    chat.sendMessage(message);
                }
                catch (XMPPException e) {
                    // Ignore
                }
            }
        });
    }

    /**
     * @see net.sf.kraken.session.TransportSession#sendChatState(org.xmpp.packet.JID, net.sf.kraken.type.ChatStateType)
     */
    @Override
    public void sendChatState(final JID jid, final ChatStateType chatState) {
        execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                final Presence presence = conn.getRoster().getPresence(jid.toString());
                if (presence == null  || presence.getType().equals(Presence.Type.unavailable)) {
                    // don't send chat state to contacts that are offline.
                    return;
                }
                Chat chat = conn.getChatManager().createChat(getTransport().convertJIDToID(jid), listener);
                try {
                    ChatState state = ChatState.active;
                    switch (chatState) {
                        case active:    state = ChatState.active;    break;
                        case composing: state = ChatState.composing; break;
                        case paused:    state = ChatState.paused;    break;
                        case inactive:  state = ChatState.inactive;  break;
                        case gone:      state = ChatState.gone;      break;
                    }

                    Message message = new Message();
                    message.addExtension(new ChatStateExtension(state));
                    chat.sendMessage(message);
                }
                catch (XMPPException e) {
                    // Ignore
                }
            }
        });
    }

    /**
     * @see net.sf.kraken.session.TransportSession#sendBuzzNotification(org.xmpp.packet.JID, String)
     */
    @Override
    public void sendBuzzNotification(final JID jid, String message) {
        execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                BaseTransport<XMPPBuddy> transport = getTransport();
                Chat chat = conn.getChatManager().createChat(transport.convertJIDToID(jid), listener);
                try {
                    Message m = new Message();
                    m.setTo(transport.convertJIDToID(jid));
                    m.addExtension(new BuzzExtension());
                    chat.sendMessage(m);
                }
                catch (XMPPException e) {
                    // Ignore
                }
            }
        });
    }

    /**
     * Returns a (legacy/Smack-based) Presence stanza that represents the
     * current presence of this session. The Presence includes relevant Mode,
     * Status and VCardUpdate information.
     * 
     * This method uses the fields {@link TransportSession#presence} and
     * {@link TransportSession#verboseStatus} to generate the result.
     * 
     * @return A Presence packet representing the current presence state of this
     *         session.
     */
    public Presence constructCurrentLegacyPresencePacket() {
        final org.jivesoftware.smack.packet.Presence presence = new org.jivesoftware.smack.packet.Presence(
                org.jivesoftware.smack.packet.Presence.Type.available);
        final Presence.Mode pMode = ((XMPPTransport) getTransport())
                .convertGatewayStatusToXMPP(this.presence);
        if (pMode != null) {
            presence.setMode(pMode);
        }
        if (verboseStatus != null && verboseStatus.trim().length() > 0) {
            presence.setStatus(verboseStatus);
        }
        final Avatar avatar = getAvatar();
        if (avatar != null) {
            final VCardUpdateExtension ext = new VCardUpdateExtension();
            ext.setPhotoHash(avatar.getLegacyIdentifier());
            presence.addExtension(ext);
        }
        return presence;
    }
    
    /**
     * @see net.sf.kraken.session.TransportSession#updateLegacyAvatar(String, byte[])
     */
    @Override
    public void updateLegacyAvatar(String type, final byte[] data) {
        new Thread() {
            @Override
            public void run() {
                execute(new ConnectionCommand() {
                    @Override
                    public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                        Avatar avatar = getAvatar();

                        VCard vCard = new VCard();
                        try {
                            vCard.load(conn);
                            vCard.setAvatar(data, avatar.getMimeType());
                            vCard.save(conn);

                            avatar.setLegacyIdentifier(avatar.getXmppHash());
                            
                            // Same thing in this case, so lets go ahead and set them.
                            final org.jivesoftware.smack.packet.Presence presence = constructCurrentLegacyPresencePacket();
                            conn.sendPacket(presence);
                        }
                        catch (XMPPException e) {
                            Log.debug("XMPP: Error while updating vcard for avatar change.", e);
                        }
                    }
                });
            }
        }.start();
    }
    
    private void syncUsers() {
        execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                for (RosterEntry entry : conn.getRoster().getEntries()) {
                    getBuddyManager().storeBuddy(new XMPPBuddy(getBuddyManager(), entry.getUser(), entry.getName(), entry.getGroups(), entry));
                    // Facebook does not support presence probes in their XMPP implementation. See http://developers.facebook.com/docs/chat#features
                    if (!TransportType.facebook.equals(getTransport().getType())) {
                        //ProbePacket probe = new ProbePacket(this.getJID()+"/"+xmppResource, entry.getUser());
                        ProbePacket probe = new ProbePacket(null, entry.getUser());
                        Log.debug("XMPP: Sending the following probe packet: "+probe.toXML());
                        try {
                            conn.sendPacket(probe);
                        }
                        catch (IllegalStateException e) {
                            Log.debug("XMPP: Not connected while trying to send probe.");
                        }
                    }
                }

                try {
                    getTransport().syncLegacyRoster(getJID(), getBuddyManager().getBuddies());
                }
                catch (UserNotFoundException ex) {
                    Log.error("XMPP: User not found while syncing legacy roster: ", ex);
                }

                getBuddyManager().activate();

                // lets repoll the roster since smack seems to get out of sync...
                // we'll let the roster listener take care of this though.
                conn.getRoster().reload();
            }
        });        
    }
    
    private void execute(ConnectionCommand command) {
        ActiveConnection c = activeConnection.get();
        if (c != null) {
            c.execute(command);
        } else {
            log("No active connection when executing a command");
        }
    }
    
    public interface ConnectionCommand {
        public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener);
    }
    
    private void log(String message) {
        String jid = String.valueOf(registration.getJID());
        String transportType = String.valueOf(registration.getTransportType());
        String password = abbreviate(registration.getPassword(), 11);
        
        System.err.println(
                new Date() + " " + message + " [" + jid + ", " + transportType + ", " + password + ", " + hashCode() + "]");
    }
    
    private String abbreviate(String s, int maxLength) {
        int length = s.length();
        if (length > maxLength) {
            int partLength = (maxLength - 3) / 2;
            return s.substring(0, partLength) + "..." + s.substring(length - partLength, length);
        } else {
            return s;
        }
    }
}
