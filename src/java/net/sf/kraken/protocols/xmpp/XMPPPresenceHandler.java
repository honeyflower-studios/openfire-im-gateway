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

import net.sf.kraken.avatars.Avatar;
import net.sf.kraken.protocols.xmpp.XMPPSession.ActiveConnection;
import net.sf.kraken.protocols.xmpp.XMPPSession.ConnectionCommand;
import net.sf.kraken.type.NameSpace;

import org.apache.log4j.Logger;
import org.jivesoftware.smack.PacketListener;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.DefaultPacketExtension;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.PacketExtension;
import org.jivesoftware.smackx.packet.VCard;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.NotFoundException;
import org.xmpp.packet.Presence;

/**
 * Presence packets are used for two purposes. First, to notify the server of
 * our the clients current presence status. Second, they are used to subscribe
 * and unsubscribe users from the roster. 
 * 
 * Instances of XMPPSubscriptionHandler
 * are responsible for handling events generated by receiving
 * both types of presence stanzas from the legacy domain.
 * 
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class XMPPPresenceHandler implements PacketListener{

	final static Logger Log = Logger.getLogger(XMPPPresenceHandler.class);
	
	private final ActiveConnection connection;
	
	/**
	 * Instantiates a new Presence handler for the given session.
	 * 
	 * @param session
	 *            The session for which to handle presence stanzas.
	 */
	public XMPPPresenceHandler(ActiveConnection connection) {
		this.connection = connection;
	}
	
	/* (non-Javadoc)
	 * @see org.jivesoftware.smack.PacketListener#processPacket(org.jivesoftware.smack.packet.Packet)
	 */
	public void processPacket(Packet packet) {
		if (!(packet instanceof org.jivesoftware.smack.packet.Presence)) {
			throw new IllegalArgumentException(getClass().getName()
					+ " can only be used to handle presence packets. "
					+ "Please modify the caller code accordingly "
					+ "(use a appropriate PacketFilter).");
		}

		final org.jivesoftware.smack.packet.Presence presence = (org.jivesoftware.smack.packet.Presence) packet;
		final org.jivesoftware.smack.packet.Presence.Type type = presence.getType();
		if (type.equals(org.jivesoftware.smack.packet.Presence.Type.available) 
				|| type.equals(org.jivesoftware.smack.packet.Presence.Type.unavailable)) {
			handlePresenceMode(presence);
		} else {
			handlePresenceSubscription(presence);
		}
	}

	/**
	 * Handles incoming presence stanzas that relate to presence status / mode
	 * changes. Ignores others.
	 * 
	 * @param presence
	 *            the stanza
	 */
	private void handlePresenceMode(final org.jivesoftware.smack.packet.Presence presence) {
	    connection.execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, final XMPPConnection conn, XMPPListener listener) {
                if (!session.getBuddyManager().isActivated()) {
                    session.getBuddyManager().storePendingStatus(session.getTransport().convertIDToJID(presence.getFrom()), ((XMPPTransport)session.getTransport()).convertXMPPStatusToGateway(presence.getType(), presence.getMode()), presence.getStatus());
                }
                else {
                    // TODO: Need to handle resources and priorities!
                    try {
                        final XMPPBuddy xmppBuddy = session.getBuddyManager().getBuddy(session.getTransport().convertIDToJID(presence.getFrom()));
                        Log.debug("XMPP: Presence changed detected type "+presence.getType()+" and mode "+presence.getMode()+" for "+presence.getFrom());
                        xmppBuddy.setPresenceAndStatus(
                                ((XMPPTransport)session.getTransport()).convertXMPPStatusToGateway(presence.getType(), presence.getMode()),
                                presence.getStatus()
                        );
                        if (JiveGlobals.getBooleanProperty("plugin.gateway."+session.getTransport().getType()+".avatars", true)) {
                            PacketExtension pe = presence.getExtension("x", NameSpace.VCARD_TEMP_X_UPDATE);
                            if (pe != null) {
                                DefaultPacketExtension dpe = (DefaultPacketExtension)pe;
                                String hash = dpe.getValue("photo");
                                final String from = presence.getFrom();
                                if (hash != null) {
                                    Avatar curAvatar = xmppBuddy.getAvatar();
                                    if (curAvatar == null || !curAvatar.getLegacyIdentifier().equals(hash)) {
                                        new Thread() {
                                            @Override
                                            public void run() {
                                                VCard vcard = new VCard();
                                                try {
                                                    vcard.load(conn, from);
                                                    xmppBuddy.setAvatar(new Avatar(xmppBuddy.getJID(), from, vcard.getAvatar()));
                                                }
                                                catch (XMPPException e) {
                                                    Log.debug("XMPP: Failed to load XMPP avatar: ", e);
                                                }
                                                catch (IllegalArgumentException e) {
                                                    Log.debug("XMPP: Got null avatar, ignoring.");
                                                }
                                            }
                                        }.start();
                                    }
                                }
                            }
                        }
                    }
                    catch (NotFoundException e) {
                        Log.debug("XMPP: Received presence notification for contact that's not in the buddy manager of user " + session.getJID() + ". GTalk is known to do this occasionally: "+presence.getFrom());
                        // We cannot add this buddy to the buddy manager, as that would result into an auto-accept of the contact sending the data.
                    }
                }
            }	        
	    });
	}
	
	/**
	 * Handles incoming presence stanzas that relate to subscription status.
	 * Ignores others.
	 * 
	 * @param presence
	 *            the stanza
	 */
	private void handlePresenceSubscription(final org.jivesoftware.smack.packet.Presence presence) {
	    connection.execute(new ConnectionCommand() {
            @Override
            public void execute(XMPPSession session, XMPPConnection conn, XMPPListener listener) {
                final Presence p = new Presence();
                p.setTo(session.getJID());
                p.setFrom(session.getTransport().convertIDToJID(presence.getFrom()));

                
                switch (presence.getType()) {
                case subscribe:
                    p.setType(Presence.Type.subscribe);
                    break;

                case subscribed:
                    final XMPPBuddy buddy = new XMPPBuddy(session.getBuddyManager(), presence.getFrom());
                    session.getBuddyManager().storeBuddy(buddy);
                    p.setType(Presence.Type.subscribed);
                    break;

                case unsubscribe:
                    p.setType(Presence.Type.unsubscribe);
                    break;

                case unsubscribed:
                    p.setType(Presence.Type.unsubscribed);
                    break;

                case error:
                    p.setType(Presence.Type.error);
                    break;

                default:
                    // don't send anything.
                    return;
                }

                session.getTransport().sendPacket(p);
            }	        
	    });
	}
}
