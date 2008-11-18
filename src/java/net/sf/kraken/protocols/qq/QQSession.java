package net.sf.kraken.protocols.qq;

import net.sf.kraken.protocols.yahoo.YahooBuddy;
import net.sf.kraken.protocols.yahoo.YahooTransport;
import net.sf.kraken.registration.Registration;
import net.sf.kraken.roster.TransportBuddy;
import net.sf.kraken.session.TransportSession;
import net.sf.kraken.type.ChatStateType;
import net.sf.kraken.type.PresenceType;
import net.sf.kraken.type.TransportLoginStatus;

import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.NotFoundException;
import org.openymsg.network.YahooUser;
import org.xmpp.packet.JID;
import org.xmpp.packet.Message;
import org.xmpp.packet.Presence;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

import edu.tsinghua.lumaqq.qq.QQ;
import edu.tsinghua.lumaqq.qq.QQClient;
import edu.tsinghua.lumaqq.qq.beans.QQUser;
import edu.tsinghua.lumaqq.qq.beans.QQFriend;
import edu.tsinghua.lumaqq.qq.beans.ClusterIM;
import edu.tsinghua.lumaqq.qq.net.PortGateFactory;
import edu.tsinghua.lumaqq.qq.events.IQQListener;
import edu.tsinghua.lumaqq.qq.events.QQEvent;
import java.util.Date;
import edu.tsinghua.lumaqq.qq.packets.in.GetFriendListReplyPacket;
import edu.tsinghua.lumaqq.qq.packets.in.DownloadGroupFriendReplyPacket;
import edu.tsinghua.lumaqq.qq.beans.DownloadFriendEntry;
import edu.tsinghua.lumaqq.qq.beans.ClusterInfo;
import java.util.*;
import edu.tsinghua.lumaqq.qq.packets.in.*;
import java.text.SimpleDateFormat;
import edu.tsinghua.lumaqq.qq.beans.NormalIM;
import edu.tsinghua.lumaqq.qq.beans.FriendOnlineEntry;
import edu.tsinghua.lumaqq.qq.Util;
import edu.tsinghua.lumaqq.qq.beans.Member;

public class QQSession extends TransportSession implements IQQListener {

    static Logger Log = Logger.getLogger(QQSession.class);

    private List<String> tcpServerList = new ArrayList<String>();
    private List<String> udpServerList = new ArrayList<String>();
    private static String defaultGroupName = JiveGlobals.getProperty(
            "plugin.gateway.qq.defaultRosterName", "Friends");
    public static final SimpleDateFormat sdf = new SimpleDateFormat(
            "yyyy-MM-dd HH:mm:ss");
    private QQClient qqclient;
    private QQUser qquser;
    private List<String> groupNames = new ArrayList<String>();
    private Map<Integer, QQFriend> friends = new HashMap<Integer, QQFriend>();
    private Map<Integer, String> friendGroup = new HashMap<Integer, String>();
    private Map<Integer,
                ClusterInfo> clusters = new HashMap<Integer, ClusterInfo>();
    private Map<Integer,
                Map<Integer, String>> clusterMembers = new Hashtable<Integer,
            Map<Integer, String>>(); //group members
    
    private void setupDefaultServerList() {
        // set up default tcp server list
        Collections.addAll(tcpServerList,
    		"tcpconn.tencent.com",
    		"tcpconn2.tencent.com",
    		"tcpconn3.tencent.com",
    		"tcpconn4.tencent.com",
    		"tcpconn5.tencent.com",
    		"tcpconn6.tencent.com"
		);
        Collections.shuffle(tcpServerList);
        // set up default udp server list
        Collections.addAll(udpServerList,
    		"sz.tencent.com",
    		"sz2.tencent.com",
    		"sz3.tencent.com",
    		"sz4.tencent.com",
    		"sz5.tencent.com",
    		"sz6.tencent.com",
    		"sz7.tencent.com",
    		"sz8.tencent.com",
    		"sz9.tencent.com"
		);
        Collections.shuffle(udpServerList);
        // TODO: Add preferred server to top of list, and add checkbox for udp vs tcp
    }
    
    public QQSession(Registration registration, JID jid,
                     QQTransport transport, Integer priority) {
        super(registration, jid, transport, priority);
        qquser = new QQUser(Integer.parseInt(registration.getUsername()),
                            registration.getPassword());
        qquser.setStatus(QQ.QQ_LOGIN_MODE_NORMAL);
        qquser.setUdp(true);
        qquser.setShowFakeCam(false);
        setupDefaultServerList();
    }

    public void updateStatus(PresenceType presenceType, String string) {
        if (isLoggedIn()) {
            try { 
                qquser.setStatus(((QQTransport) getTransport()).
                                 convertJabStatusToQQ(presenceType));
            } catch (IllegalStateException e) {
                // Nothing to do
            }
        }

    }

    public void addContact(JID jID, String string, ArrayList arrayList) {
    	// TODO: Implement this
    }

    public void removeContact(TransportBuddy transportBuddy) {
    	// TODO: Implement this
    }

    public void updateContact(TransportBuddy transportBuddy) {
    	// TODO: Implement this
    }

    public void sendMessage(JID jID, String message) {
        try {
            int qqNum = Integer.parseInt(getTransport().convertJIDToID(jID));
            if (clusters.get(qqNum) != null) {
                qqclient.im_SendCluster(clusters.get(qqNum).clusterId,
                                        message);
            } else {
                qqclient.im_Send(qqNum, message.getBytes());
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    public void sendChatState(JID jID, ChatStateType chatStateType) {
    }

    public void sendBuzzNotification(JID jID, String string) {
    }

    public void logIn(PresenceType presenceType, String string) {
    	if (udpServerList.isEmpty()) {
    		// Ran out of servers to try to log in to.  Dooh.
    		sessionDisconnectedNoReconnect("Unable to log into any QQ servers.");
    		return;
    	}
    	String qqserver = udpServerList.remove(0); // pull a server to connect to from the end of the list
        setLoginStatus(TransportLoginStatus.LOGGING_IN);
        qqclient = new QQClient();
        qqclient.setUser(qquser);
        qqclient.setConnectionPoolFactory(new PortGateFactory());
        //qqclient.setTcpLoginPort(8000);
        qqclient.addQQListener(this);
        qqclient.setLoginServer(qqserver);
        try {
			qqclient.login();
		}
        catch (Exception e) {
			Log.debug("Login attempt at server "+qqserver+" failed, trying next.");
		}
    }

    public void logOut() {
        cleanUp();
        sessionDisconnectedNoReconnect(null);
    }

    public void cleanUp() {
    	if (qqclient != null) {
    		qqclient.logout();
    		qqclient.release();
    	}
        qqclient = null;
    }

    public void updateLegacyAvatar(String string, byte[] byteArray) {
    }

    public QQUser getQquser() {
        return qquser;
    }

    public void qqEvent(QQEvent e) {
        Log.debug(" QQEvent： " + Integer.toHexString(e.type) +
                           " " + e.getSource());
        switch (e.type) {
        case QQEvent.LOGIN_FAIL:
            sessionDisconnectedNoReconnect(null);
            break;
        case QQEvent.LOGIN_NEED_VERIFY:
        case QQEvent.LOGIN_UNKNOWN_ERROR:
        case QQEvent.LOGIN_GET_TOKEN_FAIL:
            sessionDisconnected(null);
            break;
        case QQEvent.USER_STATUS_CHANGE_OK:
            processStatusChangeOK(e);
            break;
        case QQEvent.USER_STATUS_CHANGE_FAIL:
            sessionDisconnected(null);
            break;
        case QQEvent.FRIEND_DOWNLOAD_GROUPS_OK:
            processGroupFriend(e);
            break;
        case QQEvent.FRIEND_GET_GROUP_NAMES_OK:
            processGroupNames(e);
            break;
        case QQEvent.FRIEND_DOWNLOAD_GROUPS_FAIL:
            sessionDisconnected(null);
            break;
        case QQEvent.CLUSTER_GET_INFO_OK:
            processClusterInfo(e);
            break;
        case QQEvent.CLUSTER_GET_MEMBER_INFO_OK:
            processClusterMemberInfo(e);
            break;
        case QQEvent.IM_CLUSTER_RECEIVED:
            processClusterIM(e);
            break;
        case QQEvent.IM_RECEIVED:
            processNormalIM(e);
            break;
        case QQEvent.ERROR_CONNECTION_BROKEN:
        case QQEvent.ERROR_NETWORK:
        case QQEvent.SYS_TIMEOUT:
            sessionDisconnected(null);
            break;
        case QQEvent.FRIEND_GET_ONLINE_OK:
            processFriendOnline(e);
            break;
        case QQEvent.FRIEND_STATUS_CHANGED:
            processFriendChangeStatus(e);
            break;
        case QQEvent.FRIEND_GET_LIST_OK:
            processFriendList(e);
            break;
        default:
            break;

        }

    }

    private void processFriendList(QQEvent e) {
        try {
            GetFriendListReplyPacket p =
                    (GetFriendListReplyPacket) e.getSource();
            for (QQFriend f : p.friends) {
                friends.put(f.qqNum, f);
            }
            if (p.position != 0xFFFF) {
                qqclient.user_GetList(p.position);
            } else {
                syncContactGroups();
            }
        } catch (Exception ex) {
        	Log.error("Failed to process friend list: ", ex);
        }
        
        // Lets try the actual sync.
        try {
            getTransport().syncLegacyRoster(getJID(), getBuddyManager().getBuddies());
        }
        catch (UserNotFoundException ex) {
            Log.debug("Unable to sync yahoo contact list for " + getJID());
        }
        
        getBuddyManager().activate();
    }

    public void syncContactGroups() {
        for (QQFriend f : friends.values()) {
            String groupName = friendGroup.get(f.qqNum);
            if (groupName == null || groupName.trim().length() < 1) {
                groupName = defaultGroupName;
            }
            List<String> gl = new ArrayList<String>();
            gl.add(groupName);
            TransportBuddy tb = new TransportBuddy(getBuddyManager(),
                    String.valueOf(f.qqNum), f.nick, gl);
            getBuddyManager().storeBuddy(tb);
        }

    }

    private void processGroupFriend(QQEvent e) {
        try {
            DownloadGroupFriendReplyPacket p =
                    (DownloadGroupFriendReplyPacket) e.getSource();
            for (DownloadFriendEntry entry : p.friends) {
                if (entry.isCluster()) {
                    qqclient.cluster_GetInfo(entry.qqNum);
                } else {
                    if (groupNames != null && groupNames.size() > entry.group) {
                        friendGroup.put(entry.qqNum, groupNames.get(entry.group));
                    } else {
                        friendGroup.put(entry.qqNum, defaultGroupName);
                    }
                }
            }
            if (p.beginFrom != 0) {
                qqclient.cluster_GetOnlineMember(p.beginFrom);
            }
        } catch (Exception ex) {
            Log.error("Failed to process group friend: ", ex);
        }
    }

    private void processGroupNames(QQEvent e) {
        try {
            groupNames.clear();
            groupNames.add(defaultGroupName);
            GroupDataOpReplyPacket p =
                    (GroupDataOpReplyPacket) e.getSource();
            groupNames.addAll(p.groupNames);
        } catch (Exception ex) {
            Log.error("Failed to process group names: ", ex);
        }
    }

    private void processClusterInfo(QQEvent e) {
        try {
            ClusterCommandReplyPacket p = (ClusterCommandReplyPacket) e.
                                          getSource();
            ClusterInfo info = p.info;
            if (QQ.QQ_CLUSTER_TYPE_PERMANENT == info.type) {
                clusters.put(info.externalId, info);
            }
            List<String> gl = new ArrayList<String>();
            gl.add(JiveGlobals.getProperty("plugin.gateway.qq.qqGroupName",
                                           "QQ Group"));
            TransportBuddy tb = new TransportBuddy(getBuddyManager(),
            		String.valueOf(info.externalId), info.name, gl);
            getBuddyManager().storeBuddy(tb);
            Presence pp = new Presence();
            pp.setFrom(getTransport().convertIDToJID(String.valueOf(info.externalId)));
            pp.setTo(getJID());
            pp.setShow(Presence.Show.chat);
            getTransport().sendPacket(pp);
            qqclient.cluster_GetMemberInfo(info.clusterId, p.members);
        } catch (Exception ex) {
            Log.error("Failed to process cluster info: ", ex);
        }
    }

    private void processClusterMemberInfo(QQEvent e) {
        try {
            ClusterCommandReplyPacket p = (ClusterCommandReplyPacket) e.
                                          getSource();
            Map<Integer, String> cmm = new HashMap<Integer, String>();
            for (Object obj : p.memberInfos) {
                QQFriend m = (QQFriend) obj;
                cmm.put(m.qqNum, m.nick);
            }
            int clusterId = 0;
            for (ClusterInfo c : clusters.values()) {
                if (c.clusterId == p.clusterId) {
                    clusterId = c.externalId;
                }
            }
            clusterMembers.put(clusterId, cmm);
        } catch (Exception ex) {
            Log.error("Failed to process cluster member info: ", ex);
        }
    }

    private void processStatusChangeOK(QQEvent e) {
        setLoginStatus(TransportLoginStatus.LOGGED_IN);
        Presence p = new Presence();
        p.setTo(getJID());
        p.setFrom(getTransport().getJID());
        p.setStatus("Chat");
        getTransport().sendPacket(p);
        qqclient.user_GetGroupNames();
        qqclient.user_DownloadGroups(0);
        qqclient.user_GetList();
        qqclient.user_GetOnline();

    }

    private void processClusterIM(QQEvent e) {
        try {
            ReceiveIMPacket p = (ReceiveIMPacket) e.getSource();
            ClusterIM im = p.clusterIM;
            if (clusters.get(im.externalId) == null) {
                qqclient.user_DownloadGroups(0);
            }
            String sDate = sdf.format(new Date(im.sendTime));
            String clusterName = "";
            try {
                clusterName = clusters.get(im.externalId).name;
            } catch (Exception ex) {
            	Log.debug("Failed to get cluster name: ", ex);
            }
            String senderName = " ";
            try {
                senderName = clusterMembers.get(im.externalId).get(im.sender);
            } catch (Exception ex) {
            	Log.debug("Failed to get sender name: ", ex);
            }
            String msg = clusterName + "[" + im.externalId + "]"
                         + senderName + "(" + im.sender + ") "
                         + sDate + ":\n"
                         + new String(im.messageBytes) + "\n";
            Message m = new Message();
            m.setType(Message.Type.chat);
            m.setTo(getJID());
            m.setFrom(getTransport().convertIDToJID(String.valueOf(im.externalId)));
            String b = " ";
            try {
                b = new String(msg);
            } catch (Exception ex) {
            	Log.debug("Failed to string-ify message: ", ex);
            }
            m.setBody(b);
            getTransport().sendPacket(m);
        } catch (Exception ex) {
        	Log.error("Failed to handle cluster IM: ", ex);
        }
    }

    private void processNormalIM(QQEvent e) {
        try {
            ReceiveIMPacket p = (ReceiveIMPacket) e.getSource();
            NormalIM im = p.normalIM;
            Message m = new Message();
            m.setType(Message.Type.chat);
            m.setTo(getJID());
            m.setFrom(getTransport().convertIDToJID(String.valueOf(p.normalHeader.sender)));
            String b = " ";
            try {
                b = new String(im.messageBytes);
            } catch (Exception ex) {
            	Log.debug("Failed to string-ify message: ", ex);
            }
            m.setBody(b);
            getTransport().sendPacket(m);
        } catch (Exception ex) {
            Log.error("Failed to handle normal IM: ", ex);
        }
    }

    private void processFriendOnline(QQEvent e) {
        try {
            GetOnlineOpReplyPacket p =
                    (GetOnlineOpReplyPacket) e.getSource();
            for (FriendOnlineEntry f : p.onlineFriends) {
                if (getBuddyManager().isActivated()) {
                    try {
                        TransportBuddy trBuddy = getBuddyManager().getBuddy(getTransport().convertIDToJID(String.valueOf(f.status.qqNum)));
                        trBuddy.setPresenceAndStatus(((QQTransport)getTransport()).convertQQStatusToXMPP(f.status.status), null);
                    }
                    catch (NotFoundException ee) {
                        // Not in our list.
                        Log.debug("QQ: Received presense notification for contact we don't care about: "+String.valueOf(f.status.qqNum));
                    }
                }
                else {
                	getBuddyManager().storePendingStatus(getTransport().convertIDToJID(String.valueOf(f.status.qqNum)), ((QQTransport)getTransport()).convertQQStatusToXMPP(f.status.status), null);
                }
            }
            if (!p.finished) {
                qqclient.user_GetOnline(p.position);
            }
        } catch (Exception ex) {
            Log.error("Failed to handle friend online event: ", ex);
        }
    }

    private void processFriendChangeStatus(QQEvent e) {
        try {
            FriendChangeStatusPacket p =
                    (FriendChangeStatusPacket) e.getSource();
            if (getBuddyManager().isActivated()) {
                try {
                    TransportBuddy trBuddy = getBuddyManager().getBuddy(getTransport().convertIDToJID(String.valueOf(p.friendQQ)));
                    trBuddy.setPresenceAndStatus(((QQTransport)getTransport()).convertQQStatusToXMPP(p.status), null);
                }
                catch (NotFoundException ee) {
                    // Not in our list.
                    Log.debug("QQ: Received presense notification for contact we don't care about: "+String.valueOf(p.friendQQ));
                }
            }
            else {
            	getBuddyManager().storePendingStatus(getTransport().convertIDToJID(String.valueOf(p.friendQQ)), ((QQTransport)getTransport()).convertQQStatusToXMPP(p.status), null);
            }
        } catch (Exception ex) {
            Log.error("Failed to handle friend status change event: ", ex);
        }
    }

}
