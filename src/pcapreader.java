import java.util.*;
import java.util.regex.*;
import java.io.UnsupportedEncodingException;

//import javax.xml.bind.DatatypeConverter;

import net.sourceforge.jpcap.capture.CaptureFileOpenException;
import net.sourceforge.jpcap.capture.CapturePacketException;
import net.sourceforge.jpcap.capture.InvalidFilterException;
import net.sourceforge.jpcap.capture.PacketCapture;
import net.sourceforge.jpcap.capture.PacketListener;
import net.sourceforge.jpcap.net.Packet;
import net.sourceforge.jpcap.net.IPPacket;
import net.sourceforge.jpcap.net.TCPPacket;
import net.sourceforge.jpcap.net.UDPPacket;


class PacketCaptureListener extends PacketCapture implements PacketListener {

	protected String dataString;
	
	/* EDIT: this will be appended by all the data in the packets if rule type is STREAM*/
	protected String streamDataString;
	boolean streamMatch;
	
	public ArrayList<rule> setOfAllRules;

	public PacketCaptureListener() {
		setOfAllRules = new ArrayList<rule>();
	}

	public PacketCaptureListener(ArrayList<rule> rF) {
		setOfAllRules = rF;
		streamDataString = "";
	}

	public void setRuleList(ArrayList<rule> r) {
		setOfAllRules = r;
	}

	public boolean FlagsMatch(IPPacket packet, SubRule sr) {
		TCPPacket p = (TCPPacket) packet;
		boolean flagsMatch = true;

		flagsMatch = (p.isSyn() == sr.flags[0]) & (p.isAck() == sr.flags[1])
				& (p.isFin() == sr.flags[2]) & (p.isRst() == sr.flags[3])
				& (p.isPsh() == sr.flags[4]) & (p.isUrg() == sr.flags[5]);

		return flagsMatch;
	}

	//The "Entry point"
	@Override
	public void packetArrived(Packet packet) {
		// TODO Auto-generated method stub
		//System.out.println(packet.toString());
		
		IPPacket ipPacket = (IPPacket) packet;
		
		for (rule ru : setOfAllRules) {
			comparePacketToRule(ipPacket, ru);
			
			if(streamDataString.length() > 0 && streamMatch == true)
			{	//only happens in a stream data type
				//compare the rule recv message or send message to the whole data string
				
				/* NOT SURE IF I SHOULD LOOK FOR EACH WORD INDIVIDUALLY, OR THE PATTERN IN ENTIRETY*/
				Matcher m = ru.regex.matcher(streamDataString);
				
				if( m.find())
					System.out.println(ru.name);
			}
		}
	}

	public boolean TCPsrcPortMatch(TCPPacket t, int port) {
		if (port == 0)
			return true;
		if (t.getSourcePort() == port)
			return true;
		else
			return false;
		/** TODO
		 * easier code
		 if (port == 0)
		 	return true;
		 return (t.geSourcePort() == port);
		 */
	}

	public boolean TCPdestPortMatch(TCPPacket t, int port) {
		if (port == 0)
			return true;
		if (t.getDestinationPort() == port)
			return true;
		else
			return false;
	}

	public boolean UDPdestPortMatch(UDPPacket u, int port) {
		if (port == 0)
			return true;
		if (u.getDestinationPort() == port)
			return true;
		else
			return false;
	}

	public boolean UDPsrcPortMatch(UDPPacket u, int port) {
		if (port == 0)
			return true;
		if (u.getSourcePort() == port)
			return true;
		else
			return false;
	}

	public boolean srcIPMatch(IPPacket p, String addr) {
		if (p.getSourceAddress().equals(addr) || addr.equals("0.0.0.0"))
			return true;
		else
			return false;
	}

	public boolean destIPMatch(IPPacket p, String addr) {
		if (p.getDestinationAddress().equals(addr) || addr.equals("0.0.0.0"))
			return true;
		else
			return false;
	}

	public boolean isTCP(IPPacket p) {
		if (p.getProtocol() == 6)
			return true;
		else
			return false;
	}

	public boolean isUDP(IPPacket p) {
		if (p.getProtocol() == 17)
			return true;
		else
			return false;
	}

	/*
	 * TAs Note: if we see the "recv" in the message, rule.ip must match the
	 * packet's SOURCE address if we see the "send" message, rule.ip must match
	 * the packet's DESTINATION address
	 */

	public void comparePacketToRule(IPPacket packet, rule r) {
		// compare packet info with a rule object
		// using the helper methods above
		
		//we should be comparing the rule to the packet TONY, hint hint

		// the goal is to call this method when the
		// packet arrives to compare it to all rules

		// print the name of r if we have a match ( all helpers return true)

		boolean ruleMatch = true; // change to false if we find something that
									// does not match
		streamMatch = true;
		/*
		 * MATCH IN PROTOCOL
		 */
		if (r.type.equalsIgnoreCase("protocol")) {
			if ( r.proto.equalsIgnoreCase("tcp") && isTCP(packet) ) {
				// debug
				//System.out.println("Match in protocol (tcp)");
			} else if ( r.proto.equalsIgnoreCase("udp") && isUDP(packet) ) {
				// debug
				//System.out.println("Match in protocol (UDP)");
			} else {
				//System.out.println("incompatible protocols");
				streamMatch = false;
				ruleMatch = false;
				return;
			}
		}

		/*
		 * MATCH IN SRC IP ADDRESS OR DEST IP DEPENDING ON NATURE OF PACKET
		 */

		// this is raw data from the data section of the packet, to be regex'd
		byte[] data = packet.getData();
		
	//	String hex = DatatypeConverter.printHexBinary(data);
    	//	System.out.println(hex); // prints 

		try {
			// grabs byte array of data and translates to string
			dataString = new String(data, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			dataString = "";
		}

		Matcher m = null;
		
		/*EDIT: if type is stream, append to the data string instead of comparing here*/
		if(r.type.equalsIgnoreCase("protocol"))
		{
			if( r.recv || r.send ){
				m = r.regex.matcher(dataString);
				
				if( !m.find() ){
				//System.out.println("non-match: Regex not found");
					streamMatch = false;
					ruleMatch = false;
					return;
				}
			}
		}
		else if(r.type.equalsIgnoreCase("stream"))
		{
			if(r.recv || r.send)
			{
				streamDataString = streamDataString + dataString;	
			}
		}

		/**
		 * making sure the IP's are correct for the direction of packet
		 */
		if (r.recv == true)
		{
			if (srcIPMatch(packet, r.ip) == false) {
				//System.out.println("non-match: Source ip mismatch");
				ruleMatch = false;
				streamMatch = false;
				return;
			}
			else if( !destIPMatch(packet, r.ip) ){
				//System.out.println("non-match: Destination ip mismatch");
				ruleMatch = false;
				streamMatch = false;
				return;
			}
		}

		if (r.send == true)
		{
			if (destIPMatch(packet, r.ip) == false) {
				//System.out.println("non-match: Destination ip mismatch");
				ruleMatch = false;
				streamMatch = false;
				return;
			}
			else if( !srcIPMatch(packet, r.ip) ){
				//System.out.println("non-match: Source ip mismatch");
				ruleMatch = false;
				streamMatch = false;
				return;
			}
		}

		// "0" means its unspecified
		if (r.remote_port > 0) {
			// a specific port on packet's source addr must match

			// CHECK packet.getSourcePort() depending on tcp/udp
			if (  r.proto.equalsIgnoreCase("tcp") && isTCP(packet) )
			{
				if (TCPsrcPortMatch((TCPPacket) packet, r.remote_port) == false) {
					//System.out.println("non-match: remote port mismatch");
					ruleMatch = false;
					streamMatch = false;
					return;
				}
			} 
			else if (  r.proto.equalsIgnoreCase("udp") && isUDP(packet) )
			{
				if ( UDPsrcPortMatch((UDPPacket) packet, r.remote_port)== false )
				{
					//System.out.println("non-match: remote port mismatch");
					ruleMatch = false;
					streamMatch = false;
					return;
				}
			} 
			else if (r.type.equalsIgnoreCase("stream") && isTCP(packet) )
			{
				// stream protocol, try casting as tcp packet for now
				if ( TCPsrcPortMatch((TCPPacket) packet, r.remote_port) == false)
				{
					//System.out.println("non-match: stream type remote port mismatch");
					ruleMatch = false;
					streamMatch = false;
					return;
				}
			}
			else 
			{
				//System.out.println("Tony sucks at coding :D <====8 ");
				ruleMatch = false;
				streamMatch = false;
				return;
			}
		}

		if (r.local_port > 0) {
			// a specific port on user's computer must match the destination

			if ( r.proto.equalsIgnoreCase("tcp") && isTCP(packet) ) {
				if (TCPdestPortMatch((TCPPacket) packet, r.local_port) == false) {
					//System.out.println("non-match: tcp packet mismatch with rule local port");
					ruleMatch = false;
					streamMatch = false;
					return;
				}
			} else if ( r.proto.equalsIgnoreCase("udp") && isUDP(packet) ) {
				if (UDPdestPortMatch((UDPPacket) packet, r.local_port) == false) {
					//System.out.println("non-match: udp packet mismatch with rule's local port");
					ruleMatch = false;
					streamMatch = false;
					return;
				}
			} else if ( r.type.equalsIgnoreCase("stream") && isTCP(packet) ) {
				if (TCPdestPortMatch((TCPPacket) packet, r.local_port) == false) {
					//System.out.println("non-match: stream packet mismatch with rule's local port");
					ruleMatch = false;
					streamMatch = false;
					return;
				}
			} else {
				//System.out.println("tony sucks at coding 2: electric boogaloo");
				ruleMatch = false;
				streamMatch = false;
				return;
			}
		}

		/////////////////////
		/// Sub rule processing
		///////////////////////
		for (SubRule sr : r.subRules) {
			m = sr.regex.matcher(dataString);

			if (sr.hasFlags)
				ruleMatch = FlagsMatch(packet, sr);

			//the subrule is in the correct direction
			if( (sr.recv && srcIPMatch(packet, r.ip)) || (sr.send && destIPMatch(packet, r.ip) ) ){
				/*EDIT: If stream type, don't compare, just append data*/
				if(r.type.equalsIgnoreCase("protocol"))
				{
					if( m.find() && ruleMatch ){
					//we found a match in a subrule, stop checking for others
						break;	
					}
					else
						ruleMatch = false;
			
					
				}
				else streamDataString = streamDataString + dataString;
			}
			else
			{
				ruleMatch = false;
				streamMatch = false;
			}	
		}

		//if (ruleMatch == true && sendMatch != false && recvMatch != false)
		/* EDIT: only do this for protocol types. in the even of a stream*/
		if( ruleMatch && r.type.equalsIgnoreCase("protocol"))
			System.out.println( r.name);
		//else
			//System.out.println("non-match: UNKNOWN");
	}

}

public class pcapreader {

	public void readFile(String filename, ArrayList<rule> rF)
			throws CapturePacketException {

		//System.out.println("Reading file " + filename);
		PacketCaptureListener jpcap = new PacketCaptureListener(rF);

		try {
			jpcap.openOffline(filename);
		} catch (CaptureFileOpenException e1) {
			// TODO Auto-generated catch block
			System.err.println(e1.toString());
			//e1.printStackTrace();
		}

		// we only consider network layer traffic
		// this of course means we don't see things like ARP poisoning
		try {
			jpcap.setFilter("ip", true);
			jpcap.addPacketListener(jpcap);
			jpcap.capture(-1);

		} catch (InvalidFilterException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
		}
	}
}
