import java.util.*;
import java.util.regex.*;

import java.io.UnsupportedEncodingException;

import net.sourceforge.jpcap.capture.CaptureFileOpenException;
import net.sourceforge.jpcap.capture.CapturePacketException;
import net.sourceforge.jpcap.capture.InvalidFilterException;
import net.sourceforge.jpcap.capture.PacketCapture;
import net.sourceforge.jpcap.capture.PacketListener;
import net.sourceforge.jpcap.net.Packet;
import net.sourceforge.jpcap.net.IPPacket;
import net.sourceforge.jpcap.net.TCPPacket;

//edit 12_1
import net.sourceforge.jpcap.net.UDPPacket;

class PacketCaptureListener extends PacketCapture implements PacketListener{

	public ArrayList<rule> setOfAllRules;

	public PacketCaptureListener()
	{
		setOfAllRules = new ArrayList<rule>();
	}
	public PacketCaptureListener(ArrayList<rule> rF){
		setOfAllRules = rF; 
	}

	public void setRuleList(ArrayList<rule> r)
	{
		setOfAllRules = r;
	}
	
	@Override
	public void packetArrived(Packet packet) {
		// TODO Auto-generated method stub
		System.out.println(packet.toString());
		//System.out.println("foo");
		IPPacket ipPacket = (IPPacket)packet;

		if(isTCP(ipPacket) == true ) //means its TCP
			System.out.println("TCP packet from " + ipPacket.getSourceAddress() + " : " + ((TCPPacket)ipPacket).getSourcePort());
		else if(isUDP(ipPacket) == true)
		{	//a udp packet
			System.out.println("UDP packet from " + ipPacket.getSourceAddress() + " : " + ((UDPPacket)ipPacket).getSourcePort());		
		}
		else System.out.println("Packet of unknown protocol (" +ipPacket.getProtocol() + ") from " + ipPacket.getSourceAddress());


		System.out.println("Destination of packet : " + ipPacket.getDestinationAddress());	


		//System.out.println("Packet data as string : " + dataString);

		for(rule ru : setOfAllRules)
		{
			comparePacketToRule(ipPacket, ru);
		}
	}

	public boolean TCPsrcPortMatch(TCPPacket t, int port)
	{
		if(t.getSourcePort() == port) return true;
		else return false;
	}

	public boolean TCPdestPortMatch(TCPPacket t, int port)
	{
		if(t.getDestinationPort() == port) return true;
		else return false;
	}

	public boolean UDPdestPortMatch(UDPPacket u, int port)
	{
		if(u.getDestinationPort() == port) return true;
		else return false;
	}

	public boolean UDPsrcPortMatch(UDPPacket u, int port)
	{
		if(u.getSourcePort() == port) return true;
		else return false;
	}

	public boolean srcIPMatch(IPPacket p, String addr)
	{
		if(p.getSourceAddress().equals(addr) || addr.equals("0.0.0.0")) return true;
		else return false;
	}

	public boolean destIPMatch(IPPacket p, String addr)
	{
		if(p.getDestinationAddress().equals(addr) || addr.equals("0.0.0.0")) return true;
		else return false;
	}

	public boolean isTCP(IPPacket p)
	{
		if(p.getProtocol() == 6) return true;
		else return false;
	}

	public boolean isUDP(IPPacket p)
	{
		if(p.getProtocol() == 17) return true;
		else return false;
	}


	/*
		TAs Note: if we see the "recv" in the message, rule.ip must match the packet's SOURCE address
		if we see the "send" message, rule.ip must match the packet's DESTINATION address
	*/
	
	public void comparePacketToRule(IPPacket packet, rule r)
	{
			//compare packet info with a rule object
			//using the helper methods above
		
			//the goal is to call this method when the
			//packet arrives to compare it to all rules

			//print the name of r if we have a match ( all helpers return true)

			boolean ruleMatch = true;	//change to false if we find something that does not match
			
			/*
				MATCH IN PROTOCOL
			*/
			if(r.type.equalsIgnoreCase("protocol"))
			{
				if(isTCP(packet) == true && r.proto.equalsIgnoreCase("tcp")){
					//debug
					System.out.println("Match in protocol (tcp)");
				}
				else if(isUDP(packet) == true && r.proto.equalsIgnoreCase("udp"))
				{
				//debug
					System.out.println("Match in protocol (UDP)");
				}
				else
				{
					System.out.println("incompatible protocols");
					 ruleMatch = false;
					//return;
				}
			}
			
			/*
				MATCH IN SRC IP ADDRESS OR DEST IP DEPENDING ON NATURE OF PACKET
			*/

		byte[] data = packet.getData();
		String dataString;

		boolean recvMatch = false;
		boolean sendMatch = false;

		try {
			//grabs byte array of data and translates to string

			dataString = new String(data,"UTF-8");
			/*
			Pattern p = Pattern.compile(r.recv);
			Matcher m = p.matcher(dataString);
			boolean b = m.matches();

			if(b == true){ System.out.println("Found match in recv data"); recvMatch = true;}
			else System.out.println("Did not find match in recv data");

			p = Pattern.compile(r.send);
			m = p.matcher(dataString);
			b = m.matches();

			if(b == true){ System.out.println("Found match in send data"); sendMatch = true;}
			else System.out.println("Did not find match in send data");
			*/
			if( r.recv.length()>0 && (dataString.contains(r.recv) || dataString.matches(r.recv)))
			{
				recvMatch = true;
				System.out.println("Found match in recv string");
			}
				
			if( r.send.length()>0 && (dataString.contains(r.send) || dataString.matches(r.send)) )
			{
				sendMatch = true;
				System.out.println("Found match in send string");
			}
			
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

				if(r.recv.length() > 0) //a message being received indicates the source of the packet
				{			//should be compared (according to TA)
					if(srcIPMatch(packet, r.ip) == false)
					{
						if(srcIPMatch(packet,r.ip) == false)
							System.out.println("Source ip mismatch");
							
						ruleMatch = false;
					//	return;
					}	
				}
				
				if(r.send.length() > 0)	//a message being sent indicates the destination of the packet
				{			//must match
					if(destIPMatch(packet, r.ip) == false)
					{
						if(destIPMatch(packet,r.ip)==false)
							System.out.println("destination ip mismatch");
						
						ruleMatch = false;
						//return;
					}
				}

			if(r.remote_port > 0)
			{
				//a specific port on packet's source addr must match
				
				//CHECK packet.getSourcePort() depending on tcp/udp
				if(isTCP(packet) == true && r.proto.equalsIgnoreCase("tcp"))
				{
					if(TCPsrcPortMatch((TCPPacket)packet,r.remote_port) == false)
					{
						System.out.println("remote port mismatch");
						ruleMatch = false;
					}
				}
				else if(isUDP(packet) == true && r.proto.equalsIgnoreCase("udp"))
				{
					if(UDPsrcPortMatch((UDPPacket)packet,r.remote_port) == false)
					{
						System.out.println("remoe port mismatch");
						ruleMatch = false;
					}
				}
				else if(r.type.equalsIgnoreCase("stream"))
				{
					//stream protocol, try casting as tcp packet for now
					if(TCPsrcPortMatch((TCPPacket)packet,r.remote_port) == false)
					{
						System.out.println("stream type remote port mismatch");
						 ruleMatch = false;
					}
				}
				else
				{
					System.out.println("Tony sucks at coding");
					ruleMatch = false;
				}
			}
			
			if(r.local_port > 0)
			{
				//a specific port on user's computer must match the destination addr:port of the packet
			
				//CHECK packet.getDestinationPort() depending on tcp/udp
				if(isTCP(packet) == true && r.proto.equalsIgnoreCase("tcp"))
				{
					if(TCPdestPortMatch((TCPPacket)packet,r.local_port) == false){
						System.out.println("tcp packet mismatch with rule local port");
						ruleMatch = false;
					}
				}
				else if(isUDP(packet) == true && r.proto.equalsIgnoreCase("udp"))
				{
					if(UDPdestPortMatch((UDPPacket)packet,r.local_port) == false)
					{
						System.out.println("udp packet mismatch with rule's local port");
						ruleMatch = false;
					}
				}
				else if(r.type.equalsIgnoreCase("stream"))
				{
					if(TCPsrcPortMatch((TCPPacket)packet,r.local_port) == false)
					{
						System.out.println("stream packet mismatch with rule's local port");
						ruleMatch = false;
					}
				}
				else
				{
					System.out.println("tony sucks at coding 2: electric boogaloo");
					ruleMatch = false;	
				}
			}


			for(SubRule sr : r.subRules)
			{

				if(sr.recv.length() > 0) //a message being received indicates the source of the packet
				{			//should be compared (according to TA)
					if(dataString.contains(sr.recv)) recvMatch = true;
					
					if(srcIPMatch(packet, r.ip) == false || recvMatch == false )
					{
						ruleMatch = false;
						//return;
					}
				}
				
				if(sr.send.length() > 0)	//a message being sent indicates the destination of the packet
				{			//must match
					if(dataString.contains(sr.send)) sendMatch = true;
					if(destIPMatch(packet, r.ip) == false || sendMatch == false)
					{
						ruleMatch = false;
						//return;
					}
				}

			if(((TCPPacket)packet).isSyn() == true){System.out.println("syn msg");
				if(sr.flags[0] == false) ruleMatch = false;}
			else{System.out.println("no syn msg");
				if(sr.flags[0] == true) ruleMatch = false;}
			
			if(((TCPPacket)packet).isAck() == true){System.out.println("ack msg");
				if(sr.flags[1] == false) ruleMatch = false;}
			else{System.out.println("no ack msg");
				if(sr.flags[1] == true) ruleMatch = false;}
			
			if(((TCPPacket)packet).isFin() == true){System.out.println("fin msg");
				if(sr.flags[2] == false) ruleMatch = false;}
			else{System.out.println("no fin msg");
				if(sr.flags[2] == true) ruleMatch = false;}
			
			if(((TCPPacket)packet).isRst() == true){System.out.println("rst msg");
				if(sr.flags[3] == false) ruleMatch = false;}
			else{System.out.println("no rst msg");
				if(sr.flags[3] == true) ruleMatch = false;}
			
			if(((TCPPacket)packet).isPsh() == true){System.out.println("psh msg");
				if(sr.flags[4] == false) ruleMatch = false;}
			else{System.out.println("no psh msg");
				if(sr.flags[4] == true) ruleMatch = false;}
			
			if(((TCPPacket)packet).isUrg() == true){System.out.println("urg msg");
				if(sr.flags[5] == false) ruleMatch = false;}
			else{System.out.println("no urg msg");
				if(sr.flags[5] == true) ruleMatch = false;}
	
			}
				

			if(ruleMatch == true && sendMatch != false && recvMatch != false) System.out.println("Rule Match - " + r.name);
			else System.out.println("non match");
	}
	
}

public class pcapreader{

	public void readFile(String filename, ArrayList<rule> rF) throws CapturePacketException {
		
		System.out.println("Reading file "+filename);
		PacketCaptureListener jpcap = new PacketCaptureListener(rF);

		try {
			jpcap.openOffline(filename);
		} catch (CaptureFileOpenException e1) {
			// TODO Auto-generated catch block
			System.err.println(e1.toString());
			e1.printStackTrace();
		}

		// we only consider network layer traffic
		// this of course means we don't see things like ARP poisoning
		try {
			jpcap.setFilter("ip", true);
			jpcap.addPacketListener(jpcap);
			jpcap.capture(-1);
			
		} catch (InvalidFilterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
