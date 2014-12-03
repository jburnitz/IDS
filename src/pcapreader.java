import java.util.*;

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

	public Arraylist<rule> setOfAllRules;

	public PacketCaptureListener()
	{
		setOfAllRules = new ArrayList<rule>();
	}

	public void setRuleList(ArrayList<rule> r)
	{
		setOfAllRules = r;
	}
	
	@Override
	public void packetArrived(Packet packet) {
		// TODO Auto-generated method stub
		IPPacket ipPacket = (IPPacket)packet;

		if(isTCP(ipPacket) == true ) //means its TCP
			System.out.println("TCP packet from " + ipPacket.getSourceAddress() + " : " + ((TCPPacket)ipPacket).getSourcePort());
		else if(isUDP(ipPacket) == true)
		{	//a udp packet
			System.out.println("UDP packet from " + ipPacket.getSourceAddress() + " : " + ((UDPPacket)ipPacket).getSourcePort());		
		}
		else System.out.println("Packet of unknown protocol (" +ipPacket.getProtocol() + ") from " + ipPacket.getSourceAddress());


		System.out.println("Destination of packet : " + ipPacket.getDestinationAddress());	

		byte[] data = ipPacket.getData();
		String dataString = null;
		try {
			dataString = new String(data,"UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("Packet data as string : " + dataString);
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
		if(p.getSourceAddress().equals(addr)) return true;
		else return false;
	}

	public boolean destIPMatch(IPPacket p, String addr)
	{
		if(p.getDestinationAddress().equals(addr)) return true;
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
			if(isTCP(packet) == true && r.proto.equals("tcp")){
				//debug
				System.out.println("Match in protocol (tcp)");
			}
			else if(isUDP(packet) == true && r.proto.equals("udp"))
			{
				//debug
				System.out.println("Match in protocol (UDP)");
			}
			else
			{
				 ruleMatch = false;
				return;
			}

			/*
				MATCH IN SRC IP ADDRESS
			*/
			if(!(r.ip.equalsIgnoreCase("any")))
			{
				if(r.recv == true)
				{
					if(srcIPMatch(packet, r.ip) == false)
					{
						ruleMatch = false;
						return;
					}
				}
				
				if(r.send == true)
				{
					if(destIPMatch(packet, r.ip == false)
					{
						ruleMatch = false;
						return;
					}
				}
			}

			/*
				TODO: MATCHING PORTS BETWEEN PACKET/RULE
			*/
			if(!(r.remote_port.equals("any")))
			{
				//a specific port on packet's source addr must match
				
				//CHECK packet.getSourcePort() depending on tcp/udp
				if(isTCP(packet) == true && r.proto.equalsIgnoreCase("tcp"))
				{
					if(TCPsrcPortMatch((TCPPacket)packet,r.remote_port) == false)
						ruleMatch = false;
				}
				else if(isUDP(packet) == true && r.proto.equalsIgnoreCase("udp"))
				{
					if(UDPsrcPortMatch((UDPPacket)packet,r.remote_port) == false)
						ruleMatch = false;
				}
				else ruleMatch = false;	

				
			}
			
			if(!(r.local_port.equals("any")))
			{
				//a specific port on user's computer must match the destination addr:port of the packet
			
				//CHECK packet.getDestinationPort() depending on tcp/udp
				if(isTCP(packet) == true && r.proto.equalsIgnoreCase("tcp"))
				{
					if(TCPdestPortMatch((TCPPacket)packet,r.local_port) == false)
						ruleMatch = false;
				}
				else if(isUDP(packet) == true && r.proto.equalsIgnoreCase("udp"))
				{
					if(UDPdestPortMatch((UDPPacket)packet,r.local_port) == false)
						ruleMatch = false;
				}
				else ruleMatch = false;	
				
			}

			if(ruleMatch == true) System.out.println("Rule Match - " + r.name);
	}
	
}

public class pcapreader{

	public static void readFile(String filename) throws CapturePacketException {
		
		System.out.println("Reading file "+filename);
		PacketCaptureListener jpcap = new PacketCaptureListener();

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
	
	public static void main(String[] args) throws CapturePacketException
	{
		System.out.println("Begin capture");
		readFile("trace1.pcap");
		
	}
}
