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
		System.out.println("foo");
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
			if(r.type.equalsIgnoreCase("protcol"))
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
					 ruleMatch = false;
					return;
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

		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


				if(r.recv.length() > 0) //a message being received indicates the source of the packet
				{			//should be compared (according to TA)
					if(srcIPMatch(packet, r.ip) == false || recvMatch == false )
					{
						
						ruleMatch = false;
						return;
					}

					
				}
				
				if(r.send.length() > 0)	//a message being sent indicates the destination of the packet
				{			//must match
					if(destIPMatch(packet, r.ip) == false || sendMatch == false)
					{
						ruleMatch = false;
						return;
					}
				}

			/*
				TODO: MATCHING PORTS BETWEEN PACKET/RULE
			*/
			if(r.remote_port > 0)
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
				else if(r.type.equalsIgnoreCase("stream"))
				{
					//stream protocol, try casting as tcp packet for now
					if(TCPsrcPortMatch((TCPPacket)packet,r.remote_port) == false)
						 ruleMatch = false;	
				}
				else
					ruleMatch = false;
				
			}
			
			if(r.local_port > 0)
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
				else if(r.type.equalsIgnoreCase("stream"))
				{
					if(TCPsrcPortMatch((TCPPacket)packet,r.local_port) == false)
						ruleMatch = false;
				}
				else
					ruleMatch = false;	
				
			}


			for(SubRule sr : r.subRules)
			{

				if(sr.recv.length() > 0) //a message being received indicates the source of the packet
				{			//should be compared (according to TA)
					if(srcIPMatch(packet, r.ip) == false || recvMatch == false )
					{
						ruleMatch = false;
						return;
					}
				}
				
				if(sr.send.length() > 0)	//a message being sent indicates the destination of the packet
				{			//must match
					if(destIPMatch(packet, r.ip) == false || sendMatch == false)
					{
						ruleMatch = false;
						return;
					}
				}

				if(((TCPPacket)packet).isAck() == true)
					System.out.println("ack msg");
				else
					System.out.println("no ack msg");
				//send/recv stuff


				/*
							S|A|F|R|P|U
				int array of input = {isSyn(),isAck(),isFin(),isRst(),isPsh(),isUrg};

				e.g. {f,t,f,t,t,f} means 
				
				for each bit, AND the isAck()...isSyn()
		
				if the array is changed their is no match		
		
				Compare flags

				for a tcp:
				  boolean 	isAck()
          Check the ACK flag, flag indicates if the ack number is valid.
				 boolean 	isFin()
          Check the FIN flag, flag indicates the sender is finished sending.
				 boolean 	isPsh()
          Check the PSH flag, flag indicates the receiver should pass the data to the application as soon as possible.
				 boolean 	isRst()
          Check the RST flag, flag indicates the session should be reset between the sender and the receiver.
				 boolean 	isSyn()
          Check the SYN flag, flag indicates the sequence numbers should be synchronized between the sender and receiver to initiate a connection.
				 boolean 	isUrg()
          Check the URG flag, flag indicates if the urgent pointer is valid.
			*/
			}
				

			if(ruleMatch == true) System.out.println("Rule Match - " + r.name);
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
	
/*	public static void main(String[] args) throws CapturePacketException
	{
		System.out.println("Begin capture");
		readFile("trace1.pcap");
		
	}*/
}
