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

	@Override
	public void packetArrived(Packet packet) {
		// TODO Auto-generated method stub
		IPPacket ipPacket = (IPPacket)packet;

		if(ipPacket.getProtocol() == 6 ) //means its TCP
			System.out.println("TCP packet from " + ipPacket.getSourceAddress() + " : " + ((TCPPacket)ipPacket).getSourcePort());
		else if(ipPacket.getProtocol() == 17)
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
