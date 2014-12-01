import java.io.IOException;
import java.util.Vector;







/*
 * import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
*/

import net.sourceforge.jpcap.capture.CaptureFileOpenException;
import net.sourceforge.jpcap.capture.CapturePacketException;
import net.sourceforge.jpcap.capture.InvalidFilterException;
import net.sourceforge.jpcap.capture.PacketCapture;
import net.sourceforge.jpcap.capture.PacketListener;
import net.sourceforge.jpcap.net.Packet;
import java.io.*;

class PacketCaptureListener extends PacketCapture implements PacketListener{

	@Override
	public void packetArrived(Packet packet) {
		// TODO Auto-generated method stub
		System.out.println(packet.getHeader().toString());
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
		File test = new File("trace1.pcap");
		System.out.println(test.getAbsolutePath().toString());
		readFile("trace1.pcap");
		System.out.println("Begin capture");
	}
}