import java.util.ArrayList;

enum Flags{
	//S A F R P U
	SYN, ACK, FIN, RST, PUSH, URG
}

class SubRule
{
	String send;
	String recv;
	boolean[] flags;
	
	public SubRule(){

		//S A F R P U
		//SYN, ACK, FIN, RST, PUSH, URG
		flags = new boolean[6];
		//The regexp to match with
		send = "";
		recv = "";
	}
}

public class rule
{
	String name;
	String type;
	String proto;
	
	//subRules is only occupied when type==protocol
	ArrayList<SubRule> subRules;
	
	int local_port; //on MY computer
	int remote_port;	//on the sernder's computer
	String ip;	//the ip that the packet came from

	String send;	//is this a send or recv message?	
	String recv;	//
	String flags;	//

	public rule()
	{
		name = "blank rule";
		type = "";	//protocol | stream
		proto = "";	//tcp | udp
		local_port = 0;
		remote_port = 0;
		ip = "";
		send = "";
		recv = "";

		subRules = new ArrayList<SubRule>();
	}
	public void AddSubRule(boolean send, String regexp, boolean[] flags ){
		SubRule sr = new SubRule();
		if(send)
			sr.send = regexp;
		else
			sr.recv = regexp;
		sr.flags = flags;
		
		subRules.add(sr);
	}
}
