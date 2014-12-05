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
	int local_port;
	int remote_port;
	String ip;
	
	//Only send or recv can be occupied at a time
	//string in form of regexp
	String send;
	String recv;
	//subRules is only occupied when type==protocol
	ArrayList<SubRule> subRules;
	
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
