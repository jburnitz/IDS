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
		flags = new boolean[6];
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
	String send;
	String recv;
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
