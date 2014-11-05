import java.util.ArrayList;

enum Flags{
	//S A F R P U
	SYN, ACK, FIN, RST, PUSH, URG
}

class Subrule
{
	String send;
	String recv;
	boolean[] flags;
	
	Subrule(){
		flags = new boolean[6];
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
	ArrayList<Subrule> subRules;
	
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
		subRules = new ArrayList<Subrule>();
	}
}
