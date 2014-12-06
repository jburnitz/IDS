import java.util.ArrayList;
//import java.util.regex.Matcher;
import java.util.regex.Pattern;

enum Flags{
	//S A F R P U
	SYN, ACK, FIN, RST, PUSH, URG
}

class SubRule
{
//	String send;
//	String recv;
	boolean send;
	boolean recv;
	Pattern sendRegex;
	Pattern recvRegex;

	boolean[] flags;
	
	public SubRule(){

		//S A F R P U
		//SYN, ACK, FIN, RST, PUSH, URG
		flags = new boolean[6];
		//The regexp to match with
		send = false;
		recv = false;
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

	boolean send;	//is this a send or recv message?	
	boolean recv;	//
	Pattern sendRegex;
	Pattern recvRegex;
	String flags;	//

	public rule()
	{
		name = "blank rule";
		type = "";	//protocol | stream
		proto = "";	//tcp | udp
		local_port = 0;
		remote_port = 0;
		ip = "";
		send = false;
		recv = false;

		subRules = new ArrayList<SubRule>();
	}
	public void AddSubRule(boolean send, String regexp, boolean[] flags ){
		SubRule sr = new SubRule();
		if(send==true){
			sr.send = true;
			sr.sendRegex = Pattern.compile(regexp);
		}
		else{
			sr.recv = true;		
			sr.recvRegex = Pattern.compile(regexp);
		}
		
		sr.flags = flags;
		subRules.add(sr);
	}
}
