public class rule
{
	String name;
	String type;
	String proto;
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
		flags = "";
	}
}
