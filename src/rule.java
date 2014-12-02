public class rule
{
	String name;
	String type;
	String proto;
	String local_port; //on MY computer
	String remote_port;	//on the sernder's computer
	String ip;	//the ip that the packet came from

	String send;	//	
	String recv;	//
	String flags;	//

	public rule()
	{
		name = "blank rule";
		type = "";	//protocol | stream
		proto = "";	//tcp | udp
		local_port = "";
		remote_port = "";
		ip = "";
		send = "";
		recv = "";
		flags = "";
	}
}
