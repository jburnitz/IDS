public class rule
{
	String name;
	String type;
	String proto;
	String local_port;
	String remote_port;
	String ip;
	String send;
	String recv;
	String flags;

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
