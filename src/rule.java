import java.util.List;
class Proto_Subrule
{
	String send;
	String recv;
	
	String string;
	String ip;
	int port;
	String flags; //TCP flags
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
	String flags;
	

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
