import java.util.*;
import java.io.*;

/**
 * Java Instrusion Detection System
 * For CS 487 Secure Computer Systems at UIC
 * @category Homework
 * @author Joseph Burnitz & Anthony Manetti 
 */
public class IDS {

	//Entry point for application
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		//Basic error checking
		if(args.length!=2){
			usage();
			System.exit(-1);
		}
		
		File rules = new File(args[0]);
			
		if(!rules.exists()){
			System.err.println("Fatal: File '"+rules.getName()+"' does not exist");
			System.exit(-2);
		}
		if(!rules.isFile()){
			System.err.println("Fatal: File '"+rules.getName()+"' is not a file");
			System.exit(-3);
		}
		if(!rules.canRead()){
			System.err.println("Fatal: File '"+rules.getName()+"' is not readable");
			System.exit(-3);
		}
		
		String line = null; //initialize string to represent line in file
		
		try 
		{ //try
			// FileReader reads text files in the default encoding.
			FileReader fileReader =
			new FileReader(rules); //fileReader instance
			// Always wrap FileReader in BufferedReader.
			BufferedReader bufferedReader =
			new BufferedReader(fileReader);
			
			ArrayList<String> list = new ArrayList<String>();
			
			while((line = bufferedReader.readLine()) != null)
			{ //until we reach empty space in file
				list.add(line);
			}
			
			if(list.size() > 0)
			{
				String[] rulesFile = new String[list.size()];
				
				int ind = 0;
				
				for(String s : list)
				{
					rulesFile[ind] = s;
					ind++;
				}
			}
			else
			{
				System.err.println("\nNo Data Found\n");
			}
		}
		catch(FileNotFoundException ex) { //catch exception for file not there
			System.err.println(
			"Unable to open file '" +
			args[0] + "' [FILE NOT FOUND]");
			//System.exit(1);
		}
		catch(IOException ex) { //catch exception for file corrupted
			System.err.println(
			"Error reading file '"
			+ args[0] + "'");
			//System.exit(1);
			// Or we could just do this:
			// ex.printStackTrace();
		}

	}
	//How to use the IDS
	protected static void usage(){
		//experimental, trying to do something like cout << argv[0] << " <arg_name>"...
		//String exename = new java.io.File(IDS.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getName().toString();
		//System.out.println( "Usage: " + exename + " <rule_file> <packet_trace_file>" );
		System.out.println( "Usage: snids <rule_file> <packet_trace_file>" );
		
		System.out.println( "Where <rule_file> refers rule file in format:" );
		
		System.out.println(
				  "        <host>     ::=   host=<ip>\n"
				+ "\n"
				+ "        <rule>     ::=   name=<string>\n"
				+ "			<tcp_stream_rule>|<tcp_protocol_rule>\n\n"
				+ "<tcp_stream_rule>  ::=  type=stream\n"
				+ "			local_port=(any|<port>)\n"
				+ "			remote_port=(any|<port>)\n"
				+ "			ip=(any|<ip>)\n"
				+ "			(send|recv)=<regexp>\n\n"
				+ "<tcp_protocol_rule>::=  type=protocol\n"
				+ "			proto=tcp|udp\n"
				+ "			local_port=(any|<port>)\n"
				+ "			remote_port=(any|<port>)\n"
				+ "			ip=(any|<ip>)\n"
				+ "			<sub_rule>\n"
				+ "			<sub_rule>*\n\n"
				+ "   <sub_rule>      ::=  (send|recv)=<regexp>  (with flags=<flags>)?\n"
				+ "	<string>   ::=   alpha-numeric string\n"
				+ "	<ip>  	   ::=   string of form [0-255].[0-255].[0-255].[0-255]\n"
				+ "	<port>     ::=   string of form [0-65535]\n"
				+ "	<regexp>   ::=   Perl Regular Expression\n"
				+ "	<flags>    ::=   <flag>*\n"
				+ "	<flag>     ::=   S|A|F|R|P|U" );
		
	}

}
