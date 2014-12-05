import java.util.*;
import java.io.*;

import net.sourceforge.jpcap.capture.CapturePacketException;

/**
 * Java Instrusion Detection System
 * For CS 487 Secure Computer Systems at UIC
 * @category Homework
 * @author Joseph Burnitz & Anthony Manetti 
 */
public class snids {
	//Entry point for application
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		//Basic error checking
		if(args.length!=2){
			System.err.println("Fatal: Two arguments needed");
			usage();
			System.exit(-1);
		}

		File rulesFile = new File(args[0]);
			
		if(!rulesFile.exists()){
			System.err.println("Fatal: File '"+rulesFile.getName()+"' does not exist");
			System.exit(-21);
		}
		if(!rulesFile.isFile()){
			System.err.println("Fatal: File '"+rulesFile.getName()+"' is not a file");
			System.exit(-31);
		}
		if(!rulesFile.canRead()){
			System.err.println("Fatal: File '"+rulesFile.getName()+"' is not readable");
			System.exit(-41);
		}
		
		File pcap = new File(args[1]);
		
		if(!pcap.exists()){
			System.err.println("Fatal: File '"+pcap.getName()+"' does not exist");
			System.exit(-22);
		}
		if(!pcap.isFile()){
			System.err.println("Fatal: File '"+pcap.getName()+"' is not a file");
			System.exit(-32);
		}
		if(!pcap.canRead()){
			System.err.println("Fatal: File '"+pcap.getName()+"' is not readable");
			System.exit(-42);
		}
				
		try 
		{
			// FileReader reads text files in the default encoding.
			FileReader fileReader =	new FileReader(rulesFile);
			
			// Always wrap FileReader in BufferedReader.
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			
			//declare string for each line in file
			String line = null;

			ArrayList<String> list = new ArrayList<String>();
			
			//until we reach empty space in file
			while((line = bufferedReader.readLine()) != null)
				list.add(line);
			
			//we're done with the file
			bufferedReader.close();
			
			parser ruleParser = new parser( list );
			ruleParser.PrintRules();
			pcapreader pcr = new pcapreader();
			ArrayList<rule> rules = new ArrayList<rule>(ruleParser.rules);
			
			try {
				pcr.readFile( args[1], rules );
			} catch (CapturePacketException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
		catch(FileNotFoundException ex) { //catch exception for file not there
			System.err.println(
			"Unable to open file '" +
			args[0] + "' [FILE NOT FOUND]");
			System.exit(-21);
		}
		catch(IOException ex) { //catch exception for file corrupted
			System.err.println(
			"Error reading file '"
			+ args[0] + "'");
			System.exit(-41);
		}
	}
	//How to use the IDS
	protected static void usage(){
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
