import java.util.ArrayList;
import java.util.LinkedList;

/** 
 * Parses the rules file making concise rule objects
 * @author joe
 *
 */

public class parser{
	protected LinkedList<rule> rules;
	protected String host;
	
	public parser(ArrayList<String> rulesFile ){
		rules = new LinkedList<rule>();
		
		if(rulesFile.size()<=3){
			System.err.println("Fatal: Impossibly short rule file");
			System.exit(-51);
		}
		
		////////////////////////////
		//Rule cleanup		////////
		////////////////////////////
		//make sure every populated line has a left and right side
		//and apparently there aren't comments style defined, but everyone likes #
		for(int i=0; i<rulesFile.size(); i++){
			//System.out.println(rulesFile.get(i));
			//ignoring blanks and comments
			if(rulesFile.get(i).trim().isEmpty() || rulesFile.get(i).trim().startsWith("#")){
				rulesFile.remove(i);
				continue;
			}
		
			if(!rulesFile.get(i).contains("=")){
				System.err.println("Fatal: Malformed rule file on line: "+Integer.toString(i));
				System.exit(-61);
			}
		}
		
		/*
		 * print the cleaned lines
		for(int i=0; i<rulesFile.size(); i++){
			//System.out.println(rulesFile.get(i));
		}
		*/
		
		//get host before looking for rule names
		host = rulesFile.get(0).trim().split("=")[1];
		//System.out.println("Host is: "+host);
		String line;
		String left;
		String right;
		
		//we don't know the exact order of the specification in the rule
		for(int i=1; i<rulesFile.size(); i++){
			line = rulesFile.get(i).trim();
			left = line.split("=")[0];
			right = line.split("=")[1];
			//System.out.println("left: "+left);
			if(left.equalsIgnoreCase("name") ){
				rules.addFirst(new rule() );
				rules.peekFirst().name = right;
				//System.out.println("rules[0]: "+rules.get(0).name);
				continue;
			}
			//Determine if the rule is of Type "stream" or "protocol"
			if(left.equalsIgnoreCase("type")){
				rules.peekFirst().type = right;
				if(right.equalsIgnoreCase("stream") ){
					//finish out the stream rule
					for (int j=i; j<rulesFile.size(); j++ ){
						
						line = rulesFile.get(j).trim();
						left = line.split("=")[0];
						right = line.split("=")[1];
						
						if(left.equalsIgnoreCase("local_port")){
							if(right.equalsIgnoreCase("any"))
								rules.peekFirst().local_port = 0;
							else
								rules.peekFirst().local_port = Integer.parseInt(right);
							continue;
						}
						if(left.equalsIgnoreCase("remote_port") ){
							if(right.equalsIgnoreCase("any") )
								rules.peekFirst().remote_port = 0;
							else
								rules.peekFirst().remote_port = Integer.parseInt(right);
							continue;
						}
						
						if(left.equalsIgnoreCase("ip") ){
							if(right.equalsIgnoreCase("any") )
								rules.peekFirst().ip = "0.0.0.0";
							else{
								rules.peekFirst().ip = right;
							}
							continue;
						}
						
						if(left.equalsIgnoreCase("send") ){
							rules.peekFirst().send = right;
							//in stream rules, both can't exist recv OR send
							rules.peekFirst().recv = "";
							continue;
						}
						
						if(left.equalsIgnoreCase("recv") ){
							rules.peekFirst().recv.equalsIgnoreCase(right);
							//in stream rules, both can't exist recv OR send
							rules.peekFirst().send = "";
							continue;
						}
						
						/** finishing block for rule */
						if( left.equalsIgnoreCase("name") ){//means we came across a new rule;
							i=(j-1); //the (-1) so the name can be handled
							break;
						}
					}//end STREAM Parse loop
				}//End IF TYPE == STREAM
				else if( right.equalsIgnoreCase("protocol") ){
					//Go through the protocol rules
					for(int j=i; j<rulesFile.size(); j++){
						
						line = rulesFile.get(j).trim();
						left = line.split("=")[0];
						right = line.split("=")[1];
						
						if(left.equalsIgnoreCase("proto")){
							rules.peekFirst().proto = right;
							continue;
						}
						
						if(left.equalsIgnoreCase("local_port")){
							if(right.equalsIgnoreCase("any"))
								rules.peekFirst().local_port = 0;
							else
								rules.peekFirst().local_port = Integer.parseInt(right);
							continue;
						}
						if(left.equalsIgnoreCase("remote_port") ){
							if(right.equalsIgnoreCase("any") )
								rules.peekFirst().remote_port = 0;
							else
								rules.peekFirst().remote_port = Integer.parseInt(right);
							continue;
						}
						if(left.equalsIgnoreCase("ip") ){
							if(right.equalsIgnoreCase("any") )
								rules.peekFirst().ip = "0.0.0.0";
							else{
								rules.peekFirst().ip = right;
							}
							continue;
						}
						//means we found a subrule
						if(left.equalsIgnoreCase("send") || left.equalsIgnoreCase("recv") ){
							
							boolean[] flagArray={false, false, false, false, false, false};
							if(line.contains(" with flags=")){
								int endIndex = line.lastIndexOf(" with flags=");
								right=line.substring(5, endIndex );
								String flagsStr = line.substring(endIndex+12);

								if(flagsStr.contains("S"))
									flagArray[0]=true;
								if(flagsStr.contains("A"))
									flagArray[1]=true;
								if(flagsStr.contains("F"))
									flagArray[2]=true;
								if(flagsStr.contains("R"))
									flagArray[3]=true;
								if(flagsStr.contains("P"))
									flagArray[4]=true;
								if(flagsStr.contains("U"))
									flagArray[5]=true;
							}//end flag parsing
							
							if(left.equalsIgnoreCase("send") )
								rules.peekFirst().AddSubRule(true, right, flagArray);
							else
								rules.peekFirst().AddSubRule(false, right, flagArray);
							
							//get the next rule/subrule
							continue;
						}//End SEND or RECV / or subrule
						
						/** finishing block for rule */
						if( left.equalsIgnoreCase("name") ){//means we came across a new rule;
							i=(j-1); //the (-1) so the name can be handled
							break;
						}
							
					}//END Type=Protocol FOR loop
				}//END Type=Protocol Conditional
				//the type is unknown, handle the error
				else{
					System.err.println("Fatal: Unknown type= ? ");
					System.exit(-71);
				}
			}//end IF LEFT == TYPE
		}//END FOR (lines)
	}//end parser(ArrayList<String> lines) constructor
	
	public void PrintRules(){
		for(rule r : rules){
			System.out.println("Name: 		 "+r.name);
			System.out.println("Type: 		 "+r.type);
			System.out.println("Proto: 		 "+r.proto);
			System.out.println("Local port:  "+r.local_port);
			System.out.println("Remote port: "+r.remote_port);
			System.out.println("IP:			 "+r.ip);
			if(r.proto.equalsIgnoreCase("tcp")){
					if(!r.send.isEmpty())
						System.out.println("SEND: 		 "+r.send);
					if(!r.recv.isEmpty())
						System.out.println("RECV: 		 "+r.recv);
			}
			System.out.println("SubRules: ");
			for( SubRule s : r.subRules ){
				if(!s.recv.isEmpty())
					System.out.print(s.recv);
				else
					System.out.print(s.send);
				
				System.out.print("  Flags: ");
				for( int i=0; i<6; i++){
					if(s.flags[i])
						System.out.print( " "+Flags.values()[i].toString() );
				}				
				System.out.println();
			}
			
		}
	}

	public LinkedList<rule> getRules(){
		return rules;
	}
}

