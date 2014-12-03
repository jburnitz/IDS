import java.util.ArrayList;
import java.util.LinkedList;

/** 
 * Parses the rules file making concise rule objects
 * @author joe
 *
 */
public class parser{
	protected LinkedList<rule> rules;
	
	public parser(ArrayList<String> rulesFile ){
		rules = new LinkedList<rule>();
		
		if(rulesFile.size()<=3){
			System.err.println("Fatal: Impossibly short rule file");
			System.exit(-51);
		}
		
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
		for(int i=0; i<rulesFile.size(); i++){
			//System.out.println(rulesFile.get(i));
		}
		//get host before looking for rule names
		String host = rulesFile.get(0).trim().split("=")[1];
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
						
						if( left.equalsIgnoreCase("name") ){//means we came across a new rule;
							i=(j-1); //the (-1) so the name can be handled
						}
						
					}//end STREAM Parse loop
				}//End IF STREAM Type rule
				else if( right.equalsIgnoreCase("protocol") ){
					
				}
			}//end IF TYPE == ?
			
			if(left.equalsIgnoreCase("send") && rules.peekFirst().type.equalsIgnoreCase("stream") ){
				rules.peekFirst().send = right;
				//in stream rules, both can't exist recv OR send
				rules.peekFirst().recv = "";
				continue;
			}
			if(left.equalsIgnoreCase("recv") && rules.peekFirst().type.equalsIgnoreCase("stream") ){
				rules.peekFirst().recv.equalsIgnoreCase(right);
				//in stream rules, both can't exist recv OR send
				rules.peekFirst().send = "";
				continue;
			}
			
		}
		
	}

	public void PrintRules(){
		for(rule r : rules){
			System.out.println("Name: 		 "+r.name);
			System.out.println("Type: 		 "+r.type);
			System.out.println("Proto: 		 "+r.proto);
			System.out.println("Local port:  "+r.local_port);
			System.out.println("Remote port: "+r.remote_port);
			System.out.println("IP:			 "+r.ip);
			System.out.println("SEND: 		 "+r.send);
			System.out.println("RECV: 		 "+r.recv);
			System.out.println("SubRules: ");
			for( Subrule s : r.subRules )
				System.out.println("FLAGS:		 "+s.flags.toString()+"\n");
		}
	}

	public LinkedList<rule> getRules(){
		return rules;
	}
}

