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
			
			//ignoring blanks and comments
			if(rulesFile.get(i).trim().isEmpty() || rulesFile.get(i).trim().startsWith("#"))
				continue;
		
			if(!rulesFile.get(i).contains("=")){
				System.err.println("Fatal: Malformed rule file on line: "+Integer.toString(i));
				System.exit(-61);
			}
		}
		
		//get host before looking for rule names
		String host = rulesFile.get(0).trim().split("=")[1];
		
		String line;
		String left;
		String right;
		
		//we don't know the exact order of the specification in the rule
		for(int i=1; i<rulesFile.size(); i++){
			line = rulesFile.get(i).trim();
			left = line.split("=")[0];
			right = line.split("=")[1];
			
			if(left == "name"){
				rules.addFirst(new rule() );
				rules.peekFirst().name = right;
				continue;
			}
			if(left == "type"){
				rules.peekFirst().type = right;
				if(right == "stream"){
					//finish out the stream rule
					for (int j=i; j<rulesFile.size(); j++ ){
						
						line = rulesFile.get(j).trim();
						left = line.split("=")[0];
						right = line.split("=")[1];
						
						if(left == "local_port"){
							if(right == "any")
								rules.peekFirst().local_port = 0;
							else
								rules.peekFirst().local_port = Integer.parseInt(right);
							continue;
						}
						if(left == "remote_port"){
							if(right == "any")
								rules.peekFirst().local_port = 0;
							else
								rules.peekFirst().local_port = Integer.parseInt(right);
							continue;
						}
						
						if(left == "ip"){
							if(right == "any")
								rules.peekFirst().ip = "0.0.0.0";
							else{
								rules.peekFirst().ip = right;
							}
							continue;
						}
						
						if( left == "name" ){//means we came across a new rule;
							i=(j-1); //the (-1) so the name can be handled
						}
						
					}//end STREAM Parse loop
				}//End IF STREAM Type rule
				else if( right == "protocol"){
					
				}
			}//end IF TYPE == ?
			
			if(left == "send" && rules.peekFirst().type == "stream" ){
				rules.peekFirst().send = right;
				//in stream rules, both can't exist recv OR send
				rules.peekFirst().recv = null;
				continue;
			}
			if(left == "recv" && rules.peekFirst().type == "stream" ){
				rules.peekFirst().recv = right;
				//in stream rules, both can't exist recv OR send
				rules.peekFirst().send = null;
				continue;
			}
			
		}
		
	}

}
