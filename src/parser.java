public class parser{
	String[] rulesFile;
	
	public parser(String[] rulesFile ){
		this.rulesFile = rulesFile;
		//go crazy!
	}
	
		public parser(String fileName)
{
String line = null; //initialize string to represent line in file
try { //try
// FileReader reads text files in the default encoding.
FileReader fileReader =
new FileReader(fileName); //fileReader instance
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
this.rulesFile = new String[list.size()];
int ind = 0;
for(String s : list)
{
this.rulesFile[ind] = s;
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
fileName + "' [FILE NOT FOUND]");
//System.exit(1);
}
catch(IOException ex) { //catch exception for file corrupted
System.err.println(
"Error reading file '"
+ fileName + "'");
//System.exit(1);
// Or we could just do this:
// ex.printStackTrace();
}
}

}
