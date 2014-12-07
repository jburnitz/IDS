# Joseph Burnitz and Anthony Manetti
# Homework 5 - Intrusion Detection System
# 

To begin running the program, ensure you have
the proper libraries necessary for the program
to run.  PCAP essentially.

When you run the program, the intrusion detection system
will scan a specified trace file and compare it with
a specified rule file.  Any packets form the trace file
that match a rule found in the rule file will cause
the name of the matched rule to be displayed in output.

To run the program, use the included makefile:

STEP 1: Navigate to the 'src' folder of the directory
STEP 2: in your terminal, enter 'make' or 'make default'
STEP 3: Run the program in the form: 'java snids <rule_file> <trace_file>
STEP 4: That's it!  Enjoy the program!


NOTES: there should be no user input in this program.
	If you are having a problem getting the makefile
	to work properly, follow these alternate steps:

1: navigate to 'src' folder
2: in terminal, enter: 'javac *.java'
3: 'java snids <rule_file> <trace_file>'

KNOWN ISSUES:
To the best of our knowledge Java regular expression has issues
 when looking for hexadecimel values. Due to this constraint searching
 for hex values is adversely affected and can lead to undefined behavior.
