# umbrella-benchmark-tools

This is just a cheap hacky scoring tool to process umbrella results against the owasp benchmark and produce some scoring data and metrics.

# To Run:
  
  java -jar ../umbrella-benchmark-tools/target/umbrella-benchmark-tools-1.0-SNAPSHOT.jar ../umbrella-application/benchmark.sarif.json striped-expectedresults-benchmark-1.2.csv
 
 
# Data files
The owasp projects has a csv of expected-results from the benchmark.  We've also produced a version of the expected results with vulnerability types umbrella doesn't support removed so that we can get accurate metrics on what we actually should be detecting.
Both of those data files are available for convienence from the data dir in this project
