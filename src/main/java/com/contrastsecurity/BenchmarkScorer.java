package com.contrastsecurity;

import com.contrastsecurity.model.OwaspBenchmarkResult;
import com.contrastsecurity.model.UmbrellaBenchmarkResult;
import com.contrastsecurity.model.UmbrellaBenchmarkResults;
import com.contrastsecurity.sarif.SarifSchema210;
import com.fasterxml.jackson.databind.ObjectMapper;
import picocli.CommandLine;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;


import java.io.*;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;

@Command(name = "benchmark-scorer", mixinStandardHelpOptions = true,
        description = "Score Umbrella against the owasp benchmark")
public class BenchmarkScorer implements Callable<Integer> {
    private static final String CSV_DELIMITER = ",";
    private static final Pattern umbrellaNamePattern = Pattern.compile(".*? (BenchmarkTest\\d\\d\\d\\d\\d)\\.java.*");

    @Parameters(index = "0", paramLabel = "SARIF_FILE", description = "the umnbrella result sarif file.")
    File resultsFile;
    @Parameters(index = "1", paramLabel = "BENCHMARK_CSV", description = "OWASP Benchmark expected results csv")
    File expectedFile;

    public Integer call() throws Exception {
        var actualResults = readActualResults(resultsFile);
        System.out.println("Read " + actualResults.size() + " actual unique results from Umbrella");
        var expectedResults = readExpectedResults(expectedFile);
        System.out.println("Read " + expectedResults.size() + " expected OWASP Benchmark Results");

        describeUmbrellaResults(actualResults);
        printMatches(actualResults, expectedResults);

        return 0;
    }

    public static void main(String... args) {
        int exitCode = new CommandLine(new BenchmarkScorer()).execute(args);
        System.exit(exitCode);
    }

    private static String extractName(String msg) {
        // extract benchmark name in the form:
        // Found tainted data flow from BenchmarkTest01870.java:100:::{javax.servlet.http.HttpServletResponse}#addCookie({javax.servlet.http.Cookie}) to BenchmarkTest01870.java:101:::{java.io.PrintWriter}#println({java.lang.String})
        var m = umbrellaNamePattern.matcher(msg);
        if (!m.matches()) {
            return "NO MATCH";
        }
        var name = m.group(1);
        return name;
    }

    private static SortedMap<String, OwaspBenchmarkResult> readExpectedResults(File path) {
        SortedMap<String, OwaspBenchmarkResult> records = new TreeMap<>();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("#")) {
                    continue;
                }
                String[] values = line.split(CSV_DELIMITER);
                var v = OwaspBenchmarkResult.create(
                        values[0], values[1], Boolean.valueOf(values[2]), Integer.valueOf(values[3]));
                records.put(values[0], v);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return records;
    }

    private static UmbrellaBenchmarkResults readActualResults(File path) throws IOException {
        var results = new UmbrellaBenchmarkResults();
        var objectMapper = new ObjectMapper();
        SortedMap<String, UmbrellaBenchmarkResult> benchmarkResults = new TreeMap<>();
        SarifSchema210 sarif = objectMapper.readValue(path, SarifSchema210.class);
        var sarifResults = sarif.getRuns().get(0).getResults();
        System.out.println("Parsing through " + sarifResults.size() + " Umbrella SARIF result entries");

        for (var r : sarifResults) {
            var ruleId = r.getRuleId();
            var cf = r.getCodeFlows().get(0);
            var message = cf.getMessage().getText();
            var name = extractName(message);
            results.put(name, UmbrellaBenchmarkResult.create(name, ruleId, message));
        }

        return results;
    }

    /**
     * Print various high level statistics about umbrella results.
     * @param results
     */
    private static void describeUmbrellaResults(UmbrellaBenchmarkResults results) {
        for (var entry : results.getResults().entrySet()) {
            var r = entry.getValue();
            System.out.println(entry.getKey() + ":");
            for (var subr : r.entrySet()){
                    var v = subr.getValue();
                    System.out.println("    " + v.name() + "," + v.ruleId());
            }
        }
    }

    private static void printMatches(
            UmbrellaBenchmarkResults actual,
            SortedMap<String, OwaspBenchmarkResult> expected) {
        int totalTrueNegatives = 0;
        int detectedNegatives = 0;
        int totalTruePositives = 0;
        int detectedPositives=0;
        for (var e : expected.entrySet()) {
            var v = e.getValue();
            if (v.isVulnerable()) {
                totalTruePositives++;
                if (actual.get(v.name()) == null) {
                    System.out.println(v.name() + ": FAIL: expected a [" + v.ruleId() + "] finding, but didn't get one: False Negative");
                } else {
                    System.out.println(v.name() + ": PASS: Found a result!!!: True Positive");
                    detectedPositives++;
                }
            } else {
                totalTrueNegatives++;
                if (actual.get(v.name()) != null) {
                    System.out.println(v.name() + ": FAIL: Found a result where one was not expected: False Positive");
                } else {
                    System.out.println(v.name() + ": PASS: correctly identified True Negative");
                    detectedNegatives++;
                }
            }
        }
        var tpr = ((float)detectedPositives)/totalTruePositives;
        var tnr = ((float)detectedNegatives)/totalTrueNegatives;
        System.out.println("Detection Efficacy:\n    True Negative Rate: " + tnr + "\n    True Positive Rate: " + tpr);

        var youdenIndex = (tpr + tnr) - 1;
        System.out.println("Youden Index: " + youdenIndex);
        System.out.println("OWASP Benchmark Score: " + (int)(youdenIndex * 100));
    }
}
