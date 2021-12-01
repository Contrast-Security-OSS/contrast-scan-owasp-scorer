package com.contrastsecurity;

import com.contrastsecurity.model.ContrastScanBenchmarkResult;
import com.contrastsecurity.model.OwaspBenchmarkResult;
import com.contrastsecurity.model.RuleId;
import com.contrastsecurity.model.ContrastScanBenchmarkResults;
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
import java.util.stream.Collectors;

@Command(name = "benchmark-scorer", mixinStandardHelpOptions = true,
        description = "Score Contrast Scan against the owasp benchmark")
public class BenchmarkScorer implements Callable<Integer> {
    private static final String CSV_DELIMITER = ",";
    private static final Pattern ResultNamePattern = Pattern.compile("^.*(BenchmarkTest\\d\\d\\d\\d\\d)\\.java$");

    @Parameters(index = "0", paramLabel = "SARIF_FILE", description = "the umbrella result sarif file.")
    File resultsFile;
    @Parameters(index = "1", paramLabel = "BENCHMARK_CSV", description = "OWASP Benchmark expected results csv")
    File expectedFile;

    public Integer call() throws Exception {
        var actualResults = readActualResults(resultsFile);
        System.out.println("Read " + actualResults.size() + " actual unique results from Contrast Scan");
        var expectedResults = readExpectedResults(expectedFile);
        System.out.println("Read " + expectedResults.size() + " expected OWASP Benchmark Results");

        describeContrastScanResults(actualResults);
        printMatches(actualResults, expectedResults);

        return 0;
    }

    public static void main(String... args) {
        int exitCode = new CommandLine(new BenchmarkScorer()).execute(args);
        System.exit(exitCode);
    }

    private static String extractName(String uri) {
        // extract benchmark name from filenaming pattern: BenchmarkTest01870.java

        var m = ResultNamePattern.matcher(uri);
        if (!m.matches()) {
            System.err.println(String.format("NO MATCH for %s", uri));
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

    private static ContrastScanBenchmarkResults readActualResults(File path) throws IOException {
        var results = new ContrastScanBenchmarkResults();
        var objectMapper = new ObjectMapper();
        SortedMap<String, ContrastScanBenchmarkResult> benchmarkResults = new TreeMap<>();
        SarifSchema210 sarif = objectMapper.readValue(path, SarifSchema210.class);
        var sarifResults = sarif.getRuns().get(0).getResults();
        System.out.println("Parsing through " + sarifResults.size() + " Contrast Scan SARIF result entries");

        for (var r : sarifResults) {
            var ruleId = r.getRuleId();
            var uri = r.getLocations().get(0).getPhysicalLocation().getArtifactLocation().getUri();
            var name = extractName(uri);
            results.put(name, ContrastScanBenchmarkResult.create(
                name,
                ruleId,
                r.getLocations().get(0).getPhysicalLocation().getRegion().getSnippet().getText()));
        }

        return results;
    }

    /**
     * Print various high level statistics about Contrast Scan results.
     * @param results
     */
    private static void describeContrastScanResults(ContrastScanBenchmarkResults results) {
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
            ContrastScanBenchmarkResults actual,
            SortedMap<String, OwaspBenchmarkResult> expected) {
        int totalTrueNegatives = 0;
        int detectedNegatives = 0;
        int totalTruePositives = 0;
        int detectedPositives=0;
        for (var e : expected.entrySet()) {
            var v = e.getValue();
            var ruleId = RuleId.valueOf(v.ruleId());
            if (ruleId == null) {
                throw new IllegalStateException("no value exists for [" + v.ruleId() + "]");
            }

            if (v.isVulnerable()) {
                totalTruePositives++;
                if (actual.get(v.name()) == null) {
                    System.out.println(v.name() + ": FAIL: expected a [" + v.ruleId() + ", "+ ruleId.getContrastName() +"] finding, but didn't get one: False Negative");

                } else if (actual.get(v.name(), ruleId.getContrastName()) == null) {
                    System.out.println(v.name() + ": FAIL: expected a [" + v.ruleId() + ", "+ ruleId.getContrastName() +"] finding, but didn't get one: False Negative. Other rules mistakenly hit howerver. ");
                }  else {
                    System.out.println(v.name() + ": PASS: Found a [" + v.ruleId() + "] result!!!: True Positive");
                    detectedPositives++;
                }
            } else {
                totalTrueNegatives++;
                var result = actual.get((v.name()));
                if (result != null) {
                    var ruleids = result.values().stream().map((it) -> {return it.ruleId();}).collect(Collectors.toSet());
                    if (ruleids.size() > 1) {
                        System.out.println("ERROR: rule ids hit on the wrong test for them.");
                    }
                    System.out.println(v.name() + ": FAIL: Found a result of types "+ ruleids +" on test type "+ RuleId.valueOf(v.ruleId()).getContrastName() +" where one was not expected: False Positive");
                } else {
                    System.out.println(v.name() + ": PASS: correctly identified True Negative in [" + v.ruleId() + "] test");
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
