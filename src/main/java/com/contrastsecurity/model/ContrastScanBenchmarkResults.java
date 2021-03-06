package com.contrastsecurity.model;

import java.util.*;

/**
 * There is only supposed to be one vulnerability per benchmark tests but Contrast Scan will finding multiple unique
 * tainted data flows on some tests. We want to know about this and find the proper vunerability type for the test if
 * Contrast Scan actually did get it. We also want to show warnings for the other vulnerabilities if it wasn't supposed to
 * find those types.
 *
 * This data structure will allow flexible lookups of results so that this complexity is clean to deal with.
 */
public final class ContrastScanBenchmarkResults {
    private SortedMap<String, Map<String, ContrastScanBenchmarkResult>> results;

    public ContrastScanBenchmarkResults() {
        results = new TreeMap<>();
    }

    public void put(String name, ContrastScanBenchmarkResult result) {
        Map<String, ContrastScanBenchmarkResult> benchmarkEntries;
        if (results.containsKey(name)) {
            benchmarkEntries = results.get(name);
        } else {
            benchmarkEntries = new HashMap<>();
            results.put(name, benchmarkEntries);
        }

        if (!benchmarkEntries.containsKey(result.flowDesc())) {
            benchmarkEntries.put(result.flowDesc(), result);
        }
    }

    /**
     * Get the list of benchmark results associated with benchmark test {@param name}.
     * @param name
     * @return null if not results are found for {@param name}
     */
    public Map<String, ContrastScanBenchmarkResult> get(String name) {
        return results.get(name);
    }


    public SortedMap<String, Map<String, ContrastScanBenchmarkResult>> getResults() {
        return results;
    }

    /**
     * Get the first ContrastScanBenchmarkResult from the benchmark of {@param name} having the ruleId of {@param ruleId}
     * @param name
     * @param ruleId
     * @return null if no benchmark is found that meets the criteria.
     */
    public ContrastScanBenchmarkResult get(String name, String ruleId) {
        var ubrMap = results.get(name);
        if (ubrMap == null){
            return null;
        }
        for (var ubr : ubrMap.entrySet()) {
            if (ubr.getValue().ruleId().compareTo(ruleId) == 0) {
                return ubr.getValue();
            }
        }
        return null;
    }

    public int size() {
        int size = 0;
        for (var l : results.entrySet()) {
            size += l.getValue().size();
        }
        return size;
    }

}
