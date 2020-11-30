package com.contrastsecurity.model;

import com.google.auto.value.AutoValue;

@AutoValue
public abstract class OwaspBenchmarkResult {
    public abstract String name();
    public abstract String ruleId();
    public abstract boolean isVulnerable();
    public abstract int cwe();

    public static OwaspBenchmarkResult create(String name, String ruleId, boolean isVulnerable, int cwe) {
        return new AutoValue_OwaspBenchmarkResult(name, ruleId, isVulnerable, cwe);
    }
}
