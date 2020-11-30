package com.contrastsecurity.model;

import com.google.auto.value.AutoValue;

@AutoValue
public abstract class UmbrellaBenchmarkResult {
    public abstract String name();
    public abstract String ruleId();

    /**
     * Source to sink string signature.  To help denote different vulnerabilities.
     * @return
     */
    public abstract String flowDesc();

    public static UmbrellaBenchmarkResult create(String name, String ruleId, String flowDesc) {
        return new AutoValue_UmbrellaBenchmarkResult(name, ruleId, flowDesc);
    }
}
