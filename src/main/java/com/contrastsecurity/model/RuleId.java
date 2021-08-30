package com.contrastsecurity.model;

public enum RuleId {
    xss("reflected-xss"),
    trustbound("trust-boundary-violation"),
    hash("crypto-bad-mac"),
    pathtraver("path-traversal"),
    crypto("crypto-bad-ciphers"),
    cmdi("cmd-injection"),
    sqli("sql-injection"),
    ldapi("ldap-injection"),
    securecookie("cookie-flags-missing"),
    weakrand("crypto-weak-randomness"),
    xpathi("xpath-injection");

    private final String owaspName;
    private final String contrastName;
    RuleId(String name) {
        this.contrastName = name;
        this.owaspName = this.toString();
    }

    public String getOwaspName() {return this.owaspName;}
    public String getContrastName() {return this.contrastName;}
}