package com.contrastsecurity.model;

public enum RuleId {
    xss("reflected-xss"),
    trustbound("trust-boundary-violation"),
    hash("---"),
    pathtraver("path-traversal"),
    crypto("---"),
    cmdi("cmd-injection"),
    sqli("sql-injection"),
    ldapi("ldap-injection"),
    securecookie("---"),
    weakrand("---"),
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
