package com.contrastsecurity.model;

import java.util.HashMap;
import java.util.Map;

public class RuleIdMap {
    private static final Map<String, String> owaspToUmbrella;

    static {
        owaspToUmbrella = new HashMap<>();
        owaspToUmbrella.put("xss", "reflected-xss");
        owaspToUmbrella.put("trustboundary", "trust-boundary-violation");
        owaspToUmbrella.put("hash", "");
        owaspToUmbrella.put("pathtraver", "");
        owaspToUmbrella.put("crypto", "");
        owaspToUmbrella.put("cmdi", "");
        owaspToUmbrella.put("sqli", "");
        owaspToUmbrella.put("ldapi", "");
        owaspToUmbrella.put("secureookie", "");
        owaspToUmbrella.put("weakrand", "");
        owaspToUmbrella.put("xpathi", "");

    }
}
