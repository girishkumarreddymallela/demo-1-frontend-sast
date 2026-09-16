/**
 * Local SAST Security Analysis Engine
 * Simulates Semgrep / SonarQube static code rule analysis for frontend JS.
 */

const fs = require('fs');
const path = require('path');

const RULES = [
    {
        id: 'js.browser.security.dom-xss.innerhtml-sink',
        severity: 'HIGH',
        category: 'DOM-based Cross-Site Scripting (XSS)',
        description: 'Unsafe assignment to innerHTML with dynamic variable. Can lead to DOM XSS.',
        regex: /\.innerHTML\s*=\s*.*[a-zA-Z0-9_$]+/g,
        cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation'
    },
    {
        id: 'js.security.secrets.hardcoded-api-key',
        severity: 'CRITICAL',
        category: 'Secret Exposure',
        description: 'Hardcoded API secret or credential detected in source code.',
        regex: /(AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,})/g,
        cwe: 'CWE-798: Use of Hard-coded Credentials'
    },
    {
        id: 'js.lang.security.audit.eval-detected',
        severity: 'HIGH',
        category: 'Code Injection',
        description: 'Use of eval() detected. Dynamic code execution can lead to arbitrary code execution.',
        regex: /\beval\s*\(/g,
        cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code'
    }
];

function scanDirectory(dirPath) {
    let findings = [];
    const files = fs.readdirSync(dirPath);

    for (const file of files) {
        const fullPath = path.join(dirPath, file);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
            if (file !== 'node_modules' && file !== '.git') {
                findings = findings.concat(scanDirectory(fullPath));
            }
        } else if (file.endsWith('.js') || file.endsWith('.html')) {
            const content = fs.readFileSync(fullPath, 'utf8');
            const lines = content.split('\n');

            RULES.forEach(rule => {
                lines.forEach((line, index) => {
                    rule.regex.lastIndex = 0; // Reset regex matching index
                    if (rule.regex.test(line)) {
                        findings.push({
                            ruleId: rule.id,
                            severity: rule.severity,
                            category: rule.category,
                            cwe: rule.cwe,
                            file: path.relative(process.cwd(), fullPath),
                            lineNumber: index + 1,
                            codeSnippet: line.trim()
                        });
                    }
                });
            });
        }
    }
    return findings;
}

console.log("\n===============================================================================");
console.log("               🔒 SAST SECURITY ENGINE - SCAN REPORT                           ");
console.log("===============================================================================\n");

const targetDir = path.join(__dirname, '../src');
const results = scanDirectory(targetDir);

if (results.length === 0) {
    console.log("✅ SUCCESS: No security vulnerabilities found!");
    process.exit(0);
} else {
    console.log(`⚠️  SECURITY ALERT: Found ${results.length} security vulnerability findings!\n`);
    
    let criticalCount = 0;
    let highCount = 0;

    results.forEach((finding, idx) => {
        if (finding.severity === 'CRITICAL') criticalCount++;
        if (finding.severity === 'HIGH') highCount++;

        console.log(`[Finding #${idx + 1}] Severity: [${finding.severity}] - ${finding.category}`);
        console.log(`  Rule ID   : ${finding.ruleId}`);
        console.log(`  CWE       : ${finding.cwe}`);
        console.log(`  Location  : ${finding.file}:${finding.lineNumber}`);
        console.log(`  Code Snippet: "${finding.codeSnippet}"\n`);
    });

    console.log("-------------------------------------------------------------------------------");
    console.log(`SUMMARY: ${criticalCount} Critical | ${highCount} High Findings.`);
    console.log("QUALITY GATE STATUS: ❌ FAILED (Build blocked due to High/Critical vulnerabilities)");
    console.log("-------------------------------------------------------------------------------\n");

    // Exit code 1 simulates CI/CD pipeline failure
    process.exit(1);
}
