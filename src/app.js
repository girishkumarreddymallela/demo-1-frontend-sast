// ============================================================================
// Demo Frontend Application - Contains Intentional Vulnerabilities for SAST
// ============================================================================

// REMEDIATED: Secrets removed (Loaded securely from config / environment variables)
const AWS_SECRET_KEY = process.env.AWS_SECRET_KEY || "dummy_dev_aws_key";
const PAYMENT_GATEWAY_TOKEN = process.env.PAYMENT_GATEWAY_TOKEN || "dummy_dev_stripe_token";

console.log("App initialized.");

// Function to get query parameter from URL
function getQueryParam(param) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(param);
}

// Automatically render greeting from URL query parameter (e.g. ?name=<script>alert(1)</script>)
window.addEventListener('DOMContentLoaded', () => {
    const nameParam = getQueryParam('name');
    if (nameParam) {
        // VULNERABILITY 2: DOM-based XSS (Unsafe sink: innerHTML with unsanitized user input)
        document.getElementById('welcome-msg').innerHTML = "Welcome back, " + nameParam + "!";
    }

    const calcExpression = getQueryParam('calc');
    if (calcExpression) {
        // VULNERABILITY 3: Dangerous dynamic code execution (eval)
        const result = eval(calcExpression);
        console.log("Calculated result:", result);
    }
});

// Manual form greeting handler
function renderGreeting() {
    const inputVal = document.getElementById('username').value;
    
    // VULNERABILITY 4: Another DOM-based XSS via direct document modification
    const welcomeDiv = document.getElementById('welcome-msg');
    welcomeDiv.innerHTML = "Hello <b>" + inputVal + "</b>, session active.";
}
