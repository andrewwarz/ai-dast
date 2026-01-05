"""Prompt templates for AI-powered vulnerability detection.

This module provides security-focused prompt templates for:
- System prompts establishing the AI as a penetration testing expert
- Vulnerability detection prompts for analyzing HTTP responses
- Self-termination evaluation prompts for completion assessment
- Payload generation prompts for creating test vectors

Example:
    >>> from scanner.prompts import format_prompt, VULNERABILITY_DETECTION_PROMPT
    >>> prompt = format_prompt(
    ...     VULNERABILITY_DETECTION_PROMPT,
    ...     target_url="https://example.com/api/users",
    ...     method="GET",
    ...     status_code=200,
    ...     headers="Content-Type: application/json",
    ...     body='{"users": [...]}'
    ... )
"""

from string import Template
from typing import Any


# =============================================================================
# SYSTEM PROMPT
# =============================================================================

SYSTEM_PROMPT = """You are an expert penetration tester and Dynamic Application Security Testing (DAST) scanner.
Your role is to analyze web application responses and identify security vulnerabilities.

## Your Expertise Includes:
- OWASP Top 10 vulnerabilities (SQLi, XSS, Broken Authentication, SSRF, etc.)
- API security flaws (BOLA, BFLA, mass assignment, rate limiting issues)
- Authentication and session management weaknesses
- Information disclosure and sensitive data exposure
- Security misconfiguration detection
- Server-side vulnerabilities (command injection, path traversal, SSTI)

## Response Format:
When analyzing responses, provide findings in this structured format:

### Vulnerability Found
- **Type**: [Vulnerability category]
- **Severity**: [Critical/High/Medium/Low/Informational]
- **Confidence**: [High/Medium/Low]
- **Evidence**: [Specific indicators from the response]
- **Exploitation Steps**: [How to exploit this vulnerability]
- **Recommended Fix**: [Mitigation suggestion]

## Guidelines:
1. Be thorough but avoid false positives - only report issues with clear evidence
2. Consider the context of the application when assessing severity
3. Generate dynamic payloads tailored to observed technologies and behaviors
4. Track what has been tested to avoid redundant checks
5. Provide actionable exploitation steps for confirmed vulnerabilities"""


# =============================================================================
# VULNERABILITY DETECTION PROMPT
# =============================================================================

VULNERABILITY_DETECTION_PROMPT = """Analyze the following HTTP response for security vulnerabilities.

## Request Context:
- **Target URL**: ${target_url}
- **HTTP Method**: ${method}
- **Endpoint Path**: ${endpoint_path}

## Response Data:
- **Status Code**: ${status_code}
- **Response Headers**:
```
${headers}
```

- **Response Body** (truncated if large):
```
${body}
```

## Analysis Tasks:
1. **Error Analysis**: Check for stack traces, SQL errors, debug information, or verbose error messages
2. **Injection Indicators**: Look for reflected input, SQL syntax errors, command output, or template rendering issues
3. **Authentication Issues**: Analyze session tokens, authentication headers, and access control indicators
4. **Information Disclosure**: Identify exposed internal paths, server versions, or sensitive data
5. **Security Headers**: Evaluate missing or misconfigured security headers

## Expected Output:
Provide a detailed security analysis. For each potential vulnerability:
1. Describe what you found and why it's concerning
2. Rate the confidence level of your finding
3. Suggest specific test payloads to confirm the vulnerability
4. Provide exploitation steps if the vulnerability is confirmed

If no vulnerabilities are found, explain what security measures appear to be in place."""


# =============================================================================
# SELF-TERMINATION EVALUATION PROMPT
# =============================================================================

SELF_TERMINATION_PROMPT = """Evaluate whether the security testing should continue or terminate.

## Testing Statistics:
- **Total Requests Sent**: ${total_requests}
- **Unique Endpoints Tested**: ${unique_endpoints}
- **Vulnerabilities Found**: ${vulnerabilities_found}
- **Last ${recent_window} Requests**: ${recent_findings} new findings
- **Time Elapsed**: ${time_elapsed}

## Tested Attack Vectors:
${tested_vectors}

## Recent Test Results Summary:
${recent_results}

## Evaluation Criteria:
1. **Coverage Completeness**: Have all major vulnerability categories been tested?
2. **Diminishing Returns**: Are recent tests finding new issues?
3. **Unique Findings Rate**: Is the rate of new discoveries declining?
4. **Resource Efficiency**: Is continued testing likely to yield valuable results?

## Decision Required:
Based on the above information, should testing:
- **CONTINUE**: More testing is likely to find additional vulnerabilities
- **STOP**: Testing has achieved sufficient coverage with diminishing returns

Provide your decision with clear justification. If recommending CONTINUE, suggest which areas or attack vectors to prioritize next."""


# =============================================================================
# PAYLOAD GENERATION PROMPT
# =============================================================================

PAYLOAD_GENERATION_PROMPT = """Generate targeted security test payloads based on the detected context.

## Target Information:
- **URL**: ${target_url}
- **Parameter Name**: ${parameter_name}
- **Current Value**: ${current_value}
- **Detected Technology**: ${detected_technology}
- **Content Type**: ${content_type}

## Vulnerability Type to Test:
${vulnerability_type}

## Requirements:
1. Generate 5-10 payload variations for thorough testing
2. Include encoding variations (URL encoding, base64, hex, unicode)
3. Consider WAF bypass techniques where applicable
4. Tailor payloads to the detected technology stack
5. Include both detection and exploitation payloads

## Output Format:
For each payload, provide:
- **Payload**: The actual test string
- **Purpose**: What vulnerability it tests for
- **Expected Response**: What indicates success
- **Encoding**: Any encoding applied"""


# =============================================================================
# SQL INJECTION EXPLOITATION PROMPT
# =============================================================================

SQLI_EXPLOITATION_PROMPT = """You have confirmed a SQL Injection vulnerability. Now exploit it to extract data.

## Vulnerability Details:
- **URL**: ${target_url}
- **Method**: ${method}
- **Vulnerable Parameter**: ${parameter}
- **Confirmed Payload**: ${confirmed_payload}
- **Database Type**: ${db_type}

## Previous Response (showing SQLi works):
```
${previous_response}
```

## Your Task:
Generate SQL injection payloads to extract user credentials from the database.

## Common Extraction Techniques:
1. **UNION-based**: Extract data by appending UNION SELECT
2. **Error-based**: Extract data via error messages
3. **Boolean-based**: Infer data character by character
4. **Time-based**: Infer data via response delays

## For MySQL/MariaDB databases, typical steps:
1. Find number of columns: ORDER BY or UNION SELECT NULL,NULL,...
2. Find injectable columns: UNION SELECT 1,2,3,...
3. Get database name: UNION SELECT database()
4. Get table names: UNION SELECT table_name FROM information_schema.tables
5. Get column names: UNION SELECT column_name FROM information_schema.columns
6. Extract data: UNION SELECT username,password FROM users

## Output Format:
Provide a sequence of payloads to execute, in order:

### Step 1: [Description]
- **Payload**: [The SQL injection payload]
- **Purpose**: [What this step achieves]
- **Expected Data**: [What to look for in response]

### Step 2: [Description]
...

Focus on extracting usernames and passwords. The goal is to obtain valid login credentials."""


# =============================================================================
# CREDENTIAL LOGIN PROMPT
# =============================================================================

CREDENTIAL_LOGIN_PROMPT = """You have extracted credentials from the database. Now attempt to login.

## Extracted Credentials:
${credentials}

## Login Form Details:
- **Login URL**: ${login_url}
- **Method**: ${method}
- **Form Fields**: ${form_fields}

## Your Task:
1. Identify which extracted credential to try first (prefer admin accounts)
2. Determine the correct form field mapping (username field, password field)
3. Note: Passwords may be hashed - common hash types are MD5, SHA1, SHA256

## If passwords are hashed:
- MD5 hashes are 32 hex characters
- SHA1 hashes are 40 hex characters
- SHA256 hashes are 64 hex characters
- Try common passwords if hash is recognized (e.g., 5f4dcc3b5aa765d61d8327deb882cf99 = "password")

## Output Format:
- **Username**: [username to try]
- **Password**: [password or cracked password]
- **Hash Type**: [if applicable]
- **Reasoning**: [why this credential was chosen]"""


# =============================================================================
# NEXT ACTION PROMPT
# =============================================================================

NEXT_ACTION_PROMPT = """Based on the current scan state, decide what action to take next.

## Current State:
- **Target URL**: ${target_url}
- **Authenticated**: ${authenticated}
- **Vulnerabilities Found**: ${vulnerabilities}
- **Extracted Data**: ${extracted_data}
- **Last Response**:
```
${last_response}
```

## Available Actions:
1. **EXPLOIT_SQLI**: Exploit a confirmed SQL injection to extract data
2. **LOGIN**: Attempt to login with extracted credentials
3. **CONTINUE_SCAN**: Continue scanning for more vulnerabilities
4. **STOP**: Testing is complete

## Output Format:
**Action**: [ACTION_NAME]
**Target**: [URL or form to target]
**Reasoning**: [Why this action was chosen]
**Details**: [Any specific parameters or payloads]"""


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def format_prompt(template: str, **kwargs: Any) -> str:
    """Format a prompt template with the provided parameters.
    
    Uses string.Template for safe substitution with ${variable} syntax.
    
    Args:
        template: The prompt template string containing ${variable} placeholders.
        **kwargs: Variable values to substitute into the template.
        
    Returns:
        The formatted prompt string with all placeholders replaced.
        
    Raises:
        KeyError: If a required template variable is not provided.
        ValueError: If the template contains invalid placeholder syntax.
        
    Example:
        >>> prompt = format_prompt(
        ...     "Analyze ${url} with method ${method}",
        ...     url="https://example.com",
        ...     method="POST"
        ... )
        >>> print(prompt)
        Analyze https://example.com with method POST
    """
    try:
        return Template(template).substitute(**kwargs)
    except KeyError as e:
        raise KeyError(f"Missing required template variable: {e}") from e
    except ValueError as e:
        raise ValueError(f"Invalid template syntax: {e}") from e

