# Assignment 3 - Ground Truth Documentation

This directory contains comprehensive ground truth specifications extracted from the codebase for diagram generation and system understanding.

## Primary Documents

### 1. GROUND_TRUTH_SPECIFICATION.md (54 KB, 1,596 lines)
**Complete file:line evidence for all UML diagrams**

Contains exhaustive documentation of:
- 9 database tables with all columns, indexes, and foreign keys
- 5 service classes with all methods and signatures
- 6 utility classes with complete implementations
- 13 HTTP routes with rate limits and security features
- 4 critical BEGIN IMMEDIATE transactions
- 27 security controls (15 prevent, 6 detect, 6 respond)
- 3 complete authentication flows with step-by-step evidence
- 2 external API integrations

Every component includes:
- Exact file path
- Line number ranges
- Implementation details
- Security mechanisms
- Configuration values

### 2. GROUND_TRUTH_SUMMARY.md (12 KB, 395 lines)
**Quick reference guide**

Condensed version with:
- Key statistics
- Critical security mechanisms
- Configuration thresholds
- Authentication flow summaries
- Route summary table
- Data flow diagrams
- Diagram generation checklist

### 3. ground_truth_index.json (Valid JSON)
**Programmatic access**

Structured JSON index containing:
- Metadata
- Database schema with exact line numbers
- Service layer specifications
- Route definitions
- Security control mappings
- External API configurations
- Authentication flow steps
- Transaction safety locations
- Configuration thresholds
- Diagram generation checklist

## Use Cases

### For Diagram Generation
1. **System Architecture Diagram**
   - Source: GROUND_TRUTH_SPECIFICATION.md, Section 1
   - Components: Flask app, blueprints, services, database, middleware
   - Evidence: File:line for every component

2. **Class Diagram**
   - Source: GROUND_TRUTH_SPECIFICATION.md, Section 5
   - Classes: All 11 classes with complete method signatures
   - Relationships: Dependencies, uses, inheritance

3. **OAuth2 Sequence Diagram**
   - Source: GROUND_TRUTH_SPECIFICATION.md, Section 6.1
   - 5 phases with file:line evidence for each step
   - PKCE flow, transaction safety, token rotation

4. **2FA Sequence Diagram**
   - Source: GROUND_TRUTH_SPECIFICATION.md, Section 6.2
   - Password auth + TOTP verification
   - Session regeneration points, replay prevention

5. **Database Schema Diagram**
   - Source: GROUND_TRUTH_SPECIFICATION.md, Section 1.3
   - 9 tables, 15 indexes, 8 foreign keys
   - Complete column definitions with types

6. **Brute Force Protection Diagram**
   - Source: GROUND_TRUTH_SPECIFICATION.md, Section 6.3
   - 3 layers: Rate limiting, failure tracking, CAPTCHA
   - Thresholds and durations

7. **Security Controls Diagram**
   - Source: GROUND_TRUTH_SPECIFICATION.md, Section 7
   - PREVENT/DETECT/RESPOND layers
   - 27 controls with implementation evidence

### For Code Review
- Complete file:line references for every security mechanism
- Transaction safety verification
- Session fixation prevention points
- Rate limiting implementation details

### For Security Audit
- All security controls mapped to implementation
- External dependency documentation
- Configuration threshold verification
- Timing attack prevention evidence

### For Testing
- Authentication flow steps with expected behaviors
- Rate limit thresholds for testing
- Transaction scenarios requiring verification
- Error handling paths

## Key Statistics

- **Codebase Analyzed**: ~4,000 lines across 20+ Python files
- **Database Schema**: 9 tables, 15 indexes, 8 foreign keys
- **HTTP Routes**: 13 endpoints with full documentation
- **Service Classes**: 5 singletons with complete method signatures
- **Security Controls**: 27 total (15 prevent, 6 detect, 6 respond)
- **Critical Transactions**: 4 BEGIN IMMEDIATE locations
- **External APIs**: 2 (HIBP, Google reCAPTCHA)

## File Evidence Quality

Every component in these documents includes:
- ✅ Exact file path (absolute)
- ✅ Line number or line range
- ✅ Implementation details
- ✅ Configuration values
- ✅ Security mechanisms
- ✅ Dependencies and relationships

## Verification

All file:line references have been verified against the actual codebase as of 2025-10-19.

To verify a reference:
```bash
# Example: Verify AuthService.authenticate() is at lines 97-159
sed -n '97,159p' /home/torma/Assignment-3/services/auth_service.py
```

## Usage Examples

### Python Script Access
```python
import json

# Load the index
with open('ground_truth_index.json') as f:
    index = json.load(f)

# Get all service classes
services = index['services']
print(f"AuthService singleton: {services['AuthService']['singleton_lines']}")

# Get security control details
prevent_controls = index['security_controls']['prevent']
for control in prevent_controls:
    print(f"{control['control']}: {control['file']}:{control['lines']}")

# Get critical transaction locations
transactions = index['critical_transactions']
for txn in transactions:
    print(f"{txn['method']}: {txn['location']} - {txn['purpose']}")
```

### Grep for Specific Evidence
```bash
# Find all rate limit configurations
grep -n "rate_limit" ground_truth_index.json

# Find all BEGIN IMMEDIATE transactions
grep "BEGIN IMMEDIATE" GROUND_TRUTH_SPECIFICATION.md

# Find all session regeneration points
grep -n "regenerate_session" GROUND_TRUTH_SPECIFICATION.md
```

## Document Relationships

```
ground_truth_index.json (structured data)
    ↓
GROUND_TRUTH_SUMMARY.md (quick reference)
    ↓
GROUND_TRUTH_SPECIFICATION.md (complete details)
    ↓
Source Code (implementation)
```

## Maintenance

These documents are generated from static code analysis. When the codebase changes:
1. Re-run the ground truth extraction
2. Update line numbers in the specification
3. Validate all file:line references
4. Regenerate the JSON index
5. Update the summary with new statistics

## Related Documents

- `FINAL_ASSIGNMENT_REPORT.md`: Assignment completion summary
- `HOW_2FA_WORKS.md`: 2FA implementation guide
- `TESTING_EVIDENCE.md`: Test results and evidence
- `SETUP_GUIDE.md`: Installation and configuration

## Generated

- **Date**: 2025-10-19
- **Version**: 1.0
- **Tool**: Claude Code Intelligence Agent
- **Purpose**: Complete ground truth for diagram generation
- **Completeness**: 100% - All critical paths documented

---

**Note**: These documents provide the foundation for generating accurate UML diagrams that match the actual implementation. All file:line evidence ensures diagrams are not speculative but reflect real code.
