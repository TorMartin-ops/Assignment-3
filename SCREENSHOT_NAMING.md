# Screenshot Naming Convention

## Directory Structure
```
screenshots/                    # Lowercase, no spaces
├── registration_hibp_breach.png
├── account_lockout.png
├── recaptcha_challenge.png
├── 2fa_setup_qr.png
├── backup_codes.png
├── 2fa_login_verification.png
├── oauth2_consent.png
├── login_page.png              # Additional (not in report)
└── rate_limiting.png            # Additional (not in report)
```

## Naming Convention

**Format**: `feature_description.png`
- All lowercase
- Underscores instead of spaces
- Descriptive names indicating purpose
- No special characters except underscores and hyphens

## Screenshot Mapping

### Old Names → New Names

| Old Name | New Name | Used In Report | Purpose |
|----------|----------|----------------|---------|
| `Register.png` | `registration_hibp_breach.png` | ✅ Yes | HIBP password breach detection during registration |
| `account locked.png` | `account_lockout.png` | ✅ Yes | Account lockout message after 5 failed attempts |
| `reCaptcha.png` | `recaptcha_challenge.png` | ✅ Yes | Google reCAPTCHA v2 checkbox challenge |
| `2fa.png` | `2fa_setup_qr.png` | ✅ Yes | 2FA QR code setup page |
| `backup codes.png` | `backup_codes.png` | ✅ Yes | 10 single-use backup codes display |
| `2fa login.png` | `2fa_login_verification.png` | ✅ Yes | 2FA code verification during login |
| `oauth2_consent.png` | `oauth2_consent.png` | ✅ Yes | OAuth2 authorization consent screen |
| `Login page.png` | `login_page.png` | ❌ No | Standard login page (reference only) |
| `ratelimitng.png` | `rate_limiting.png` | ❌ No | Rate limiting demonstration (reference only) |

## Report References Updated

All 7 screenshot references in `Assignment_3_Report.tex` have been updated:

1. **Line 185**: Task 2 - HIBP Breach Detection
   ```latex
   \includegraphics[width=0.85\textwidth]{screenshots/registration_hibp_breach.png}
   ```

2. **Line 232**: Task 3 - Account Lockout
   ```latex
   \includegraphics[width=0.85\textwidth]{screenshots/account_lockout.png}
   ```

3. **Line 239**: Task 3 - CAPTCHA Challenge
   ```latex
   \includegraphics[width=0.85\textwidth]{screenshots/recaptcha_challenge.png}
   ```

4. **Line 287**: Task 4 - 2FA QR Setup
   ```latex
   \includegraphics[width=0.85\textwidth]{screenshots/2fa_setup_qr.png}
   ```

5. **Line 294**: Task 4 - Backup Codes
   ```latex
   \includegraphics[width=0.85\textwidth]{screenshots/backup_codes.png}
   ```

6. **Line 318**: Task 4 - 2FA Verification
   ```latex
   \includegraphics[width=0.85\textwidth]{screenshots/2fa_login_verification.png}
   ```

7. **Line 382**: Task 5 - OAuth2 Consent
   ```latex
   \includegraphics[width=0.85\textwidth]{screenshots/oauth2_consent.png}
   ```

## Benefits of New Naming

✅ **Lowercase convention**: Standard across Unix/Linux systems
✅ **No spaces**: Prevents path issues in LaTeX and command-line tools
✅ **Descriptive names**: Clear purpose from filename
✅ **Consistent format**: Easy to understand and maintain
✅ **Professional**: Follows software industry best practices

## For Overleaf Upload

When uploading to Overleaf:
1. Upload entire `screenshots/` directory (lowercase)
2. All references in `Assignment_3_Report.tex` already point to correct paths
3. No manual editing needed after upload
4. LaTeX will compile without path errors

## File Size Summary

```
registration_hibp_breach.png      51 KB
account_lockout.png               40 KB
recaptcha_challenge.png           66 KB
2fa_setup_qr.png                  77 KB
backup_codes.png                  56 KB
2fa_login_verification.png        27 KB
oauth2_consent.png                59 KB
-----------------------------------
Total (7 screenshots)            376 KB
```

All screenshots are PNG format, properly sized for report inclusion, and meet academic documentation standards.
