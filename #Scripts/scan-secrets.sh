#!/usr/bin/env bash

set -u

ROOT_DIR="${1:-.}"
FOUND=0

echo "🔐 Docker Secret Scanner"
echo "Scanning: $ROOT_DIR"
echo

report() {
    echo "🚨 $1"
    echo "   File: $2"
    echo "   Line: $3"
    echo
    FOUND=1
}

while IFS= read -r -d '' file; do

    # Skip .git, node_modules, caches and other obvious noise
    [[ "$file" == */.git/* ]] && continue
    [[ "$file" == */node_modules/* ]] && continue

    # ------------------------------------------------------------------
    # 1. Environment files
    # ------------------------------------------------------------------

    filename="$(basename "$file")"

    if [[ "$filename" =~ ^\.env($|\.) ]] &&
       [[ "$filename" != ".env.example" ]] &&
       [[ "$filename" != ".env.template" ]]; then

        report "ENVIRONMENT FILE" "$file" "Entire file may contain secrets"
    fi

    # ------------------------------------------------------------------
    # 2. Private keys
    # ------------------------------------------------------------------

    if grep -Eiq \
        '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----' \
        "$file" 2>/dev/null; then

        report "PRIVATE KEY" "$file" "Private key detected"
    fi

    # ------------------------------------------------------------------
    # 3. Generic secret variable names
    # ------------------------------------------------------------------

    while IFS= read -r line; do

        [[ "$line" =~ ^[[:space:]]*# ]] && continue

        # Ignore references such as ${PASSWORD}
        if [[ "$line" =~ \$\{[A-Za-z_][A-Za-z0-9_]*\} ]]; then
            continue
        fi

        if echo "$line" | grep -Eiq \
            '(password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|refresh[_-]?token|session[_-]?secret|encryption[_-]?key|signing[_-]?key)[[:space:]]*[:=][[:space:]]*["'\'']?[^$[:space:]#"'\'']{6,}'; then

            report "HARDCODED SECRET-LIKE VALUE" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 4. Authorization headers
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            '(authorization|proxy-authorization)[[:space:]]*:[[:space:]]*(bearer|basic)[[:space:]]+[A-Za-z0-9+/=_\.-]{10,}'; then

            report "AUTHORIZATION CREDENTIAL" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 5. Bearer tokens
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            'bearer[[:space:]]+[A-Za-z0-9._~+/=-]{20,}'; then

            report "BEARER TOKEN" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 6. JWT
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eq \
            'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'; then

            report "JWT TOKEN" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 7. GitHub tokens
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            'gh[pousr]_[A-Za-z0-9_]{20,}'; then

            report "GITHUB TOKEN" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 8. GitLab tokens
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            'glpat-[A-Za-z0-9_-]{20,}'; then

            report "GITLAB TOKEN" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 9. AWS
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            'AKIA[0-9A-Z]{16}'; then

            report "AWS ACCESS KEY" "$file" "$line"
        fi

        if echo "$line" | grep -Eiq \
            '(aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[[:space:]]*[:=][[:space:]]*[^$[:space:]]+'; then

            report "AWS SECRET KEY" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 10. Google service-account credentials
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            '"type"[[:space:]]*:[[:space:]]*"service_account"'; then

            report "GOOGLE SERVICE ACCOUNT" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 11. OpenAI-style keys
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            'sk-[A-Za-z0-9_-]{20,}'; then

            report "API KEY (sk-...)" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 12. Discord bot tokens
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eq \
            '[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{20,}'; then

            report "DISCORD TOKEN" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 13. Database URLs containing credentials
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            '(postgres|postgresql|mysql|mariadb|mongodb|redis|amqp)://[^[:space:]]+:[^[:space:]@]+@'; then

            report "DATABASE URL WITH PASSWORD" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 14. user:password@host URLs
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eq \
            '[a-zA-Z0-9._-]+:[^[:space:]@]{6,}@[a-zA-Z0-9.-]+'; then

            report "CREDENTIALS IN URL" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 15. SMTP credentials
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            '(smtp[_-]?(user|username|password)|mail[_-]?(user|username|password))[[:space:]]*[:=][[:space:]]*[^$[:space:]]{6,}'; then

            report "SMTP/MAIL CREDENTIAL" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 16. Webhook URLs
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            '(webhook|hook).*https?://[^[:space:]]{30,}'; then

            report "WEBHOOK URL" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 17. Docker registry credentials
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            '(dockerhub|docker[_-]?username|docker[_-]?password|registry[_-]?(user|username|password))[[:space:]]*[:=][[:space:]]*[^$[:space:]]+'; then

            report "DOCKER REGISTRY CREDENTIAL" "$file" "$line"
        fi

        # ------------------------------------------------------------------
        # 18. curl/wget authentication
        # ------------------------------------------------------------------

        if echo "$line" | grep -Eiq \
            '(curl|wget).*(-u|--user|--password|--header.*authorization)'; then

            report "COMMAND CONTAINS CREDENTIAL" "$file" "$line"
        fi

    done < "$file"

done < <(
    find "$ROOT_DIR" -type f \
        ! -path '*/.git/*' \
        ! -path '*/node_modules/*' \
        -print0
)

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ "$FOUND" -eq 0 ]]; then
    echo "✅ No obvious secrets detected."
    echo
    echo "This is not a guarantee that the repository is secret-free."
    exit 0
else
    echo "❌ Potential secrets detected."
    echo
    echo "Review everything above before pushing to GitHub."
    exit 1
fi
