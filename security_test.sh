#!/bin/bash

# =============================================================================
# Modular Comprehensive Security Testing Suite
# =============================================================================

if [ -z "$1" ]; then
    echo "Usage: $0 <target.com> [test1 test2 ...]"
    echo "Available tests: portscan, ssl, headers, webapp, dns, cloudflare, waf, vuln, info"
    exit 1
fi

TARGET=$1
shift # Remove target from arguments, leaving only the tests
TESTS_TO_RUN="$@"

# If no specific tests are provided, run all of them
if [ -z "$TESTS_TO_RUN" ]; then
    TESTS_TO_RUN="portscan ssl headers webapp dns cloudflare waf vuln info"
fi

# Helper function to check if a test should be run
should_run() {
    echo "$TESTS_TO_RUN" | grep -q -w "$1"
}

echo "🛡️  Starting Security Assessment for $TARGET..."
echo "Tests to run: $TESTS_TO_RUN"
echo "==============================================$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

IP=$(dig +short $TARGET)

echo -e "${BLUE}Target: $TARGET ($IP)${NC}"
echo ""

# =============================================================================
# 1. PORT SCANNING & SERVICE DETECTION
# =============================================================================
if should_run "portscan"; then
    echo -e "${BLUE}1. PORT SCANNING${NC}"
    echo "=================="
    echo "Top 1000 ports scan:"
    nmap -T4 -F $TARGET
    echo ""
    echo "Service version detection:"
    nmap -sV -p 80,443 $TARGET
    echo ""
    echo "OS Detection:"
    nmap -O $TARGET 2>/dev/null || echo "OS detection requires root"
fi

# =============================================================================
# 2. SSL/TLS SECURITY ASSESSMENT
# =============================================================================
if should_run "ssl"; then
    echo -e "\n${BLUE}2. SSL/TLS SECURITY${NC}"
    echo "==================="
    echo "SSL Certificate Info:"
    openssl s_client -connect $TARGET:443 -servername $TARGET </dev/null 2>/dev/null | openssl x509 -noout -text | grep -E "(Subject:|Issuer:|Not Before:|Not After:|DNS:)"
    echo ""
    echo "SSL/TLS Cipher Suites:"
    nmap --script ssl-enum-ciphers -p 443 $TARGET
    echo ""
    echo "SSL Configuration Test:"
    /opt/testssl.sh/testssl.sh --quiet --color 0 $TARGET 2>/dev/null || echo "testssl.sh not found"
fi

# =============================================================================
# 3. HTTP SECURITY HEADERS
# =============================================================================
if should_run "headers"; then
    echo -e "\n${BLUE}3. HTTP SECURITY HEADERS${NC}"
    echo "========================="
    echo "Security Headers Analysis:"
    curl -I -s https://$TARGET | grep -i -E "(strict-transport|content-security|x-frame|x-content|x-xss|referrer-policy|permissions-policy)"
    echo ""
    echo "Complete HTTP Headers:"
    curl -I -s https://$TARGET
fi

# =============================================================================
# 4. WEB APPLICATION SECURITY
# =============================================================================
if should_run "webapp"; then
    echo -e "\n${BLUE}4. WEB APPLICATION SECURITY${NC}"
    echo "============================"
    echo "Checking for common vulnerabilities:"
    echo "Common file/directory check:"
    for path in robots.txt sitemap.xml .htaccess wp-config.php.bak admin login wp-admin phpinfo.php; do
        status=$(curl -s -o /dev/null -w "%{\http_code}" https://$TARGET/$path)
        if [ "$status" -eq 200 ]; then
            echo -e "${RED}Found: /$path (Status: $status)${NC}"
        elif [ "$status" -eq 403 ]; then
            echo -e "${YELLOW}Forbidden: /$path (Status: $status)${NC}"
        else
            echo -e "${GREEN}Not found: /$path (Status: $status)${NC}"
        fi
    done
fi

# =============================================================================
# 5. DNS SECURITY
# =============================================================================
if should_run "dns"; then
    echo -e "\n${BLUE}5. DNS SECURITY${NC}"
    echo "==============="
    echo "DNS Records:"
    dig $TARGET ANY +short
    echo ""
    echo "DNS Security Extensions (DNSSEC):"
    dig $TARGET +dnssec +short
    echo ""
    echo "SPF/DMARC Records:"
    dig TXT $TARGET | grep -i -E "(spf|dmarc)"
fi

# =============================================================================
# 6. CLOUDFLARE SECURITY CHECK
# =============================================================================
if should_run "cloudflare"; then
    echo -e "\n${BLUE}6. CLOUDFLARE SECURITY${NC}"
    echo "======================"
    echo "Cloudflare Detection:"
    curl -I -s https://$TARGET | grep -i cloudflare
    echo ""
    echo "Real IP Detection Attempts:"
    for subdomain in direct origin www mail; do
        ip=$(dig +short $subdomain.$TARGET 2>/dev/null)
        if [ ! -z "$ip" ]; then
            echo "$subdomain.$TARGET: $ip"
        fi
    done
fi

# =============================================================================
# 7. LOAD BALANCER / WAF DETECTION
# =============================================================================
if should_run "waf"; then
    echo -e "\n${BLUE}7. WAF/LOAD BALANCER DETECTION${NC}"
    echo "==============================="
    echo "WAF Detection:"
    wafw00f https://$TARGET 2>/dev/null || echo "wafw00f not installed"
    echo ""
    echo "Server Headers:"
    curl -I -s https://$TARGET | grep -i server
fi

# =============================================================================
# 8. VULNERABILITY SCANNING
# =============================================================================
if should_run "vuln"; then
    echo -e "\n${BLUE}8. VULNERABILITY SCANNING${NC}"
    echo "========================="
    echo "Nikto Web Scanner:"
    nikto -h https://$TARGET -maxtime 5m 2>/dev/null || echo "Nikto not installed"
    echo ""
    echo "SQLMap Basic Test (safe):"
    /opt/sqlmap/sqlmap.py -u "https://$TARGET" --batch --level 1 --risk 1 --timeout 10 2>/dev/null || echo "SQLMap not found"
fi

# =============================================================================
# 9. INFORMATION GATHERING
# =============================================================================
if should_run "info"; then
    echo -e "\n${BLUE}9. INFORMATION GATHERING${NC}"
    echo "========================="
    echo "Technology Stack Detection:"
    whatweb -v https://$TARGET 2>/dev/null || echo "WhatWeb not installed"
    echo ""
    echo "Subdomain Enumeration (basic):"
    for sub in www mail ftp admin api blog shop test dev staging; do
        if nslookup $sub.$TARGET >/dev/null 2>&1; then
            echo -e "${GREEN}Found: $sub.$TARGET${NC}"
        fi
    done
fi

# =============================================================================
# 10. SUMMARY
# =============================================================================
echo -e "\n${BLUE}10. SECURITY ASSESSMENT SUMMARY${NC}"
echo "================================"
echo -e "${GREEN}✅ Tests Completed${NC}"
echo "Review the output above for any security concerns."