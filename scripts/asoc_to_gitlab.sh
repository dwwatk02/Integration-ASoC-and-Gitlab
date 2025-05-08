#asocApiKeyId="xxxxxxxxxxxxx"
#asocApiKeySecret="xxxxxxxxxxxxx"
#serviceUrl="xxxxxxxxxxxxx"

# Read scan ID from file
SCAN_ID=$(<scanId.txt)
START_TIME=$(date +"%Y-%m-%dT%H:%M:%S")
# Get bearer token
echo "Authenticating with ASoC..."
TOKEN=$(curl -s -k -X POST "https://$serviceUrl/api/v4/Account/ApiKeyLogin" \
  -H "Content-Type: application/json" \
  -d "{\"KeyId\":\"$asocApiKeyId\", \"KeySecret\":\"$asocApiKeySecret\"}" | jq -r .Token)

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "Failed to authenticate. Check API credentials."
  exit 1
fi

# Get scan issues
echo "Retrieving scan issues..."
ISSUES=$(curl -s -k -H "Authorization: Bearer $TOKEN" \
  "https://$serviceUrl/api/v4/Issues/Scan/$SCAN_ID")

if [[ -z "$ISSUES" || "$ISSUES" == "null" ]]; then
  echo "Failed to retrieve scan issues."
  exit 1
fi

# Map to GitLab SAST format
echo "Mapping issues to GitLab SAST format..."

END_TIME=$(date +"%Y-%m-%dT%H:%M:%S")

# Extract items and build GitLab report
VULNERABILITIES=$(echo "$ISSUES" | jq -r '
  .Items | map({
    id: (.Id | tostring),
    category: "sast",
    description: (.IssueType // ""),
    severity: .Severity,
    confidence: "High",
    scanner: {
      id: "appscan",
      name: "HCL AppScan on Cloud"
    },
    location: {
      file: (.SourceFile // "unknown"),
      start_line: (.Line | tonumber? // 1),
      end_line: (.Line | tonumber? // 1)
    },
    identifiers: (
      if .Cwe then [{
        type: "cwe",
        name: "CWE-\(.Cwe)",
        value: "CWE-\(.Cwe)",
        url: "https://cwe.mitre.org/data/definitions/\(.Cwe).html"
      }] else [] end
    )
  })')

# Combine everything into final JSON structure
jq -n \
  --argjson vulns "$VULNERABILITIES" \
  --arg start "$START_TIME" \
  --arg endtime "$END_TIME" \
  '{
    version: "15.1.4",
    vulnerabilities: $vulns,
    scan: {
      type: "sast",
      status: "success",
      start_time: $start,
      end_time: $endtime,
      scanner: {
        id: "appscan",
        name: "HCL AppScan on Cloud",
        vendor: { name: "HCL" },
        version: "N/A"
      },
      analyzer: {
        id: "appscan",
        name: "HCL AppScan on Cloud",
        vendor: { name: "HCL" },
        version: "N/A"
      }
    }
  }' > gl-sast-report.json

echo "gl-sast-report.json created successfully."
