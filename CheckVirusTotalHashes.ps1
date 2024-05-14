# Define the API key and endpoint
$apiKey = "YOUR APIKEY"
$vtEndpoint = "https://www.virustotal.com/api/v3/files/"

# Function to query VirusTotal
function Get-VirusTotalReport {
    param (
        [string]$fileHash
    )

    $uri = "$vtEndpoint$fileHash"
    $headers = @{
        "x-apikey" = $apiKey
    }

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $response
    }
    catch {
        Write-Error "No match found for hash: $fileHash" -ErrorAction SilentlyContinue
        return $null
    }
}

# List of hash values to check
$fileHashes = @(
       "dbbc3abfece27a5542593e2638171cb81bbe0f96"
)

# Process each hash and query VirusTotal
foreach ($hash in $fileHashes) {
    $vtReport = Get-VirusTotalReport -fileHash $hash

    if ($vtReport) {
        $scanDate = [datetime]::FromFileTimeUtc($vtReport.data.attributes.last_analysis_date)
        $scanResults = $vtReport.data.attributes.last_analysis_stats

        Write-Output "Hash: $hash"
        Write-Output "Scan Date: $scanDate"
        Write-Output "Scan Results: "
        Write-Output "  Harmless: $($scanResults.harmless)"
        Write-Output "  Malicious: $($scanResults.malicious)"
        Write-Output "  Suspicious: $($scanResults.suspicious)"
        Write-Output "  Undetected: $($scanResults.undetected)"
        Write-Output "VirusTotal URL: https://www.virustotal.com/gui/file/$hash"
        Write-Output "-----------------------------------"
    } else {
        Write-Output "No match found for hash: $hash"
        Write-Output "-----------------------------------"
    }
}
