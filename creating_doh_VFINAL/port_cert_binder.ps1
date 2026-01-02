<#
.SYNOPSIS
    Hardened script to prepare and bind TLS certificate for DoH/DoT.

.DESCRIPTION
    - Creates secure folder D:\TLS_Secure
    - Applies restrictive ACLs (only current user has full control)
    - Imports PFX certificate into LocalMachine\My store
    - Extracts thumbprint of the certificate
    - Binds certificate to ports 443 (DoH) and 853 (DoT)

.AUTHOR
    Herbé (operational owner)

.VERSION
    1.0

.DATE
    2025-12-23

.NOTES
    Run as Administrator.
    Replace file path with your actual PFX if different.
    Verify bindings with: netsh http show sslcert
#>

# --- Step 1: Create secure folder ---
New-Item -Path "D:\TLS_Secure" -ItemType Directory -Force

# --- Step 2: Apply restrictive ACLs ---
icacls "D:\TLS_Secure" /inheritance:r
icacls "D:\TLS_Secure" /remove "Users" "Authenticated Users" "Everyone"
icacls "D:\TLS_Secure" /grant:r "$env:USERNAME:(OI)(CI)(F)"

# --- Step 3: Import certificate into LocalMachine store ---
Import-PfxCertificate -FilePath "D:\TLS_Secure\hehospitalityconsulting.pfx" `
    -CertStoreLocation Cert:\LocalMachine\My

# --- Step 4: Extract thumbprint ---
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*hehospitalityconsulting*" }
$thumb = $cert.Thumbprint

Write-Output "Certificate Thumbprint: $thumb"

# --- Step 5: Bind certificate to DoH (443) ---
netsh http add sslcert ipport=0.0.0.0:443 certhash=$thumb appid="{00112233-4455-6677-8899-AABBCCDDEEFF}"

# --- Step 6: Bind certificate to DoT (853) ---
netsh http add sslcert ipport=0.0.0.0:853 certhash=$thumb appid="{00112233-4455-6677-8899-AABBCCDDEEFF}"

# --- Step 7: Verify bindings ---
netsh http show sslcert
