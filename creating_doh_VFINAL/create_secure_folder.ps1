<#
.SYNOPSIS
    Creates a secure folder on D:\TLS_Secure with restrictive ACLs.

.DESCRIPTION
    - Removes inherited permissions
    - Strips default groups (Users, Everyone, Authenticated Users)
    - Grants full control only to the current user
    - Ensures all files/subfolders inherit the same ACLs

.AUTHOR
    Herbé (operational owner)

.VERSION
    1.0

.DATE
    2025-12-23

.NOTES
    Run as Administrator.
    After execution, verify ACLs with: icacls D:\TLS_Secure
#>

# Create the folder
New-Item -Path "D:\TLS_Secure" -ItemType Directory -Force

# Remove inheritance
icacls "D:\TLS_Secure" /inheritance:r

# Remove default groups
icacls "D:\TLS_Secure" /remove "Users" "Authenticated Users" "Everyone"

# Grant full control to your account
icacls "D:\TLS_Secure" /grant:r "$env:USERNAME:(OI)(CI)(F)"
