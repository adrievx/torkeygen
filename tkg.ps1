# tkg.ps1
# Generates Tor v3 client auth keys
# Outputs:
#  - descriptor:x25519:<public key> (goes in a .auth file on the server)
#  - <private key> (give to user)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# -- check openssl --
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "OpenSSL not found in PATH"
}

# -- temp file --
$privPem = Join-Path $PSScriptRoot "client_private.pem"
$privDer = Join-Path $PSScriptRoot "client_private.der"
$pubDer  = Join-Path $PSScriptRoot "client_public.der"

# -- UTIL FUNCS --
function Base32Encode {
    param ([byte[]]$data)
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $out = ""
    $buffer = 0
    $bits = 0
    
    foreach ($b in $data) {
        $buffer = ($buffer -shl 8) -bor $b
        $bits += 8
        while ($bits -ge 5) {
            $out += $alphabet[($buffer -shr ($bits - 5)) -band 31]
            $bits -= 5
        }
    }
    
    if ($bits -gt 0) {
        $out += $alphabet[($buffer -shl (5 - $bits)) -band 31]
    }

    return $out
}

# -- generate key --
& openssl genpkey -algorithm x25519 -out $privPem | Out-Null
& openssl pkey -in $privPem -outform DER -out $privDer | Out-Null
& openssl pkey -in $privPem -pubout -outform DER -out $pubDer | Out-Null

# -- ensure exists --
foreach ($f in @($privDer, $pubDer)) {
    if (-not (Test-Path $f)) {
        throw "Failed to create $f"
    }
}

# -- read last 32 bytes (actual key) -- 
$privBytes = [System.IO.File]::ReadAllBytes($privDer)[-32..-1]
$pubBytes  = [System.IO.File]::ReadAllBytes($pubDer)[-32..-1]

# -- encode --
$privB32 = Base32Encode $privBytes
$pubB32  = Base32Encode $pubBytes

# -- additional checks --
if ($privB32.Length -ne 52 -or $pubB32.Length -ne 52) {
    throw "Data length invalid (expected 52 char.)"
}

# -- give back to user --
Write-Host ""
Write-Host "PUBLIC:"
Write-Host "descriptor:x25519:$pubB32"
Write-Host ""
Write-Host "PRIVATE:"
Write-Host $privB32
Write-Host ""

# clear
Remove-Item $privPem, $privDer, $pubDer -Force