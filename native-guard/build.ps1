param(
  [string]$NdkRoot = "$env:LOCALAPPDATA\Android\Sdk\ndk\26.3.11579264"
)

$ErrorActionPreference = "Stop"
$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$Output = Join-Path (Split-Path -Parent $Project) "native-libs"
$Cmake = Join-Path $env:LOCALAPPDATA "Android\Sdk\cmake\3.22.1\bin\cmake.exe"
$Ninja = Join-Path $env:LOCALAPPDATA "Android\Sdk\cmake\3.22.1\bin\ninja.exe"
$Toolchain = Join-Path $NdkRoot "build\cmake\android.toolchain.cmake"
$Strip = Join-Path $NdkRoot "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe"

if (!(Test-Path -LiteralPath $Cmake)) { throw "CMake not found: $Cmake" }
if (!(Test-Path -LiteralPath $Ninja)) { throw "Ninja not found: $Ninja" }
if (!(Test-Path -LiteralPath $Toolchain)) { throw "NDK toolchain not found: $Toolchain" }
if (!(Test-Path -LiteralPath $Strip)) { throw "llvm-strip not found: $Strip" }

$Targets = @(
  @{ Abi = "arm64-v8a"; Api = 23 },
  @{ Abi = "armeabi-v7a"; Api = 23 },
  @{ Abi = "x86"; Api = 23 },
  @{ Abi = "x86_64"; Api = 23 }
)

foreach ($Target in $Targets) {
  $Build = Join-Path $Project ("build-" + $Target.Abi)
  & $Cmake -S $Project -B $Build -G Ninja `
    "-DCMAKE_MAKE_PROGRAM=$Ninja" `
    "-DCMAKE_TOOLCHAIN_FILE=$Toolchain" `
    "-DANDROID_ABI=$($Target.Abi)" `
    "-DANDROID_PLATFORM=android-$($Target.Api)" `
    "-DCMAKE_BUILD_TYPE=Release"
  if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for $($Target.Abi)" }
  & $Cmake --build $Build --config Release
  if ($LASTEXITCODE -ne 0) { throw "Native build failed for $($Target.Abi)" }
  $AbiOutput = Join-Path $Output $Target.Abi
  New-Item -ItemType Directory -Force -Path $AbiOutput | Out-Null
  Copy-Item -LiteralPath (Join-Path $Build "liblicenseguard.so") -Destination (Join-Path $AbiOutput "liblicenseguard.so") -Force
  & $Strip --strip-unneeded (Join-Path $AbiOutput "liblicenseguard.so")
  if ($LASTEXITCODE -ne 0) { throw "Native strip failed for $($Target.Abi)" }
}

Write-Host "Native guard libraries written to $Output"
