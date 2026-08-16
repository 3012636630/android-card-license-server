# Xiaomi / OnePlus Multi-Kernel Cloud Build

This bundle builds one ARM64 `lsdriver` carrier for each verified stock target:

| Target ID | Device | Stock release |
|---|---|---|
| `xiaomi-fuxi-5.15` | Xiaomi 13 | `5.15.74-android13-8-00049-g8945ccdb2203-ab9500309` |
| `oneplus-11-5.15` | OnePlus 11 | `5.15.180-android13-8-o-01179-g15b0e605e4c2` |
| `xiaomi-shennong-6.1` | Xiaomi 14 Pro | `6.1.25-android14-11-g8744d1c0cf31-ab10888519` |
| `oneplus-12-6.1` | OnePlus 12 | `6.1.141-android14-11-o-g984c12362a16` |
| `xiaomi-dada-6.6` | Xiaomi 15 | `6.6.30-android15-8-geae86f166c48-abogki367569362-4k` |
| `oneplus-13-6.6` | OnePlus 13 | `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k` |

## Run

1. Extract `lsdriver-multi-kernel-cloud-src.tar.gz` into an empty GitHub repository.
2. Push the extracted tree, including `.github/workflows`.
3. Open **Actions**, select **build-multi-kernel-lsdriver**, and choose **Run workflow**.
4. Select one target or `all`. Each target uses a separate Ubuntu runner.
5. Download the `lsdriver-<target-id>` artifact after the job completes.

The workflow clones the source commit recorded in `multi-kernel-targets.json`,
uses the requested AOSP Clang revision, prepares the stock config, restores the
Image-derived `Module.symvers`, and compiles with target CFI/KCFI, LTO, BTI/PAC,
shadow-call-stack, MODVERSIONS, and DWARF settings. It does not run QEMU on the PC.

## Artifact Contents

- `lsdriver-<target-id>-carrier.ko`: unsigned exact-release carrier module.
- `carrier-manifest.json`: module hash, exact vermagic, import CRC results,
  CFI mode, architecture features, DWARF evidence, source commit, Clang source
  commit, and Clang binary hash.
- `adapter-analysis.json`: strict adapter analysis against the stock reference
  module and Image-derived `Module.symvers`.
- `kbuild.log`, `config.build`, `config.delta`, and `clang-version.txt`.

Cloud output is static compatibility evidence, not the final runtime-tested
release. After the phone reconnects, the carrier still needs the isolated
Termux QEMU load, 13-function test, hide/restore, IOCTL 22, clean `rmmod`, guest
survival, QEMU exit, and target-bound internal-KABI runtime evidence.

## Regenerate The Bundle

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File work\export-multi-kernel-cloud-bundle.ps1 -Force
```

The command rechecks every bundled config, `Module.symvers`, reference module,
and source manifest hash before publishing the archive.
