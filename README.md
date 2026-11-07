# SmbServer

Source reconstruction of KaimoSystemSolutions **SMB-Server 2.1.1**, decompiled with ILSpyCmd 11.2.0.10050. The goal is a maintained, fully C# SMB2/3 server with Native AOT support. Correctness repairs and AOT validation are pending; this import is not a validated server release.

## Build

Use the .NET SDK selected by `global.json` (10.0.114, with patch roll-forward):

```sh
dotnet build SmbServer.slnx -c Release
```

Debug and Release builds pass after reconstructing the init-only property assignment in `SetInfoMessage.ParseBasicInfo`. The original failing build is retained in the [import build log](docs/provenance/import-build.log). Full builds currently report 333 warnings (nullable annotation context, platform compatibility and unawaited calls); protocol correctness and Native AOT compatibility remain unverified. See the [build reconstruction record](docs/validation/build-reconstruction.txt).

All six projects target `net10.0` and reference one another from source. `Smb.Host` is a library, not an executable; the test host is planned work. No original binaries or NuGet archives are included. Build outputs should remain outside version control.

## Layout

- `src/`: Smb.Protocol, Smb.Crypto, Smb.Auth, Smb.FileSystem, Smb.Server and Smb.Host.
- [Repair plan](docs/correctness-repair-plan.txt): phases, findings, required red–green TDD and coordinator/implementation-agent settings. Microsoft Protocol Test Suites integration is strongly recommended but optional.
- [Static review](docs/review/astra-protocol-review.txt): original findings, before runtime confirmation. Source locations refer to the original decompilation.
- [Provenance](docs/provenance/decompilation-manifest.json): package hash, upstream commit and decompiler version. Paths in this original manifest refer to the external evidence archive at `/mnt/storage/SMB-Server`.

The raw evidence archive is retained separately. This repository is the maintained source tree; future implementation should follow the plan here rather than create another `maintained/` directory. Original assembly attribution and version metadata are retained; they identify the source package, not a newly published release. Behavioral changes require the plan's red–green workflow. Authorization/authentication/signing and encryption review remain outside the agreed scope.

## License

The original package's [Apache-2.0 license](LICENSE) is included unchanged. Original author: KaimoSystemSolutions (assembly metadata also names kaimoSystem). Source was recovered from the published package, not an upstream source checkout.
