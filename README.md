# TruKare Report Tracker

## Prerequisites

- Install the .NET SDK (10.0.x with preview support). The [`dotnet-install` script](https://learn.microsoft.com/dotnet/core/tools/dotnet-install-script) is the quickest option:
  ```bash
  curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin -c 10.0 -InstallDir "$HOME/.dotnet"
  export PATH="$HOME/.dotnet:$HOME/.dotnet/tools:$PATH"
  ```

## Local development

1. Restore packages:
   ```bash
   dotnet restore TruKare.Reports.Tests/TruKare.Reports.Tests.csproj
   ```
2. Build (Release configuration mirrors CI):
   ```bash
   dotnet build TruKare.Reports/TruKare.Reports.csproj --configuration Release --no-restore
   dotnet build TruKare.Reports.Tests/TruKare.Reports.Tests.csproj --configuration Release --no-restore
   ```
3. Lint with `dotnet format`:
   ```bash
   dotnet tool install -g dotnet-format
   export PATH="$HOME/.dotnet/tools:$PATH"
   dotnet format TruKare.Reports/TruKare.Reports.csproj --verify-no-changes
   dotnet format TruKare.Reports.Tests/TruKare.Reports.Tests.csproj --verify-no-changes
   ```
4. Run tests:
   ```bash
   dotnet test TruKare.Reports.Tests/TruKare.Reports.Tests.csproj --configuration Release --no-build
   ```
   - Repository integration tests are opt-in. Set `RUN_REPOSITORY_INTEGRATION_TESTS=1` to include them:
     ```bash
     RUN_REPOSITORY_INTEGRATION_TESTS=1 dotnet test TruKare.Reports.Tests/TruKare.Reports.Tests.csproj --configuration Release --no-build
     ```

## Continuous integration

- GitHub Actions: `.github/workflows/dotnet.yml`
- Azure Pipelines: `azure-pipelines.yml`

Both pipelines run restore, build, `dotnet format --verify-no-changes`, and tests. Preview SDKs are enabled to support the `net10.0` target.
