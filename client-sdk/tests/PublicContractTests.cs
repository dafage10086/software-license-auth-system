using System.Text;
using Xunit;

namespace SoftwareLicenseAuth.Client.Tests;

public sealed class PublicContractTests
{
    [Fact]
    public void WindowsDemo_ReferencesSdkAndContainsOnlyFixedAuthorizationActions()
    {
        var repositoryRoot = FindRepositoryRoot();
        var demoRoot = Path.Combine(repositoryRoot, "examples", "windows-demo");
        var projectPath = Path.Combine(demoRoot, "SoftwareLicenseAuth.Demo.csproj");
        var programPath = Path.Combine(demoRoot, "Program.cs");
        var configPath = Path.Combine(demoRoot, "auth-config.example.json");

        Assert.True(File.Exists(projectPath));
        Assert.True(File.Exists(programPath));
        Assert.True(File.Exists(configPath));

        var project = File.ReadAllText(projectPath, Encoding.UTF8);
        var program = File.ReadAllText(programPath, Encoding.UTF8);
        var config = File.ReadAllText(configPath, Encoding.UTF8);
        Assert.Contains("SoftwareLicenseAuth.Client.csproj", project, StringComparison.Ordinal);
        Assert.Contains("LoginAsync", program, StringComparison.Ordinal);
        Assert.Contains("ActivateAsync", program, StringComparison.Ordinal);
        Assert.Contains("RefreshAsync", program, StringComparison.Ordinal);
        Assert.Contains("LogoutAsync", program, StringComparison.Ordinal);
        Assert.Contains("https://license.example.com", config, StringComparison.Ordinal);
        Assert.Contains("auth-config.example.json", project, StringComparison.Ordinal);
    }

    [Fact]
    public void PublicClientFiles_ContainOnlyGenericAuthorizationComponents()
    {
        var repositoryRoot = FindRepositoryRoot();
        var clientRoot = Path.Combine(repositoryRoot, "client-sdk");
        var forbidden = new[]
        {
            "QL" + "W10",
            "Qing" + "Lan",
            string.Concat((char)0x9752, (char)0x84DD),
            string.Join(".", new[] { "159", "195", "58", "181" }),
            "best" + "srv.de",
            "ql-keygen" + "-tunnel",
            "@accounts." + "ql.invalid",
            "Owner" + "LicenseShell",
            "auth_config.json",
            string.Concat((char)0x6388, (char)0x6743, (char)0x6570, (char)0x636E)
        };

        var files = Directory.EnumerateFiles(clientRoot, "*", SearchOption.AllDirectories)
            .Where(path => !HasGeneratedSegment(path))
            .Where(path => Path.GetExtension(path) is ".cs" or ".csproj" or ".txt")
            .Where(path => !path.EndsWith(
                nameof(PublicContractTests) + ".cs",
                StringComparison.Ordinal));

        foreach (var path in files)
        {
            var content = File.ReadAllText(path, Encoding.UTF8);
            foreach (var marker in forbidden)
            {
                Assert.DoesNotContain(marker, content, StringComparison.OrdinalIgnoreCase);
            }
        }

        var sourceRoot = Path.Combine(clientRoot, "src");
        Assert.False(File.Exists(Path.Combine(sourceRoot, "RuntimeBroker.cs")));
        Assert.False(File.Exists(Path.Combine(sourceRoot, "IntegrityArtifacts.cs")));
        Assert.False(File.Exists(Path.Combine(sourceRoot, "V2LicenseApplication.cs")));
        Assert.False(File.Exists(Path.Combine(sourceRoot, "IntegrityPublicKey.bin")));
    }

    private static bool HasGeneratedSegment(string path)
    {
        var segments = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return segments.Contains("bin", StringComparer.OrdinalIgnoreCase)
            || segments.Contains("obj", StringComparer.OrdinalIgnoreCase);
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, "client-sdk", "src")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Repository root was not found.");
    }
}
