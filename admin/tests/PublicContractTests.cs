using System.Text;
using Xunit;

namespace SoftwareLicenseAuth.Admin.Tests;

public sealed class PublicContractTests
{
    [Fact]
    public void PublicAdminContract_UsesGenericTitleAndExampleConfiguration()
    {
        var repositoryRoot = FindRepositoryRoot();
        var sourceRoot = Path.Combine(repositoryRoot, "admin", "src");
        var program = File.ReadAllText(Path.Combine(sourceRoot, "Program.cs"), Encoding.UTF8);

        Assert.Contains("Software License Auth - Administrator", program, StringComparison.Ordinal);
        Assert.Contains("admin-config.json", program, StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(sourceRoot, "admin-config.json.example")));
    }

    [Fact]
    public void PublicAdminFiles_ContainNoPrivateBrandOrProductionConfiguration()
    {
        var repositoryRoot = FindRepositoryRoot();
        var forbidden = new[]
        {
            "QL" + "W10",
            "Qing" + "Lan",
            string.Concat((char)0x9752, (char)0x84DD),
            string.Join(".", new[] { "159", "195", "58", "181" }),
            "best" + "srv.de",
            "ql-keygen" + "-tunnel",
            "@accounts." + "ql.invalid",
            "keygen." + "ql.invalid",
            "Owner" + "Keygen",
            "owner-config.json"
        };

        foreach (var directory in new[] { "src", "tests" })
        {
            var files = Directory.EnumerateFiles(
                Path.Combine(repositoryRoot, "admin", directory),
                "*",
                SearchOption.AllDirectories)
                .Where(path => Path.GetExtension(path) is ".cs" or ".csproj")
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
        }
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, "admin", "src")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Repository root was not found.");
    }
}
