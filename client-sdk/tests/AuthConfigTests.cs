using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SoftwareLicenseAuth.Client.Tests;

public sealed class AuthConfigTests
{
    private const string PublicKey =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    [Fact]
    public void Load_MissingFileFailsClosed()
    {
        using var directory = new TemporaryDirectory();

        Assert.Throws<AuthConfigException>(() => Load(directory.GetPath("auth-config.json")));
    }

    [Fact]
    public void Load_AcceptsExactPublicConfiguration()
    {
        using var directory = new TemporaryDirectory();
        var path = directory.GetPath("auth-config.json");
        File.WriteAllText(path, ValidJson(), new UTF8Encoding(false));

        var config = Assert.IsType<AuthConfig>(Load(path));

        Assert.Equal(new Uri("https://auth.example.test/"), config.GatewayBaseUrl);
        Assert.Equal(PublicKey, config.KeygenPublicKey);
        Assert.Equal("account_1", config.KeygenAccountId);
        Assert.Equal("product-1", config.KeygenProductId);
        Assert.DoesNotContain(PublicKey, config.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Load_RejectsMalformedOrUnexpectedConfiguration()
    {
        var invalidDocuments = new[]
        {
            "{}",
            ValidJson(extraProperty: ",\"token\":\"must-not-be-accepted\""),
            ValidJson(gateway: "http://auth.example.test"),
            ValidJson(gateway: "https://user@auth.example.test"),
            ValidJson(gateway: "https://auth.example.test/api"),
            ValidJson(gateway: "https://auth.example.test/?query=1"),
            ValidJson(accountId: "account.invalid"),
            ValidJson(productId: ""),
            ValidJson(publicKey: PublicKey.ToLowerInvariant()),
            ValidJson(publicKey: new string('G', 64)),
            ValidJson()[..^1] + ",}",
            "{/*comment*/" + ValidJson()[1..],
            "{\"gateway_base_url\":\"https://auth.example.test\","
                + "\"gateway_base_url\":\"https://other.example.test\","
                + "\"keygen_public_key\":\"" + PublicKey + "\","
                + "\"keygen_account_id\":\"account_1\","
                + "\"keygen_product_id\":\"product-1\"}",
        };

        using var directory = new TemporaryDirectory();
        var path = directory.GetPath("auth-config.json");
        foreach (var document in invalidDocuments)
        {
            File.WriteAllText(path, document, new UTF8Encoding(false));
            var exception = Assert.Throws<AuthConfigException>(() => Load(path));
            Assert.DoesNotContain(document, exception.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Load_RejectsOversizedOrReparsePointFile()
    {
        using var directory = new TemporaryDirectory();
        var oversizedPath = directory.GetPath("oversized.json");
        File.WriteAllBytes(oversizedPath, new byte[32 * 1024 + 1]);
        Assert.Throws<AuthConfigException>(() => Load(oversizedPath));

        var targetPath = directory.GetPath("target.json");
        var linkedPath = directory.GetPath("auth-config.json");
        File.WriteAllText(targetPath, ValidJson(), new UTF8Encoding(false));
        File.CreateSymbolicLink(linkedPath, targetPath);
        Assert.Throws<AuthConfigException>(() => Load(linkedPath));
    }

    [Fact]
    public void ProductionType_ExposesOnlyParameterlessFixedFactory()
    {
        var factories = typeof(AuthConfig)
            .GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(method => !method.IsPrivate && method.ReturnType == typeof(AuthConfig))
            .ToArray();

        var factory = Assert.Single(factories);
        Assert.Equal("LoadForCurrentApplication", factory.Name);
        Assert.Empty(factory.GetParameters());
        Assert.All(
            typeof(AuthConfig).GetProperties(),
            property => Assert.Null(property.GetSetMethod(nonPublic: true)));
        Assert.DoesNotContain(
            typeof(AuthConfig).GetProperties(),
            property => property.Name.Contains("Password", StringComparison.OrdinalIgnoreCase)
                || property.Name.Contains("Token", StringComparison.OrdinalIgnoreCase)
                || property.Name.Contains("Private", StringComparison.OrdinalIgnoreCase));
    }

    private static AuthConfig? Load(string path)
    {
        var method = typeof(AuthConfig).GetMethod(
            "LoadFromPath",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new Xunit.Sdk.XunitException("Private config loader was not found.");
        try
        {
            return (AuthConfig?)method.Invoke(null, [path]);
        }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
            throw;
        }
    }

    private static string ValidJson(
        string gateway = "https://auth.example.test",
        string publicKey = PublicKey,
        string accountId = "account_1",
        string productId = "product-1",
        string extraProperty = "")
    {
        return "{"
            + "\"gateway_base_url\":" + JsonSerializer.Serialize(gateway) + ","
            + "\"keygen_public_key\":" + JsonSerializer.Serialize(publicKey) + ","
            + "\"keygen_account_id\":" + JsonSerializer.Serialize(accountId) + ","
            + "\"keygen_product_id\":" + JsonSerializer.Serialize(productId)
            + extraProperty
            + "}";
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly string path = Path.Combine(
            Path.GetTempPath(),
            "SoftwareLicenseAuth.Client.AuthConfigTests",
            Guid.NewGuid().ToString("N"));

        internal TemporaryDirectory()
        {
            Directory.CreateDirectory(path);
        }

        internal string GetPath(string name) => Path.Combine(path, name);

        public void Dispose()
        {
            Directory.Delete(path, recursive: true);
        }
    }
}
