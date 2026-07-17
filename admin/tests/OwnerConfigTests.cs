using System.Reflection;
using System.Text.Json;
using Xunit;

namespace SoftwareLicenseAuth.Admin.Tests;

public sealed class OwnerConfigTests
{
    private const string ValidConfigJson = """
        {
          "admin_url": "http://127.0.0.1:18788/",
          "account_id": "account-test",
          "product_id": "product-test",
          "trial_policy_id": "policy-trial",
          "year_policy_id": "policy-year",
          "forever_policy_id": "policy-forever"
        }
        """;

    private static readonly string[] ExpectedJsonFields =
    [
        "account_id",
        "admin_url",
        "forever_policy_id",
        "product_id",
        "trial_policy_id",
        "year_policy_id"
    ];

    [Fact]
    public void Load_ReadsOnlyExpectedNonSecretFields()
    {
        using var directory = new TemporaryDirectory();
        var path = directory.WriteFile("admin-config.json", ValidConfigJson);

        var config = OwnerConfig.Load(path);

        Assert.Equal(new Uri("http://127.0.0.1:18788/"), config.AdminUrl);
        Assert.Equal("account-test", config.AccountId);
        Assert.Equal("product-test", config.ProductId);
        Assert.Equal("policy-trial", config.TrialPolicyId);
        Assert.Equal("policy-year", config.YearPolicyId);
        Assert.Equal("policy-forever", config.ForeverPolicyId);

        var json = JsonSerializer.Serialize(config);
        using var document = JsonDocument.Parse(json);
        var fields = document.RootElement.EnumerateObject()
            .Select(property => property.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(ExpectedJsonFields, fields);

        var dataMemberNames = typeof(OwnerConfig)
            .GetMembers(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(member => member.MemberType is MemberTypes.Field or MemberTypes.Property)
            .Select(member => member.Name);
        Assert.DoesNotContain(dataMemberNames, IsSensitiveName);
        Assert.DoesNotContain(document.RootElement.EnumerateObject(), property => IsSensitiveName(property.Name));
    }

    [Theory]
    [InlineData("token")]
    [InlineData("password")]
    [InlineData("secret")]
    [InlineData("unexpected")]
    public void Load_RejectsUnknownFields(string fieldName)
    {
        using var directory = new TemporaryDirectory();
        var json = InsertBeforeClosingBrace(
            ValidConfigJson,
            $",\n  \"{fieldName}\": \"test-only-value\"\n");
        var path = directory.WriteFile("admin-config.json", json);

        Assert.Throws<JsonException>(() => OwnerConfig.Load(path));
    }

    [Fact]
    public void Load_RejectsDuplicateRootFieldsBeforeDeserialization()
    {
        using var directory = new TemporaryDirectory();
        var json = InsertBeforeClosingBrace(
            ValidConfigJson,
            ",\n  \"account_id\": \"replacement-account\"\n");
        var path = directory.WriteFile("duplicate-field.json", json);

        Assert.Throws<JsonException>(() => OwnerConfig.Load(path));
    }

    [Fact]
    public void Load_RejectsCommentsAndTrailingCommas()
    {
        using var directory = new TemporaryDirectory();
        var withComment = ValidConfigJson.Replace("{", "{\n  // not strict JSON", StringComparison.Ordinal);
        var withTrailingComma = InsertBeforeClosingBrace(ValidConfigJson, ",");
        var commentPath = directory.WriteFile("comment.json", withComment);
        var trailingCommaPath = directory.WriteFile("trailing-comma.json", withTrailingComma);

        Assert.ThrowsAny<JsonException>(() => OwnerConfig.Load(commentPath));
        Assert.ThrowsAny<JsonException>(() => OwnerConfig.Load(trailingCommaPath));
    }

    [Fact]
    public void Load_RejectsMissingRequiredField()
    {
        using var directory = new TemporaryDirectory();
        var json = ValidConfigJson.Replace(
            "\"account_id\": \"account-test\",",
            string.Empty,
            StringComparison.Ordinal);
        var path = directory.WriteFile("admin-config.json", json);

        Assert.DoesNotContain("\"account_id\"", json, StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(() => OwnerConfig.Load(path));
    }

    [Fact]
    public void Load_AcceptsOnlyTheFixedTunnelAdminUrl()
    {
        using var directory = new TemporaryDirectory();
        var path = directory.WriteFile(
            "admin-config.json",
            ValidConfigJson);

        var config = OwnerConfig.Load(path);

        Assert.Equal(new Uri("http://127.0.0.1:18788/"), config.AdminUrl);
    }

    [Theory]
    [InlineData("http://127.0.0.1:18788")]
    [InlineData("http://localhost:18788/")]
    [InlineData("http://127.0.0.1:18789/")]
    [InlineData("http://127.0.0.2:18788/")]
    [InlineData("https://127.0.0.1:18788/")]
    [InlineData("https://license-admin.example.invalid/")]
    public void Load_RejectsEveryAdminUrlExceptTheExactFixedTunnelUrl(string adminUrl)
    {
        using var directory = new TemporaryDirectory();
        var path = directory.WriteFile(
            "admin-config.json",
            WithAdminUrl(adminUrl));

        Assert.Throws<InvalidDataException>(() => OwnerConfig.Load(path));
    }

    private static string InsertBeforeClosingBrace(string json, string value)
    {
        var closingBrace = json.LastIndexOf('}');
        Assert.True(closingBrace >= 0);
        return json.Insert(closingBrace, value);
    }

    private static string WithAdminUrl(string adminUrl)
    {
        return ValidConfigJson.Replace(
            "http://127.0.0.1:18788/",
            adminUrl,
            StringComparison.Ordinal);
    }

    private static bool IsSensitiveName(string name)
    {
        return name.Contains("token", StringComparison.OrdinalIgnoreCase)
            || name.Contains("password", StringComparison.OrdinalIgnoreCase)
            || name.Contains("secret", StringComparison.OrdinalIgnoreCase);
    }
}
