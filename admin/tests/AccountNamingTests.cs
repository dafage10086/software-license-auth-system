using Xunit;

namespace SoftwareLicenseAuth.Admin.Tests;

public sealed class AccountNamingTests
{
    [Fact]
    public void Normalize_TrimsAndLowercasesAsciiUsername()
    {
        Assert.Equal("account.name_9-x", AccountNaming.Normalize("  Account.Name_9-X  "));
    }

    [Theory]
    [InlineData("abcd")]
    [InlineData("user0123")]
    [InlineData("a.b_c-d")]
    [InlineData("abcdefghijklmnopqrstuvwxyz012345")]
    public void Normalize_AcceptsAllowedCharactersAndBoundaryLengths(string username)
    {
        Assert.Equal(username, AccountNaming.Normalize(username));
    }

    [Theory]
    [InlineData("ab c")]
    [InlineData("user@example")]
    [InlineData("user+tag")]
    [InlineData("user/name")]
    public void Normalize_RejectsCharactersOutsideAsciiAllowList(string username)
    {
        Assert.Throws<ArgumentException>(() => AccountNaming.Normalize(username));
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("abcdefghijklmnopqrstuvwxyz0123456")]
    public void Normalize_RejectsLengthOutsideFourToThirtyTwo(string username)
    {
        Assert.Throws<ArgumentException>(() => AccountNaming.Normalize(username));
    }

    [Fact]
    public void ToAccountEmail_UsesNormalizedUsernameAndFixedSuffix()
    {
        const string expected = "customer.one@accounts.license.invalid";

        Assert.Equal(expected, AccountNaming.ToAccountEmail(" Customer.One "));
        Assert.Equal(expected, AccountNaming.ToAccountEmail("customer.one"));
    }

    [Theory]
    [InlineData("\u212Aabc")]
    [InlineData("café")]
    [InlineData("用户abc")]
    [InlineData("ａbcd")]
    public void Normalize_RejectsUnicodeCharacters(string username)
    {
        Assert.Throws<ArgumentException>(() => AccountNaming.Normalize(username));
    }
}
