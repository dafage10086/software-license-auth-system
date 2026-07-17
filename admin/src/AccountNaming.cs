internal static class AccountNaming
{
    private const string AccountEmailSuffix = "@accounts.license.invalid";

    internal static string Normalize(string username)
    {
        ArgumentNullException.ThrowIfNull(username);

        var trimmed = username.Trim();
        if (trimmed.Length is < 4 or > 32)
        {
            throw new ArgumentException("Username must contain 4 to 32 characters.", nameof(username));
        }

        foreach (var character in trimmed)
        {
            var allowed = character is >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'
                or >= '0' and <= '9'
                or '.' or '_' or '-';
            if (!allowed)
            {
                throw new ArgumentException("Username contains an unsupported character.", nameof(username));
            }
        }

        return trimmed.ToLowerInvariant();
    }

    internal static string ToAccountEmail(string username)
    {
        return Normalize(username) + AccountEmailSuffix;
    }
}
