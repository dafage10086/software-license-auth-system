using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal sealed class AuthConfigException : Exception
{
    internal AuthConfigException()
        : base("Authorization configuration is invalid.")
    {
    }
}

internal sealed class AuthConfig
{
    private const string FileName = "auth-config.json";
    private const int MaximumFileBytes = 32 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private AuthConfig(
        Uri gatewayBaseUrl,
        string keygenPublicKey,
        string keygenAccountId,
        string keygenProductId)
    {
        GatewayBaseUrl = gatewayBaseUrl;
        KeygenPublicKey = keygenPublicKey;
        KeygenAccountId = keygenAccountId;
        KeygenProductId = keygenProductId;
    }

    public Uri GatewayBaseUrl { get; }

    public string KeygenPublicKey { get; }

    public string KeygenAccountId { get; }

    public string KeygenProductId { get; }

    internal static AuthConfig LoadForCurrentApplication()
    {
        return LoadFromPath(Path.Combine(AppContext.BaseDirectory, FileName));
    }

    public override string ToString()
    {
        return $"{nameof(AuthConfig)} {{ GatewayBaseUrl = {GatewayBaseUrl}, "
            + $"KeygenAccountId = {KeygenAccountId}, KeygenProductId = {KeygenProductId} }}";
    }

    private static AuthConfig LoadFromPath(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                throw new AuthConfigException();
            }

            RejectReparsePoint(path);
            byte[] payload;
            using (var stream = new FileStream(
                       path,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.Read,
                       bufferSize: 4096,
                       FileOptions.SequentialScan))
            {
                if (stream.Length <= 0 || stream.Length > MaximumFileBytes)
                {
                    throw new AuthConfigException();
                }

                payload = new byte[checked((int)stream.Length)];
                stream.ReadExactly(payload);
                if (stream.ReadByte() != -1)
                {
                    throw new AuthConfigException();
                }
            }

            RejectReparsePoint(path);
            try
            {
                _ = StrictUtf8.GetString(payload);
                return Parse(payload);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
        catch (AuthConfigException)
        {
            throw;
        }
        catch (FileNotFoundException)
        {
            throw new AuthConfigException();
        }
        catch (DirectoryNotFoundException)
        {
            throw new AuthConfigException();
        }
        catch
        {
            throw new AuthConfigException();
        }
    }

    private static AuthConfig Parse(byte[] payload)
    {
        using var document = JsonDocument.Parse(
            payload,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4,
            });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new AuthConfigException();
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!IsAllowedProperty(property.Name) || !names.Add(property.Name))
            {
                throw new AuthConfigException();
            }
        }

        if (names.Count != 4)
        {
            throw new AuthConfigException();
        }

        var gatewayText = ReadRequiredString(root, "gateway_base_url");
        var publicKey = ReadRequiredString(root, "keygen_public_key");
        var accountId = ReadRequiredString(root, "keygen_account_id");
        var productId = ReadRequiredString(root, "keygen_product_id");
        if (!TryParseGateway(gatewayText, out var gateway)
            || !IsValidId(accountId)
            || !IsValidId(productId)
            || !IsUppercaseHex(publicKey, 64))
        {
            throw new AuthConfigException();
        }

        try
        {
            _ = new MachineFileVerifier(publicKey);
        }
        catch
        {
            throw new AuthConfigException();
        }

        return new AuthConfig(gateway, publicKey, accountId, productId);
    }

    private static string ReadRequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var element)
            || element.ValueKind != JsonValueKind.String)
        {
            throw new AuthConfigException();
        }

        var value = element.GetString();
        if (string.IsNullOrWhiteSpace(value) || value != value.Trim())
        {
            throw new AuthConfigException();
        }

        return value;
    }

    private static bool TryParseGateway(string value, out Uri gateway)
    {
        gateway = null!;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var candidate)
            || candidate.Scheme != Uri.UriSchemeHttps
            || string.IsNullOrEmpty(candidate.Host)
            || !string.IsNullOrEmpty(candidate.UserInfo)
            || !string.IsNullOrEmpty(candidate.Query)
            || !string.IsNullOrEmpty(candidate.Fragment)
            || candidate.AbsolutePath != "/")
        {
            return false;
        }

        gateway = candidate;
        return true;
    }

    private static bool IsValidId(string value)
    {
        return value.Length is >= 1 and <= 128
            && value.All(character => character is >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'
                or >= '0' and <= '9'
                or '_' or '-');
    }

    private static bool IsUppercaseHex(string value, int length)
    {
        return value.Length == length
            && value.All(character => character is >= '0' and <= '9'
                or >= 'A' and <= 'F');
    }

    private static bool IsAllowedProperty(string name)
    {
        return name is "gateway_base_url"
            or "keygen_public_key"
            or "keygen_account_id"
            or "keygen_product_id";
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new AuthConfigException();
        }
    }
}
