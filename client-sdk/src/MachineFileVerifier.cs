using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NSec.Cryptography;

internal sealed class MachineFileException : Exception
{
    private const string FailureMessage = "Machine file verification failed.";

    internal MachineFileException()
        : base(FailureMessage)
    {
    }
}

internal sealed record ExpectedMachineClaims(
    string AccountId,
    string ProductId,
    string LicenseId,
    string MachineId,
    string OwnerId,
    string Fingerprint)
{
    public override string ToString()
    {
        return nameof(ExpectedMachineClaims);
    }
}

internal sealed record VerifiedMachineFile(
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset TrustedServerTime);

internal sealed class MachineFileVerifier
{
    private const int MaximumCertificateUtf8Bytes = 1024 * 1024;
    private const string Header = "-----BEGIN MACHINE FILE-----\n";
    private const string Footer = "-----END MACHINE FILE-----\n";
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);
    private readonly PublicKey publicKey;

    internal MachineFileVerifier(string publicKeyHex)
    {
        byte[]? publicKeyBytes = null;
        try
        {
            if (publicKeyHex is null || publicKeyHex.Length != 64)
            {
                throw new FormatException();
            }

            publicKeyBytes = Convert.FromHexString(publicKeyHex);
            if (publicKeyBytes.Length != 32)
            {
                throw new FormatException();
            }

            publicKey = PublicKey.Import(
                SignatureAlgorithm.Ed25519,
                publicKeyBytes,
                KeyBlobFormat.RawPublicKey);
        }
        catch
        {
            throw new MachineFileException();
        }
        finally
        {
            if (publicKeyBytes is not null)
            {
                CryptographicOperations.ZeroMemory(publicKeyBytes);
            }
        }
    }

    internal VerifiedMachineFile Verify(
        string certificate,
        ExpectedMachineClaims expected,
        DateTimeOffset serverTime,
        DateTimeOffset envelopeExpiry,
        DateTimeOffset? lastServerTime)
    {
        byte[]? envelopeBytes = null;
        byte[]? signature = null;
        byte[]? signingData = null;
        byte[]? payloadBytes = null;
        try
        {
            envelopeBytes = DecodeArmoredEnvelope(certificate);
            var (encodedPayload, encodedSignature, algorithm) =
                ParseEnvelope(envelopeBytes);
            if (algorithm != "base64+ed25519")
            {
                throw new MachineFileException();
            }

            signature = DecodeCanonicalBase64(encodedSignature);
            if (signature.Length != 64)
            {
                throw new MachineFileException();
            }

            signingData = Encoding.UTF8.GetBytes("machine/" + encodedPayload);
            if (!SignatureAlgorithm.Ed25519.Verify(publicKey, signingData, signature))
            {
                throw new MachineFileException();
            }

            payloadBytes = DecodeCanonicalBase64(encodedPayload);
            var (issuedAt, expiresAt) = ParsePayload(payloadBytes, expected);
            var trustedAt = serverTime > issuedAt ? serverTime : issuedAt;
            if (expiresAt - issuedAt != TimeSpan.FromSeconds(3600)
                || issuedAt < serverTime.AddMinutes(-6)
                || issuedAt > serverTime.AddMinutes(1)
                || envelopeExpiry.ToUnixTimeSeconds() != expiresAt.ToUnixTimeSeconds()
                || envelopeExpiry > expiresAt
                || trustedAt >= expiresAt
                || (lastServerTime.HasValue && trustedAt < lastServerTime.Value))
            {
                throw new MachineFileException();
            }

            return new VerifiedMachineFile(issuedAt, expiresAt, trustedAt);
        }
        catch (MachineFileException)
        {
            throw;
        }
        catch
        {
            throw new MachineFileException();
        }
        finally
        {
            ZeroMemory(envelopeBytes);
            ZeroMemory(signature);
            ZeroMemory(signingData);
            ZeroMemory(payloadBytes);
        }
    }

    private static (DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt) ParsePayload(
        byte[] payloadBytes,
        ExpectedMachineClaims expected)
    {
        if (expected is null)
        {
            throw new MachineFileException();
        }

        using var payload = JsonDocument.Parse(
            payloadBytes,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
        RejectDuplicateProperties(payload.RootElement);

        var root = RequireObject(payload.RootElement);
        var meta = GetRequiredObject(root, "meta");
        var data = GetRequiredObject(root, "data");
        var issuedAt = ParseUtcTimestamp(GetRequiredString(meta, "issued"));
        var expiresAt = ParseUtcTimestamp(GetRequiredString(meta, "expiry"));
        if (!meta.TryGetProperty("ttl", out var ttl)
            || ttl.ValueKind != JsonValueKind.Number
            || !ttl.TryGetInt32(out var ttlSeconds)
            || ttlSeconds != 3600)
        {
            throw new MachineFileException();
        }

        if (GetRequiredString(data, "type") != "machines"
            || GetRequiredString(data, "id") != expected.MachineId)
        {
            throw new MachineFileException();
        }

        var attributes = GetRequiredObject(data, "attributes");
        if (GetRequiredString(attributes, "fingerprint") != expected.Fingerprint)
        {
            throw new MachineFileException();
        }

        var relationships = GetRequiredObject(data, "relationships");
        ValidateRelationship(
            relationships,
            "account",
            "accounts",
            expected.AccountId);
        ValidateRelationship(
            relationships,
            "product",
            "products",
            expected.ProductId);
        ValidateRelationship(
            relationships,
            "license",
            "licenses",
            expected.LicenseId);
        ValidateRelationship(
            relationships,
            "owner",
            "users",
            expected.OwnerId);

        return (issuedAt, expiresAt);
    }

    private static void ValidateRelationship(
        JsonElement relationships,
        string name,
        string expectedType,
        string expectedId)
    {
        var relationship = GetRequiredObject(relationships, name);
        var linkage = GetRequiredObject(relationship, "data");
        if (GetRequiredString(linkage, "type") != expectedType
            || GetRequiredString(linkage, "id") != expectedId)
        {
            throw new MachineFileException();
        }
    }

    private static JsonElement RequireObject(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new MachineFileException();
        }

        return element;
    }

    private static JsonElement GetRequiredObject(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value))
        {
            throw new MachineFileException();
        }

        return RequireObject(value);
    }

    private static string GetRequiredString(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value)
            || value.ValueKind != JsonValueKind.String)
        {
            throw new MachineFileException();
        }

        return value.GetString() ?? throw new MachineFileException();
    }

    private static DateTimeOffset ParseUtcTimestamp(string value)
    {
        if (value.Length < 20
            || value[4] != '-'
            || value[7] != '-'
            || value[10] != 'T'
            || value[13] != ':'
            || value[16] != ':'
            || value[^1] != 'Z')
        {
            throw new MachineFileException();
        }

        string format;
        if (value.Length == 20)
        {
            format = "yyyy-MM-dd'T'HH:mm:ss'Z'";
        }
        else
        {
            var fractionalDigits = value.Length - 21;
            if (value[19] != '.'
                || fractionalDigits is < 1 or > 7
                || value.AsSpan(20, fractionalDigits).IndexOfAnyExceptInRange('0', '9') >= 0)
            {
                throw new MachineFileException();
            }

            format = "yyyy-MM-dd'T'HH:mm:ss."
                + new string('f', fractionalDigits)
                + "'Z'";
        }

        if (!DateTimeOffset.TryParseExact(
                value,
                format,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var timestamp)
            || timestamp.Offset != TimeSpan.Zero)
        {
            throw new MachineFileException();
        }

        return timestamp;
    }

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new MachineFileException();
                }

                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicateProperties(item);
            }
        }
    }

    private static byte[] DecodeArmoredEnvelope(string certificate)
    {
        if (certificate is null
            || StrictUtf8.GetByteCount(certificate) > MaximumCertificateUtf8Bytes
            || !certificate.StartsWith(Header, StringComparison.Ordinal)
            || !certificate.EndsWith(Footer, StringComparison.Ordinal))
        {
            throw new MachineFileException();
        }

        var bodyWithFinalLf = certificate.AsSpan(
            Header.Length,
            certificate.Length - Header.Length - Footer.Length);
        if (bodyWithFinalLf.Length < 2
            || bodyWithFinalLf[^1] != '\n')
        {
            throw new MachineFileException();
        }

        var body = bodyWithFinalLf[..^1];
        var currentLineLength = 0;
        var encodedLength = 0;
        foreach (var character in body)
        {
            if (character == '\n')
            {
                if (currentLineLength != 60)
                {
                    throw new MachineFileException();
                }

                encodedLength += currentLineLength;
                currentLineLength = 0;
                continue;
            }

            currentLineLength++;
            if (currentLineLength > 60)
            {
                throw new MachineFileException();
            }
        }

        if (currentLineLength is < 1 or > 60)
        {
            throw new MachineFileException();
        }

        encodedLength += currentLineLength;
        var encodedEnvelope = string.Create(
            encodedLength,
            certificate,
            static (destination, source) =>
            {
                var sourceBody = source.AsSpan(
                    Header.Length,
                    source.Length - Header.Length - Footer.Length - 1);
                var destinationOffset = 0;
                foreach (var character in sourceBody)
                {
                    if (character != '\n')
                    {
                        destination[destinationOffset++] = character;
                    }
                }
            });

        byte[]? envelopeBytes = null;
        try
        {
            envelopeBytes = DecodeCanonicalBase64(encodedEnvelope);
            if (!body.SequenceEqual(EncodeRubyBase64(envelopeBytes).AsSpan()))
            {
                throw new MachineFileException();
            }

            return envelopeBytes;
        }
        catch
        {
            ZeroMemory(envelopeBytes);
            throw;
        }
    }

    private static (string EncodedPayload, string EncodedSignature, string Algorithm)
        ParseEnvelope(byte[] envelopeBytes)
    {
        using var envelope = JsonDocument.Parse(
            envelopeBytes,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
        if (envelope.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new MachineFileException();
        }

        string? encodedPayload = null;
        string? encodedSignature = null;
        string? algorithm = null;
        var fieldCount = 0;
        foreach (var property in envelope.RootElement.EnumerateObject())
        {
            fieldCount++;
            if (property.Value.ValueKind != JsonValueKind.String)
            {
                throw new MachineFileException();
            }

            var value = property.Value.GetString();
            if (string.IsNullOrEmpty(value))
            {
                throw new MachineFileException();
            }

            switch (property.Name)
            {
                case "enc" when encodedPayload is null:
                    encodedPayload = value;
                    break;
                case "sig" when encodedSignature is null:
                    encodedSignature = value;
                    break;
                case "alg" when algorithm is null:
                    algorithm = value;
                    break;
                default:
                    throw new MachineFileException();
            }
        }

        if (fieldCount != 3
            || encodedPayload is null
            || encodedSignature is null
            || algorithm is null)
        {
            throw new MachineFileException();
        }

        return (encodedPayload, encodedSignature, algorithm);
    }

    private static byte[] DecodeCanonicalBase64(string encoded)
    {
        byte[]? decoded = null;
        try
        {
            decoded = Convert.FromBase64String(encoded);
            if (!string.Equals(
                    Convert.ToBase64String(decoded),
                    encoded,
                    StringComparison.Ordinal))
            {
                throw new MachineFileException();
            }

            return decoded;
        }
        catch
        {
            ZeroMemory(decoded);
            throw;
        }
    }

    private static string EncodeRubyBase64(byte[] bytes)
    {
        var encoded = Convert.ToBase64String(bytes);
        var builder = new StringBuilder(encoded.Length + (encoded.Length / 60));
        for (var offset = 0; offset < encoded.Length; offset += 60)
        {
            if (offset > 0)
            {
                builder.Append('\n');
            }

            builder.Append(encoded, offset, Math.Min(60, encoded.Length - offset));
        }

        return builder.ToString();
    }

    private static void ZeroMemory(byte[]? bytes)
    {
        if (bytes is not null)
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
