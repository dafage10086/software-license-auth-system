using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NSec.Cryptography;
using Xunit;

namespace SoftwareLicenseAuth.Client.Tests;

public sealed class MachineFileVerifierTests
{
    private const string VerificationFailureMessage = "Machine file verification failed.";
    private const string Header = "-----BEGIN MACHINE FILE-----\n";
    private const string Footer = "-----END MACHINE FILE-----\n";
    private static readonly DateTimeOffset IssuedAt =
        new(2026, 7, 15, 10, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset ExpiresAt = IssuedAt.AddHours(1);
    private static readonly ExpectedMachineClaims Expected = new(
        "account_1",
        "product_1",
        "license_1",
        "machine_1",
        "owner_1",
        "fingerprint_1");

    [Fact]
    public void Verify_AcceptsValidEphemeralEd25519MachineFile()
    {
        using var key = Key.Create(
            SignatureAlgorithm.Ed25519,
            new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport,
            });
        var publicKeyHex = Convert.ToHexString(
            key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        var certificate = CreateCertificate(key);
        var verifier = new MachineFileVerifier(publicKeyHex);

        var result = verifier.Verify(
            certificate,
            Expected,
            IssuedAt,
            ExpiresAt,
            lastServerTime: null);

        Assert.Equal(IssuedAt, result.IssuedAt);
        Assert.Equal(ExpiresAt, result.ExpiresAt);
        Assert.Equal(IssuedAt, result.TrustedServerTime);
    }

    [Fact]
    public void Constructor_RejectsNonRawHexKeyFormatsWithFixedRedactedException()
    {
        var invalidKeys = new string?[]
        {
            null,
            string.Empty,
            new string('a', 63),
            new string('a', 65),
            new string('g', 64),
            Convert.ToBase64String(new byte[32]),
            "-----BEGIN PUBLIC KEY-----\nTEST_ONLY_PUBLIC_KEY_SECRET\n-----END PUBLIC KEY-----",
            Convert.ToHexString(Encoding.ASCII.GetBytes(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")),
        };

        foreach (var invalidKey in invalidKeys)
        {
            var exception = Assert.Throws<MachineFileException>(() =>
                new MachineFileVerifier(invalidKey!));

            Assert.Equal(VerificationFailureMessage, exception.Message);
            Assert.Null(exception.InnerException);
            if (!string.IsNullOrEmpty(invalidKey))
            {
                Assert.DoesNotContain(invalidKey, exception.ToString(), StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Verify_RejectsMachineFileSignedByWrongPublicKey()
    {
        using var signingKey = NewKey();
        using var verifierKey = NewKey();
        var certificate = CreateCertificate(signingKey);
        var verifier = NewVerifier(verifierKey);

        AssertVerificationFailure(() => Verify(verifier, certificate));
    }

    [Fact]
    public void Verify_RejectsBadSixtyFourByteSignature()
    {
        using var key = NewKey();
        var certificate = CreateCertificate(key, signature: new byte[64]);

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData(63)]
    [InlineData(65)]
    public void Verify_RejectsSignatureWithWrongLength(int length)
    {
        using var key = NewKey();
        var certificate = CreateCertificate(key, signature: new byte[length]);

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Fact]
    public void Verify_RejectsSignatureOverLicensePrefix()
    {
        using var key = NewKey();
        var certificate = CreateCertificate(key, signingPrefix: "license");

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("aes-256-gcm+ed25519")]
    [InlineData("base64+rsa-sha256")]
    [InlineData("BASE64+ED25519")]
    [InlineData("Base64+Ed25519")]
    public void Verify_RejectsEncryptedRsaOrMisCasedAlgorithm(string algorithm)
    {
        using var key = NewKey();
        var certificate = CreateCertificate(key, algorithm: algorithm);

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("bom")]
    [InlineData("crlf")]
    [InlineData("prefix-text")]
    [InlineData("suffix-text")]
    [InlineData("header-space")]
    [InlineData("footer-tab")]
    [InlineData("blank-line")]
    [InlineData("body-space")]
    [InlineData("body-tab")]
    [InlineData("sixty-one-columns")]
    public void Verify_RejectsNonCanonicalArmor(string mutation)
    {
        using var key = NewKey();
        var certificate = CreateCertificate(key);
        var malformed = mutation switch
        {
            "bom" => "\uFEFF" + certificate,
            "crlf" => certificate.Replace("\n", "\r\n", StringComparison.Ordinal),
            "prefix-text" => "before\n" + certificate,
            "suffix-text" => certificate + "after\n",
            "header-space" => certificate.Replace(
                Header,
                "-----BEGIN MACHINE FILE----- \n",
                StringComparison.Ordinal),
            "footer-tab" => certificate.Replace(
                Footer,
                "-----END MACHINE FILE-----\t\n",
                StringComparison.Ordinal),
            "blank-line" => certificate.Insert(Header.Length, "\n"),
            "body-space" => certificate.Insert(Header.Length + 1, " "),
            "body-tab" => certificate.Insert(Header.Length + 1, "\t"),
            "sixty-one-columns" => ArmorEncodedEnvelope(
                ExtractEncodedEnvelope(certificate),
                lineLength: 61),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

        AssertVerificationFailure(() => Verify(NewVerifier(key), malformed));
    }

    [Fact]
    public void Verify_RejectsManyShortArmorLinesWithoutMemoryAmplification()
    {
        const int ShortLineCount = 300_000;
        const long AllocationLimitBytes = 1024 * 1024;
        using var key = NewKey();
        var verifier = NewVerifier(key);
        var shortLines = string.Concat(Enumerable.Repeat("A\n", ShortLineCount));
        var certificate = Header + shortLines + Footer;
        Assert.Equal(ShortLineCount, shortLines.Count(character => character == '\n'));
        Assert.True(Encoding.UTF8.GetByteCount(certificate) < 1024 * 1024);
        AssertVerificationFailure(() => Verify(verifier, Header + "A\nA\n" + Footer));

        var before = GC.GetAllocatedBytesForCurrentThread();
        var exception = Record.Exception(() => Verify(verifier, certificate));
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - before;

        Console.WriteLine($"Verification allocated {allocatedBytes} bytes.");
        Assert.IsType<MachineFileException>(exception);
        Assert.True(
            allocatedBytes < AllocationLimitBytes,
            $"Verification allocated {allocatedBytes} bytes; limit is {AllocationLimitBytes} bytes.");
    }

    [Fact]
    public void Verify_RejectsCertificateLargerThanOneMiBUtf8()
    {
        using var key = NewKey();
        var oversized = Header + new string('A', (1024 * 1024) + 1) + "\n" + Footer;

        Assert.True(Encoding.UTF8.GetByteCount(oversized) > 1024 * 1024);
        AssertVerificationFailure(() => Verify(NewVerifier(key), oversized));
    }

    [Fact]
    public void Verify_RejectsOuterBase64WithInvalidCharacter()
    {
        using var key = NewKey();
        var encoded = ExtractEncodedEnvelope(CreateCertificate(key));
        var malformed = ArmorEncodedEnvelope("*" + encoded[1..]);

        AssertVerificationFailure(() => Verify(NewVerifier(key), malformed));
    }

    [Fact]
    public void Verify_RejectsEquivalentButNonCanonicalOuterBase64()
    {
        using var key = NewKey();
        var envelopeBytes = ExtractEnvelopeBytes(CreateCertificate(key));
        envelopeBytes = AddJsonSpacesUntilBase64HasPadding(envelopeBytes);
        var canonical = Convert.ToBase64String(envelopeBytes);
        var nonCanonical = MakeEquivalentNonCanonicalBase64(canonical);
        Assert.Equal(envelopeBytes, Convert.FromBase64String(nonCanonical));

        AssertVerificationFailure(() =>
            Verify(NewVerifier(key), ArmorEncodedEnvelope(nonCanonical)));
    }

    [Fact]
    public void Verify_RejectsEnvelopeThatIsNotStrictUtf8()
    {
        using var key = NewKey();
        var malformed = ArmorEnvelopeBytes([0x7b, 0x22, 0xc3, 0x28, 0x22, 0x7d]);

        AssertVerificationFailure(() => Verify(NewVerifier(key), malformed));
    }

    [Fact]
    public void Verify_RejectsInvalidEnvelopeJson()
    {
        using var key = NewKey();
        var malformed = ArmorEnvelopeBytes(Encoding.UTF8.GetBytes("{"));

        AssertVerificationFailure(() => Verify(NewVerifier(key), malformed));
    }

    [Theory]
    [InlineData("enc")]
    [InlineData("sig")]
    [InlineData("alg")]
    public void Verify_RejectsDuplicateEnvelopeField(string field)
    {
        using var key = NewKey();
        var certificate = CreateCertificate(
            key,
            envelopeFactory: (enc, sig, alg) => field switch
            {
                "enc" => $"{{\"enc\":{Quote(enc)},\"enc\":{Quote(enc)},\"sig\":{Quote(sig)},\"alg\":{Quote(alg)}}}",
                "sig" => $"{{\"enc\":{Quote(enc)},\"sig\":{Quote(sig)},\"sig\":{Quote(sig)},\"alg\":{Quote(alg)}}}",
                "alg" => $"{{\"enc\":{Quote(enc)},\"sig\":{Quote(sig)},\"alg\":{Quote(alg)},\"alg\":{Quote(alg)}}}",
                _ => throw new ArgumentOutOfRangeException(nameof(field)),
            });

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Fact]
    public void Verify_RejectsUnknownEnvelopeField()
    {
        using var key = NewKey();
        var certificate = CreateCertificate(
            key,
            envelopeFactory: (enc, sig, alg) =>
                $"{{\"enc\":{Quote(enc)},\"sig\":{Quote(sig)},\"alg\":{Quote(alg)},\"unknown\":\"TEST_ONLY_ENVELOPE_SECRET\"}}");

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("enc")]
    [InlineData("sig")]
    [InlineData("alg")]
    public void Verify_RejectsNonStringEnvelopeField(string field)
    {
        using var key = NewKey();
        var certificate = CreateCertificate(
            key,
            envelopeFactory: (enc, sig, alg) =>
                $"{{\"enc\":{(field == "enc" ? "null" : Quote(enc))},"
                + $"\"sig\":{(field == "sig" ? "123" : Quote(sig))},"
                + $"\"alg\":{(field == "alg" ? "{}" : Quote(alg))}}}");

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("enc")]
    [InlineData("sig")]
    [InlineData("alg")]
    public void Verify_RejectsEmptyEnvelopeField(string field)
    {
        using var key = NewKey();
        var certificate = CreateCertificate(
            key,
            algorithm: field == "alg" ? string.Empty : "base64+ed25519",
            encodedPayload: field == "enc" ? string.Empty : null,
            encodedSignature: field == "sig" ? string.Empty : null);

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("whitespace")]
    [InlineData("missing-padding")]
    [InlineData("noncanonical-pad-bits")]
    public void Verify_RejectsNonCanonicalInnerPayloadBase64(string mutation)
    {
        using var key = NewKey();
        var payloadBytes = AddJsonSpacesUntilBase64HasPadding(CreateValidPayloadBytes());
        var certificate = CreateCertificate(
            key,
            payloadBytes: payloadBytes,
            encodedPayloadTransform: encoded => mutation switch
            {
                "whitespace" => encoded.Insert(4, " "),
                "missing-padding" => encoded.TrimEnd('='),
                "noncanonical-pad-bits" => MakeEquivalentNonCanonicalBase64(encoded),
                _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
            });

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("whitespace")]
    [InlineData("missing-padding")]
    [InlineData("noncanonical-pad-bits")]
    public void Verify_RejectsNonCanonicalSignatureBase64(string mutation)
    {
        using var key = NewKey();
        var certificate = CreateCertificate(
            key,
            encodedSignatureTransform: encoded => mutation switch
            {
                "whitespace" => encoded.Insert(4, "\n"),
                "missing-padding" => encoded.TrimEnd('='),
                "noncanonical-pad-bits" => MakeEquivalentNonCanonicalBase64(encoded),
                _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
            });

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Fact]
    public void Verify_RejectsPayloadThatIsNotStrictUtf8()
    {
        using var key = NewKey();
        var certificate = CreateCertificate(
            key,
            payloadBytes: [0x7b, 0x22, 0xc3, 0x28, 0x22, 0x7d]);

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Fact]
    public void Verify_RejectsInvalidPayloadJson()
    {
        using var key = NewKey();
        var certificate = CreateCertificate(
            key,
            payloadBytes: Encoding.UTF8.GetBytes("{"));

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("root")]
    [InlineData("meta")]
    [InlineData("data")]
    [InlineData("attributes")]
    [InlineData("relationships")]
    [InlineData("relationship")]
    [InlineData("linkage")]
    [InlineData("included")]
    public void Verify_RejectsDuplicateFieldInAnySignedPayloadObject(string location)
    {
        using var key = NewKey();
        var json = Encoding.UTF8.GetString(CreateValidPayloadBytes());
        var duplicateJson = location switch
        {
            "root" => json.Insert(1, "\"meta\":{},"),
            "meta" => json.Replace(
                "\"meta\":{\"issued\":",
                "\"meta\":{\"issued\":\"2000-01-01T00:00:00.000Z\",\"issued\":",
                StringComparison.Ordinal),
            "data" => json.Replace(
                "\"data\":{\"type\":",
                "\"data\":{\"type\":\"wrong\",\"type\":",
                StringComparison.Ordinal),
            "attributes" => json.Replace(
                "\"attributes\":{\"fingerprint\":",
                "\"attributes\":{\"fingerprint\":\"wrong\",\"fingerprint\":",
                StringComparison.Ordinal),
            "relationships" => json.Replace(
                "\"relationships\":{\"account\":",
                "\"relationships\":{\"account\":{\"data\":null},\"account\":",
                StringComparison.Ordinal),
            "relationship" => json.Replace(
                "\"account\":{\"data\":",
                "\"account\":{\"data\":null,\"data\":",
                StringComparison.Ordinal),
            "linkage" => json.Replace(
                "\"data\":{\"type\":\"accounts\"",
                "\"data\":{\"type\":\"wrong\",\"type\":\"accounts\"",
                StringComparison.Ordinal),
            "included" => json.Insert(1, "\"included\":[{\"x\":1,\"x\":1}],"),
            _ => throw new ArgumentOutOfRangeException(nameof(location)),
        };
        Assert.NotEqual(json, duplicateJson);
        var certificate = CreateCertificate(
            key,
            payloadBytes: Encoding.UTF8.GetBytes(duplicateJson));

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Fact]
    public void Verify_AcceptsUnknownSignedAttributesLinksRelationshipsAndIncluded()
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        Data(payload)["links"] = new JsonObject
        {
            ["self"] = "https://signed.example.test/machines/machine_1",
        };
        Attributes(payload)["cores"] = 8;
        Attributes(payload)["metadata"] = new JsonObject
        {
            ["channel"] = "stable",
        };
        Relationships(payload)["components"] = new JsonObject
        {
            ["data"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "components",
                    ["id"] = "component_1",
                },
            },
            ["links"] = new JsonObject
            {
                ["related"] = "https://signed.example.test/components",
            },
        };
        payload["included"] = new JsonArray
        {
            new JsonObject
            {
                ["type"] = "components",
                ["id"] = "component_1",
                ["attributes"] = new JsonObject
                {
                    ["name"] = "signed extension",
                },
            },
        };
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        var result = Verify(NewVerifier(key), certificate);

        Assert.Equal(ExpiresAt, result.ExpiresAt);
    }

    [Theory]
    [InlineData("machine")]
    [InlineData("account")]
    [InlineData("product")]
    [InlineData("license")]
    [InlineData("owner")]
    [InlineData("fingerprint")]
    public void Verify_RejectsWrongSignedClaim(string claim)
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        switch (claim)
        {
            case "machine":
                Data(payload)["id"] = "wrong_machine";
                break;
            case "fingerprint":
                Attributes(payload)["fingerprint"] = "wrong_fingerprint";
                break;
            default:
                Linkage(payload, claim)["id"] = "wrong_" + claim;
                break;
        }

        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Fact]
    public void Verify_RejectsWrongMachineResourceType()
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        Data(payload)["type"] = "licenses";
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("string")]
    [InlineData("3599")]
    [InlineData("3601")]
    [InlineData("3600.0")]
    public void Verify_RejectsTtlThatIsNotJsonIntegerThreeThousandSixHundred(string value)
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        payload["meta"]!["ttl"] = value switch
        {
            "null" => null,
            "string" => JsonValue.Create("3600"),
            _ => JsonNode.Parse(value),
        };
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("issued", "2026-07-15T10:00:00+00:00")]
    [InlineData("expiry", "2026-07-15T11:00:00+00:00")]
    [InlineData("issued", "2026-07-15T10:00:00.000z")]
    [InlineData("expiry", "2026-07-15 11:00:00.000Z")]
    public void Verify_RejectsSignedTimestampThatIsNotExactUtcZIso8601(
        string field,
        string value)
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        payload["meta"]![field] = value;
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("account", "wrong_accounts")]
    [InlineData("product", "wrong_products")]
    [InlineData("license", "wrong_licenses")]
    [InlineData("owner", "wrong_users")]
    public void Verify_RejectsWrongRelationshipType(string relationship, string wrongType)
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        Linkage(payload, relationship)["type"] = wrongType;
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("array")]
    [InlineData("string")]
    public void Verify_RejectsRelationshipDataThatIsNotSingleObject(string kind)
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        Relationships(payload)["account"]!["data"] = kind switch
        {
            "null" => null,
            "array" => new JsonArray(),
            "string" => JsonValue.Create("accounts/account_1"),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData("root.meta")]
    [InlineData("root.data")]
    [InlineData("meta.issued")]
    [InlineData("meta.expiry")]
    [InlineData("meta.ttl")]
    [InlineData("data.type")]
    [InlineData("data.id")]
    [InlineData("data.attributes")]
    [InlineData("attributes.fingerprint")]
    [InlineData("data.relationships")]
    [InlineData("relationships.account")]
    [InlineData("relationships.product")]
    [InlineData("relationships.license")]
    [InlineData("relationships.owner")]
    [InlineData("account.data")]
    [InlineData("account.type")]
    [InlineData("account.id")]
    public void Verify_RejectsMissingRequiredSignedField(string field)
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        var removed = field switch
        {
            "root.meta" => payload.Remove("meta"),
            "root.data" => payload.Remove("data"),
            "meta.issued" => payload["meta"]!.AsObject().Remove("issued"),
            "meta.expiry" => payload["meta"]!.AsObject().Remove("expiry"),
            "meta.ttl" => payload["meta"]!.AsObject().Remove("ttl"),
            "data.type" => Data(payload).Remove("type"),
            "data.id" => Data(payload).Remove("id"),
            "data.attributes" => Data(payload).Remove("attributes"),
            "attributes.fingerprint" => Attributes(payload).Remove("fingerprint"),
            "data.relationships" => Data(payload).Remove("relationships"),
            "relationships.account" => Relationships(payload).Remove("account"),
            "relationships.product" => Relationships(payload).Remove("product"),
            "relationships.license" => Relationships(payload).Remove("license"),
            "relationships.owner" => Relationships(payload).Remove("owner"),
            "account.data" => Relationships(payload)["account"]!.AsObject().Remove("data"),
            "account.type" => Linkage(payload, "account").Remove("type"),
            "account.id" => Linkage(payload, "account").Remove("id"),
            _ => throw new ArgumentOutOfRangeException(nameof(field)),
        };
        Assert.True(removed);
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(NewVerifier(key), certificate));
    }

    [Theory]
    [InlineData(3599)]
    [InlineData(3601)]
    public void Verify_RejectsSignedExpiryIntervalThatIsNotExactlyOneHour(int seconds)
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        SetSignedTimes(payload, IssuedAt, IssuedAt.AddSeconds(seconds));
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(
            NewVerifier(key),
            certificate,
            envelopeExpiry: IssuedAt.AddSeconds(seconds)));
    }

    [Theory]
    [InlineData(-360)]
    [InlineData(60)]
    public void Verify_AcceptsIssuedAtServerWindowBoundary(int issuedOffsetSeconds)
    {
        using var key = NewKey();
        var serverTime = IssuedAt;
        var signedIssuedAt = serverTime.AddSeconds(issuedOffsetSeconds);
        var signedExpiry = signedIssuedAt.AddHours(1);
        var payload = CreateValidPayload();
        SetSignedTimes(payload, signedIssuedAt, signedExpiry);
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        var result = Verify(
            NewVerifier(key),
            certificate,
            serverTime: serverTime,
            envelopeExpiry: signedExpiry);

        Assert.Equal(
            serverTime > signedIssuedAt ? serverTime : signedIssuedAt,
            result.TrustedServerTime);
    }

    [Theory]
    [InlineData(-361)]
    [InlineData(61)]
    public void Verify_RejectsIssuedAtOutsideServerWindow(int issuedOffsetSeconds)
    {
        using var key = NewKey();
        var serverTime = IssuedAt;
        var signedIssuedAt = serverTime.AddSeconds(issuedOffsetSeconds);
        var signedExpiry = signedIssuedAt.AddHours(1);
        var payload = CreateValidPayload();
        SetSignedTimes(payload, signedIssuedAt, signedExpiry);
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(
            NewVerifier(key),
            certificate,
            serverTime: serverTime,
            envelopeExpiry: signedExpiry));
    }

    [Fact]
    public void Verify_AcceptsOuterExpiryWithinSameUnixSecondAsSignedExpiry()
    {
        using var key = NewKey();
        var signedIssuedAt = IssuedAt.AddMilliseconds(456);
        var signedExpiry = signedIssuedAt.AddHours(1);
        var outerExpiry = DateTimeOffset.FromUnixTimeSeconds(signedExpiry.ToUnixTimeSeconds());
        var payload = CreateValidPayload();
        SetSignedTimes(payload, signedIssuedAt, signedExpiry);
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        var result = Verify(
            NewVerifier(key),
            certificate,
            serverTime: signedIssuedAt,
            envelopeExpiry: outerExpiry);

        Assert.Equal(signedExpiry, result.ExpiresAt);
    }

    [Fact]
    public void Verify_RejectsOuterExpiryLaterThanSignedExpiryWithinSameUnixSecond()
    {
        using var key = NewKey();
        var signedIssuedAt = IssuedAt.AddMilliseconds(100);
        var signedExpiry = signedIssuedAt.AddHours(1);
        var outerExpiry = signedExpiry.AddMilliseconds(100);
        Assert.Equal(signedExpiry.ToUnixTimeSeconds(), outerExpiry.ToUnixTimeSeconds());
        Assert.True(outerExpiry > signedExpiry);
        var payload = CreateValidPayload();
        SetSignedTimes(payload, signedIssuedAt, signedExpiry);
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(
            NewVerifier(key),
            certificate,
            serverTime: signedIssuedAt,
            envelopeExpiry: outerExpiry));
    }

    [Fact]
    public void Verify_RejectsOuterExpiryInDifferentUnixSecond()
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(
            NewVerifier(key),
            certificate,
            envelopeExpiry: ExpiresAt.AddSeconds(1)));
    }

    [Fact]
    public void Verify_RejectsWhenTrustedAtIsNotBeforeExpiry()
    {
        using var key = NewKey();
        var payload = CreateValidPayload();
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        AssertVerificationFailure(() => Verify(
            NewVerifier(key),
            certificate,
            serverTime: ExpiresAt,
            envelopeExpiry: ExpiresAt));
    }

    [Fact]
    public void Verify_AcceptsTrustedAtEqualToPersistedLastServerTime()
    {
        using var key = NewKey();
        var certificate = CreateCertificate(key);

        var result = Verify(
            NewVerifier(key),
            certificate,
            lastServerTime: IssuedAt);

        Assert.Equal(IssuedAt, result.TrustedServerTime);
    }

    [Fact]
    public void Verify_RejectsRollbackBehindPersistedLastServerTime()
    {
        using var key = NewKey();
        var certificate = CreateCertificate(key);

        AssertVerificationFailure(() => Verify(
            NewVerifier(key),
            certificate,
            lastServerTime: IssuedAt.AddTicks(1)));
    }

    [Fact]
    public void Verify_UsesSignedExpiryAndPassedServerTimeInsteadOfLocalClockOrTtlExtension()
    {
        using var key = NewKey();
        var serverTime = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var signedIssuedAt = serverTime.AddSeconds(30).AddMilliseconds(321);
        var signedExpiry = signedIssuedAt.AddHours(1);
        var payload = CreateValidPayload();
        SetSignedTimes(payload, signedIssuedAt, signedExpiry);
        var certificate = CreateCertificate(key, payloadBytes: PayloadBytes(payload));

        var result = Verify(
            NewVerifier(key),
            certificate,
            serverTime: serverTime,
            envelopeExpiry: DateTimeOffset.FromUnixTimeSeconds(
                signedExpiry.ToUnixTimeSeconds()));

        Assert.Equal(signedIssuedAt, result.TrustedServerTime);
        Assert.Equal(signedExpiry, result.ExpiresAt);
        Assert.NotEqual(serverTime.AddHours(1), result.ExpiresAt);
        Assert.True(result.ExpiresAt < new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public void Verify_AcceptsLowercaseHexPublicKeyAndReorderedEnvelopeFields()
    {
        using var key = NewKey();
        var publicKeyHex = Convert.ToHexString(
            key.PublicKey.Export(KeyBlobFormat.RawPublicKey)).ToLowerInvariant();
        var certificate = CreateCertificate(
            key,
            envelopeFactory: (enc, sig, alg) =>
                $"{{\"alg\":{Quote(alg)},\"sig\":{Quote(sig)},\"enc\":{Quote(enc)}}}");

        var result = Verify(new MachineFileVerifier(publicKeyHex), certificate);

        Assert.Equal(ExpiresAt, result.ExpiresAt);
    }

    [Fact]
    public void ExceptionsAndToStringNeverRevealFixtureSecrets()
    {
        using var key = NewKey();
        var publicKeyHex = Convert.ToHexString(
            key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        var verifier = new MachineFileVerifier(publicKeyHex);
        var certificate = CreateCertificate(key, signature: new byte[64]);
        var envelopeBytes = ExtractEnvelopeBytes(certificate);
        using var envelope = JsonDocument.Parse(envelopeBytes);
        var encodedPayload = envelope.RootElement.GetProperty("enc").GetString()!;
        var encodedSignature = envelope.RootElement.GetProperty("sig").GetString()!;
        var payloadJson = Encoding.UTF8.GetString(
            Convert.FromBase64String(encodedPayload));
        var exception = Assert.Throws<MachineFileException>(() =>
            Verify(verifier, certificate));
        var texts = new[]
        {
            exception.ToString(),
            verifier.ToString()!,
            Expected.ToString(),
        };
        var secrets = new[]
        {
            certificate,
            encodedPayload,
            encodedSignature,
            payloadJson,
            publicKeyHex,
            Expected.AccountId,
            Expected.ProductId,
            Expected.LicenseId,
            Expected.MachineId,
            Expected.OwnerId,
            Expected.Fingerprint,
        };

        Assert.Equal(VerificationFailureMessage, exception.Message);
        Assert.Null(exception.InnerException);
        foreach (var text in texts)
        {
            foreach (var secret in secrets)
            {
                Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
            }
        }
    }

    private static Key NewKey()
    {
        return Key.Create(
            SignatureAlgorithm.Ed25519,
            new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport,
            });
    }

    private static MachineFileVerifier NewVerifier(Key key)
    {
        return new MachineFileVerifier(Convert.ToHexString(
            key.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
    }

    private static VerifiedMachineFile Verify(
        MachineFileVerifier verifier,
        string certificate,
        ExpectedMachineClaims? expected = null,
        DateTimeOffset? serverTime = null,
        DateTimeOffset? envelopeExpiry = null,
        DateTimeOffset? lastServerTime = null)
    {
        return verifier.Verify(
            certificate,
            expected ?? Expected,
            serverTime ?? IssuedAt,
            envelopeExpiry ?? ExpiresAt,
            lastServerTime);
    }

    private static void AssertVerificationFailure(Action action)
    {
        var exception = Assert.Throws<MachineFileException>(action);
        Assert.Equal(VerificationFailureMessage, exception.Message);
        Assert.Null(exception.InnerException);
    }

    private static string CreateCertificate(
        Key key,
        string algorithm = "base64+ed25519",
        string signingPrefix = "machine",
        byte[]? signature = null,
        byte[]? payloadBytes = null,
        string? encodedPayload = null,
        string? encodedSignature = null,
        Func<string, string>? encodedPayloadTransform = null,
        Func<string, string>? encodedSignatureTransform = null,
        Func<string, string, string, string>? envelopeFactory = null)
    {
        payloadBytes ??= CreateValidPayloadBytes();
        encodedPayload ??= Convert.ToBase64String(payloadBytes);
        if (encodedPayloadTransform is not null)
        {
            encodedPayload = encodedPayloadTransform(encodedPayload);
        }

        var signingData = Encoding.UTF8.GetBytes(signingPrefix + "/" + encodedPayload);
        signature ??= SignatureAlgorithm.Ed25519.Sign(key, signingData);
        encodedSignature ??= Convert.ToBase64String(signature);
        if (encodedSignatureTransform is not null)
        {
            encodedSignature = encodedSignatureTransform(encodedSignature);
        }

        var envelopeJson = envelopeFactory?.Invoke(
            encodedPayload,
            encodedSignature,
            algorithm)
            ?? JsonSerializer.Serialize(new
            {
                enc = encodedPayload,
                sig = encodedSignature,
                alg = algorithm,
            });

        return ArmorEnvelopeBytes(Encoding.UTF8.GetBytes(envelopeJson));
    }

    private static byte[] CreateValidPayloadBytes()
    {
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            meta = new
            {
                issued = IssuedAt.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"),
                expiry = ExpiresAt.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"),
                ttl = 3600,
            },
            data = new
            {
                type = "machines",
                id = Expected.MachineId,
                attributes = new
                {
                    fingerprint = Expected.Fingerprint,
                },
                relationships = new
                {
                    account = Relationship("accounts", Expected.AccountId),
                    product = Relationship("products", Expected.ProductId),
                    license = Relationship("licenses", Expected.LicenseId),
                    owner = Relationship("users", Expected.OwnerId),
                },
            },
        });
    }

    private static object Relationship(string type, string id)
    {
        return new { data = new { type, id } };
    }

    private static JsonObject CreateValidPayload()
    {
        return JsonNode.Parse(CreateValidPayloadBytes())!.AsObject();
    }

    private static JsonObject Data(JsonObject payload)
    {
        return payload["data"]!.AsObject();
    }

    private static JsonObject Attributes(JsonObject payload)
    {
        return Data(payload)["attributes"]!.AsObject();
    }

    private static JsonObject Relationships(JsonObject payload)
    {
        return Data(payload)["relationships"]!.AsObject();
    }

    private static JsonObject Linkage(JsonObject payload, string relationship)
    {
        return Relationships(payload)[relationship]!["data"]!.AsObject();
    }

    private static byte[] PayloadBytes(JsonNode payload)
    {
        return Encoding.UTF8.GetBytes(payload.ToJsonString());
    }

    private static void SetSignedTimes(
        JsonObject payload,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        payload["meta"]!["issued"] = FormatSignedTime(issuedAt);
        payload["meta"]!["expiry"] = FormatSignedTime(expiresAt);
    }

    private static string FormatSignedTime(DateTimeOffset value)
    {
        return value.ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'");
    }

    private static string RubyEncode64(byte[] value)
    {
        var encoded = Convert.ToBase64String(value);
        return string.Join(
            "\n",
            Enumerable.Range(0, (encoded.Length + 59) / 60)
                .Select(index => encoded.Substring(
                    index * 60,
                    Math.Min(60, encoded.Length - (index * 60)))));
    }

    private static string ArmorEnvelopeBytes(byte[] envelopeBytes)
    {
        return ArmorEncodedEnvelope(Convert.ToBase64String(envelopeBytes));
    }

    private static string ArmorEncodedEnvelope(string encodedEnvelope, int lineLength = 60)
    {
        var lines = Enumerable.Range(
                0,
                (encodedEnvelope.Length + lineLength - 1) / lineLength)
            .Select(index => encodedEnvelope.Substring(
                index * lineLength,
                Math.Min(lineLength, encodedEnvelope.Length - (index * lineLength))));
        return Header + string.Join("\n", lines) + "\n" + Footer;
    }

    private static string ExtractEncodedEnvelope(string certificate)
    {
        return certificate[Header.Length..^Footer.Length]
            .Replace("\n", string.Empty, StringComparison.Ordinal);
    }

    private static byte[] ExtractEnvelopeBytes(string certificate)
    {
        return Convert.FromBase64String(ExtractEncodedEnvelope(certificate));
    }

    private static byte[] AddJsonSpacesUntilBase64HasPadding(byte[] bytes)
    {
        var result = bytes;
        while (!Convert.ToBase64String(result).EndsWith("=", StringComparison.Ordinal))
        {
            result = [.. result, (byte)' '];
        }

        return result;
    }

    private static string MakeEquivalentNonCanonicalBase64(string canonical)
    {
        const string alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var paddingLength = canonical.EndsWith("==", StringComparison.Ordinal) ? 2 : 1;
        Assert.EndsWith("=", canonical, StringComparison.Ordinal);
        var index = canonical.Length - paddingLength - 1;
        var value = alphabet.IndexOf(canonical[index], StringComparison.Ordinal);
        Assert.True(value >= 0 && value < alphabet.Length - 1);
        return canonical[..index] + alphabet[value + 1] + canonical[(index + 1)..];
    }

    private static string Quote(string value)
    {
        return JsonSerializer.Serialize(value);
    }
}
