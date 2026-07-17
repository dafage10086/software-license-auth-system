using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SoftwareLicenseAuth.Client.Tests;

public sealed class SessionStoreTests
{
    private const string TestToken = "TEST_ONLY_SESSION_TOKEN_NOT_A_SECRET";
    private const string ReplacementToken = "TEST_ONLY_REPLACEMENT_SESSION_TOKEN";
    private const string MachineFingerprint =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static readonly DateTimeOffset TestServerTime =
        new(2026, 7, 15, 8, 30, 45, TimeSpan.Zero);
    private static readonly byte[] TestEntropy =
        Encoding.UTF8.GetBytes("SoftwareLicenseAuth.Client.Tests.SessionStore.v3");

    [Fact]
    public void ProductionFactory_UsesFixedV3Path()
    {
        var store = SessionStore.CreateForCurrentUser();
        var expectedPath = Path.Combine(
            AppContext.BaseDirectory,
            "license-data",
            "online_session_v3.dpapi");

        Assert.True(Path.IsPathFullyQualified(store.StoragePath));
        Assert.Equal(Path.GetFullPath(expectedPath), store.StoragePath);
        Assert.NotEqual(
            Path.Combine(AppContext.BaseDirectory, "license-data", "online_license.dat"),
            store.StoragePath);
    }

    [Fact]
    public void ProductionType_ExposesOnlyFixedSessionStoreFactory()
    {
        Assert.All(
            typeof(SessionStore).GetConstructors(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic),
            constructor => Assert.True(constructor.IsPrivate));

        var factory = Assert.Single(
            typeof(SessionStore)
                .GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic),
            method => !method.IsPrivate && method.ReturnType == typeof(SessionStore));
        Assert.Equal("CreateForCurrentUser", factory.Name);
        Assert.Empty(factory.GetParameters());
    }

    [Fact]
    public void ProductionType_HasNoCallableDataProtectionScopeParameter()
    {
        Assert.DoesNotContain(
            typeof(SessionStore)
                .GetMethods(
                    BindingFlags.Instance
                    | BindingFlags.Static
                    | BindingFlags.Public
                    | BindingFlags.NonPublic)
                .Where(method => !method.IsPrivate),
            method => method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(DataProtectionScope)));
        Assert.DoesNotContain(
            typeof(SessionStore)
                .GetConstructors(
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                .Where(constructor => !constructor.IsPrivate),
            constructor => constructor.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(DataProtectionScope)));
    }

    [Fact]
    public void PrivateConstructor_RejectsRelativePath()
    {
        Assert.Throws<ArgumentException>(() => CreateStoreForTesting(
            Path.Combine("relative", "online_session_v3.dpapi"),
            TestEntropy));
    }

    [Fact]
    public void PrivateConstructor_RejectsDirectoryReparsePoint()
    {
        using var directory = new TemporaryDirectory();
        var targetDirectory = directory.GetPath("target-directory");
        var linkedDirectory = directory.GetPath("linked-directory");
        Directory.CreateDirectory(targetDirectory);
        Directory.CreateSymbolicLink(linkedDirectory, targetDirectory);

        Assert.Throws<IOException>(() => CreateStoreForTesting(
            Path.Combine(linkedDirectory, "online_session_v3.dpapi"),
            TestEntropy));
    }

    [Fact]
    public void PrivateConstructor_RejectsTargetReparsePoint()
    {
        using var directory = new TemporaryDirectory();
        var targetPath = directory.GetPath("target.dpapi");
        var linkedPath = directory.GetPath("online_session_v3.dpapi");
        File.WriteAllBytes(targetPath, [1, 2, 3]);
        File.CreateSymbolicLink(linkedPath, targetPath);

        Assert.Throws<IOException>(() =>
            CreateStoreForTesting(linkedPath, TestEntropy));
    }

    [Fact]
    public void SaveAndLoad_RoundTripsAllSevenFields()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        var expected = ValidSession();

        store.Save(expected);
        var actual = Assert.IsType<SessionData>(store.Load());

        Assert.Equal(expected.Username, actual.Username);
        Assert.Equal(expected.UserId, actual.UserId);
        Assert.Equal(expected.SessionToken, actual.SessionToken);
        Assert.Equal(expected.MachineId, actual.MachineId);
        Assert.Equal(expected.LicenseId, actual.LicenseId);
        Assert.Equal(expected.MachineFingerprint, actual.MachineFingerprint);
        Assert.Equal(expected.LastServerTime, actual.LastServerTime);
    }

    [Fact]
    public void Save_EncryptsTokenAndPersistsExactlyTheAllowedFields()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        store.Save(ValidSession());
        var ciphertext = File.ReadAllBytes(store.StoragePath);
        var tokenBytes = Encoding.UTF8.GetBytes(TestToken);
        byte[]? plaintext = null;

        try
        {
            Assert.True(ciphertext.AsSpan().IndexOf(tokenBytes) < 0);
            plaintext = ProtectedData.Unprotect(
                ciphertext,
                TestEntropy,
                DataProtectionScope.CurrentUser);
            using var document = JsonDocument.Parse(plaintext);
            var properties = document.RootElement
                .EnumerateObject()
                .Select(property => property.Name)
                .Order(StringComparer.Ordinal)
                .ToArray();

            Assert.Equal(
                new[]
                {
                    "last_server_time",
                    "license_id",
                    "machine_fingerprint",
                    "machine_id",
                    "session_token",
                    "user_id",
                    "username",
                },
                properties);
            Assert.Equal(TestToken, document.RootElement.GetProperty("session_token").GetString());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tokenBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    [Fact]
    public void Load_WithWrongEntropyRejectsCiphertext()
    {
        using var directory = new TemporaryDirectory();
        var path = directory.GetPath("online_session_v3.dpapi");
        CreateStoreForTesting(path, TestEntropy).Save(ValidSession());
        var wrongEntropy = Encoding.UTF8.GetBytes("SoftwareLicenseAuth.Client.Tests.WrongEntropy.v3");

        try
        {
            var store = CreateStoreForTesting(path, wrongEntropy);
            Assert.Throws<CryptographicException>(() => store.Load());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrongEntropy);
        }
    }

    [Fact]
    public void Load_RejectsCorruptedCiphertext()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        store.Save(ValidSession());
        var ciphertext = File.ReadAllBytes(store.StoragePath);
        ciphertext[ciphertext.Length / 2] ^= 0x5a;
        File.WriteAllBytes(store.StoragePath, ciphertext);

        try
        {
            Assert.Throws<CryptographicException>(() => store.Load());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    [Fact]
    public void Load_RejectsTruncatedCiphertext()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        store.Save(ValidSession());
        var ciphertext = File.ReadAllBytes(store.StoragePath);
        var truncated = ciphertext[..(ciphertext.Length / 2)];
        File.WriteAllBytes(store.StoragePath, truncated);

        try
        {
            Assert.Throws<CryptographicException>(() => store.Load());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(truncated);
        }
    }

    [Fact]
    public void Load_RejectsOversizedCiphertext()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        File.WriteAllBytes(store.StoragePath, new byte[1024 * 1024]);

        Assert.Throws<InvalidDataException>(() => store.Load());
    }

    [Fact]
    public void Load_MissingV3FileReturnsNullWithoutReadingV2OrLegacyCache()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        File.WriteAllText(
            directory.GetPath("online_license.dat"),
            "{\"session_token\":\"LEGACY_TOKEN_MUST_NOT_BE_LOADED\"}");
        File.WriteAllBytes(directory.GetPath("online_session_v2.dpapi"), [1, 2, 3, 4]);

        Assert.Null(store.Load());
    }

    [Fact]
    public void Load_CorruptedV3FileDoesNotFallBackToLegacyCache()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        File.WriteAllText(
            directory.GetPath("online_license.dat"),
            "{\"session_token\":\"LEGACY_TOKEN_MUST_NOT_BE_LOADED\"}");
        File.WriteAllBytes(store.StoragePath, [1, 2, 3, 4]);

        Assert.Throws<CryptographicException>(() => store.Load());
    }

    [Fact]
    public void Clear_RemovesSessionAndIsIdempotent()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);

        store.Clear();
        store.Save(ValidSession());
        Assert.True(File.Exists(store.StoragePath));

        store.Clear();
        store.Clear();

        Assert.False(File.Exists(store.StoragePath));
        Assert.Null(store.Load());
    }

    [Fact]
    public void Save_AtomicallyReplacesExistingSession()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        store.Save(ValidSession());
        var originalCiphertext = File.ReadAllBytes(store.StoragePath);

        store.Save(ValidSession(ReplacementToken));

        var replacementCiphertext = File.ReadAllBytes(store.StoragePath);
        try
        {
            Assert.NotEqual(originalCiphertext, replacementCiphertext);
            Assert.Equal(ReplacementToken, Assert.IsType<SessionData>(store.Load()).SessionToken);
            Assert.Equal(
                new[] { Path.GetFileName(store.StoragePath) },
                Directory.EnumerateFiles(Path.GetDirectoryName(store.StoragePath)!)
                    .Select(Path.GetFileName)
                    .Order(StringComparer.Ordinal)
                    .ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(originalCiphertext);
            CryptographicOperations.ZeroMemory(replacementCiphertext);
        }
    }

    [Fact]
    public void Save_WhenReplacementFailsPreservesOldSessionAndCleansTempFile()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        store.Save(ValidSession());
        var originalCiphertext = File.ReadAllBytes(store.StoragePath);

        using (new FileStream(
            store.StoragePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read))
        {
            var exception = Assert.Throws<IOException>(() =>
                store.Save(ValidSession(ReplacementToken)));
            Assert.DoesNotContain(ReplacementToken, exception.ToString(), StringComparison.Ordinal);
        }

        try
        {
            Assert.Equal(originalCiphertext, File.ReadAllBytes(store.StoragePath));
            Assert.Equal(TestToken, Assert.IsType<SessionData>(store.Load()).SessionToken);
            Assert.Equal(
                new[] { Path.GetFileName(store.StoragePath) },
                Directory.EnumerateFiles(Path.GetDirectoryName(store.StoragePath)!)
                    .Select(Path.GetFileName)
                    .Order(StringComparer.Ordinal)
                    .ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(originalCiphertext);
        }
    }

    [Theory]
    [InlineData("username")]
    [InlineData("user_id")]
    [InlineData("session_token")]
    [InlineData("machine_id")]
    [InlineData("license_id")]
    [InlineData("machine_fingerprint")]
    public void Save_RejectsBlankRequiredString(string field)
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        var session = SessionWithBlankField(field);

        var exception = Assert.Throws<ArgumentException>(() => store.Save(session));

        Assert.DoesNotContain(TestToken, exception.ToString(), StringComparison.Ordinal);
        Assert.False(File.Exists(store.StoragePath));
    }

    [Fact]
    public void Save_RejectsMissingLastServerTime()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        var session = new SessionData(
            "account.name",
            "user-123",
            TestToken,
            "machine-456",
            "license-789",
            MachineFingerprint,
            default);

        var exception = Assert.Throws<ArgumentException>(() => store.Save(session));

        Assert.DoesNotContain(TestToken, exception.ToString(), StringComparison.Ordinal);
        Assert.False(File.Exists(store.StoragePath));
    }

    [Fact]
    public void Load_RejectsEveryMissingRequiredField()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        var requiredFields = new[]
        {
            "username",
            "user_id",
            "session_token",
            "machine_id",
            "license_id",
            "machine_fingerprint",
            "last_server_time",
        };

        foreach (var field in requiredFields)
        {
            var payload = ValidPayload();
            Assert.True(payload.Remove(field));
            WriteProtectedJson(store.StoragePath, JsonSerializer.Serialize(payload), TestEntropy);

            var exception = Record.Exception(() => store.Load());
            Assert.True(
                exception is InvalidDataException,
                $"Missing required field was accepted: {field}");
            Assert.DoesNotContain(TestToken, exception.ToString()!, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Load_RejectsUnknownField()
    {
        using var directory = new TemporaryDirectory();
        var store = CreateStore(directory);
        var payload = ValidPayload();
        payload.Add("password", "TEST_ONLY_PASSWORD_MUST_NOT_BE_STORED");
        WriteProtectedJson(store.StoragePath, JsonSerializer.Serialize(payload), TestEntropy);

        var exception = Assert.Throws<InvalidDataException>(() => store.Load());

        Assert.DoesNotContain(TestToken, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void SessionData_ToStringDoesNotRevealToken()
    {
        var text = ValidSession().ToString();

        Assert.DoesNotContain(TestToken, text, StringComparison.Ordinal);
    }

    private static SessionStore CreateStore(TemporaryDirectory directory)
    {
        return CreateStoreForTesting(
            directory.GetPath("online_session_v3.dpapi"),
            TestEntropy);
    }

    private static SessionStore CreateStoreForTesting(string path, byte[] entropy)
    {
        var constructor = Assert.Single(
            typeof(SessionStore).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic),
            candidate => candidate.GetParameters()
                .Select(parameter => parameter.ParameterType)
                .SequenceEqual([typeof(string), typeof(byte[])]));

        try
        {
            return Assert.IsType<SessionStore>(constructor.Invoke([path, entropy]));
        }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
            throw;
        }
    }

    private static SessionData ValidSession(string token = TestToken)
    {
        return new SessionData(
            "account.name",
            "user-123",
            token,
            "machine-456",
            "license-789",
            MachineFingerprint,
            TestServerTime);
    }

    private static SessionData SessionWithBlankField(string field)
    {
        return new SessionData(
            field == "username" ? " " : "account.name",
            field == "user_id" ? " " : "user-123",
            field == "session_token" ? " " : TestToken,
            field == "machine_id" ? " " : "machine-456",
            field == "license_id" ? " " : "license-789",
            field == "machine_fingerprint" ? " " : MachineFingerprint,
            TestServerTime);
    }

    private static Dictionary<string, object?> ValidPayload()
    {
        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["username"] = "account.name",
            ["user_id"] = "user-123",
            ["session_token"] = TestToken,
            ["machine_id"] = "machine-456",
            ["license_id"] = "license-789",
            ["machine_fingerprint"] = MachineFingerprint,
            ["last_server_time"] = TestServerTime,
        };
    }

    private static void WriteProtectedJson(string path, string json, byte[] entropy)
    {
        var plaintext = Encoding.UTF8.GetBytes(json);
        byte[]? ciphertext = null;
        try
        {
            ciphertext = ProtectedData.Protect(
                plaintext,
                entropy,
                DataProtectionScope.CurrentUser);
            File.WriteAllBytes(path, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (ciphertext is not null)
            {
                CryptographicOperations.ZeroMemory(ciphertext);
            }
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly string _path;

        internal TemporaryDirectory()
        {
            _path = Path.Combine(
                Path.GetTempPath(),
                "SoftwareLicenseAuth.Client.Tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_path);
        }

        internal string GetPath(string name)
        {
            return Path.Combine(_path, name);
        }

        public void Dispose()
        {
            if (Directory.Exists(_path))
            {
                Directory.Delete(_path, recursive: true);
            }
        }
    }
}
