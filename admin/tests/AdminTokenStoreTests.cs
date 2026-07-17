using System.Reflection;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SoftwareLicenseAuth.Admin.Tests;

public sealed class AdminTokenStoreTests
{
    private const string TestToken = "TEST_ONLY_NOT_A_REAL_ADMIN_TOKEN";
    private const string ReplacementToken = "TEST_ONLY_REPLACEMENT_ADMIN_TOKEN";
    private static readonly byte[] ExpectedProductEntropy =
        Encoding.UTF8.GetBytes("SoftwareLicenseAuth.Admin.AdminToken.v1");

    [Fact]
    public void ProductionFactory_UsesOnlyFixedCurrentUserLocalAppDataPath()
    {
        var store = AdminTokenStore.CreateForCurrentUser();
        var expectedPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SoftwareLicenseAuth",
            "Admin",
            "admin-token.dpapi");

        Assert.True(Path.IsPathFullyQualified(store.StoragePath));
        Assert.Equal(Path.GetFullPath(expectedPath), store.StoragePath);
        Assert.DoesNotContain(
            typeof(AdminTokenStore).GetConstructors(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic),
            constructor => !constructor.IsPrivate);
        Assert.All(typeof(AdminTokenStore)
            .GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(method => method.ReturnType == typeof(AdminTokenStore)
                && method.GetParameters().Any(parameter => parameter.ParameterType == typeof(string))),
            method => Assert.Equal("CreateForTesting", method.Name));
    }

    [Fact]
    public void TestFactory_RejectsRelativePath()
    {
        Assert.Throws<ArgumentException>(() =>
            AdminTokenStore.CreateForTesting(Path.Combine("relative", "admin-token.dpapi")));
    }

    [Fact]
    public void TestFactory_RejectsDirectoryReparsePoint()
    {
        using var directory = new TemporaryDirectory();
        var targetDirectory = directory.GetPath("target-directory");
        var linkedDirectory = directory.GetPath("linked-directory");
        Directory.CreateDirectory(targetDirectory);
        Directory.CreateSymbolicLink(linkedDirectory, targetDirectory);

        Assert.Throws<IOException>(() => AdminTokenStore.CreateForTesting(
            Path.Combine(linkedDirectory, "admin-token.dpapi")));
    }

    [Fact]
    public void TestFactory_RejectsFileReparsePoint()
    {
        using var directory = new TemporaryDirectory();
        var targetFile = directory.WriteFile("target.dpapi", "test-only-data");
        var linkedFile = directory.GetPath("linked.dpapi");
        File.CreateSymbolicLink(linkedFile, targetFile);

        Assert.Throws<IOException>(() =>
            AdminTokenStore.CreateForTesting(linkedFile));
    }

    [Fact]
    public void Save_WritesSeparateCiphertextDecryptableWithFixedLiteralEntropy()
    {
        using var directory = new TemporaryDirectory();
        var configPath = directory.WriteFile("admin-config.json", "{\"admin_url\":\"https://example.invalid\"}");
        var originalConfig = File.ReadAllBytes(configPath);
        var tokenPath = directory.GetPath("admin-token.dpapi");

        AdminTokenStore.CreateForTesting(tokenPath).Save(TestToken);

        Assert.True(File.Exists(tokenPath));
        Assert.Equal(originalConfig, File.ReadAllBytes(configPath));
        var ciphertext = File.ReadAllBytes(tokenPath);
        var plaintext = Encoding.UTF8.GetBytes(TestToken);
        Assert.False(ciphertext.AsSpan().IndexOf(plaintext) >= 0);
        Assert.Equal(TestToken, IndependentlyDecrypt(ciphertext));
    }

    [Fact]
    public void Save_WhenCommitFailsPreservesOldCiphertextAndRemovesTempFile()
    {
        using var directory = new TemporaryDirectory();
        var tokenPath = directory.GetPath("admin-token.dpapi");
        AdminTokenStore.CreateForTesting(tokenPath).Save(TestToken);
        var originalCiphertext = File.ReadAllBytes(tokenPath);
        var beforeCommitReached = false;
        var failingStore = AdminTokenStore.CreateForTesting(
            tokenPath,
            beforeCommit: tempPath =>
            {
                beforeCommitReached = true;
                Assert.Equal(
                    Path.GetDirectoryName(tokenPath),
                    Path.GetDirectoryName(tempPath));
                Assert.Equal(ReplacementToken, IndependentlyDecrypt(File.ReadAllBytes(tempPath)));
                throw new IOException("Injected commit failure.");
            });

        Assert.Throws<IOException>(() => failingStore.Save(ReplacementToken));

        Assert.True(beforeCommitReached);
        Assert.Equal(originalCiphertext, File.ReadAllBytes(tokenPath));
        Assert.Equal(TestToken, IndependentlyDecrypt(File.ReadAllBytes(tokenPath)));
        var remainingFiles = Directory.EnumerateFiles(Path.GetDirectoryName(tokenPath)!)
            .Select(path => Path.GetFileName(path)!)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal([Path.GetFileName(tokenPath)!], remainingFiles);
    }

    [Fact]
    public void Save_WhenWindowsReplaceIsBlockedPreservesOldCiphertextAndRemovesTempFile()
    {
        using var directory = new TemporaryDirectory();
        var tokenPath = directory.GetPath("admin-token.dpapi");
        var store = AdminTokenStore.CreateForTesting(tokenPath);
        store.Save(TestToken);
        var originalCiphertext = File.ReadAllBytes(tokenPath);

        using (var targetLock = new FileStream(
            tokenPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read))
        {
            Assert.Throws<IOException>(() => store.Save(ReplacementToken));
        }

        Assert.Equal(originalCiphertext, File.ReadAllBytes(tokenPath));
        Assert.Equal(TestToken, IndependentlyDecrypt(File.ReadAllBytes(tokenPath)));
        var remainingFiles = Directory.EnumerateFiles(Path.GetDirectoryName(tokenPath)!)
            .Select(path => Path.GetFileName(path)!)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal([Path.GetFileName(tokenPath)!], remainingFiles);
    }

    [Fact]
    public void Save_WhenTempCleanupRemainsBlockedReportsVisibleCleanupFailure()
    {
        using var directory = new TemporaryDirectory();
        var tokenPath = directory.GetPath("admin-token.dpapi");
        AdminTokenStore.CreateForTesting(tokenPath).Save(TestToken);
        var originalCiphertext = File.ReadAllBytes(tokenPath);
        FileStream? tempLock = null;
        string? tempPath = null;
        var store = AdminTokenStore.CreateForTesting(
            tokenPath,
            beforeCommit: path =>
            {
                tempPath = path;
                tempLock = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read);
                throw new IOException("Injected commit failure.");
            });

        try
        {
            var stopwatch = Stopwatch.StartNew();
            var exception = Record.Exception(() => store.Save(ReplacementToken));
            stopwatch.Stop();

            var aggregate = Assert.IsType<AggregateException>(exception);
            Assert.Contains(aggregate.InnerExceptions, error =>
                error is IOException && error.Message == "Injected commit failure.");
            Assert.Contains(aggregate.InnerExceptions, error =>
                error is IOException
                && error.Message.Contains("cleanup", StringComparison.OrdinalIgnoreCase));
            Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5));
            Assert.NotNull(tempPath);
            Assert.True(File.Exists(tempPath));
            Assert.Equal(originalCiphertext, File.ReadAllBytes(tokenPath));
        }
        finally
        {
            tempLock?.Dispose();
            if (tempPath is not null && File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    [Fact]
    public void Save_PinsStorageDirectoryAgainstRenameAndReparseSwapDuringCommit()
    {
        using var directory = new TemporaryDirectory();
        var storageDirectory = directory.GetPath("token-store");
        var movedDirectory = directory.GetPath("moved-token-store");
        var attackerDirectory = directory.GetPath("attacker-store");
        var tokenPath = Path.Combine(storageDirectory, "admin-token.dpapi");
        AdminTokenStore.CreateForTesting(tokenPath).Save(TestToken);
        Directory.CreateDirectory(attackerDirectory);
        Exception? swapError = null;
        var store = AdminTokenStore.CreateForTesting(
            tokenPath,
            beforeCommit: _ =>
            {
                swapError = Record.Exception(() =>
                {
                    Directory.Move(storageDirectory, movedDirectory);
                    Directory.CreateSymbolicLink(storageDirectory, attackerDirectory);
                });
            });

        var saveError = Record.Exception(() => store.Save(ReplacementToken));

        Assert.Null(saveError);
        Assert.True(swapError is IOException or UnauthorizedAccessException);
        Assert.Equal(ReplacementToken, IndependentlyDecrypt(File.ReadAllBytes(tokenPath)));
        Assert.Equal(
            FileAttributes.Directory,
            File.GetAttributes(storageDirectory) &
                (FileAttributes.Directory | FileAttributes.ReparsePoint));
    }

    [Fact]
    public void Save_AtomicallyReplacesExistingCiphertext()
    {
        using var directory = new TemporaryDirectory();
        var tokenPath = directory.GetPath("admin-token.dpapi");
        var store = AdminTokenStore.CreateForTesting(tokenPath);
        store.Save(TestToken);
        var originalCiphertext = File.ReadAllBytes(tokenPath);

        store.Save(ReplacementToken);

        Assert.NotEqual(originalCiphertext, File.ReadAllBytes(tokenPath));
        Assert.Equal(ReplacementToken, IndependentlyDecrypt(File.ReadAllBytes(tokenPath)));
    }

    [Fact]
    public void Save_CiphertextCannotBeDecryptedWithWrongEntropy()
    {
        using var directory = new TemporaryDirectory();
        var tokenPath = directory.GetPath("admin-token.dpapi");
        AdminTokenStore.CreateForTesting(tokenPath).Save(TestToken);
        var wrongEntropy = Encoding.UTF8.GetBytes("SoftwareLicenseAuth.Admin.Tests.WrongEntropy.v1");
        var ciphertext = File.ReadAllBytes(tokenPath);

        Assert.Throws<CryptographicException>(() => ProtectedData.Unprotect(
            ciphertext,
            wrongEntropy,
            DataProtectionScope.CurrentUser));
    }

    [Theory]
    [InlineData(DataProtectionScope.LocalMachine)]
    [InlineData((DataProtectionScope)int.MaxValue)]
    public void TestFactory_RejectsNonCurrentUserScope(DataProtectionScope protectionScope)
    {
        using var directory = new TemporaryDirectory();
        var tokenPath = directory.GetPath("admin-token.dpapi");

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            AdminTokenStore.CreateForTesting(
                tokenPath,
                protectionScope: protectionScope));
    }

    [Fact]
    public void Load_DecryptsIndependentlyProtectedCurrentUserCiphertext()
    {
        using var directory = new TemporaryDirectory();
        var tokenPath = directory.GetPath("admin-token.dpapi");
        var plaintext = Encoding.UTF8.GetBytes(TestToken);
        try
        {
            var ciphertext = ProtectedData.Protect(
                plaintext,
                ExpectedProductEntropy,
                DataProtectionScope.CurrentUser);
            try
            {
                File.WriteAllBytes(tokenPath, ciphertext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertext);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        Assert.Equal(TestToken, AdminTokenStore.CreateForTesting(tokenPath).Load());
    }

    [Fact]
    public void HasSavedToken_ReturnsTrueOnlyForDecryptableCurrentUserCiphertext()
    {
        using var directory = new TemporaryDirectory();
        var tokenPath = directory.GetPath("admin-token.dpapi");
        var store = AdminTokenStore.CreateForTesting(tokenPath);

        Assert.False(store.HasSavedToken);

        store.Save(TestToken);

        Assert.True(store.HasSavedToken);

        File.WriteAllBytes(tokenPath, [0x01, 0x02, 0x03, 0x04]);

        Assert.False(store.HasSavedToken);
    }

    [Fact]
    public void Save_BlankTokenIsRejectedWithoutChangingExistingCiphertextOrStatus()
    {
        using var directory = new TemporaryDirectory();
        var tokenPath = directory.GetPath("admin-token.dpapi");
        var store = AdminTokenStore.CreateForTesting(tokenPath);
        store.Save(TestToken);
        var originalCiphertext = File.ReadAllBytes(tokenPath);

        Assert.Throws<ArgumentException>(() => store.Save("   \t"));

        Assert.Equal(originalCiphertext, File.ReadAllBytes(tokenPath));
        Assert.True(store.HasSavedToken);
        Assert.Equal(TestToken, IndependentlyDecrypt(File.ReadAllBytes(tokenPath)));
    }

    [Fact]
    public void Save_AppliesProtectedCurrentUserOnlyAclToDirectoryAndFile()
    {
        using var directory = new TemporaryDirectory();
        var secureDirectory = directory.GetPath("secure-store");
        var tokenPath = Path.Combine(secureDirectory, "admin-token.dpapi");
        var store = AdminTokenStore.CreateForTesting(
            tokenPath,
            applyCurrentUserAcl: true);

        store.Save(TestToken);
        store.Save(ReplacementToken);

        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User ?? throw new InvalidOperationException("Current user has no SID.");
        AssertCurrentUserOnlyAcl(
            new DirectoryInfo(secureDirectory).GetAccessControl(
                AccessControlSections.Access),
            currentUser);
        AssertCurrentUserOnlyAcl(
            new FileInfo(tokenPath).GetAccessControl(
                AccessControlSections.Access),
            currentUser);
        Assert.Equal(ReplacementToken, IndependentlyDecrypt(File.ReadAllBytes(tokenPath)));
    }

    [Fact]
    public void StoreSerializationAndDisplayDoNotContainPlaintext()
    {
        using var directory = new TemporaryDirectory();
        var store = AdminTokenStore.CreateForTesting(directory.GetPath("admin-token.dpapi"));
        store.Save(TestToken);

        Assert.False(JsonSerializer.Serialize(store).Contains(TestToken, StringComparison.Ordinal));
        Assert.False(store.ToString()!.Contains(TestToken, StringComparison.Ordinal));
    }

    private static string IndependentlyDecrypt(byte[] ciphertext)
    {
        var plaintext = ProtectedData.Unprotect(
            ciphertext,
            ExpectedProductEntropy,
            DataProtectionScope.CurrentUser);
        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static void AssertCurrentUserOnlyAcl(
        FileSystemSecurity security,
        SecurityIdentifier currentUser)
    {
        Assert.True(security.AreAccessRulesProtected);
        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        Assert.NotEmpty(rules);
        Assert.All(rules, rule =>
        {
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.Equal(currentUser.Value, ((SecurityIdentifier)rule.IdentityReference).Value);
        });
        Assert.Contains(rules, rule =>
            (rule.FileSystemRights & FileSystemRights.Modify) == FileSystemRights.Modify);
        Assert.Contains(rules, rule =>
            (rule.FileSystemRights & FileSystemRights.ChangePermissions)
                == FileSystemRights.ChangePermissions);
        Assert.DoesNotContain(rules, rule =>
            (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl);
    }
}
