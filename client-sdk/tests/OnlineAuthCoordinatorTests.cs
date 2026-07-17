using Xunit;

namespace SoftwareLicenseAuth.Client.Tests;

public sealed class OnlineAuthCoordinatorTests
{
    private const string ManifestSha256 =
        "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
    private const string CandidateFingerprint =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    private const string MachineFingerprint =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string Challenge = "challenge_ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";
    private static readonly DateTimeOffset ServerTime =
        new(2026, 7, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task LoginAsync_VerifiesLeaseWithOriginalMachineFingerprintBeforeSaving()
    {
        SessionData? saved = null;
        var binding = ValidBinding();
        var operations = DefaultOperations(
            loginAsync: (username, password, _) =>
            {
                Assert.Equal("account.one", username);
                Assert.Equal("TEST_ONLY_PASSWORD", password);
                return Task.FromResult(new GatewayLoginResult(
                    "user-1", username, "session-token", ServerTime));
            },
            activateAsync: (token, userId, candidate, cardKey, _) =>
            {
                Assert.Equal("session-token", token);
                Assert.Equal("user-1", userId);
                Assert.Same(binding, candidate);
                Assert.Null(cardKey);
                return Task.FromResult(new GatewayActivationResult(
                    userId,
                    "license-1",
                    "machine-1",
                    MachineFingerprint,
                    "YEAR",
                    128,
                    ServerTime.AddDays(365),
                    ServerTime));
            },
            leaseAsync: (token, machineId, candidate, manifest, challenge, _) =>
            {
                Assert.Equal("session-token", token);
                Assert.Equal("machine-1", machineId);
                Assert.Same(binding, candidate);
                Assert.Equal(ManifestSha256, manifest);
                Assert.Equal(Challenge, challenge);
                return Task.FromResult(ValidLease());
            },
            verify: (_, expected, serverTime, envelopeExpiry, lastServerTime) =>
            {
                Assert.Equal("account-1", expected.AccountId);
                Assert.Equal("product-1", expected.ProductId);
                Assert.Equal("license-1", expected.LicenseId);
                Assert.Equal("machine-1", expected.MachineId);
                Assert.Equal("user-1", expected.OwnerId);
                Assert.Equal(MachineFingerprint, expected.Fingerprint);
                Assert.Equal(ServerTime, serverTime);
                Assert.Equal(ServerTime.AddHours(1), envelopeExpiry);
                Assert.Null(lastServerTime);
                return new VerifiedMachineFile(
                    ServerTime,
                    ServerTime.AddHours(1),
                    ServerTime);
            },
            createBinding: () => binding,
            saveSession: session => saved = session);
        using var coordinator = new OnlineAuthCoordinator(
            "account-1", "product-1", ManifestSha256, operations);

        var result = await coordinator.LoginAsync("account.one", "TEST_ONLY_PASSWORD");

        Assert.Equal("YEAR", result.Plan);
        Assert.Equal("machine-1", result.MachineId);
        Assert.Equal(ServerTime.AddHours(1), result.MachineFileExpiresAt);
        var session = Assert.IsType<SessionData>(saved);
        Assert.Equal(MachineFingerprint, session.MachineFingerprint);
        Assert.Equal("machine-1", session.MachineId);
        Assert.Equal(ServerTime, session.LastServerTime);
        Assert.DoesNotContain("TEST_ONLY_PASSWORD", session.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RefreshAsync_UsesCandidateBindingButStoredMachineFingerprintForClaims()
    {
        var binding = ValidBinding();
        var existing = ValidSession();
        SessionData? saved = null;
        var operations = DefaultOperations(
            leaseAsync: (_, _, candidate, _, _, _) =>
            {
                Assert.Same(binding, candidate);
                Assert.Equal(CandidateFingerprint, candidate.Fingerprint);
                return Task.FromResult(ValidLease());
            },
            verify: (_, expected, _, _, lastServerTime) =>
            {
                Assert.Equal(MachineFingerprint, expected.Fingerprint);
                Assert.Equal(existing.LastServerTime, lastServerTime);
                return new VerifiedMachineFile(
                    ServerTime,
                    ServerTime.AddHours(1),
                    ServerTime);
            },
            createBinding: () => binding,
            loadSession: () => existing,
            saveSession: session => saved = session);
        using var coordinator = new OnlineAuthCoordinator(
            "account-1", "product-1", ManifestSha256, operations);

        var result = await coordinator.RefreshAsync();

        Assert.Equal(existing.MachineId, result.MachineId);
        Assert.Equal(MachineFingerprint, Assert.IsType<SessionData>(saved).MachineFingerprint);
    }

    [Fact]
    public async Task ActivateCardAsync_RequiresStoredSessionAndPersistsVerifiedReplacement()
    {
        var existing = ValidSession();
        var binding = ValidBinding();
        SessionData? saved = null;
        var operations = DefaultOperations(
            activateAsync: (token, userId, candidate, cardKey, _) =>
            {
                Assert.Equal(existing.SessionToken, token);
                Assert.Equal(existing.UserId, userId);
                Assert.Same(binding, candidate);
                Assert.Equal("YEAR-CARD", cardKey);
                return Task.FromResult(new GatewayActivationResult(
                    userId,
                    "paid-license",
                    "paid-machine",
                    MachineFingerprint,
                    "YEAR",
                    128,
                    ServerTime.AddDays(365),
                    ServerTime));
            },
            leaseAsync: (_, machineId, _, _, _, _) =>
            {
                Assert.Equal("paid-machine", machineId);
                return Task.FromResult(ValidLease());
            },
            verify: (_, expected, _, _, _) =>
            {
                Assert.Equal("paid-license", expected.LicenseId);
                Assert.Equal("paid-machine", expected.MachineId);
                return new VerifiedMachineFile(
                    ServerTime,
                    ServerTime.AddHours(1),
                    ServerTime);
            },
            createBinding: () => binding,
            loadSession: () => existing,
            saveSession: session => saved = session);
        using var coordinator = new OnlineAuthCoordinator(
            "account-1", "product-1", ManifestSha256, operations);

        var result = await coordinator.ActivateCardAsync("YEAR-CARD");

        Assert.Equal("YEAR", result.Plan);
        Assert.Equal("paid-machine", result.MachineId);
        Assert.Equal("paid-license", Assert.IsType<SessionData>(saved).LicenseId);
    }

    [Fact]
    public async Task FailedVerificationNeverSavesSessionAndLogoutAlwaysClears()
    {
        var saveCalls = 0;
        var clearCalls = 0;
        var operations = DefaultOperations(
            verify: (_, _, _, _, _) => throw new MachineFileException(),
            createBinding: ValidBinding,
            saveSession: _ => saveCalls++,
            loadSession: ValidSession,
            clearSession: () => clearCalls++,
            logoutAsync: (_, _) => throw new GatewayException("logout failed"));
        using var coordinator = new OnlineAuthCoordinator(
            "account-1", "product-1", ManifestSha256, operations);

        await Assert.ThrowsAsync<MachineFileException>(() =>
            coordinator.LoginAsync("account.one", "TEST_ONLY_PASSWORD"));
        Assert.Equal(0, saveCalls);

        await Assert.ThrowsAsync<GatewayException>(() => coordinator.LogoutAsync());
        Assert.Equal(1, clearCalls);
    }

    [Fact]
    public async Task LoginAsync_CategorizesSessionSaveFailureWithoutLeakingInnerDetails()
    {
        const string secretFailure = "SESSION_SAVE_SECRET_MUST_NOT_LEAK";
        var operations = DefaultOperations(
            createBinding: ValidBinding,
            saveSession: _ => throw new IOException(secretFailure));
        using var coordinator = new OnlineAuthCoordinator(
            "account-1", "product-1", ManifestSha256, operations);

        var error = await Assert.ThrowsAnyAsync<Exception>(() =>
            coordinator.LoginAsync("account.one", "TEST_ONLY_PASSWORD"));

        Assert.Equal("AuthorizationStageException", error.GetType().Name);
        var stage = error.GetType().GetProperty("Stage")?.GetValue(error)?.ToString();
        Assert.Equal("SaveSession", stage);
        Assert.DoesNotContain(secretFailure, error.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("load-session", "LoadSession")]
    [InlineData("create-binding", "CreateBinding")]
    [InlineData("login", "Login")]
    public async Task LoginAsync_CategorizesUnexpectedPreRequestFailure(
        string failurePoint,
        string expectedStage)
    {
        const string secretFailure = "PRE_REQUEST_SECRET_MUST_NOT_LEAK";
        var operations = DefaultOperations(
            loginAsync: failurePoint == "login"
                ? (_, _, _) => Task.FromException<GatewayLoginResult>(
                    new FormatException(secretFailure))
                : null,
            createBinding: failurePoint == "create-binding"
                ? () => throw new FormatException(secretFailure)
                : ValidBinding,
            loadSession: failurePoint == "load-session"
                ? () => throw new InvalidDataException(secretFailure)
                : () => null);
        using var coordinator = new OnlineAuthCoordinator(
            "account-1", "product-1", ManifestSha256, operations);

        var error = await Assert.ThrowsAnyAsync<Exception>(() =>
            coordinator.LoginAsync("account.one", "TEST_ONLY_PASSWORD"));

        Assert.Equal("AuthorizationStageException", error.GetType().Name);
        var stage = error.GetType().GetProperty("Stage")?.GetValue(error)?.ToString();
        Assert.Equal(expectedStage, stage);
        Assert.DoesNotContain(secretFailure, error.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(
        "Hardware identity is unavailable. Contact the administrator.",
        "HardwareSourcesUnavailable")]
    [InlineData(
        "Device identity is unavailable. Contact the administrator.",
        "DeviceKeyUnavailable")]
    public async Task LoginAsync_CategorizesKnownHardwareBindingFailure(
        string fixedFailureMessage,
        string expectedDetail)
    {
        var operations = DefaultOperations(
            createBinding: () => throw new InvalidOperationException(fixedFailureMessage));
        using var coordinator = new OnlineAuthCoordinator(
            "account-1", "product-1", ManifestSha256, operations);

        var error = await Assert.ThrowsAnyAsync<Exception>(() =>
            coordinator.LoginAsync("account.one", "TEST_ONLY_PASSWORD"));

        Assert.Equal("AuthorizationStageException", error.GetType().Name);
        var detail = error.GetType().GetProperty("Detail")?.GetValue(error)?.ToString();
        Assert.Equal(expectedDetail, detail);
        Assert.DoesNotContain(fixedFailureMessage, error.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("invalid-operation", "H01")]
    [InlineData("argument", "H02")]
    [InlineData("type-initialization", "H05")]
    [InlineData("dependency", "H06")]
    [InlineData("cryptography", "H07")]
    [InlineData("io", "H08")]
    [InlineData("access", "H09")]
    [InlineData("platform", "H10")]
    [InlineData("other", "H99")]
    public async Task LoginAsync_AssignsFixedCodeToUnexpectedHardwareFailure(
        string failureKind,
        string expectedCode)
    {
        const string secretFailure = "HARDWARE_FAILURE_SECRET_MUST_NOT_LEAK";
        Exception failure = failureKind switch
        {
            "invalid-operation" => new InvalidOperationException(secretFailure),
            "argument" => new FormatException(secretFailure),
            "type-initialization" => new TypeInitializationException(
                "Secret.Type",
                new Exception(secretFailure)),
            "dependency" => new FileNotFoundException(secretFailure),
            "cryptography" => new System.Security.Cryptography.CryptographicException(secretFailure),
            "io" => new IOException(secretFailure),
            "access" => new UnauthorizedAccessException(secretFailure),
            "platform" => new PlatformNotSupportedException(secretFailure),
            _ => new Exception(secretFailure),
        };
        var operations = DefaultOperations(createBinding: () => throw failure);
        using var coordinator = new OnlineAuthCoordinator(
            "account-1", "product-1", ManifestSha256, operations);

        var error = await Assert.ThrowsAnyAsync<Exception>(() =>
            coordinator.LoginAsync("account.one", "TEST_ONLY_PASSWORD"));

        var code = error.GetType().GetProperty("FailureCode")?.GetValue(error)?.ToString();
        Assert.Equal(expectedCode, code);
        var failureType = error.GetType().GetProperty("FailureTypeName")
            ?.GetValue(error)?.ToString();
        Assert.Equal(failureKind == "other" ? "Exception" : string.Empty, failureType);
        Assert.DoesNotContain(secretFailure, error.ToString(), StringComparison.Ordinal);
    }

    private static OnlineAuthOperations DefaultOperations(
        Func<string, string, CancellationToken, Task<GatewayLoginResult>>? loginAsync = null,
        Func<string, string, DeviceBinding, string?, CancellationToken, Task<GatewayActivationResult>>? activateAsync = null,
        Func<string, string, DeviceBinding, string, string, CancellationToken, Task<GatewayLeaseResult>>? leaseAsync = null,
        Func<string, CancellationToken, Task<GatewayLogoutResult>>? logoutAsync = null,
        Func<DeviceBinding>? createBinding = null,
        Func<SessionData?>? loadSession = null,
        Action<SessionData>? saveSession = null,
        Action? clearSession = null,
        Func<string, ExpectedMachineClaims, DateTimeOffset, DateTimeOffset, DateTimeOffset?, VerifiedMachineFile>? verify = null)
    {
        return new OnlineAuthOperations(
            loginAsync ?? ((username, _, _) => Task.FromResult(new GatewayLoginResult(
                "user-1", username, "session-token", ServerTime))),
            activateAsync ?? ((_, userId, _, _, _) => Task.FromResult(
                new GatewayActivationResult(
                    userId,
                    "license-1",
                    "machine-1",
                    MachineFingerprint,
                    "YEAR",
                    128,
                    ServerTime.AddDays(365),
                    ServerTime))),
            leaseAsync ?? ((_, _, _, _, _, _) => Task.FromResult(ValidLease())),
            logoutAsync ?? ((_, _) => Task.FromResult(new GatewayLogoutResult(ServerTime))),
            createBinding ?? ValidBinding,
            loadSession ?? (() => null),
            saveSession ?? (_ => { }),
            clearSession ?? (() => { }),
            verify ?? ((_, _, _, _, _) => new VerifiedMachineFile(
                ServerTime,
                ServerTime.AddHours(1),
                ServerTime)),
            () => Challenge,
            () => { });
    }

    private static DeviceBinding ValidBinding()
    {
        return new DeviceBinding(
            CandidateFingerprint,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["smbios"] = new string('B', 64),
                ["bios"] = new string('C', 64),
                ["system_disk"] = new string('D', 64),
            });
    }

    private static SessionData ValidSession()
    {
        return new SessionData(
            "account.one",
            "user-1",
            "session-token",
            "machine-1",
            "license-1",
            MachineFingerprint,
            ServerTime.AddMinutes(-5));
    }

    private static GatewayLeaseResult ValidLease()
    {
        return new GatewayLeaseResult(
            "signed-machine-file",
            ServerTime.AddHours(1),
            600,
            Challenge,
            ManifestSha256,
            new string('B', 64),
            "YEAR",
            ServerTime.AddDays(365),
            ServerTime);
    }
}
