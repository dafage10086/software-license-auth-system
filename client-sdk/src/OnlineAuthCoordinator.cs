using System.Security.Cryptography;

internal enum AuthorizationStage
{
    LoadSession,
    CreateBinding,
    Login,
    SaveSession,
}

internal enum AuthorizationStageDetail
{
    None,
    HardwareSourcesUnavailable,
    DeviceKeyUnavailable,
}

internal sealed class AuthorizationStageException : Exception
{
    internal AuthorizationStageException(
        AuthorizationStage stage,
        AuthorizationStageDetail detail = AuthorizationStageDetail.None,
        string failureCode = "",
        string failureTypeName = "")
        : base("Authorization workflow stage failed.")
    {
        Stage = stage;
        Detail = detail;
        FailureCode = failureCode;
        FailureTypeName = failureTypeName;
    }

    public AuthorizationStage Stage { get; }

    public AuthorizationStageDetail Detail { get; }

    public string FailureCode { get; }

    public string FailureTypeName { get; }
}

internal sealed record OnlineAuthorizationResult(
    string Plan,
    string MachineId,
    DateTimeOffset? BusinessExpiresAt,
    DateTimeOffset MachineFileExpiresAt,
    DateTimeOffset ServerTime,
    string MachineFile)
{
    public override string ToString()
    {
        return $"{nameof(OnlineAuthorizationResult)} {{ Plan = {Plan}, "
            + $"MachineFileExpiresAt = {MachineFileExpiresAt:O}, MachineFile = <REDACTED> }}";
    }
}

internal sealed record OnlineAuthOperations(
    Func<string, string, CancellationToken, Task<GatewayLoginResult>> LoginAsync,
    Func<string, string, DeviceBinding, string?, CancellationToken, Task<GatewayActivationResult>> ActivateAsync,
    Func<string, string, DeviceBinding, string, string, CancellationToken, Task<GatewayLeaseResult>> LeaseAsync,
    Func<string, CancellationToken, Task<GatewayLogoutResult>> LogoutAsync,
    Func<DeviceBinding> CreateBinding,
    Func<SessionData?> LoadSession,
    Action<SessionData> SaveSession,
    Action ClearSession,
    Func<string, ExpectedMachineClaims, DateTimeOffset, DateTimeOffset, DateTimeOffset?, VerifiedMachineFile> VerifyMachineFile,
    Func<string> CreateChallenge,
    Action Dispose);

internal sealed class OnlineAuthCoordinator : IDisposable
{
    private const string ClientVersion = "2.0.0";
    private readonly string keygenAccountId;
    private readonly string keygenProductId;
    private readonly string manifestSha256;
    private readonly OnlineAuthOperations operations;
    private int disposeState;

    internal OnlineAuthCoordinator(AuthConfig config, string manifestSha256)
        : this(
            config?.KeygenAccountId ?? throw new ArgumentNullException(nameof(config)),
            config.KeygenProductId,
            manifestSha256,
            CreateProductionOperations(config))
    {
    }

    internal OnlineAuthCoordinator(
        string keygenAccountId,
        string keygenProductId,
        string manifestSha256,
        OnlineAuthOperations operations)
    {
        if (!IsValidId(keygenAccountId)
            || !IsValidId(keygenProductId)
            || !IsUppercaseSha256(manifestSha256))
        {
            throw new ArgumentException("Authorization context is invalid.");
        }

        this.operations = operations ?? throw new ArgumentNullException(nameof(operations));
        ArgumentNullException.ThrowIfNull(operations.LoginAsync);
        ArgumentNullException.ThrowIfNull(operations.ActivateAsync);
        ArgumentNullException.ThrowIfNull(operations.LeaseAsync);
        ArgumentNullException.ThrowIfNull(operations.LogoutAsync);
        ArgumentNullException.ThrowIfNull(operations.CreateBinding);
        ArgumentNullException.ThrowIfNull(operations.LoadSession);
        ArgumentNullException.ThrowIfNull(operations.SaveSession);
        ArgumentNullException.ThrowIfNull(operations.ClearSession);
        ArgumentNullException.ThrowIfNull(operations.VerifyMachineFile);
        ArgumentNullException.ThrowIfNull(operations.CreateChallenge);
        ArgumentNullException.ThrowIfNull(operations.Dispose);
        this.keygenAccountId = keygenAccountId;
        this.keygenProductId = keygenProductId;
        this.manifestSha256 = manifestSha256;
    }

    internal async Task<OnlineAuthorizationResult> LoginAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var previousSession = ExecuteStage(
            AuthorizationStage.LoadSession,
            operations.LoadSession);
        var binding = ExecuteStage(
            AuthorizationStage.CreateBinding,
            operations.CreateBinding);
        var login = await ExecuteStageAsync(
                AuthorizationStage.Login,
                () => operations.LoginAsync(username, password, cancellationToken))
            .ConfigureAwait(false);
        try
        {
            var activation = await operations.ActivateAsync(
                    login.SessionToken,
                    login.UserId,
                    binding,
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
            DateTimeOffset? lastServerTime = previousSession?.UserId == login.UserId
                ? previousSession.LastServerTime
                : null;
            return await LeaseVerifyAndSaveAsync(
                    login.Username,
                    login.UserId,
                    login.SessionToken,
                    activation,
                    binding,
                    lastServerTime,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            try
            {
                _ = await operations.LogoutAsync(login.SessionToken, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch
            {
            }

            throw;
        }
    }

    internal async Task<OnlineAuthorizationResult> ActivateCardAsync(
        string cardKey,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var session = RequireSession();
        var binding = operations.CreateBinding();
        var activation = await operations.ActivateAsync(
                session.SessionToken,
                session.UserId,
                binding,
                cardKey,
                cancellationToken)
            .ConfigureAwait(false);
        return await LeaseVerifyAndSaveAsync(
                session.Username,
                session.UserId,
                session.SessionToken,
                activation,
                binding,
                session.LastServerTime,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal async Task<OnlineAuthorizationResult> RefreshAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var session = RequireSession();
        var binding = operations.CreateBinding();
        var lease = await RequestAndVerifyLeaseAsync(
                session.SessionToken,
                session.UserId,
                session.LicenseId,
                session.MachineId,
                session.MachineFingerprint,
                binding,
                session.LastServerTime,
                cancellationToken)
            .ConfigureAwait(false);
        SaveSession(new SessionData(
            session.Username,
            session.UserId,
            session.SessionToken,
            session.MachineId,
            session.LicenseId,
            session.MachineFingerprint,
            lease.Verified.TrustedServerTime));
        return lease.Result;
    }

    internal async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var session = operations.LoadSession();
        try
        {
            if (session is not null)
            {
                _ = await operations.LogoutAsync(session.SessionToken, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            operations.ClearSession();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposeState, 1) == 0)
        {
            operations.Dispose();
        }
    }

    private async Task<OnlineAuthorizationResult> LeaseVerifyAndSaveAsync(
        string username,
        string userId,
        string sessionToken,
        GatewayActivationResult activation,
        DeviceBinding binding,
        DateTimeOffset? lastServerTime,
        CancellationToken cancellationToken)
    {
        var lease = await RequestAndVerifyLeaseAsync(
                sessionToken,
                userId,
                activation.LicenseId,
                activation.MachineId,
                activation.MachineFingerprint,
                binding,
                lastServerTime,
                cancellationToken)
            .ConfigureAwait(false);
        SaveSession(new SessionData(
            username,
            userId,
            sessionToken,
            activation.MachineId,
            activation.LicenseId,
            activation.MachineFingerprint,
            lease.Verified.TrustedServerTime));
        return lease.Result;
    }

    private void SaveSession(SessionData session)
    {
        try
        {
            operations.SaveSession(session);
        }
        catch
        {
            throw new AuthorizationStageException(AuthorizationStage.SaveSession);
        }
    }

    private static T ExecuteStage<T>(AuthorizationStage stage, Func<T> operation)
    {
        try
        {
            return operation();
        }
        catch (Exception error) when (!IsExpectedAuthorizationFailure(error))
        {
            throw CreateStageException(stage, error);
        }
    }

    private static async Task<T> ExecuteStageAsync<T>(
        AuthorizationStage stage,
        Func<Task<T>> operation)
    {
        try
        {
            return await operation().ConfigureAwait(false);
        }
        catch (Exception error) when (!IsExpectedAuthorizationFailure(error))
        {
            throw CreateStageException(stage, error);
        }
    }

    private static AuthorizationStageException CreateStageException(
        AuthorizationStage stage,
        Exception error)
    {
        var detail = stage == AuthorizationStage.CreateBinding
            ? error.Message switch
            {
                "Hardware identity is unavailable. Contact the administrator."
                    => AuthorizationStageDetail.HardwareSourcesUnavailable,
                "Device identity is unavailable. Contact the administrator."
                    => AuthorizationStageDetail.DeviceKeyUnavailable,
                _ => AuthorizationStageDetail.None,
            }
            : AuthorizationStageDetail.None;
        var failureCode = stage == AuthorizationStage.CreateBinding
            && detail == AuthorizationStageDetail.None
            ? HardwareFailureCode(error)
            : string.Empty;
        var failureTypeName = failureCode == "H99"
            ? error.GetType().Name
            : string.Empty;
        return new AuthorizationStageException(
            stage,
            detail,
            failureCode,
            failureTypeName);
    }

    private static string HardwareFailureCode(Exception error)
    {
        return error switch
        {
            InvalidOperationException => "H01",
            ArgumentException or FormatException => "H02",
            TypeInitializationException => "H05",
            FileNotFoundException or FileLoadException => "H06",
            CryptographicException => "H07",
            IOException => "H08",
            UnauthorizedAccessException => "H09",
            PlatformNotSupportedException => "H10",
            _ => "H99",
        };
    }

    private static bool IsExpectedAuthorizationFailure(Exception error)
    {
        return error is GatewayException
            or MachineFileException
            or AuthorizationStageException
            or OperationCanceledException;
    }

    private async Task<(OnlineAuthorizationResult Result, VerifiedMachineFile Verified)>
        RequestAndVerifyLeaseAsync(
            string sessionToken,
            string userId,
            string licenseId,
            string machineId,
            string machineFingerprint,
            DeviceBinding binding,
            DateTimeOffset? lastServerTime,
            CancellationToken cancellationToken)
    {
        var challenge = operations.CreateChallenge();
        var lease = await operations.LeaseAsync(
                sessionToken,
                machineId,
                binding,
                manifestSha256,
                challenge,
                cancellationToken)
            .ConfigureAwait(false);
        var verified = operations.VerifyMachineFile(
            lease.MachineFile,
            new ExpectedMachineClaims(
                keygenAccountId,
                keygenProductId,
                licenseId,
                machineId,
                userId,
                machineFingerprint),
            lease.ServerTime,
            lease.MachineFileExpiresAt,
            lastServerTime);
        return (
            new OnlineAuthorizationResult(
                lease.Plan,
                machineId,
                lease.BusinessExpiresAt,
                verified.ExpiresAt,
                lease.ServerTime,
                lease.MachineFile),
            verified);
    }

    private SessionData RequireSession()
    {
        return operations.LoadSession()
            ?? throw new InvalidOperationException("Authorization session is unavailable.");
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(disposeState != 0, this);
    }

    private static OnlineAuthOperations CreateProductionOperations(AuthConfig config)
    {
        var gateway = new GatewayClient(config.GatewayBaseUrl, ClientVersion);
        var store = SessionStore.CreateForCurrentUser();
        var hardware = new HardwareFingerprint(
            new WindowsHardwareSource(new WindowsHardwareBackend()),
            new CngDeviceKeyProvider());
        var verifier = new MachineFileVerifier(config.KeygenPublicKey);
        return new OnlineAuthOperations(
            gateway.LoginAsync,
            gateway.ActivateAsync,
            gateway.LeaseAsync,
            gateway.LogoutAsync,
            hardware.CreateBinding,
            store.Load,
            store.Save,
            store.Clear,
            verifier.Verify,
            CreateChallenge,
            () => ((IDisposable)gateway).Dispose());
    }

    private static string CreateChallenge()
    {
        var random = RandomNumberGenerator.GetBytes(32);
        try
        {
            return Convert.ToBase64String(random)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    private static bool IsUppercaseSha256(string? value)
    {
        return value is not null
            && value.Length == 64
            && value.All(character => character is >= '0' and <= '9'
                or >= 'A' and <= 'F');
    }

    private static bool IsValidId(string? value)
    {
        return value is not null
            && value.Length is >= 1 and <= 128
            && value.All(character => character is >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'
                or >= '0' and <= '9'
                or '_' or '-');
    }
}
