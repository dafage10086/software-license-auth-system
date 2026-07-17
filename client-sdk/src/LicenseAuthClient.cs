namespace SoftwareLicenseAuth.Client;

public sealed record LicenseAuthorization(
    string State,
    DateTimeOffset ExpiresAt,
    string MachineId,
    string? Plan);

public sealed class LicenseAuthException : Exception
{
    internal LicenseAuthException()
        : base("License authorization failed.")
    {
    }
}

internal sealed record LicenseAuthOperations(
    Func<string, string, CancellationToken, Task<global::OnlineAuthorizationResult>> LoginAsync,
    Func<string, CancellationToken, Task<global::OnlineAuthorizationResult>> ActivateAsync,
    Func<CancellationToken, Task<global::OnlineAuthorizationResult>> RefreshAsync,
    Func<CancellationToken, Task> LogoutAsync,
    Action Dispose);

public sealed class LicenseAuthClient : IDisposable
{
    private const string AuthorizedState = "AUTHORIZED";
    private readonly LicenseAuthOperations operations;
    private int disposeState;

    public LicenseAuthClient(string manifestSha256)
        : this(CreateProductionOperations(manifestSha256))
    {
    }

    internal LicenseAuthClient(LicenseAuthOperations operations)
    {
        this.operations = operations ?? throw new ArgumentNullException(nameof(operations));
        ArgumentNullException.ThrowIfNull(operations.LoginAsync);
        ArgumentNullException.ThrowIfNull(operations.ActivateAsync);
        ArgumentNullException.ThrowIfNull(operations.RefreshAsync);
        ArgumentNullException.ThrowIfNull(operations.LogoutAsync);
        ArgumentNullException.ThrowIfNull(operations.Dispose);
    }

    public Task<LicenseAuthorization> LoginAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var normalizedUsername = global::AccountNaming.Normalize(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        cancellationToken.ThrowIfCancellationRequested();
        return ExecuteAuthorizationAsync(
            () => operations.LoginAsync(normalizedUsername, password, cancellationToken));
    }

    public Task<LicenseAuthorization> ActivateAsync(
        string licenseKey,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(licenseKey);
        cancellationToken.ThrowIfCancellationRequested();
        return ExecuteAuthorizationAsync(
            () => operations.ActivateAsync(licenseKey.Trim(), cancellationToken));
    }

    public Task<LicenseAuthorization> RefreshAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        return ExecuteAuthorizationAsync(() => operations.RefreshAsync(cancellationToken));
    }

    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            await operations.LogoutAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            throw new LicenseAuthException();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposeState, 1) == 0)
        {
            operations.Dispose();
        }
    }

    private static LicenseAuthOperations CreateProductionOperations(string manifestSha256)
    {
        ValidateManifestSha256(manifestSha256);
        try
        {
            var config = global::AuthConfig.LoadForCurrentApplication();
            var coordinator = new global::OnlineAuthCoordinator(config, manifestSha256);
            return new LicenseAuthOperations(
                coordinator.LoginAsync,
                coordinator.ActivateCardAsync,
                coordinator.RefreshAsync,
                coordinator.LogoutAsync,
                coordinator.Dispose);
        }
        catch
        {
            throw new LicenseAuthException();
        }
    }

    private async Task<LicenseAuthorization> ExecuteAuthorizationAsync(
        Func<Task<global::OnlineAuthorizationResult>> operation)
    {
        try
        {
            var result = await operation().ConfigureAwait(false);
            return new LicenseAuthorization(
                AuthorizedState,
                result.MachineFileExpiresAt,
                result.MachineId,
                result.Plan);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            throw new LicenseAuthException();
        }
    }

    private static void ValidateManifestSha256(string manifestSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestSha256);
        if (manifestSha256.Length != 64
            || manifestSha256.Any(character => character is not (>= '0' and <= '9'
                or >= 'A' and <= 'F')))
        {
            throw new ArgumentException(
                "Manifest SHA-256 must be 64 uppercase hexadecimal characters.",
                nameof(manifestSha256));
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(disposeState != 0, this);
    }
}
