using System.Reflection;
using Xunit;

namespace SoftwareLicenseAuth.Client.Tests;

public sealed class LicenseAuthClientTests
{
    [Fact]
    public async Task LoginAsync_NormalizesUsernameAndMapsVerifiedLease()
    {
        string? receivedUsername = null;
        var leaseExpiry = DateTimeOffset.Parse("2030-01-01T01:00:00Z");
        using var client = CreateClient(
            login: (username, _, _) =>
            {
                receivedUsername = username;
                return Task.FromResult(Result("YEAR", "machine-1", leaseExpiry));
            });

        var authorization = await client.LoginAsync("  Customer.One  ", "test-password");

        Assert.Equal("customer.one", receivedUsername);
        Assert.Equal("AUTHORIZED", authorization.State);
        Assert.Equal(leaseExpiry, authorization.ExpiresAt);
        Assert.Equal("machine-1", authorization.MachineId);
        Assert.Equal("YEAR", authorization.Plan);
    }

    [Fact]
    public async Task ActivateRefreshAndLogout_DelegateOnlyFixedCommands()
    {
        string? receivedKey = null;
        var refreshCount = 0;
        var logoutCount = 0;
        using var client = CreateClient(
            activate: (licenseKey, _) =>
            {
                receivedKey = licenseKey;
                return Task.FromResult(Result("FOREVER", "machine-2"));
            },
            refresh: _ =>
            {
                refreshCount++;
                return Task.FromResult(Result("FOREVER", "machine-2"));
            },
            logout: _ =>
            {
                logoutCount++;
                return Task.CompletedTask;
            });

        var activated = await client.ActivateAsync("DEMO-KEY-1234");
        var refreshed = await client.RefreshAsync();
        await client.LogoutAsync();

        Assert.Equal("DEMO-KEY-1234", receivedKey);
        Assert.Equal("FOREVER", activated.Plan);
        Assert.Equal("FOREVER", refreshed.Plan);
        Assert.Equal(1, refreshCount);
        Assert.Equal(1, logoutCount);
    }

    [Fact]
    public async Task Cancellation_IsPreservedWithoutWrapping()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        using var client = CreateClient();

        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.RefreshAsync(cancellation.Token));

        Assert.Equal(cancellation.Token, error.CancellationToken);
    }

    [Fact]
    public async Task UnexpectedFailure_IsReturnedAsFixedSanitizedException()
    {
        using var client = CreateClient(
            refresh: _ => throw new InvalidOperationException("upstream-secret-detail"));

        var error = await Assert.ThrowsAsync<LicenseAuthException>(() => client.RefreshAsync());

        Assert.Equal("License authorization failed.", error.Message);
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("upstream-secret-detail", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void PublicSurface_ExposesOnlyAuthorizationCommandsAndManifestConstructor()
    {
        var methods = typeof(LicenseAuthClient)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(method => !method.IsSpecialName)
            .OrderBy(method => method.Name, StringComparer.Ordinal)
            .Select(method => method.Name)
            .ToArray();

        Assert.Equal(
            new[] { "ActivateAsync", "Dispose", "LoginAsync", "LogoutAsync", "RefreshAsync" },
            methods);
        Assert.DoesNotContain(
            typeof(LicenseAuthClient).GetMethods(BindingFlags.Public | BindingFlags.Instance),
            method => method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(Uri)
                || parameter.ParameterType == typeof(HttpMethod)
                || parameter.ParameterType == typeof(TimeSpan)));

        var constructor = Assert.Single(typeof(LicenseAuthClient).GetConstructors());
        var parameter = Assert.Single(constructor.GetParameters());
        Assert.Equal(typeof(string), parameter.ParameterType);
        Assert.Equal("manifestSha256", parameter.Name);
    }

    [Fact]
    public async Task Dispose_IsIdempotent()
    {
        var disposeCount = 0;
        var client = CreateClient(dispose: () => disposeCount++);

        client.Dispose();
        client.Dispose();

        Assert.Equal(1, disposeCount);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.RefreshAsync());
    }

    private static LicenseAuthClient CreateClient(
        Func<string, string, CancellationToken, Task<OnlineAuthorizationResult>>? login = null,
        Func<string, CancellationToken, Task<OnlineAuthorizationResult>>? activate = null,
        Func<CancellationToken, Task<OnlineAuthorizationResult>>? refresh = null,
        Func<CancellationToken, Task>? logout = null,
        Action? dispose = null)
    {
        var operations = new LicenseAuthOperations(
            login ?? ((_, _, _) => Task.FromResult(Result("TRIAL", "machine-1"))),
            activate ?? ((_, _) => Task.FromResult(Result("TRIAL", "machine-1"))),
            refresh ?? (_ => Task.FromResult(Result("TRIAL", "machine-1"))),
            logout ?? (_ => Task.CompletedTask),
            dispose ?? (() => { }));
        return new LicenseAuthClient(operations);
    }

    private static OnlineAuthorizationResult Result(
        string plan,
        string machineId,
        DateTimeOffset? leaseExpiry = null)
    {
        var serverTime = DateTimeOffset.Parse("2030-01-01T00:00:00Z");
        return new OnlineAuthorizationResult(
            plan,
            machineId,
            BusinessExpiresAt: null,
            leaseExpiry ?? serverTime.AddHours(1),
            serverTime,
            "<REDACTED>");
    }
}
