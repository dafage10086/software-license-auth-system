using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Xunit;

namespace SoftwareLicenseAuth.Admin.Tests;

public sealed class SecureTunnelTests
{
    private const string FixedHost = "license.example.com";
    private const string FixedUser = "license-auth-tunnel";
    private const string PrivateKeyContents = "TEST_PRIVATE_KEY_MATERIAL_MUST_NOT_BE_LOGGED";
    private const string SensitiveToken = "TEST_ADMIN_TOKEN_MUST_NOT_BE_LOGGED";

    [Fact]
    public void Paths_UseFixedCurrentUserLocalAppDataLayout()
    {
        using var directory = new TemporaryDirectory();

        var paths = OwnerTunnelPaths.FromLocalAppData(directory.GetPath("LocalAppData"));

        var root = Path.Combine(
            directory.GetPath("LocalAppData"),
            "SoftwareLicenseAuth",
            "Admin");
        Assert.Equal(Path.Combine(root, "admin-tunnel.json"), paths.ConfigPath);
        Assert.Equal(Path.Combine(root, "ssh", "tunnel_ed25519"), paths.PrivateKeyPath);
        Assert.Equal(Path.Combine(root, "ssh", "known_hosts"), paths.KnownHostsPath);
        Assert.True(Path.IsPathFullyQualified(paths.ConfigPath));
        Assert.True(Path.IsPathFullyQualified(paths.PrivateKeyPath));
        Assert.True(Path.IsPathFullyQualified(paths.KnownHostsPath));
    }

    [Fact]
    public void Configuration_LoadsOnlyTheFixedHostPortAndUser()
    {
        using var directory = new TemporaryDirectory();
        var paths = WriteValidArtifacts(directory);

        var config = OwnerTunnelConfiguration.Load(paths);

        Assert.Equal(FixedHost, config.Host);
        Assert.Equal(22, config.Port);
        Assert.Equal(FixedUser, config.User);
    }

    [Fact]
    public void Configuration_LoadProtectsArtifactsForCurrentUserAndSystemOnly()
    {
        using var directory = new TemporaryDirectory();
        var paths = WriteValidArtifacts(directory);

        _ = OwnerTunnelConfiguration.Load(paths);

        AssertCurrentUserAndSystemOnly(
            new DirectoryInfo(Path.GetDirectoryName(paths.ConfigPath)!)
                .GetAccessControl(AccessControlSections.Access));
        AssertCurrentUserAndSystemOnly(
            new DirectoryInfo(Path.GetDirectoryName(paths.PrivateKeyPath)!)
                .GetAccessControl(AccessControlSections.Access));
        AssertCurrentUserAndSystemOnly(
            new FileInfo(paths.ConfigPath).GetAccessControl(AccessControlSections.Access));
        AssertCurrentUserAndSystemOnly(
            new FileInfo(paths.PrivateKeyPath).GetAccessControl(AccessControlSections.Access));
        AssertCurrentUserAndSystemOnly(
            new FileInfo(paths.KnownHostsPath).GetAccessControl(AccessControlSections.Access));
    }

    [Fact]
    public void Configuration_LoadWithAdministratorsOwnedTokenStyleRootRestoresTunnelAcl()
    {
        using var directory = new TemporaryDirectory();
        var paths = OwnerTunnelPaths.FromLocalAppData(directory.GetPath("LocalAppData"));
        var root = Path.GetDirectoryName(paths.ConfigPath)!;
        Directory.CreateDirectory(root);
        var administrators = new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            domainSid: null);
        ApplyCurrentUserMaintenanceAcl(root, administrators);
        Directory.CreateDirectory(Path.GetDirectoryName(paths.PrivateKeyPath)!);
        File.WriteAllText(
            paths.ConfigPath,
            JsonSerializer.Serialize(new
            {
                host = FixedHost,
                port = 22,
                user = FixedUser
            }));
        File.WriteAllText(paths.PrivateKeyPath, PrivateKeyContents);
        File.WriteAllText(
            paths.KnownHostsPath,
            $"{FixedHost} ssh-ed25519 TEST_ONLY_HOST_KEY");

        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new InvalidOperationException("Current user has no SID.");
        var restrictedSecurity = new DirectoryInfo(root).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        Assert.Equal(
            administrators,
            restrictedSecurity.GetOwner(typeof(SecurityIdentifier)));
        var restrictedRule = Assert.Single(
            restrictedSecurity.GetAccessRules(
                    includeExplicit: true,
                    includeInherited: true,
                    targetType: typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>());
        Assert.Equal(currentUser, restrictedRule.IdentityReference);
        Assert.Equal(
            (FileSystemRights)0,
            restrictedRule.FileSystemRights & FileSystemRights.TakeOwnership);

        var config = OwnerTunnelConfiguration.Load(paths);

        Assert.Equal(FixedHost, config.Host);
        Assert.Equal(22, config.Port);
        Assert.Equal(FixedUser, config.User);
        Assert.Equal(
            administrators,
            new DirectoryInfo(root)
                .GetAccessControl(AccessControlSections.Owner)
                .GetOwner(typeof(SecurityIdentifier)));
        AssertCurrentUserAndSystemOnly(
            new DirectoryInfo(root).GetAccessControl(AccessControlSections.Access));
        AssertCurrentUserAndSystemOnly(
            new DirectoryInfo(Path.GetDirectoryName(paths.PrivateKeyPath)!)
                .GetAccessControl(AccessControlSections.Access));
        AssertCurrentUserAndSystemOnly(
            new FileInfo(paths.ConfigPath).GetAccessControl(AccessControlSections.Access));
        AssertCurrentUserAndSystemOnly(
            new FileInfo(paths.PrivateKeyPath).GetAccessControl(AccessControlSections.Access));
        AssertCurrentUserAndSystemOnly(
            new FileInfo(paths.KnownHostsPath).GetAccessControl(AccessControlSections.Access));
    }

    [Fact]
    public void OwnerValidation_TrustsCurrentUserAdministratorsAndSystem()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new InvalidOperationException("Current user has no SID.");
        var trustedOwners = new[]
        {
            currentUser,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)
        };

        Assert.All(trustedOwners, owner =>
            Assert.Null(Record.Exception(() =>
                OwnerTunnelConfiguration.ValidateTrustedOwner(owner, currentUser))));
    }

    [Fact]
    public void OwnerValidation_RejectsOrdinaryAndUnknownOwners()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new InvalidOperationException("Current user has no SID.");
        var untrustedOwners = new[]
        {
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            new SecurityIdentifier("S-1-5-21-111111111-222222222-333333333-1001")
        };

        Assert.All(untrustedOwners, owner =>
        {
            var error = Assert.Throws<OwnerTunnelConfigurationException>(() =>
                OwnerTunnelConfiguration.ValidateTrustedOwner(owner, currentUser));
            Assert.Equal("Secure tunnel artifact owner is not trusted.", error.Message);
        });
    }

    [Theory]
    [MemberData(nameof(InvalidConfigurations))]
    public void Configuration_RejectsNonStrictOrNonFixedJson(string json)
    {
        using var directory = new TemporaryDirectory();
        var paths = WriteArtifacts(directory, json);

        Assert.Throws<OwnerTunnelConfigurationException>(() =>
            OwnerTunnelConfiguration.Load(paths));
    }

    public static TheoryData<string> InvalidConfigurations => new()
    {
        { $$"""{"host":"{{FixedHost}}","port":22,"user":"{{FixedUser}}","extra":true}""" },
        { $$"""{"host":"{{FixedHost}}","host":"{{FixedHost}}","port":22,"user":"{{FixedUser}}"}""" },
        { $$"""{"host":"other.example.invalid","port":22,"user":"{{FixedUser}}"}""" },
        { $$"""{"host":"{{FixedHost}}","port":2222,"user":"{{FixedUser}}"}""" },
        { $$"""{"host":"{{FixedHost}}","port":22,"user":"other-user"}""" },
        { $$"""{"host":"{{FixedHost}}","port":22}""" },
        { $$"""{"host":"{{FixedHost}}","port":22,"user":"{{FixedUser}}",}""" },
        { $$"""{// comment\n"host":"{{FixedHost}}","port":22,"user":"{{FixedUser}}"}""" },
        { "[]" }
    };

    [Theory]
    [InlineData("config")]
    [InlineData("private-key")]
    [InlineData("known-hosts")]
    public async Task EnsureStarted_MissingArtifactReturnsConfigurationFailureBeforeLaunch(
        string missingArtifact)
    {
        using var directory = new TemporaryDirectory();
        var paths = WriteValidArtifacts(directory);
        File.Delete(missingArtifact switch
        {
            "config" => paths.ConfigPath,
            "private-key" => paths.PrivateKeyPath,
            _ => paths.KnownHostsPath
        });
        var launcher = new FakeProcessLauncher();
        var readiness = new FakeReadiness(TunnelReadinessResult.Ready);
        using var tunnel = CreateTunnel(directory, paths, launcher, readiness);

        var error = await Assert.ThrowsAsync<OwnerTunnelConfigurationException>(() =>
            tunnel.EnsureStartedAsync(CancellationToken.None));

        Assert.Equal(0, launcher.StartCalls);
        Assert.DoesNotContain(PrivateKeyContents, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EnsureStarted_UsesLockedDownHiddenOpenSshArgumentsAndStartsOnce()
    {
        using var directory = new TemporaryDirectory();
        var paths = WriteValidArtifacts(directory);
        var launcher = new FakeProcessLauncher();
        var readiness = new FakeReadiness(TunnelReadinessResult.Ready);
        using var tunnel = CreateTunnel(directory, paths, launcher, readiness);

        await tunnel.EnsureStartedAsync(CancellationToken.None);
        await tunnel.EnsureStartedAsync(CancellationToken.None);

        Assert.Equal(1, launcher.StartCalls);
        Assert.Equal(2, readiness.WaitCalls);
        var startInfo = Assert.IsType<ProcessStartInfo>(launcher.LastStartInfo);
        Assert.False(startInfo.UseShellExecute);
        Assert.True(startInfo.CreateNoWindow);
        Assert.Equal(ProcessWindowStyle.Hidden, startInfo.WindowStyle);
        Assert.True(startInfo.RedirectStandardOutput);
        Assert.True(startInfo.RedirectStandardError);
        Assert.Equal(18788, readiness.LastPort);

        var arguments = startInfo.ArgumentList.ToArray();
        Assert.Contains("-N", arguments);
        Assert.Contains("-T", arguments);
        AssertOption(arguments, "BatchMode=yes");
        AssertOption(arguments, "StrictHostKeyChecking=yes");
        AssertOption(arguments, "ExitOnForwardFailure=yes");
        AssertOption(arguments, "IdentitiesOnly=yes");
        AssertOption(arguments, $"UserKnownHostsFile={paths.KnownHostsPath}");
        AssertOption(arguments, "GlobalKnownHostsFile=NUL");
        AssertArgumentPair(arguments, "-F", "NUL");
        AssertArgumentPair(arguments, "-i", paths.PrivateKeyPath);
        AssertArgumentPair(arguments, "-p", "22");
        AssertArgumentPair(
            arguments,
            "-L",
            "127.0.0.1:18788:127.0.0.1:18788");
        Assert.Equal($"{FixedUser}@{FixedHost}", arguments[^1]);
        Assert.DoesNotContain(PrivateKeyContents, string.Join("\n", arguments), StringComparison.Ordinal);
        Assert.DoesNotContain(SensitiveToken, string.Join("\n", arguments), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EnsureStarted_PreexistingLoopbackListenerIsNeverTrustedOrReused()
    {
        using var directory = new TemporaryDirectory();
        var paths = WriteValidArtifacts(directory);
        var launcher = new FakeProcessLauncher();
        var readiness = new FakeReadiness(TunnelReadinessResult.Ready)
        {
            PortOccupied = true
        };
        using var tunnel = CreateTunnel(directory, paths, launcher, readiness);

        var error = await Assert.ThrowsAsync<OwnerTunnelConnectionException>(() =>
            tunnel.EnsureStartedAsync(CancellationToken.None));

        Assert.Equal(1, readiness.PreflightCalls);
        Assert.Equal(0, readiness.WaitCalls);
        Assert.Equal(0, launcher.StartCalls);
        Assert.DoesNotContain(SensitiveToken, error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(PrivateKeyContents, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task LoopbackReadiness_DetectsAnActuallyOccupiedLocalPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var readiness = new LoopbackTunnelReadiness();

        var occupied = await readiness.IsPortOccupiedAsync(
            port,
            CancellationToken.None);

        Assert.True(occupied);
    }

    [Fact]
    public async Task EnsureStarted_WhenOwnedProcessExitedStartsReplacement()
    {
        using var directory = new TemporaryDirectory();
        var paths = WriteValidArtifacts(directory);
        var launcher = new FakeProcessLauncher();
        var readiness = new FakeReadiness(TunnelReadinessResult.Ready);
        using var tunnel = CreateTunnel(directory, paths, launcher, readiness);
        await tunnel.EnsureStartedAsync(CancellationToken.None);
        launcher.Process.HasExitedValue = true;

        await tunnel.EnsureStartedAsync(CancellationToken.None);

        Assert.Equal(2, launcher.StartCalls);
        Assert.Equal(2, readiness.WaitCalls);
    }

    [Fact]
    public async Task EnsureStarted_WhenCachedProcessReadinessFailsStopsAndStartsReplacement()
    {
        using var directory = new TemporaryDirectory();
        var paths = WriteValidArtifacts(directory);
        var launcher = new FakeProcessLauncher();
        var readiness = new FakeReadiness(
            TunnelReadinessResult.Ready,
            TunnelReadinessResult.TimedOut,
            TunnelReadinessResult.Ready);
        using var tunnel = CreateTunnel(directory, paths, launcher, readiness);
        await tunnel.EnsureStartedAsync(CancellationToken.None);
        var firstProcess = launcher.Process;

        await tunnel.EnsureStartedAsync(CancellationToken.None);

        Assert.Equal(2, launcher.StartCalls);
        Assert.Equal(3, readiness.WaitCalls);
        Assert.Equal(1, firstProcess.TerminateCalls);
        Assert.True(firstProcess.IsDisposed);
    }

    [Theory]
    [InlineData("exited")]
    [InlineData("timeout")]
    public async Task EnsureStarted_FailedReadinessStopsOwnedProcessAndReturnsFixedFailure(
        string failure)
    {
        using var directory = new TemporaryDirectory();
        var paths = WriteValidArtifacts(directory);
        var launcher = new FakeProcessLauncher();
        var readiness = new FakeReadiness(
            failure == "exited"
                ? TunnelReadinessResult.ProcessExited
                : TunnelReadinessResult.TimedOut);
        using var tunnel = CreateTunnel(directory, paths, launcher, readiness);

        var error = await Assert.ThrowsAsync<OwnerTunnelConnectionException>(() =>
            tunnel.EnsureStartedAsync(CancellationToken.None));

        Assert.Equal(1, launcher.Process.TerminateCalls);
        Assert.True(launcher.Process.IsDisposed);
        Assert.DoesNotContain(PrivateKeyContents, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Dispose_TerminatesOnlyTheProcessStartedByThisTunnel()
    {
        using var directory = new TemporaryDirectory();
        var paths = WriteValidArtifacts(directory);
        var launcher = new FakeProcessLauncher();
        var readiness = new FakeReadiness(TunnelReadinessResult.Ready);
        var tunnel = CreateTunnel(directory, paths, launcher, readiness);
        await tunnel.EnsureStartedAsync(CancellationToken.None);

        tunnel.Dispose();

        Assert.Equal(1, launcher.Process.TerminateCalls);
        Assert.True(launcher.Process.IsDisposed);
    }

    [Fact]
    public void ProcessLauncher_AssignsStartedProcessToJobAndReleasesBoth()
    {
        var process = new FakeTunnelProcess();
        var job = new FakeTunnelJob();
        var binder = new FakeTunnelJobBinder(job);
        var launcher = new OwnerTunnelProcessLauncher(_ => process, binder);

        var launched = launcher.Start(new ProcessStartInfo("unused-test-process"));
        launched.Dispose();

        Assert.Equal(1, binder.AssignCalls);
        Assert.Same(process, binder.LastProcess);
        Assert.Equal(1, job.DisposeCalls);
        Assert.True(process.IsDisposed);
    }

    [Fact]
    public void ProcessLauncher_WhenJobAssignmentFailsTerminatesAndDisposesProcess()
    {
        var process = new FakeTunnelProcess();
        var binder = new FakeTunnelJobBinder(new FakeTunnelJob())
        {
            Failure = new Win32Exception($"job failure {PrivateKeyContents}")
        };
        var launcher = new OwnerTunnelProcessLauncher(_ => process, binder);

        var error = Assert.Throws<OwnerTunnelConnectionException>(() =>
            launcher.Start(new ProcessStartInfo("unused-test-process")));

        Assert.Equal("OpenSSH tunnel process job assignment failed.", error.Message);
        Assert.Equal(1, process.TerminateCalls);
        Assert.True(process.IsDisposed);
        Assert.DoesNotContain(PrivateKeyContents, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WindowsJobBinder_AssignsAnActualChildProcess()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "ping.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add("127.0.0.1");
        startInfo.ArgumentList.Add("-n");
        startInfo.ArgumentList.Add("30");
        var nativeProcess = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Test child process did not start.");
        var process = new OwnerTunnelProcess(nativeProcess);
        IOwnerTunnelJob? job = null;
        try
        {
            job = new WindowsOwnerTunnelJobBinder().Assign(process);

            Assert.False(process.HasExited);
            process.Terminate();
            Assert.True(process.HasExited);
        }
        finally
        {
            try
            {
                process.Terminate();
            }
            finally
            {
                job?.Dispose();
                process.Dispose();
            }
        }
    }

    [Fact]
    public async Task Runtime_MissingDpapiTokenDoesNotStartTunnelAndReturnsFixedPrompt()
    {
        var tunnel = new FakeSecureTunnel();
        using var runtime = CreateRuntime(
            tunnel,
            () => throw new FileNotFoundException($"missing {SensitiveToken}"));

        var error = await Assert.ThrowsAsync<OwnerRuntimeException>(() =>
            runtime.CreateOperationsAsync(CancellationToken.None));

        Assert.Equal(OwnerFailureMessages.MissingAdminCredential, error.UserMessage);
        Assert.Equal(0, tunnel.EnsureCalls);
        Assert.DoesNotContain(SensitiveToken, error.UserMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("configuration")]
    [InlineData("connection")]
    public async Task Runtime_TunnelFailuresReturnDifferentFixedSanitizedPrompts(string failure)
    {
        var tunnel = new FakeSecureTunnel
        {
            Failure = failure == "configuration"
                ? new OwnerTunnelConfigurationException($"bad key {PrivateKeyContents}")
                : new OwnerTunnelConnectionException($"ssh stderr {PrivateKeyContents}")
        };
        using var runtime = CreateRuntime(tunnel, () => SensitiveToken);

        var error = await Assert.ThrowsAsync<OwnerRuntimeException>(() =>
            runtime.CreateOperationsAsync(CancellationToken.None));

        Assert.Equal(
            failure == "configuration"
                ? OwnerFailureMessages.TunnelConfigurationIncomplete
                : OwnerFailureMessages.TunnelConnectionFailed,
            error.UserMessage);
        Assert.Equal(1, tunnel.EnsureCalls);
        Assert.DoesNotContain(PrivateKeyContents, error.UserMessage, StringComparison.Ordinal);
        Assert.DoesNotContain(SensitiveToken, error.UserMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void AdminForm_DisposeReleasesRuntimeTunnel()
    {
        var tunnel = new FakeSecureTunnel();
        var runtime = CreateRuntime(tunnel, () => SensitiveToken);
        var form = new OwnerAdminForm(runtime, () => "test-password", new FakeClipboard());

        form.Dispose();

        Assert.True(tunnel.IsDisposed);
    }

    [Fact]
    public void AdminForm_DisposeIsIdempotentAndReleasesTunnelOnce()
    {
        var tunnel = new FakeSecureTunnel();
        var runtime = CreateRuntime(tunnel, () => SensitiveToken);
        var form = new OwnerAdminForm(runtime, () => "test-password", new FakeClipboard());

        form.Dispose();
        var secondDisposeError = Record.Exception(form.Dispose);

        Assert.Null(secondDisposeError);
        Assert.Equal(1, tunnel.DisposeCalls);
    }

    [Fact]
    public async Task AdminForm_RechecksTunnelBeforeReusingExistingWorkflow()
    {
        var tunnel = new FakeSecureTunnel();
        var operations = new FakeAdminOperations();
        using var runtime = new OwnerRuntime(
            () => true,
            () => SensitiveToken,
            _ => { },
            tunnel,
            _ => operations);
        using var form = new OwnerAdminForm(
            runtime,
            () => "test-password",
            new FakeClipboard());
        var ensureWorkflow = typeof(OwnerAdminForm).GetMethod(
            "EnsureWorkflowAsync",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(ensureWorkflow);

        var first = await Assert.IsType<Task<OwnerWorkflow>>(
            ensureWorkflow.Invoke(form, null));
        var second = await Assert.IsType<Task<OwnerWorkflow>>(
            ensureWorkflow.Invoke(form, null));

        Assert.Same(first, second);
        Assert.Equal(2, tunnel.EnsureCalls);
    }

    private static OwnerRuntime CreateRuntime(
        IOwnerSecureTunnel tunnel,
        Func<string> tokenLoader)
    {
        return new OwnerRuntime(
            () => true,
            tokenLoader,
            _ => { },
            tunnel,
            _ => throw new InvalidOperationException("Operations must not be created in this test."));
    }

    private static OpenSshTunnel CreateTunnel(
        TemporaryDirectory directory,
        OwnerTunnelPaths paths,
        FakeProcessLauncher launcher,
        FakeReadiness readiness)
    {
        var sshExecutable = directory.WriteFile("ssh.exe", "test executable placeholder");
        return new OpenSshTunnel(paths, sshExecutable, launcher, readiness);
    }

    private static OwnerTunnelPaths WriteValidArtifacts(TemporaryDirectory directory)
    {
        return WriteArtifacts(directory, JsonSerializer.Serialize(new
        {
            host = FixedHost,
            port = 22,
            user = FixedUser
        }));
    }

    private static OwnerTunnelPaths WriteArtifacts(
        TemporaryDirectory directory,
        string configJson)
    {
        var paths = OwnerTunnelPaths.FromLocalAppData(directory.GetPath("LocalAppData"));
        Directory.CreateDirectory(Path.GetDirectoryName(paths.ConfigPath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(paths.PrivateKeyPath)!);
        File.WriteAllText(paths.ConfigPath, configJson);
        File.WriteAllText(paths.PrivateKeyPath, PrivateKeyContents);
        File.WriteAllText(
            paths.KnownHostsPath,
            $"{FixedHost} ssh-ed25519 TEST_ONLY_HOST_KEY");
        return paths;
    }

    private static void AssertOption(IReadOnlyList<string> arguments, string value)
    {
        AssertArgumentPair(arguments, "-o", value);
    }

    private static void AssertCurrentUserAndSystemOnly(FileSystemSecurity security)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new InvalidOperationException("Current user has no SID.");
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();

        Assert.True(security.AreAccessRulesProtected);
        Assert.NotEmpty(rules);
        Assert.All(rules, rule => Assert.Equal(AccessControlType.Allow, rule.AccessControlType));
        Assert.Equal(
            new[] { currentUser.Value, localSystem.Value }.Order(StringComparer.Ordinal),
            rules.Select(rule => ((SecurityIdentifier)rule.IdentityReference).Value)
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal));
    }

    private static void ApplyCurrentUserMaintenanceAcl(
        string directory,
        SecurityIdentifier owner)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new InvalidOperationException("Current user has no SID.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(owner);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.Modify | FileSystemRights.ChangePermissions,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    private static void AssertArgumentPair(
        IReadOnlyList<string> arguments,
        string name,
        string value)
    {
        Assert.Contains(
            Enumerable.Range(0, arguments.Count - 1),
            index => arguments[index] == name && arguments[index + 1] == value);
    }

    private sealed class FakeProcessLauncher : IOwnerTunnelProcessLauncher
    {
        internal FakeTunnelProcess Process { get; private set; } = new();
        internal ProcessStartInfo? LastStartInfo { get; private set; }
        internal int StartCalls { get; private set; }

        public IOwnerTunnelProcess Start(ProcessStartInfo startInfo)
        {
            StartCalls++;
            LastStartInfo = startInfo;
            Process = new FakeTunnelProcess();
            return Process;
        }
    }

    private sealed class FakeTunnelProcess : IOwnerTunnelProcess
    {
        internal bool HasExitedValue { get; set; }
        internal bool IsDisposed { get; private set; }
        internal int TerminateCalls { get; private set; }

        public bool HasExited => HasExitedValue;

        public void Terminate()
        {
            TerminateCalls++;
            HasExitedValue = true;
        }

        public void Dispose()
        {
            IsDisposed = true;
        }
    }

    private sealed class FakeTunnelJob : IOwnerTunnelJob
    {
        internal int DisposeCalls { get; private set; }

        public void Dispose()
        {
            DisposeCalls++;
        }
    }

    private sealed class FakeTunnelJobBinder(FakeTunnelJob job) : IOwnerTunnelJobBinder
    {
        internal int AssignCalls { get; private set; }
        internal Exception? Failure { get; init; }
        internal IOwnerTunnelProcess? LastProcess { get; private set; }

        public IOwnerTunnelJob Assign(IOwnerTunnelProcess process)
        {
            AssignCalls++;
            LastProcess = process;
            if (Failure is not null)
            {
                throw Failure;
            }

            return job;
        }
    }

    private sealed class FakeReadiness : IOwnerTunnelReadiness
    {
        private readonly Queue<TunnelReadinessResult> _results;

        internal FakeReadiness(params TunnelReadinessResult[] results)
        {
            Assert.NotEmpty(results);
            _results = new Queue<TunnelReadinessResult>(results);
        }

        internal int LastPort { get; private set; }
        internal bool PortOccupied { get; init; }
        internal int PreflightCalls { get; private set; }
        internal int WaitCalls { get; private set; }

        public Task<bool> IsPortOccupiedAsync(
            int localPort,
            CancellationToken cancellationToken)
        {
            LastPort = localPort;
            PreflightCalls++;
            return Task.FromResult(PortOccupied);
        }

        public Task<TunnelReadinessResult> WaitAsync(
            int localPort,
            IOwnerTunnelProcess process,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            LastPort = localPort;
            WaitCalls++;
            var result = _results.Count > 1
                ? _results.Dequeue()
                : _results.Peek();
            return Task.FromResult(result);
        }
    }

    private sealed class FakeSecureTunnel : IOwnerSecureTunnel
    {
        internal int EnsureCalls { get; private set; }
        internal Exception? Failure { get; init; }
        internal bool IsDisposed { get; private set; }
        internal int DisposeCalls { get; private set; }

        public Task EnsureStartedAsync(CancellationToken cancellationToken)
        {
            EnsureCalls++;
            return Failure is null
                ? Task.CompletedTask
                : Task.FromException(Failure);
        }

        public void Dispose()
        {
            IsDisposed = true;
            DisposeCalls++;
        }
    }

    private sealed class FakeClipboard : IOwnerClipboard
    {
        public void SetText(string text)
        {
        }
    }

    private sealed class FakeAdminOperations : IKeygenAdminOperations
    {
        public Task<KeygenUser> FindOrCreateUserAsync(
            string username,
            string password,
            string customer,
            CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<KeygenLicense> EnsureTrialAsync(
            KeygenUser user,
            CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<KeygenLicense> IssuePaidAsync(
            KeygenUser user,
            string plan,
            CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task ResetPasswordAsync(
            KeygenUser user,
            string newPassword,
            CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<string>> ListMachineIdsAsync(
            KeygenUser user,
            CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task RevokeMachineAsync(
            string machineId,
            CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public void Dispose()
        {
        }
    }
}
