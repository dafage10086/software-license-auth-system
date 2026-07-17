using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

internal sealed record OwnerTunnelPaths(
    string ConfigPath,
    string PrivateKeyPath,
    string KnownHostsPath)
{
    internal static OwnerTunnelPaths FromLocalAppData(string localAppData)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(localAppData);
        if (!Path.IsPathFullyQualified(localAppData))
        {
            throw new ArgumentException(
                "LocalAppData path must be absolute.",
                nameof(localAppData));
        }

        var root = Path.Combine(
            Path.GetFullPath(localAppData),
            "SoftwareLicenseAuth",
            "Admin");
        var sshDirectory = Path.Combine(root, "ssh");
        return new OwnerTunnelPaths(
            Path.Combine(root, "admin-tunnel.json"),
            Path.Combine(sshDirectory, "tunnel_ed25519"),
            Path.Combine(sshDirectory, "known_hosts"));
    }

    internal static OwnerTunnelPaths ForCurrentUser()
    {
        var localAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            throw new OwnerTunnelConfigurationException(
                "Current user LocalAppData is unavailable.");
        }

        return FromLocalAppData(localAppData);
    }
}

internal sealed record OwnerTunnelConfiguration(string Host, int Port, string User)
{
    internal const string RequiredHost = "license.example.com";
    internal const int RequiredPort = 22;
    internal const string RequiredUser = "license-auth-tunnel";

    private static readonly JsonSerializerOptions LoadOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal static OwnerTunnelConfiguration Load(OwnerTunnelPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        try
        {
            ValidateArtifact(paths.ConfigPath);
            ValidateArtifact(paths.PrivateKeyPath);
            ValidateArtifact(paths.KnownHostsPath);
            ProtectArtifacts(paths);

            using var stream = File.OpenRead(paths.ConfigPath);
            using var json = JsonDocument.Parse(stream, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });
            if (json.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException("Tunnel configuration root must be an object.");
            }

            var fields = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in json.RootElement.EnumerateObject())
            {
                if (!fields.Add(property.Name))
                {
                    throw new JsonException("Tunnel configuration contains a duplicate field.");
                }
            }

            var document = json.RootElement.Deserialize<ConfigurationDocument>(LoadOptions)
                ?? throw new JsonException("Tunnel configuration is empty.");
            if (!string.Equals(document.Host, RequiredHost, StringComparison.Ordinal)
                || document.Port != RequiredPort
                || !string.Equals(document.User, RequiredUser, StringComparison.Ordinal))
            {
                throw new JsonException("Tunnel configuration values do not match fixed constraints.");
            }

            return new OwnerTunnelConfiguration(
                RequiredHost,
                RequiredPort,
                RequiredUser);
        }
        catch (OwnerTunnelConfigurationException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException
            or UnauthorizedAccessException
            or JsonException
            or NotSupportedException)
        {
            throw new OwnerTunnelConfigurationException(
                "Secure tunnel configuration is unavailable or invalid.",
                error);
        }
    }

    private static void ValidateArtifact(string path)
    {
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path))
        {
            throw new OwnerTunnelConfigurationException(
                "A required secure tunnel artifact is missing.");
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.Directory) != 0
            || (attributes & FileAttributes.ReparsePoint) != 0
            || new FileInfo(path).Length == 0)
        {
            throw new OwnerTunnelConfigurationException(
                "A secure tunnel artifact is invalid.");
        }

        var directory = Path.GetDirectoryName(path)
            ?? throw new OwnerTunnelConfigurationException(
                "A secure tunnel artifact has no directory.");
        while (!string.IsNullOrEmpty(directory))
        {
            if (Directory.Exists(directory)
                && (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            {
                throw new OwnerTunnelConfigurationException(
                    "A secure tunnel directory must not be a reparse point.");
            }

            var parent = Path.GetDirectoryName(directory);
            if (string.Equals(parent, directory, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            directory = parent ?? string.Empty;
        }
    }

    private static void ProtectArtifacts(OwnerTunnelPaths paths)
    {
        var root = Path.GetDirectoryName(paths.ConfigPath)
            ?? throw new OwnerTunnelConfigurationException(
                "Tunnel configuration has no directory.");
        var sshDirectory = Path.GetDirectoryName(paths.PrivateKeyPath)
            ?? throw new OwnerTunnelConfigurationException(
                "Tunnel private key has no directory.");
        ProtectDirectory(root);
        ProtectDirectory(sshDirectory);
        ProtectFile(paths.ConfigPath);
        ProtectFile(paths.PrivateKeyPath);
        ProtectFile(paths.KnownHostsPath);
    }

    private static void ProtectDirectory(string path)
    {
        var (currentUser, localSystem) = GetAllowedSids();
        var directory = new DirectoryInfo(path);
        ValidateTrustedOwner(
            GetOwnerSid(directory.GetAccessControl(AccessControlSections.Owner)),
            currentUser);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddDirectoryRule(security, currentUser);
        AddDirectoryRule(security, localSystem);
        directory.SetAccessControl(security);
    }

    private static void AddDirectoryRule(
        DirectorySecurity security,
        SecurityIdentifier identity)
    {
        security.AddAccessRule(new FileSystemAccessRule(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
    }

    private static void ProtectFile(string path)
    {
        var (currentUser, localSystem) = GetAllowedSids();
        var file = new FileInfo(path);
        ValidateTrustedOwner(
            GetOwnerSid(file.GetAccessControl(AccessControlSections.Owner)),
            currentUser);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            localSystem,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        file.SetAccessControl(security);
    }

    internal static void ValidateTrustedOwner(
        SecurityIdentifier owner,
        SecurityIdentifier currentUser)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(currentUser);
        if (owner.Equals(currentUser)
            || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
            || owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
        {
            return;
        }

        throw new OwnerTunnelConfigurationException(
            "Secure tunnel artifact owner is not trusted.");
    }

    private static SecurityIdentifier GetOwnerSid(FileSystemSecurity security)
    {
        return security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new OwnerTunnelConfigurationException(
                "Secure tunnel artifact owner is unavailable.");
    }

    private static (SecurityIdentifier CurrentUser, SecurityIdentifier LocalSystem)
        GetAllowedSids()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new OwnerTunnelConfigurationException(
                "Current Windows user has no SID.");
        var localSystem = new SecurityIdentifier(
            WellKnownSidType.LocalSystemSid,
            domainSid: null);
        return (currentUser, localSystem);
    }

    private sealed class ConfigurationDocument
    {
        [JsonPropertyName("host")]
        public string? Host { get; init; }

        [JsonPropertyName("port")]
        public int Port { get; init; }

        [JsonPropertyName("user")]
        public string? User { get; init; }
    }
}

internal sealed class OwnerTunnelConfigurationException : Exception
{
    internal OwnerTunnelConfigurationException(string message)
        : base(message)
    {
    }

    internal OwnerTunnelConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

internal sealed class OwnerTunnelConnectionException : Exception
{
    internal OwnerTunnelConnectionException(string message)
        : base(message)
    {
    }

    internal OwnerTunnelConnectionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

internal enum TunnelReadinessResult
{
    Ready,
    ProcessExited,
    TimedOut
}

internal interface IOwnerSecureTunnel : IDisposable
{
    Task EnsureStartedAsync(CancellationToken cancellationToken);
}

internal interface IOwnerTunnelProcess : IDisposable
{
    bool HasExited { get; }

    void Terminate();
}

internal interface IOwnerTunnelProcessLauncher
{
    IOwnerTunnelProcess Start(ProcessStartInfo startInfo);
}

internal interface IOwnerTunnelJob : IDisposable
{
}

internal interface IOwnerTunnelJobBinder
{
    IOwnerTunnelJob Assign(IOwnerTunnelProcess process);
}

internal interface IOwnerTunnelReadiness
{
    Task<bool> IsPortOccupiedAsync(
        int localPort,
        CancellationToken cancellationToken);

    Task<TunnelReadinessResult> WaitAsync(
        int localPort,
        IOwnerTunnelProcess process,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

internal sealed class OpenSshTunnel : IOwnerSecureTunnel
{
    private const int LocalPort = 18788;
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(8);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly IOwnerTunnelProcessLauncher _launcher;
    private readonly OwnerTunnelPaths _paths;
    private readonly IOwnerTunnelReadiness _readiness;
    private readonly string _sshExecutable;
    private bool _disposed;
    private IOwnerTunnelProcess? _process;

    internal OpenSshTunnel(
        OwnerTunnelPaths paths,
        string sshExecutable,
        IOwnerTunnelProcessLauncher launcher,
        IOwnerTunnelReadiness readiness)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        ArgumentException.ThrowIfNullOrWhiteSpace(sshExecutable);
        if (!Path.IsPathFullyQualified(sshExecutable))
        {
            throw new ArgumentException(
                "OpenSSH executable path must be absolute.",
                nameof(sshExecutable));
        }

        _sshExecutable = Path.GetFullPath(sshExecutable);
        _launcher = launcher ?? throw new ArgumentNullException(nameof(launcher));
        _readiness = readiness ?? throw new ArgumentNullException(nameof(readiness));
    }

    internal static OpenSshTunnel CreateForCurrentUser()
    {
        var sshExecutable = Path.Combine(
            Environment.SystemDirectory,
            "OpenSSH",
            "ssh.exe");
        return new OpenSshTunnel(
            OwnerTunnelPaths.ForCurrentUser(),
            sshExecutable,
            new OwnerTunnelProcessLauncher(),
            new LoopbackTunnelReadiness());
    }

    public async Task EnsureStartedAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_process is not null && !_process.HasExited)
            {
                var cachedReadiness = await _readiness.WaitAsync(
                        LocalPort,
                        _process,
                        StartupTimeout,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (cachedReadiness == TunnelReadinessResult.Ready
                    && !_process.HasExited)
                {
                    return;
                }
            }

            var processToStop = _process;
            _process = null;
            StopProcess(processToStop);
            var configuration = OwnerTunnelConfiguration.Load(_paths);
            if (!File.Exists(_sshExecutable))
            {
                throw new OwnerTunnelConnectionException(
                    "Windows OpenSSH client is unavailable.");
            }

            if (await _readiness.IsPortOccupiedAsync(LocalPort, cancellationToken)
                    .ConfigureAwait(false))
            {
                throw new OwnerTunnelConnectionException(
                    "The secure tunnel loopback port is already occupied.");
            }

            IOwnerTunnelProcess? process = null;
            try
            {
                process = _launcher.Start(BuildStartInfo(configuration));
                var readiness = await _readiness.WaitAsync(
                        LocalPort,
                        process,
                        StartupTimeout,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (readiness != TunnelReadinessResult.Ready || process.HasExited)
                {
                    throw new OwnerTunnelConnectionException(
                        "OpenSSH tunnel did not become ready.");
                }

                _process = process;
                process = null;
            }
            catch (OperationCanceledException)
            {
                StopProcess(process);
                throw;
            }
            catch (OwnerTunnelConnectionException)
            {
                StopProcess(process);
                throw;
            }
            catch (Exception error) when (error is IOException
                or InvalidOperationException
                or Win32Exception)
            {
                StopProcess(process);
                throw new OwnerTunnelConnectionException(
                    "OpenSSH tunnel could not be started.",
                    error);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        _gate.Wait();
        try
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            var processToStop = _process;
            _process = null;
            StopProcess(processToStop);
        }
        finally
        {
            _gate.Release();
        }
    }

    private ProcessStartInfo BuildStartInfo(OwnerTunnelConfiguration configuration)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _sshExecutable,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        Add(startInfo, "-F", "NUL");
        startInfo.ArgumentList.Add("-N");
        startInfo.ArgumentList.Add("-T");
        AddOption(startInfo, "BatchMode=yes");
        AddOption(startInfo, "StrictHostKeyChecking=yes");
        AddOption(startInfo, "ExitOnForwardFailure=yes");
        AddOption(startInfo, "IdentitiesOnly=yes");
        AddOption(startInfo, "PasswordAuthentication=no");
        AddOption(startInfo, "KbdInteractiveAuthentication=no");
        AddOption(startInfo, "LogLevel=ERROR");
        AddOption(startInfo, $"UserKnownHostsFile={_paths.KnownHostsPath}");
        AddOption(startInfo, "GlobalKnownHostsFile=NUL");
        Add(startInfo, "-i", _paths.PrivateKeyPath);
        Add(startInfo, "-p", configuration.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(startInfo, "-L", "127.0.0.1:18788:127.0.0.1:18788");
        startInfo.ArgumentList.Add($"{configuration.User}@{configuration.Host}");
        return startInfo;
    }

    private static void AddOption(ProcessStartInfo startInfo, string option)
    {
        Add(startInfo, "-o", option);
    }

    private static void Add(ProcessStartInfo startInfo, string name, string value)
    {
        startInfo.ArgumentList.Add(name);
        startInfo.ArgumentList.Add(value);
    }

    private static void StopProcess(IOwnerTunnelProcess? process)
    {
        if (process is null)
        {
            return;
        }

        try
        {
            if (!process.HasExited)
            {
                process.Terminate();
            }
        }
        finally
        {
            process.Dispose();
        }
    }
}

internal sealed class OwnerTunnelProcessLauncher : IOwnerTunnelProcessLauncher
{
    private readonly IOwnerTunnelJobBinder _jobBinder;
    private readonly Func<ProcessStartInfo, IOwnerTunnelProcess> _processStarter;

    internal OwnerTunnelProcessLauncher()
        : this(StartProcess, new WindowsOwnerTunnelJobBinder())
    {
    }

    internal OwnerTunnelProcessLauncher(
        Func<ProcessStartInfo, IOwnerTunnelProcess> processStarter,
        IOwnerTunnelJobBinder jobBinder)
    {
        _processStarter = processStarter ?? throw new ArgumentNullException(nameof(processStarter));
        _jobBinder = jobBinder ?? throw new ArgumentNullException(nameof(jobBinder));
    }

    public IOwnerTunnelProcess Start(ProcessStartInfo startInfo)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        var process = _processStarter(startInfo);
        try
        {
            var job = _jobBinder.Assign(process);
            return new JobBoundOwnerTunnelProcess(process, job);
        }
        catch (Exception error)
        {
            StopAfterJobAssignmentFailure(process);
            throw new OwnerTunnelConnectionException(
                "OpenSSH tunnel process job assignment failed.",
                error);
        }
    }

    private static IOwnerTunnelProcess StartProcess(ProcessStartInfo startInfo)
    {
        var process = new Process
        {
            StartInfo = startInfo,
            EnableRaisingEvents = false
        };
        try
        {
            if (!process.Start())
            {
                throw new InvalidOperationException("OpenSSH process did not start.");
            }

            process.OutputDataReceived += static (_, _) => { };
            process.ErrorDataReceived += static (_, _) => { };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            return new OwnerTunnelProcess(process);
        }
        catch
        {
            process.Dispose();
            throw;
        }
    }

    private static void StopAfterJobAssignmentFailure(IOwnerTunnelProcess process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Terminate();
            }
        }
        catch
        {
        }
        finally
        {
            process.Dispose();
        }
    }
}

internal sealed class OwnerTunnelProcess(Process process) : IOwnerTunnelProcess
{
    internal SafeProcessHandle SafeHandle => process.SafeHandle;

    public bool HasExited => process.HasExited;

    public void Terminate()
    {
        if (process.HasExited)
        {
            return;
        }

        try
        {
            process.Kill(entireProcessTree: true);
            if (!process.WaitForExit(milliseconds: 5000))
            {
                throw new OwnerTunnelConnectionException(
                    "OpenSSH tunnel process did not exit after termination.");
            }
        }
        catch (InvalidOperationException error)
        {
            if (!HasExitedAfterTerminationRace())
            {
                throw new OwnerTunnelConnectionException(
                    "OpenSSH tunnel process could not be terminated.",
                    error);
            }
        }
        catch (Win32Exception error)
        {
            if (!HasExitedAfterTerminationRace())
            {
                throw new OwnerTunnelConnectionException(
                    "OpenSSH tunnel process could not be terminated.",
                    error);
            }
        }
    }

    public void Dispose()
    {
        process.Dispose();
    }

    private bool HasExitedAfterTerminationRace()
    {
        try
        {
            return process.HasExited;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}

internal sealed class JobBoundOwnerTunnelProcess(
    IOwnerTunnelProcess process,
    IOwnerTunnelJob job) : IOwnerTunnelProcess
{
    private bool _disposed;

    public bool HasExited => process.HasExited;

    public void Terminate()
    {
        process.Terminate();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            job.Dispose();
        }
        finally
        {
            process.Dispose();
        }
    }
}

internal sealed class WindowsOwnerTunnelJobBinder : IOwnerTunnelJobBinder
{
    public IOwnerTunnelJob Assign(IOwnerTunnelProcess process)
    {
        if (process is not OwnerTunnelProcess windowsProcess)
        {
            throw new InvalidOperationException(
                "Only a started Windows OpenSSH process can be assigned to the tunnel job.");
        }

        var jobHandle = NativeMethods.CreateJobObjectW(IntPtr.Zero, null);
        if (jobHandle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            jobHandle.Dispose();
            throw new Win32Exception(error);
        }

        try
        {
            var information = new NativeMethods.JobObjectExtendedLimitInformation
            {
                BasicLimitInformation = new NativeMethods.JobObjectBasicLimitInformation
                {
                    LimitFlags = NativeMethods.JobObjectLimitKillOnJobClose
                }
            };
            if (!NativeMethods.SetInformationJobObject(
                    jobHandle,
                    NativeMethods.JobObjectExtendedLimitInformationClass,
                    ref information,
                    (uint)Marshal.SizeOf<NativeMethods.JobObjectExtendedLimitInformation>()))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!NativeMethods.AssignProcessToJobObject(jobHandle, windowsProcess.SafeHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return new WindowsOwnerTunnelJob(jobHandle);
        }
        catch
        {
            jobHandle.Dispose();
            throw;
        }
    }

    private sealed class WindowsOwnerTunnelJob(SafeFileHandle handle) : IOwnerTunnelJob
    {
        public void Dispose()
        {
            handle.Dispose();
        }
    }

    private static class NativeMethods
    {
        internal const uint JobObjectLimitKillOnJobClose = 0x00002000;
        internal const int JobObjectExtendedLimitInformationClass = 9;

        [StructLayout(LayoutKind.Sequential)]
        internal struct JobObjectBasicLimitInformation
        {
            internal long PerProcessUserTimeLimit;
            internal long PerJobUserTimeLimit;
            internal uint LimitFlags;
            internal UIntPtr MinimumWorkingSetSize;
            internal UIntPtr MaximumWorkingSetSize;
            internal uint ActiveProcessLimit;
            internal UIntPtr Affinity;
            internal uint PriorityClass;
            internal uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IoCounters
        {
            internal ulong ReadOperationCount;
            internal ulong WriteOperationCount;
            internal ulong OtherOperationCount;
            internal ulong ReadTransferCount;
            internal ulong WriteTransferCount;
            internal ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JobObjectExtendedLimitInformation
        {
            internal JobObjectBasicLimitInformation BasicLimitInformation;
            internal IoCounters IoInfo;
            internal UIntPtr ProcessMemoryLimit;
            internal UIntPtr JobMemoryLimit;
            internal UIntPtr PeakProcessMemoryUsed;
            internal UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SafeFileHandle CreateJobObjectW(
            IntPtr jobAttributes,
            string? name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetInformationJobObject(
            SafeFileHandle job,
            int informationClass,
            ref JobObjectExtendedLimitInformation information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AssignProcessToJobObject(
            SafeFileHandle job,
            SafeProcessHandle process);
    }
}

internal sealed class LoopbackTunnelReadiness : IOwnerTunnelReadiness
{
    public async Task<bool> IsPortOccupiedAsync(
        int localPort,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = new TcpClient(AddressFamily.InterNetwork);
            await client.ConnectAsync(
                    IPAddress.Loopback,
                    localPort,
                    cancellationToken)
                .ConfigureAwait(false);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    public async Task<TunnelReadinessResult> WaitAsync(
        int localPort,
        IOwnerTunnelProcess process,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var consecutiveConnections = 0;
        while (stopwatch.Elapsed < timeout)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (process.HasExited)
            {
                return TunnelReadinessResult.ProcessExited;
            }

            try
            {
                using var client = new TcpClient(AddressFamily.InterNetwork);
                await client.ConnectAsync(
                        IPAddress.Loopback,
                        localPort,
                        cancellationToken)
                    .ConfigureAwait(false);
                consecutiveConnections++;
                if (consecutiveConnections >= 2)
                {
                    return process.HasExited
                        ? TunnelReadinessResult.ProcessExited
                        : TunnelReadinessResult.Ready;
                }
            }
            catch (SocketException)
            {
                consecutiveConnections = 0;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken)
                .ConfigureAwait(false);
        }

        return TunnelReadinessResult.TimedOut;
    }
}
