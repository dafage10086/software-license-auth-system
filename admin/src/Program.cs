using System.Drawing;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        return RunAsync(args).GetAwaiter().GetResult();
    }

    private static async Task<int> RunAsync(string[] args)
    {
        using var runtime = new OwnerRuntime();
        if (args.Length == 0)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new OwnerAdminForm(runtime));
            return 0;
        }

        var cli = new OwnerCli(
            runtime.CreateOperationsAsync,
            ConsoleSecretReader.Read,
            runtime.SaveToken,
            OwnerPasswordGenerator.Generate);
        return await cli.RunAsync(args, Console.Out, Console.Error);
    }
}

internal interface IKeygenAdminOperations : IDisposable
{
    Task<KeygenUser> FindOrCreateUserAsync(
        string username,
        string password,
        string customer,
        CancellationToken cancellationToken);

    Task<KeygenLicense> EnsureTrialAsync(
        KeygenUser user,
        CancellationToken cancellationToken);

    Task<KeygenLicense> IssuePaidAsync(
        KeygenUser user,
        string plan,
        CancellationToken cancellationToken);

    Task ResetPasswordAsync(
        KeygenUser user,
        string newPassword,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<string>> ListMachineIdsAsync(
        KeygenUser user,
        CancellationToken cancellationToken);

    Task RevokeMachineAsync(
        string machineId,
        CancellationToken cancellationToken);
}

internal sealed class KeygenAdminOperations : IKeygenAdminOperations
{
    private readonly KeygenAdminClient _client;

    internal KeygenAdminOperations(
        OwnerConfig config,
        string adminToken)
    {
        _client = new KeygenAdminClient(config, adminToken);
    }

    public Task<KeygenUser> FindOrCreateUserAsync(
        string username,
        string password,
        string customer,
        CancellationToken cancellationToken)
    {
        return _client.FindOrCreateUserAsync(
            username,
            password,
            customer,
            cancellationToken);
    }

    public Task<KeygenLicense> EnsureTrialAsync(
        KeygenUser user,
        CancellationToken cancellationToken)
    {
        return _client.EnsureTrialAsync(user, cancellationToken);
    }

    public Task<KeygenLicense> IssuePaidAsync(
        KeygenUser user,
        string plan,
        CancellationToken cancellationToken)
    {
        return _client.IssuePaidAsync(user, plan, cancellationToken);
    }

    public Task ResetPasswordAsync(
        KeygenUser user,
        string newPassword,
        CancellationToken cancellationToken)
    {
        return _client.ResetPasswordAsync(user, newPassword, cancellationToken);
    }

    public Task<IReadOnlyList<string>> ListMachineIdsAsync(
        KeygenUser user,
        CancellationToken cancellationToken)
    {
        return _client.ListMachineIdsAsync(user, cancellationToken);
    }

    public Task RevokeMachineAsync(
        string machineId,
        CancellationToken cancellationToken)
    {
        return _client.RevokeMachineAsync(machineId, cancellationToken);
    }

    public void Dispose()
    {
        _client.Dispose();
    }
}

internal sealed class OwnerRuntime : IDisposable
{
    private readonly Func<bool> _hasSavedToken;
    private readonly Func<string, IKeygenAdminOperations> _operationsFactory;
    private readonly IOwnerSecureTunnel _secureTunnel;
    private readonly Func<string> _tokenLoader;
    private readonly Action<string> _tokenSaver;
    private bool _disposed;

    internal OwnerRuntime()
        : this(
            () => AdminTokenStore.CreateForCurrentUser().HasSavedToken,
            () => AdminTokenStore.CreateForCurrentUser().Load(),
            token => AdminTokenStore.CreateForCurrentUser().Save(token),
            OpenSshTunnel.CreateForCurrentUser(),
            token => new KeygenAdminOperations(
                LoadConfigForOperations(ConfigPath),
                token))
    {
    }

    internal OwnerRuntime(Func<bool> hasSavedToken, Action<string> tokenSaver)
        : this(
            hasSavedToken,
            () => throw new InvalidOperationException("Token loading is not configured."),
            tokenSaver,
            new NoOpOwnerSecureTunnel(),
            _ => throw new InvalidOperationException("Operations are not configured."))
    {
    }

    internal OwnerRuntime(
        Func<bool> hasSavedToken,
        Func<string> tokenLoader,
        Action<string> tokenSaver,
        IOwnerSecureTunnel secureTunnel,
        Func<string, IKeygenAdminOperations> operationsFactory)
    {
        _hasSavedToken = hasSavedToken ?? throw new ArgumentNullException(nameof(hasSavedToken));
        _tokenLoader = tokenLoader ?? throw new ArgumentNullException(nameof(tokenLoader));
        _tokenSaver = tokenSaver ?? throw new ArgumentNullException(nameof(tokenSaver));
        _secureTunnel = secureTunnel ?? throw new ArgumentNullException(nameof(secureTunnel));
        _operationsFactory = operationsFactory
            ?? throw new ArgumentNullException(nameof(operationsFactory));
    }

    internal static string ConfigPath =>
        Path.Combine(AppContext.BaseDirectory, "admin-config.json");

    internal bool HasSavedToken => _hasSavedToken();

    internal async Task<IKeygenAdminOperations> CreateOperationsAsync(
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string token;
        try
        {
            token = _tokenLoader();
        }
        catch (Exception error) when (error is IOException
            or UnauthorizedAccessException
            or CryptographicException)
        {
            throw new OwnerRuntimeException(
                OwnerFailureMessages.MissingAdminCredential,
                error);
        }

        await EnsureTunnelAsync(cancellationToken);

        return _operationsFactory(token);
    }

    internal async Task EnsureTunnelAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        try
        {
            await _secureTunnel.EnsureStartedAsync(cancellationToken);
        }
        catch (OwnerTunnelConfigurationException error)
        {
            throw new OwnerRuntimeException(
                OwnerFailureMessages.TunnelConfigurationIncomplete,
                error);
        }
        catch (OwnerTunnelConnectionException error)
        {
            throw new OwnerRuntimeException(
                OwnerFailureMessages.TunnelConnectionFailed,
                error);
        }
    }

    internal static OwnerConfig LoadConfigForOperations(string path)
    {
        return OwnerConfig.Load(path);
    }

    internal void SaveToken(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        _tokenSaver(token);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _secureTunnel.Dispose();
    }

    private sealed class NoOpOwnerSecureTunnel : IOwnerSecureTunnel
    {
        public Task EnsureStartedAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public void Dispose()
        {
        }
    }
}

internal sealed class OwnerRuntimeException : Exception
{
    internal OwnerRuntimeException(string userMessage, Exception innerException)
        : base("Owner runtime initialization failed.", innerException)
    {
        UserMessage = userMessage;
    }

    internal string UserMessage { get; }
}

internal static class ConsoleSecretReader
{
    internal static string Read()
    {
        if (Console.IsInputRedirected)
        {
            return Console.In.ReadLine() ?? string.Empty;
        }

        var value = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                return value.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (value.Length > 0)
                {
                    value.Length--;
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                value.Append(key.KeyChar);
            }
        }
    }
}

internal static class OwnerPasswordGenerator
{
    internal static string Generate()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

internal interface IOwnerClipboard
{
    void SetText(string text);
}

internal sealed class WindowsOwnerClipboard : IOwnerClipboard
{
    private const int RetryTimes = 50;
    private const int RetryDelayMilliseconds = 100;
    private readonly Action<object, bool, int, int> _setDataObject;

    internal WindowsOwnerClipboard()
        : this(Clipboard.SetDataObject)
    {
    }

    internal WindowsOwnerClipboard(Action<object, bool, int, int> setDataObject)
    {
        _setDataObject = setDataObject
            ?? throw new ArgumentNullException(nameof(setDataObject));
    }

    public void SetText(string text)
    {
        _setDataObject(text, true, RetryTimes, RetryDelayMilliseconds);
    }
}

internal static class OwnerFailureMessages
{
    internal const string MissingAdminCredential =
        "未找到管理员令牌，请先保存管理员令牌。";
    internal const string InvalidAdminCredential =
        "管理员令牌无效或已失效，请重新保存管理员令牌后重试。";
    internal const string TunnelConfigurationIncomplete =
        "安全隧道配置不完整，请检查隧道配置、私钥和 known_hosts。";
    internal const string TunnelConnectionFailed =
        "安全隧道连接失败，请检查 SSH 服务后重试。";
    internal const string NetworkFailure =
        "网络连接失败，请检查本机网络和安全隧道后重试。";
}

internal sealed record OwnerOperationResult(
    bool Succeeded,
    string Output,
    bool IsPartialSuccess = false,
    bool IsCommitStateUnknown = false,
    string? MachineIdToFill = null)
{
    internal static OwnerOperationResult Success(
        string output,
        string? machineIdToFill = null)
    {
        return new OwnerOperationResult(
            true,
            output,
            MachineIdToFill: machineIdToFill);
    }

    internal static OwnerOperationResult Failure(string output)
    {
        return new OwnerOperationResult(false, output);
    }

    internal static OwnerOperationResult PartialSuccess(string output)
    {
        return new OwnerOperationResult(false, output, true);
    }

    internal static OwnerOperationResult CommitStateUnknown(string output)
    {
        return new OwnerOperationResult(
            false,
            output,
            IsPartialSuccess: false,
            IsCommitStateUnknown: true);
    }
}

internal sealed class OwnerWorkflow
{
    private static readonly TimeSpan ProductionOperationTimeout = TimeSpan.FromSeconds(8);
    internal const string AccountFailure =
        "账号创建失败，请检查输入、配置和网络后重试。";
    internal const string IssueFailure =
        "授权失败，请检查账号选择、配置和网络后重试。";
    internal const string ResetFailure =
        "密码重置失败，请检查账号选择、配置和网络后重试。";
    internal const string RevokeFailure =
        "机器解绑失败，请检查机器 ID、配置和网络后重试。";
    internal const string MachineQueryFailure =
        "机器查询失败，请确认已选择账号后重试。";
    internal const string CommitStateUnknownWarning =
        "CommitStateUnknown: 操作可能已提交，请先核实远端状态再重试。";

    private readonly IKeygenAdminOperations _admin;
    private readonly TimeSpan _operationTimeout;
    private readonly Func<string> _passwordFactory;
    private string _selectedUsername = string.Empty;

    internal OwnerWorkflow(
        IKeygenAdminOperations admin,
        Func<string>? passwordFactory = null)
        : this(admin, passwordFactory, ProductionOperationTimeout)
    {
    }

    internal OwnerWorkflow(
        IKeygenAdminOperations admin,
        Func<string>? passwordFactory,
        TimeSpan operationTimeout)
    {
        if (operationTimeout <= TimeSpan.Zero
            || operationTimeout > ProductionOperationTimeout)
        {
            throw new ArgumentOutOfRangeException(nameof(operationTimeout));
        }

        _admin = admin ?? throw new ArgumentNullException(nameof(admin));
        _passwordFactory = passwordFactory ?? OwnerPasswordGenerator.Generate;
        _operationTimeout = operationTimeout;
    }

    internal KeygenUser? SelectedUser { get; private set; }

    internal async Task<OwnerOperationResult> CreateAccountAsync(
        string username,
        string customer,
        string? initialPassword = null)
    {
        using var deadline = CreateDeadline();
        var cancellationToken = deadline.Token;
        var password = initialPassword ?? _passwordFactory();
        string normalizedUsername = string.Empty;
        KeygenUser user;
        try
        {
            normalizedUsername = AccountNaming.Normalize(username);
            var normalizedCustomer = customer.Trim();
            if (normalizedCustomer.Length == 0)
            {
                return OwnerOperationResult.Failure(AccountFailure);
            }

            user = await _admin.FindOrCreateUserAsync(
                normalizedUsername,
                password,
                normalizedCustomer,
                cancellationToken);
        }
        catch (KeygenAdminException error) when (error.CommitStateUnknown)
        {
            return OwnerOperationResult.CommitStateUnknown(
                FormatCommitStateUnknown(normalizedUsername));
        }
        catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.InvalidAdminCredential);
        }
        catch (KeygenAdminException error) when (error.IsNetworkFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.NetworkFailure);
        }
        catch
        {
            return OwnerOperationResult.Failure(AccountFailure);
        }

        SelectUser(normalizedUsername, user);

        try
        {
            var trial = await _admin.EnsureTrialAsync(user, cancellationToken);
            return OwnerOperationResult.Success(
                FormatAccount(normalizedUsername, user, trial, password));
        }
        catch (KeygenAdminException error) when (error.CommitStateUnknown)
        {
            return OwnerOperationResult.CommitStateUnknown(
                FormatCommitStateUnknown(normalizedUsername));
        }
        catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
        {
            return user.WasCreated
                ? OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        password,
                        OwnerFailureMessages.InvalidAdminCredential))
                : OwnerOperationResult.Failure(OwnerFailureMessages.InvalidAdminCredential);
        }
        catch (KeygenAdminException error) when (error.IsNetworkFailure)
        {
            return user.WasCreated
                ? OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        password,
                        "部分成功：账号已创建，但网络连接失败，请稍后重试试用授权。"))
                : OwnerOperationResult.Failure(OwnerFailureMessages.NetworkFailure);
        }
        catch
        {
            return user.WasCreated
                ? OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        password,
                        "部分成功：账号已创建，但试用授权失败，请稍后重试试用授权。"))
                : OwnerOperationResult.Failure(AccountFailure);
        }
    }

    internal async Task<OwnerOperationResult> IssueSelectedLicenseAsync(string plan)
    {
        using var deadline = CreateDeadline();
        var cancellationToken = deadline.Token;
        if (SelectedUser is null || !TryNormalizePlan(plan, out var normalizedPlan))
        {
            return OwnerOperationResult.Failure(IssueFailure);
        }

        try
        {
            var license = await _admin.IssuePaidAsync(
                SelectedUser,
                normalizedPlan,
                cancellationToken);
            return OwnerOperationResult.Success(
                FormatLicense(_selectedUsername, license, null));
        }
        catch (KeygenAdminException error) when (error.CommitStateUnknown)
        {
            return OwnerOperationResult.CommitStateUnknown(
                FormatCommitStateUnknown(_selectedUsername));
        }
        catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.InvalidAdminCredential);
        }
        catch (KeygenAdminException error) when (error.IsNetworkFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.NetworkFailure);
        }
        catch
        {
            return OwnerOperationResult.Failure(IssueFailure);
        }
    }

    internal async Task<OwnerOperationResult> ResetSelectedPasswordAsync()
    {
        using var deadline = CreateDeadline();
        var cancellationToken = deadline.Token;
        if (SelectedUser is null)
        {
            return OwnerOperationResult.Failure(ResetFailure);
        }

        var newPassword = _passwordFactory();
        try
        {
            await _admin.ResetPasswordAsync(
                SelectedUser,
                newPassword,
                cancellationToken);
            return OwnerOperationResult.Success(
                FormatPasswordReset(_selectedUsername, newPassword));
        }
        catch (KeygenAdminException error) when (error.CommitStateUnknown)
        {
            return OwnerOperationResult.CommitStateUnknown(
                FormatCommitStateUnknown(_selectedUsername));
        }
        catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.InvalidAdminCredential);
        }
        catch (KeygenAdminException error) when (error.IsNetworkFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.NetworkFailure);
        }
        catch
        {
            return OwnerOperationResult.Failure(ResetFailure);
        }
    }

    internal async Task<OwnerOperationResult> IssueLicenseForCliAsync(
        string username,
        string plan)
    {
        using var deadline = CreateDeadline();
        var cancellationToken = deadline.Token;
        if (!TryNormalizePlan(plan, out var normalizedPlan))
        {
            return OwnerOperationResult.Failure(IssueFailure);
        }

        var initialPassword = _passwordFactory();
        string normalizedUsername = string.Empty;
        KeygenUser user;
        try
        {
            normalizedUsername = AccountNaming.Normalize(username);
            user = await _admin.FindOrCreateUserAsync(
                normalizedUsername,
                initialPassword,
                string.Empty,
                cancellationToken);
        }
        catch (KeygenAdminException error) when (error.CommitStateUnknown)
        {
            return OwnerOperationResult.CommitStateUnknown(
                FormatCommitStateUnknown(normalizedUsername));
        }
        catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.InvalidAdminCredential);
        }
        catch (KeygenAdminException error) when (error.IsNetworkFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.NetworkFailure);
        }
        catch
        {
            return OwnerOperationResult.Failure(IssueFailure);
        }

        SelectUser(normalizedUsername, user);
        if (user.WasCreated)
        {
            try
            {
                await _admin.EnsureTrialAsync(user, cancellationToken);
            }
            catch (KeygenAdminException error) when (error.CommitStateUnknown)
            {
                return OwnerOperationResult.CommitStateUnknown(
                    FormatCommitStateUnknown(normalizedUsername));
            }
            catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
            {
                return OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        initialPassword,
                        OwnerFailureMessages.InvalidAdminCredential));
            }
            catch (KeygenAdminException error) when (error.IsNetworkFailure)
            {
                return OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        initialPassword,
                        "部分成功：账号已创建，但网络连接失败，未签发付费授权。"));
            }
            catch
            {
                return OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        initialPassword,
                        "部分成功：账号已创建，但试用授权失败，未签发付费授权。"));
            }
        }

        try
        {
            var license = await _admin.IssuePaidAsync(
                user,
                normalizedPlan,
                cancellationToken);
            return OwnerOperationResult.Success(
                FormatLicense(
                    normalizedUsername,
                    license,
                    user.WasCreated ? initialPassword : null));
        }
        catch (KeygenAdminException error) when (error.CommitStateUnknown)
        {
            return OwnerOperationResult.CommitStateUnknown(
                FormatCommitStateUnknown(normalizedUsername));
        }
        catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
        {
            return user.WasCreated
                ? OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        initialPassword,
                        OwnerFailureMessages.InvalidAdminCredential))
                : OwnerOperationResult.Failure(OwnerFailureMessages.InvalidAdminCredential);
        }
        catch (KeygenAdminException error) when (error.IsNetworkFailure)
        {
            return user.WasCreated
                ? OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        initialPassword,
                        "部分成功：账号已创建，但网络连接失败，请稍后重试授权。"))
                : OwnerOperationResult.Failure(OwnerFailureMessages.NetworkFailure);
        }
        catch
        {
            return user.WasCreated
                ? OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        initialPassword,
                        "部分成功：账号已创建，但付费授权失败，请稍后重试授权。"))
                : OwnerOperationResult.Failure(IssueFailure);
        }
    }

    internal async Task<OwnerOperationResult> ResetPasswordForCliAsync(string username)
    {
        using var deadline = CreateDeadline();
        var cancellationToken = deadline.Token;
        var newPassword = _passwordFactory();
        string normalizedUsername = string.Empty;
        KeygenUser user;
        try
        {
            normalizedUsername = AccountNaming.Normalize(username);
            user = await _admin.FindOrCreateUserAsync(
                normalizedUsername,
                newPassword,
                string.Empty,
                cancellationToken);
        }
        catch (KeygenAdminException error) when (error.CommitStateUnknown)
        {
            return OwnerOperationResult.CommitStateUnknown(
                FormatCommitStateUnknown(normalizedUsername));
        }
        catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.InvalidAdminCredential);
        }
        catch (KeygenAdminException error) when (error.IsNetworkFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.NetworkFailure);
        }
        catch
        {
            return OwnerOperationResult.Failure(ResetFailure);
        }

        SelectUser(normalizedUsername, user);

        try
        {
            await _admin.ResetPasswordAsync(
                user,
                newPassword,
                cancellationToken);
            return OwnerOperationResult.Success(
                FormatPasswordReset(normalizedUsername, newPassword));
        }
        catch (KeygenAdminException error) when (error.CommitStateUnknown)
        {
            return OwnerOperationResult.CommitStateUnknown(
                FormatCommitStateUnknown(normalizedUsername));
        }
        catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
        {
            return user.WasCreated
                ? OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        newPassword,
                        OwnerFailureMessages.InvalidAdminCredential))
                : OwnerOperationResult.Failure(OwnerFailureMessages.InvalidAdminCredential);
        }
        catch (KeygenAdminException error) when (error.IsNetworkFailure)
        {
            return user.WasCreated
                ? OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        newPassword,
                        "部分成功：账号已创建，但网络连接失败；以下初始密码仍然有效。"))
                : OwnerOperationResult.Failure(OwnerFailureMessages.NetworkFailure);
        }
        catch
        {
            return user.WasCreated
                ? OwnerOperationResult.PartialSuccess(
                    FormatCreatedUserPartial(
                        normalizedUsername,
                        user,
                        newPassword,
                        "部分成功：账号已创建，但密码重置失败；以下初始密码仍然有效。"))
                : OwnerOperationResult.Failure(ResetFailure);
        }
    }

    internal async Task<OwnerOperationResult> RevokeMachineAsync(string machineId)
    {
        using var deadline = CreateDeadline();
        var cancellationToken = deadline.Token;
        try
        {
            var normalizedMachineId = machineId.Trim();
            if (!KeygenAdminClient.IsValidResourceId(normalizedMachineId))
            {
                return OwnerOperationResult.Failure(RevokeFailure);
            }

            await _admin.RevokeMachineAsync(
                normalizedMachineId,
                cancellationToken);
            return OwnerOperationResult.Success("机器解绑成功。");
        }
        catch (KeygenAdminException error) when (error.CommitStateUnknown)
        {
            return OwnerOperationResult.CommitStateUnknown(
                FormatCommitStateUnknown(string.Empty));
        }
        catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.InvalidAdminCredential);
        }
        catch (KeygenAdminException error) when (error.IsNetworkFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.NetworkFailure);
        }
        catch
        {
            return OwnerOperationResult.Failure(RevokeFailure);
        }
    }

    internal async Task<OwnerOperationResult> QuerySelectedMachinesAsync()
    {
        using var deadline = CreateDeadline();
        if (SelectedUser is null)
        {
            return OwnerOperationResult.Failure(MachineQueryFailure);
        }

        try
        {
            var machineIds = await _admin.ListMachineIdsAsync(
                SelectedUser,
                deadline.Token);
            if (machineIds.Count > 500
                || machineIds.Any(id => !KeygenAdminClient.IsValidResourceId(id))
                || machineIds.Distinct(StringComparer.Ordinal).Count() != machineIds.Count)
            {
                return OwnerOperationResult.Failure(MachineQueryFailure);
            }

            var sortedIds = machineIds.Order(StringComparer.Ordinal).ToArray();
            if (sortedIds.Length == 0)
            {
                return OwnerOperationResult.Success("未查询到已绑定机器。");
            }

            if (sortedIds.Length == 1)
            {
                return OwnerOperationResult.Success(
                    $"查询到 1 台机器。{Environment.NewLine}机器 ID: {sortedIds[0]}",
                    sortedIds[0]);
            }

            var lines = new List<string>
            {
                $"查询到 {sortedIds.Length} 台机器，请将需要解绑的单个机器 ID 填入输入框："
            };
            lines.AddRange(sortedIds.Select(id => $"机器 ID: {id}"));
            return OwnerOperationResult.Success(string.Join(Environment.NewLine, lines));
        }
        catch (KeygenAdminException error) when (error.IsAuthenticationFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.InvalidAdminCredential);
        }
        catch (KeygenAdminException error) when (error.IsNetworkFailure)
        {
            return OwnerOperationResult.Failure(OwnerFailureMessages.NetworkFailure);
        }
        catch
        {
            return OwnerOperationResult.Failure(MachineQueryFailure);
        }
    }

    private CancellationTokenSource CreateDeadline()
    {
        return new CancellationTokenSource(_operationTimeout);
    }

    private static string FormatAccount(
        string username,
        KeygenUser user,
        KeygenLicense trial,
        string initialPassword)
    {
        var lines = new List<string>
        {
            user.WasCreated ? "账号创建成功" : "账号已存在，已选择该账号",
            $"账号: {username}",
            $"用户 ID: {user.Id}",
            $"试用计划: {trial.Plan}"
        };
        if (user.WasCreated)
        {
            lines.Add($"一次性初始密码: {initialPassword}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatCreatedUserPartial(
        string username,
        KeygenUser user,
        string initialPassword,
        string warning)
    {
        return string.Join(
            Environment.NewLine,
            warning,
            $"账号: {username}",
            $"用户 ID: {user.Id}",
            $"一次性初始密码: {initialPassword}");
    }

    private static string FormatLicense(
        string username,
        KeygenLicense license,
        string? possibleInitialPassword)
    {
        var expiry = license.BusinessExpiresAt ?? license.Expiry;
        var expiryText = expiry is not null
            ? expiry.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
            : license.Plan switch
            {
                "TRIAL" => "首次激活后30天",
                "YEAR" => "首次激活后365天",
                "FOREVER" => "永久",
                _ => "未知"
            };
        var lines = new List<string>
        {
            "授权签发成功",
            $"账号: {username}",
            $"许可证密钥: {license.Key}",
            $"计划: {license.Plan}",
            $"价格: {license.Price.ToString(CultureInfo.InvariantCulture)} 元",
            $"到期: {expiryText}"
        };

        if (possibleInitialPassword is not null)
        {
            lines.Add(
                $"一次性初始密码（仅账号本次新建时有效）: {possibleInitialPassword}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatPasswordReset(string username, string newPassword)
    {
        return string.Join(
            Environment.NewLine,
            "密码重置成功",
            $"账号: {username}",
            $"一次性新密码: {newPassword}");
    }

    private static string FormatCommitStateUnknown(string username)
    {
        var lines = new List<string>
        {
            CommitStateUnknownWarning
        };
        if (username.Length > 0)
        {
            lines.Add($"账号: {username}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static bool TryNormalizePlan(string plan, out string normalizedPlan)
    {
        normalizedPlan = plan switch
        {
            "year" => "YEAR",
            "forever" => "FOREVER",
            _ => string.Empty
        };
        return normalizedPlan.Length > 0;
    }

    private void SelectUser(string username, KeygenUser user)
    {
        SelectedUser = user;
        _selectedUsername = username;
    }
}

internal sealed class OwnerCli
{
    private const string InvalidArguments =
        "命令或参数无效。请使用 help 查看用法。";
    private const string RuntimeFailure =
        "操作失败，请检查 admin-config.json、管理员令牌和网络后重试。";
    private readonly Func<CancellationToken, Task<IKeygenAdminOperations>> _operationsFactory;
    private readonly Func<string> _passwordFactory;
    private readonly Action<string> _tokenSaver;
    private readonly Func<string> _tokenReader;

    internal OwnerCli(
        Func<IKeygenAdminOperations> operationsFactory,
        Func<string> tokenReader,
        Action<string> tokenSaver,
        Func<string>? passwordFactory = null)
        : this(
            _ => Task.FromResult(
                (operationsFactory
                    ?? throw new ArgumentNullException(nameof(operationsFactory)))()),
            tokenReader,
            tokenSaver,
            passwordFactory)
    {
    }

    internal OwnerCli(
        Func<CancellationToken, Task<IKeygenAdminOperations>> operationsFactory,
        Func<string> tokenReader,
        Action<string> tokenSaver,
        Func<string>? passwordFactory = null)
    {
        _operationsFactory = operationsFactory
            ?? throw new ArgumentNullException(nameof(operationsFactory));
        _tokenReader = tokenReader ?? throw new ArgumentNullException(nameof(tokenReader));
        _tokenSaver = tokenSaver ?? throw new ArgumentNullException(nameof(tokenSaver));
        _passwordFactory = passwordFactory ?? OwnerPasswordGenerator.Generate;
    }

    internal async Task<int> RunAsync(
        string[] args,
        TextWriter output,
        TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (IsHelp(args))
        {
            WriteHelp(output);
            return 0;
        }

        if (args.Length == 1 && args[0] == "token-set")
        {
            return SaveToken(output, error);
        }

        if (!HasValidCommandShape(args))
        {
            error.WriteLine(InvalidArguments);
            return 2;
        }

        try
        {
            using var operations = await _operationsFactory(CancellationToken.None);
            var workflow = new OwnerWorkflow(operations, _passwordFactory);
            var result = args[0] switch
            {
                "account-create" => await workflow.CreateAccountAsync(args[1], args[2]),
                "license-issue" => await workflow.IssueLicenseForCliAsync(args[1], args[2]),
                "password-reset" => await workflow.ResetPasswordForCliAsync(args[1]),
                "machine-revoke" => await workflow.RevokeMachineAsync(args[1]),
                _ => OwnerOperationResult.Failure(InvalidArguments)
            };

            if (result.Succeeded)
            {
                output.WriteLine(result.Output);
                return 0;
            }

            if (result.IsPartialSuccess)
            {
                output.WriteLine(result.Output);
                return 3;
            }

            if (result.IsCommitStateUnknown)
            {
                output.WriteLine(result.Output);
                return 4;
            }

            error.WriteLine(result.Output);
            return 1;
        }
        catch (OwnerRuntimeException runtimeError)
        {
            error.WriteLine(runtimeError.UserMessage);
            return 1;
        }
        catch
        {
            error.WriteLine(RuntimeFailure);
            return 1;
        }
    }

    private int SaveToken(TextWriter output, TextWriter error)
    {
        try
        {
            output.Write("管理员令牌（输入隐藏）: ");
            var token = _tokenReader();
            ArgumentException.ThrowIfNullOrWhiteSpace(token);
            _tokenSaver(token);
            output.WriteLine();
            output.WriteLine("管理员令牌已保存。");
            return 0;
        }
        catch
        {
            error.WriteLine("管理员令牌保存失败，请重新输入后重试。");
            return 1;
        }
    }

    private static bool IsHelp(string[] args)
    {
        return args.Length == 1 && args[0] is "help" or "-h" or "--help";
    }

    private static bool HasValidCommandShape(string[] args)
    {
        return args switch
        {
            ["account-create", _, _] => true,
            ["license-issue", _, "year" or "forever"] => true,
            ["password-reset", _] => true,
            ["machine-revoke", _] => true,
            _ => false
        };
    }

    private static void WriteHelp(TextWriter output)
    {
        output.WriteLine("用法:");
        output.WriteLine("  account-create <username> <customer>");
        output.WriteLine("  license-issue <username> year|forever");
        output.WriteLine("  password-reset <username>");
        output.WriteLine("  machine-revoke <machine-id>");
        output.WriteLine("  token-set  # 从标准输入或隐藏输入读取管理员令牌");
        output.WriteLine("  help");
    }
}

internal sealed class OwnerAdminForm : Form
{
    internal const int FormWidth = 860;
    internal const int FormHeight = 640;

    private readonly TextBox _accountText = new();
    private readonly List<Button> _actionButtons = [];
    private readonly IOwnerClipboard _clipboard;
    private readonly TextBox _customerText = new();
    private readonly RadioButton _foreverRadio = new();
    private readonly TextBox _initialPasswordText = new();
    private readonly TextBox _machineText = new();
    private readonly Func<string> _passwordFactory;
    private readonly TextBox _resultText = new();
    private readonly OwnerRuntime _runtime;
    private readonly CancellationTokenSource _runtimeLifetime = new();
    private readonly Label _statusLabel = new();
    private readonly TextBox _tokenText = new();
    private readonly Label _tokenStateLabel = new();
    private readonly RadioButton _yearRadio = new();
    private bool _ownedResourcesDisposed;
    private IKeygenAdminOperations? _operations;
    private OwnerWorkflow? _workflow;

    internal OwnerAdminForm(
        OwnerRuntime runtime,
        Func<string>? passwordFactory = null,
        IOwnerClipboard? clipboard = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _passwordFactory = passwordFactory ?? OwnerPasswordGenerator.Generate;
        _clipboard = clipboard ?? new WindowsOwnerClipboard();

        Text = "Software License Auth - Administrator";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(FormWidth, FormHeight);
        Font = new Font("Microsoft YaHei UI", 9F);

        var accountLabel = LabelAt("账号：", 24, 24, 105);
        PlaceTextBox(_accountText, 130, 20, 280);
        var customerLabel = LabelAt("客户：", 440, 24, 85);
        PlaceTextBox(_customerText, 525, 20, 310);

        var passwordLabel = LabelAt("初始密码：", 24, 67, 105);
        PlaceTextBox(_initialPasswordText, 130, 63, 280);
        _initialPasswordText.ReadOnly = true;
        _initialPasswordText.UseSystemPasswordChar = true;
        var generatePasswordButton = ButtonAt("生成密码", 425, 61, 105);
        generatePasswordButton.Click += GeneratePassword_Click;
        var togglePasswordButton = ButtonAt("显示密码", 540, 61, 105);
        togglePasswordButton.Click += TogglePassword_Click;
        var copyPasswordButton = ButtonAt("复制密码", 655, 61, 105);
        copyPasswordButton.Click += CopyPassword_Click;

        var planLabel = LabelAt("授权计划：", 24, 110, 105);
        _yearRadio.SetBounds(130, 106, 105, 28);
        _yearRadio.Text = "年卡";
        _yearRadio.Checked = true;
        _foreverRadio.SetBounds(245, 106, 105, 28);
        _foreverRadio.Text = "永久";

        var createButton = ButtonAt("创建账号", 425, 101, 120);
        createButton.Click += CreateAccount_Click;
        var issueButton = ButtonAt("签发授权", 555, 101, 120);
        issueButton.Click += IssueLicense_Click;
        var resetButton = ButtonAt("重置密码", 685, 101, 120);
        resetButton.Click += ResetPassword_Click;

        var machineLabel = LabelAt("机器 ID：", 24, 162, 105);
        PlaceTextBox(_machineText, 130, 158, 285);
        var queryMachinesButton = ButtonAt("查询机器", 425, 156, 120);
        queryMachinesButton.Click += QueryMachines_Click;
        var revokeButton = ButtonAt("解绑机器", 555, 156, 120);
        revokeButton.Click += RevokeMachine_Click;

        var tokenLabel = LabelAt("管理员令牌：", 24, 210, 105);
        PlaceTextBox(_tokenText, 130, 206, 545);
        _tokenText.UseSystemPasswordChar = true;
        var saveTokenButton = ButtonAt("保存令牌", 685, 204, 120);
        saveTokenButton.Click += SaveToken_Click;
        _tokenStateLabel.SetBounds(130, 234, 545, 22);
        _tokenStateLabel.ForeColor = Color.FromArgb(80, 80, 80);
        RefreshTokenState();

        var resultLabel = LabelAt("操作结果：", 24, 260, 105);
        var copyButton = ButtonAt("复制结果", 605, 252, 100);
        copyButton.Click += CopyResult_Click;
        var clearButton = ButtonAt("清空", 715, 252, 90);
        clearButton.Click += Clear_Click;

        _resultText.SetBounds(24, 292, 811, 275);
        _resultText.AccessibleName = "操作结果：";
        _resultText.Multiline = true;
        _resultText.ReadOnly = true;
        _resultText.ScrollBars = ScrollBars.Vertical;
        _resultText.Font = new Font("Consolas", 9F);

        _statusLabel.SetBounds(24, 582, 811, 36);
        _statusLabel.ForeColor = Color.FromArgb(25, 105, 45);

        _actionButtons.AddRange(
            [
                createButton,
                issueButton,
                resetButton,
                queryMachinesButton,
                revokeButton,
                saveTokenButton
            ]);
        Controls.AddRange(
        [
            accountLabel,
            _accountText,
            customerLabel,
            _customerText,
            passwordLabel,
            _initialPasswordText,
            generatePasswordButton,
            togglePasswordButton,
            copyPasswordButton,
            planLabel,
            _yearRadio,
            _foreverRadio,
            createButton,
            issueButton,
            resetButton,
            machineLabel,
            _machineText,
            queryMachinesButton,
            revokeButton,
            tokenLabel,
            _tokenText,
            _tokenStateLabel,
            saveTokenButton,
            resultLabel,
            copyButton,
            clearButton,
            _resultText,
            _statusLabel
        ]);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_ownedResourcesDisposed)
        {
            _ownedResourcesDisposed = true;
            _runtimeLifetime.Cancel();
            _operations?.Dispose();
            _runtime.Dispose();
            _runtimeLifetime.Dispose();
        }

        base.Dispose(disposing);
    }

    private async void CreateAccount_Click(object? sender, EventArgs e)
    {
        try
        {
            SetBusy(true);
            var workflow = await EnsureWorkflowAsync();
            if (_initialPasswordText.TextLength == 0)
            {
                _initialPasswordText.Text = _passwordFactory();
            }

            var result = await workflow.CreateAccountAsync(
                _accountText.Text,
                _customerText.Text,
                _initialPasswordText.Text);
            ShowResult(result);
            if (result.Succeeded || result.IsPartialSuccess)
            {
                _initialPasswordText.Clear();
            }
        }
        catch (OwnerRuntimeException runtimeError)
        {
            ShowFixedError(runtimeError.UserMessage);
        }
        catch
        {
            ShowFixedError(OwnerWorkflow.AccountFailure);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void IssueLicense_Click(object? sender, EventArgs e)
    {
        try
        {
            SetBusy(true);
            if (_workflow?.SelectedUser is null)
            {
                ShowFixedError(OwnerWorkflow.IssueFailure);
                return;
            }

            var workflow = await EnsureWorkflowAsync();
            var plan = _yearRadio.Checked ? "year" : "forever";
            ShowResult(await workflow.IssueSelectedLicenseAsync(plan));
        }
        catch (OwnerRuntimeException runtimeError)
        {
            ShowFixedError(runtimeError.UserMessage);
        }
        catch
        {
            ShowFixedError(OwnerWorkflow.IssueFailure);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void ResetPassword_Click(object? sender, EventArgs e)
    {
        try
        {
            SetBusy(true);
            if (_workflow?.SelectedUser is null)
            {
                ShowFixedError(OwnerWorkflow.ResetFailure);
                return;
            }

            var workflow = await EnsureWorkflowAsync();
            ShowResult(await workflow.ResetSelectedPasswordAsync());
        }
        catch (OwnerRuntimeException runtimeError)
        {
            ShowFixedError(runtimeError.UserMessage);
        }
        catch
        {
            ShowFixedError(OwnerWorkflow.ResetFailure);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void RevokeMachine_Click(object? sender, EventArgs e)
    {
        try
        {
            SetBusy(true);
            ShowResult(await (await EnsureWorkflowAsync()).RevokeMachineAsync(_machineText.Text));
        }
        catch (OwnerRuntimeException runtimeError)
        {
            ShowFixedError(runtimeError.UserMessage);
        }
        catch
        {
            ShowFixedError(OwnerWorkflow.RevokeFailure);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void QueryMachines_Click(object? sender, EventArgs e)
    {
        try
        {
            SetBusy(true);
            if (_workflow?.SelectedUser is null)
            {
                ShowFixedError(OwnerWorkflow.MachineQueryFailure);
                return;
            }

            var workflow = await EnsureWorkflowAsync();
            ShowMachineQueryResult(await workflow.QuerySelectedMachinesAsync());
        }
        catch (OwnerRuntimeException runtimeError)
        {
            ShowFixedError(runtimeError.UserMessage);
        }
        catch
        {
            ShowFixedError(OwnerWorkflow.MachineQueryFailure);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SaveToken_Click(object? sender, EventArgs e)
    {
        try
        {
            SetBusy(true);
            if (string.IsNullOrWhiteSpace(_tokenText.Text))
            {
                ShowFixedError("管理员令牌不能为空，未修改已保存令牌。");
                return;
            }

            _runtime.SaveToken(_tokenText.Text);
            _tokenText.Clear();
            ResetWorkflow();
            RefreshTokenState();
            ShowStatus("管理员令牌已保存。", success: true);
        }
        catch
        {
            ShowFixedError("管理员令牌保存失败，请重新输入后重试。");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void GeneratePassword_Click(object? sender, EventArgs e)
    {
        try
        {
            _initialPasswordText.Text = _passwordFactory();
            ShowStatus("已生成初始密码。", success: true);
        }
        catch
        {
            ShowFixedError("初始密码生成失败，请重试。");
        }
    }

    private void TogglePassword_Click(object? sender, EventArgs e)
    {
        var password = _initialPasswordText.Text;
        _initialPasswordText.UseSystemPasswordChar =
            !_initialPasswordText.UseSystemPasswordChar;
        if (!string.Equals(
            _initialPasswordText.Text,
            password,
            StringComparison.Ordinal))
        {
            _initialPasswordText.Text = password;
        }
        if (sender is Button button)
        {
            button.Text = _initialPasswordText.UseSystemPasswordChar
                ? "显示密码"
                : "隐藏密码";
        }
    }

    private void CopyPassword_Click(object? sender, EventArgs e)
    {
        try
        {
            if (_initialPasswordText.TextLength == 0)
            {
                ShowFixedError("当前没有可复制的密码。");
                return;
            }

            _clipboard.SetText(_initialPasswordText.Text);
            ShowStatus("密码已复制。", success: true);
        }
        catch
        {
            ShowFixedError("密码复制失败，请重新生成后重试。");
        }
    }

    private void CopyResult_Click(object? sender, EventArgs e)
    {
        try
        {
            if (_resultText.TextLength == 0)
            {
                ShowFixedError("当前没有可复制的结果。");
                return;
            }

            _clipboard.SetText(_resultText.Text);
            ShowStatus("结果已复制。", success: true);
        }
        catch
        {
            ShowFixedError("复制失败，请手动选择结果文本。");
        }
    }

    private void Clear_Click(object? sender, EventArgs e)
    {
        _accountText.Clear();
        _customerText.Clear();
        _initialPasswordText.Clear();
        _machineText.Clear();
        _tokenText.Clear();
        _resultText.Clear();
        _statusLabel.Text = string.Empty;
    }

    private async Task<OwnerWorkflow> EnsureWorkflowAsync()
    {
        if (_workflow is not null)
        {
            await _runtime.EnsureTunnelAsync(_runtimeLifetime.Token);
            return _workflow;
        }

        _operations = await _runtime.CreateOperationsAsync(_runtimeLifetime.Token);
        _workflow = new OwnerWorkflow(_operations, _passwordFactory);
        return _workflow;
    }

    private void ResetWorkflow()
    {
        _operations?.Dispose();
        _operations = null;
        _workflow = null;
    }

    private void SetBusy(bool busy)
    {
        foreach (var button in _actionButtons)
        {
            button.Enabled = !busy;
        }
    }

    private void ShowResult(OwnerOperationResult result)
    {
        if (result.Succeeded)
        {
            _resultText.Text = result.Output;
            ShowStatus("操作成功。", success: true);
            return;
        }

        if (result.IsPartialSuccess)
        {
            _resultText.Text = result.Output;
            ShowStatus("操作部分成功，请按结果中的警告处理。", success: false);
            return;
        }

        if (result.IsCommitStateUnknown)
        {
            _initialPasswordText.Clear();
            _resultText.Text = result.Output;
            ShowStatus(OwnerWorkflow.CommitStateUnknownWarning, success: false);
            return;
        }

        ShowFixedError(result.Output);
    }

    private void ShowMachineQueryResult(OwnerOperationResult result)
    {
        _machineText.Text = result.Succeeded
            ? result.MachineIdToFill ?? string.Empty
            : string.Empty;
        ShowResult(result);
    }

    private void ShowFixedError(string message)
    {
        _resultText.Clear();
        ShowStatus(message, success: false);
    }

    private void ShowStatus(string message, bool success)
    {
        _statusLabel.ForeColor = success
            ? Color.FromArgb(25, 105, 45)
            : Color.FromArgb(160, 40, 40);
        _statusLabel.Text = message;
    }

    private void RefreshTokenState()
    {
        var hasSavedToken = false;
        try
        {
            hasSavedToken = _runtime.HasSavedToken;
        }
        catch
        {
            hasSavedToken = false;
        }

        _tokenStateLabel.Text = hasSavedToken
            ? "管理员令牌状态：已安全保存"
            : "管理员令牌状态：尚未配置";
    }

    private static Label LabelAt(string text, int left, int top, int width)
    {
        return new Label
        {
            Left = left,
            Top = top,
            Width = width,
            Height = 28,
            Text = text,
            TextAlign = ContentAlignment.MiddleLeft
        };
    }

    private static Button ButtonAt(
        string text,
        int left,
        int top,
        int width)
    {
        return new Button
        {
            Left = left,
            Top = top,
            Width = width,
            Height = 34,
            Text = text
        };
    }

    private static void PlaceTextBox(
        TextBox textBox,
        int left,
        int top,
        int width)
    {
        textBox.Left = left;
        textBox.Top = top;
        textBox.Width = width;
        textBox.Height = 28;
    }
}
