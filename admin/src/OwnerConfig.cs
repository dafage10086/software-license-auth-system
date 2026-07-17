using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal sealed class OwnerConfig
{
    internal const string RequiredAdminUrl = "http://127.0.0.1:18788/";

    private static readonly JsonSerializerOptions LoadOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private OwnerConfig(
        Uri adminUrl,
        string accountId,
        string productId,
        string trialPolicyId,
        string yearPolicyId,
        string foreverPolicyId)
    {
        AdminUrl = adminUrl;
        AccountId = accountId;
        ProductId = productId;
        TrialPolicyId = trialPolicyId;
        YearPolicyId = yearPolicyId;
        ForeverPolicyId = foreverPolicyId;
    }

    [JsonPropertyName("admin_url")]
    public Uri AdminUrl { get; }

    [JsonPropertyName("account_id")]
    public string AccountId { get; }

    [JsonPropertyName("product_id")]
    public string ProductId { get; }

    [JsonPropertyName("trial_policy_id")]
    public string TrialPolicyId { get; }

    [JsonPropertyName("year_policy_id")]
    public string YearPolicyId { get; }

    [JsonPropertyName("forever_policy_id")]
    public string ForeverPolicyId { get; }

    internal static OwnerConfig Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        using var stream = File.OpenRead(path);
        using var json = JsonDocument.Parse(stream, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow
        });
        if (json.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("Owner configuration root must be a JSON object.");
        }

        var fieldNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in json.RootElement.EnumerateObject())
        {
            if (!fieldNames.Add(property.Name))
            {
                throw new JsonException(
                    $"Owner configuration contains duplicate field '{property.Name}'.");
            }
        }

        var document = json.RootElement.Deserialize<ConfigDocument>(LoadOptions)
            ?? throw new InvalidDataException("Owner configuration must be a JSON object.");

        return new OwnerConfig(
            ParseAdminUrl(Require(document.AdminUrl, "admin_url")),
            Require(document.AccountId, "account_id"),
            Require(document.ProductId, "product_id"),
            Require(document.TrialPolicyId, "trial_policy_id"),
            Require(document.YearPolicyId, "year_policy_id"),
            Require(document.ForeverPolicyId, "forever_policy_id"));
    }

    private static string Require(string? value, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException($"Owner configuration field '{fieldName}' is required.");
        }

        return value;
    }

    private static Uri ParseAdminUrl(string value)
    {
        if (!string.Equals(value, RequiredAdminUrl, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Owner configuration admin_url must be exactly '{RequiredAdminUrl}'.");
        }

        return new Uri(RequiredAdminUrl, UriKind.Absolute);
    }

    private sealed class ConfigDocument
    {
        [JsonPropertyName("admin_url")]
        public string? AdminUrl { get; init; }

        [JsonPropertyName("account_id")]
        public string? AccountId { get; init; }

        [JsonPropertyName("product_id")]
        public string? ProductId { get; init; }

        [JsonPropertyName("trial_policy_id")]
        public string? TrialPolicyId { get; init; }

        [JsonPropertyName("year_policy_id")]
        public string? YearPolicyId { get; init; }

        [JsonPropertyName("forever_policy_id")]
        public string? ForeverPolicyId { get; init; }
    }
}

internal sealed class AdminTokenStore
{
    private const string CredentialFileName = "admin-token.dpapi";
    private const int TempCleanupAttemptCount = 3;
    private const int TempCleanupRetryDelayMilliseconds = 25;
    private const FileSystemRights CurrentUserMaintenanceRights =
        FileSystemRights.Modify | FileSystemRights.ChangePermissions;
    private static readonly byte[] ProductEntropy =
        Encoding.UTF8.GetBytes("SoftwareLicenseAuth.Admin.AdminToken.v1");

    private readonly bool _applyCurrentUserAcl;
    private readonly Action<string>? _beforeCommit;
    private readonly string _path;

    private AdminTokenStore(
        string path,
        bool applyCurrentUserAcl,
        Action<string>? beforeCommit)
    {
        _path = ValidateStoragePath(path);
        _applyCurrentUserAcl = applyCurrentUserAcl;
        _beforeCommit = beforeCommit;
    }

    internal string StoragePath => _path;

    internal bool HasSavedToken
    {
        get
        {
            try
            {
                var directory = PrepareStorageDirectory(createIfMissing: false);
                using var pinnedDirectories = PinnedDirectoryChain.Open(directory);
                var ciphertext = WindowsPathHandles.ReadAllBytes(_path);
                try
                {
                    var plaintext = ProtectedData.Unprotect(
                        ciphertext,
                        ProductEntropy,
                        DataProtectionScope.CurrentUser);
                    try
                    {
                        return plaintext.Length > 0;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(plaintext);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ciphertext);
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    internal static AdminTokenStore CreateForCurrentUser()
    {
        var localAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            throw new InvalidOperationException("Current user LocalAppData is unavailable.");
        }

        return new AdminTokenStore(
            Path.Combine(localAppData, "SoftwareLicenseAuth", "Admin", CredentialFileName),
            applyCurrentUserAcl: true,
            beforeCommit: null);
    }

    internal static AdminTokenStore CreateForTesting(
        string path,
        Action<string>? beforeCommit = null,
        bool applyCurrentUserAcl = false,
        DataProtectionScope protectionScope = DataProtectionScope.CurrentUser)
    {
        if (protectionScope != DataProtectionScope.CurrentUser)
        {
            throw new ArgumentOutOfRangeException(
                nameof(protectionScope),
                "Admin tokens must use CurrentUser DPAPI scope.");
        }

        return new AdminTokenStore(path, applyCurrentUserAcl, beforeCommit);
    }

    internal void Save(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        var directory = PrepareStorageDirectory(createIfMissing: true);

        var plaintext = Encoding.UTF8.GetBytes(token);
        try
        {
            var ciphertext = ProtectedData.Protect(
                plaintext,
                ProductEntropy,
                DataProtectionScope.CurrentUser);
            try
            {
                WriteCiphertextAtomically(directory, ciphertext);
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
    }

    internal string Load()
    {
        var directory = PrepareStorageDirectory(createIfMissing: false);
        using var pinnedDirectories = PinnedDirectoryChain.Open(directory);
        var ciphertext = WindowsPathHandles.ReadAllBytes(_path);
        try
        {
            var plaintext = ProtectedData.Unprotect(
                ciphertext,
                ProductEntropy,
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
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private void WriteCiphertextAtomically(string directory, byte[] ciphertext)
    {
        using var pinnedDirectories = PinnedDirectoryChain.Open(directory);
        var tempPath = Path.Combine(
            directory,
            $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
        Exception? operationError = null;
        try
        {
            using (var stream = new FileStream(
                tempPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough))
            {
                stream.Write(ciphertext);
                stream.Flush(flushToDisk: true);
            }

            if (_applyCurrentUserAcl)
            {
                ApplyCurrentUserFileAcl(tempPath);
            }

            _beforeCommit?.Invoke(tempPath);

            ValidateDirectoryChain(directory);
            ValidateTargetPath(_path);
            ValidateTargetPath(tempPath);
            if (!File.Exists(tempPath))
            {
                throw new IOException("Temporary token file disappeared before commit.");
            }

            WindowsPathHandles.ValidateFile(_path, required: false);
            WindowsPathHandles.ValidateFile(tempPath, required: true);

            if (_applyCurrentUserAcl && File.Exists(_path))
            {
                ApplyCurrentUserFileAcl(_path);
            }

            pinnedDirectories.ReleaseCommitBlock();

            if (File.Exists(_path))
            {
                File.Replace(tempPath, _path, destinationBackupFileName: null);
            }
            else
            {
                File.Move(tempPath, _path);
            }
        }
        catch (Exception error)
        {
            operationError = error;
        }

        pinnedDirectories.ReleaseCommitBlock();
        var cleanupError = DeleteTempFileWithRetries(tempPath);
        if (operationError is null)
        {
            if (cleanupError is not null)
            {
                throw cleanupError;
            }

            return;
        }

        if (cleanupError is not null)
        {
            throw new AggregateException(
                "Token update failed and temporary file cleanup also failed.",
                operationError,
                cleanupError);
        }

        ExceptionDispatchInfo.Capture(operationError).Throw();
    }

    private string PrepareStorageDirectory(bool createIfMissing)
    {
        var directory = Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException("Token path has no directory.");
        ValidateDirectoryChain(directory);

        if (createIfMissing)
        {
            Directory.CreateDirectory(directory);
        }
        else if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException("Token directory does not exist.");
        }

        ValidateDirectoryChain(directory);
        ValidateTargetPath(_path);

        if (_applyCurrentUserAcl)
        {
            ApplyCurrentUserDirectoryAcl(directory);
            ValidateDirectoryChain(directory);
            if (File.Exists(_path))
            {
                ApplyCurrentUserFileAcl(_path);
                ValidateTargetPath(_path);
            }
        }

        return directory;
    }

    private static string ValidateStoragePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("Token path must be absolute.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);
        if (string.IsNullOrEmpty(Path.GetFileName(fullPath)))
        {
            throw new ArgumentException("Token path must identify a file.", nameof(path));
        }

        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException("Token path must have a directory.", nameof(path));
        ValidateDirectoryChain(directory);
        ValidateTargetPath(fullPath);
        return fullPath;
    }

    private static void ValidateDirectoryChain(string directory)
    {
        foreach (var current in EnumerateDirectoryChain(directory))
        {
            if (!TryGetAttributes(current, out var attributes))
            {
                continue;
            }

            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("Token directory must not contain a reparse point.");
            }

            if ((attributes & FileAttributes.Directory) == 0)
            {
                throw new IOException("Token directory path contains a file.");
            }
        }
    }

    private static IEnumerable<string> EnumerateDirectoryChain(string directory)
    {
        var root = Path.GetPathRoot(directory);
        if (string.IsNullOrEmpty(root))
        {
            throw new IOException("Token directory has no filesystem root.");
        }

        var current = root;
        var relative = directory[root.Length..];
        foreach (var segment in relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            yield return current;
        }
    }

    private static void ValidateTargetPath(string path)
    {
        if (!TryGetAttributes(path, out var attributes))
        {
            return;
        }

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("Token file must not be a reparse point.");
        }

        if ((attributes & FileAttributes.Directory) != 0)
        {
            throw new IOException("Token path must identify a file.");
        }
    }

    private static bool TryGetAttributes(string path, out FileAttributes attributes)
    {
        try
        {
            attributes = File.GetAttributes(path);
            return true;
        }
        catch (FileNotFoundException)
        {
            attributes = default;
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            attributes = default;
            return false;
        }
    }

    private static void ApplyCurrentUserDirectoryAcl(string directory)
    {
        var currentUser = GetCurrentUserSid();
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            CurrentUserMaintenanceRights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    private static void ApplyCurrentUserFileAcl(string path)
    {
        var currentUser = GetCurrentUserSid();
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            CurrentUserMaintenanceRights,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static SecurityIdentifier GetCurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User
            ?? throw new InvalidOperationException("Current Windows user has no SID.");
    }

    private sealed class PinnedDirectoryChain : IDisposable
    {
        private readonly IReadOnlyList<SafeFileHandle> _handles;
        private SafeFileHandle? _commitBlock;

        private PinnedDirectoryChain(
            IReadOnlyList<SafeFileHandle> handles,
            SafeFileHandle commitBlock)
        {
            _handles = handles;
            _commitBlock = commitBlock;
        }

        internal static PinnedDirectoryChain Open(string directory)
        {
            var handles = new List<SafeFileHandle>();
            try
            {
                var paths = EnumerateDirectoryChain(directory).ToArray();
                for (var index = 0; index < paths.Length - 1; index++)
                {
                    handles.Add(WindowsPathHandles.OpenDirectoryForPinning(
                        paths[index],
                        requestDeleteAccess: false));
                }

                var commitBlock = WindowsPathHandles.OpenDirectoryForPinning(
                    paths[^1],
                    requestDeleteAccess: true);
                return new PinnedDirectoryChain(handles, commitBlock);
            }
            catch
            {
                foreach (var handle in handles)
                {
                    handle.Dispose();
                }

                throw;
            }
        }

        internal void ReleaseCommitBlock()
        {
            _commitBlock?.Dispose();
            _commitBlock = null;
        }

        public void Dispose()
        {
            ReleaseCommitBlock();
            for (var index = _handles.Count - 1; index >= 0; index--)
            {
                _handles[index].Dispose();
            }
        }
    }

    private static class WindowsPathHandles
    {
        private const uint ErrorFileNotFound = 2;
        private const uint ErrorPathNotFound = 3;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileReadAttributes = 0x00000080;
        private const uint DeleteAccess = 0x00010000;
        private const uint GenericRead = 0x80000000;
        private const uint OpenExisting = 3;
        private const int FileAttributeTagInfo = 9;

        internal static SafeFileHandle OpenDirectoryForPinning(
            string path,
            bool requestDeleteAccess)
        {
            return OpenValidated(
                path,
                expectedDirectory: true,
                required: true,
                denyDeleteSharing: true,
                desiredAccess: FileReadAttributes
                    | (requestDeleteAccess ? DeleteAccess : 0))!;
        }

        internal static void ValidateFile(string path, bool required)
        {
            using var handle = OpenValidated(
                path,
                expectedDirectory: false,
                required,
                denyDeleteSharing: false,
                desiredAccess: FileReadAttributes);
        }

        internal static byte[] ReadAllBytes(string path)
        {
            var handle = OpenValidated(
                path,
                expectedDirectory: false,
                required: true,
                denyDeleteSharing: true,
                desiredAccess: GenericRead)!;
            try
            {
                using var stream = new FileStream(handle, FileAccess.Read);
                using var buffer = new MemoryStream();
                stream.CopyTo(buffer);
                return buffer.ToArray();
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        private static SafeFileHandle? OpenValidated(
            string path,
            bool expectedDirectory,
            bool required,
            bool denyDeleteSharing,
            uint desiredAccess)
        {
            var shareMode = (uint)(FileShare.Read | FileShare.Write);
            if (!denyDeleteSharing)
            {
                shareMode |= (uint)FileShare.Delete;
            }

            var flags = FileFlagOpenReparsePoint;
            if (expectedDirectory)
            {
                flags |= FileFlagBackupSemantics;
            }

            var handle = CreateFileW(
                path,
                desiredAccess,
                shareMode,
                IntPtr.Zero,
                OpenExisting,
                flags,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = (uint)Marshal.GetLastWin32Error();
                handle.Dispose();
                if (!required && error is ErrorFileNotFound or ErrorPathNotFound)
                {
                    return null;
                }

                throw new IOException(
                    "Unable to open token path for reparse-safe validation.",
                    new Win32Exception((int)error));
            }

            try
            {
                if (!GetFileInformationByHandleEx(
                    handle,
                    FileAttributeTagInfo,
                    out var information,
                    (uint)Marshal.SizeOf<FileAttributeTagInformation>()))
                {
                    throw new IOException(
                        "Unable to inspect token path handle.",
                        new Win32Exception(Marshal.GetLastWin32Error()));
                }

                if ((information.FileAttributes & FileAttributeReparsePoint) != 0)
                {
                    throw new IOException("Token path handle must not be a reparse point.");
                }

                var isDirectory =
                    (information.FileAttributes & FileAttributeDirectory) != 0;
                if (isDirectory != expectedDirectory)
                {
                    throw new IOException("Token path handle has an unexpected file type.");
                }

                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileAttributeTagInformation
        {
            internal uint FileAttributes;
            internal uint ReparseTag;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            int fileInformationClass,
            out FileAttributeTagInformation fileInformation,
            uint bufferSize);
    }

    private static IOException? DeleteTempFileWithRetries(string path)
    {
        Exception? lastError = null;
        for (var attempt = 1; attempt <= TempCleanupAttemptCount; attempt++)
        {
            try
            {
                File.Delete(path);
                return null;
            }
            catch (IOException error)
            {
                lastError = error;
            }
            catch (UnauthorizedAccessException error)
            {
                lastError = error;
            }

            if (attempt < TempCleanupAttemptCount)
            {
                Thread.Sleep(TempCleanupRetryDelayMilliseconds);
            }
        }

        return new IOException(
            $"Temporary token file cleanup failed after {TempCleanupAttemptCount} attempts; "
                + $"ciphertext may remain in '{Path.GetFileName(path)}'.",
            lastError);
    }
}
