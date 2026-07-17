using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal sealed class SessionData
{
    internal SessionData(
        string username,
        string userId,
        string sessionToken,
        string machineId,
        string licenseId,
        string machineFingerprint,
        DateTimeOffset lastServerTime)
    {
        Username = username;
        UserId = userId;
        SessionToken = sessionToken;
        MachineId = machineId;
        LicenseId = licenseId;
        MachineFingerprint = machineFingerprint;
        LastServerTime = lastServerTime;
    }

    internal string Username { get; }

    internal string UserId { get; }

    internal string SessionToken { get; }

    internal string MachineId { get; }

    internal string LicenseId { get; }

    internal string MachineFingerprint { get; }

    internal DateTimeOffset LastServerTime { get; }

    public override string ToString()
    {
        return "SessionData { SessionToken = <REDACTED> }";
    }
}

internal sealed class SessionStore
{
    private const string SessionFileName = "online_session_v3.dpapi";
    private const int MaxPlaintextBytes = 48 * 1024;
    private const int MaxCiphertextBytes = 64 * 1024;
    private static readonly byte[] ProductEntropy =
        Encoding.UTF8.GetBytes("SoftwareLicenseAuth.Client.SessionStore.v3");

    private readonly string _path;
    private readonly byte[] _entropy;

    private SessionStore(string path, byte[] entropy)
    {
        _path = ValidateStoragePath(path);
        _entropy = entropy.ToArray();
    }

    internal string StoragePath => _path;

    internal static SessionStore CreateForCurrentUser()
    {
        return new SessionStore(
            Path.Combine(
                AppContext.BaseDirectory,
                "license-data",
                SessionFileName),
            ProductEntropy);
    }

    internal void Save(SessionData session)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (!HasRequiredValues(session))
        {
            throw new ArgumentException(
                "Session contains a missing required field.",
                nameof(session));
        }

        var directory = PrepareStorageDirectory(createIfMissing: true)
            ?? throw new InvalidOperationException("Session directory was not created.");
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(new PersistedSession(session));
        try
        {
            if (plaintext.Length > MaxPlaintextBytes)
            {
                throw new ArgumentException("Session data is too large.", nameof(session));
            }

            var ciphertext = ProtectedData.Protect(
                plaintext,
                _entropy,
                DataProtectionScope.CurrentUser);
            try
            {
                if (ciphertext.Length > MaxCiphertextBytes)
                {
                    throw new InvalidDataException("Protected session data is too large.");
                }

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

    internal SessionData? Load()
    {
        var directory = PrepareStorageDirectory(createIfMissing: false);
        if (directory is null || !File.Exists(_path))
        {
            return null;
        }

        var ciphertext = ReadCiphertext();
        try
        {
            var plaintext = ProtectedData.Unprotect(
                ciphertext,
                _entropy,
                DataProtectionScope.CurrentUser);
            try
            {
                if (plaintext.Length > MaxPlaintextBytes)
                {
                    throw new InvalidDataException("Session data is too large.");
                }

                return DeserializeSession(plaintext);
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

    internal void Clear()
    {
        var directory = PrepareStorageDirectory(createIfMissing: false);
        if (directory is null)
        {
            return;
        }

        ValidateDirectoryChain(directory);
        ValidateTargetPath(_path);
        File.Delete(_path);
    }

    private static bool HasRequiredValues(SessionData session)
    {
        return !string.IsNullOrWhiteSpace(session.Username)
            && !string.IsNullOrWhiteSpace(session.UserId)
            && !string.IsNullOrWhiteSpace(session.SessionToken)
            && !string.IsNullOrWhiteSpace(session.MachineId)
            && !string.IsNullOrWhiteSpace(session.LicenseId)
            && !string.IsNullOrWhiteSpace(session.MachineFingerprint)
            && session.LastServerTime != default;
    }

    private static SessionData DeserializeSession(byte[] plaintext)
    {
        try
        {
            using var document = JsonDocument.Parse(
                plaintext,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 4,
                });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw InvalidSessionData();
            }

            var propertyNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!IsAllowedProperty(property.Name) || !propertyNames.Add(property.Name))
                {
                    throw InvalidSessionData();
                }
            }

            if (propertyNames.Count != 7)
            {
                throw InvalidSessionData();
            }

            var lastServerTimeElement = GetRequiredProperty(root, "last_server_time");
            if (lastServerTimeElement.ValueKind != JsonValueKind.String
                || !lastServerTimeElement.TryGetDateTimeOffset(out var lastServerTime))
            {
                throw InvalidSessionData();
            }

            var session = new SessionData(
                ReadRequiredString(root, "username"),
                ReadRequiredString(root, "user_id"),
                ReadRequiredString(root, "session_token"),
                ReadRequiredString(root, "machine_id"),
                ReadRequiredString(root, "license_id"),
                ReadRequiredString(root, "machine_fingerprint"),
                lastServerTime);
            if (!HasRequiredValues(session))
            {
                throw InvalidSessionData();
            }

            return session;
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("Session data is invalid.", error);
        }
    }

    private static JsonElement GetRequiredProperty(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var value))
        {
            throw InvalidSessionData();
        }

        return value;
    }

    private static string ReadRequiredString(JsonElement root, string propertyName)
    {
        var element = GetRequiredProperty(root, propertyName);
        if (element.ValueKind != JsonValueKind.String)
        {
            throw InvalidSessionData();
        }

        var value = element.GetString();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw InvalidSessionData();
        }

        return value;
    }

    private static bool IsAllowedProperty(string propertyName)
    {
        return propertyName is "username"
            or "user_id"
            or "session_token"
            or "machine_id"
            or "license_id"
            or "machine_fingerprint"
            or "last_server_time";
    }

    private static InvalidDataException InvalidSessionData()
    {
        return new InvalidDataException("Session data is invalid.");
    }

    private byte[] ReadCiphertext()
    {
        ValidateDirectoryChain(Path.GetDirectoryName(_path)!);
        ValidateTargetPath(_path);
        byte[]? ciphertext = null;
        try
        {
            using var stream = new FileStream(
                _path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.SequentialScan);
            if (stream.Length <= 0 || stream.Length > MaxCiphertextBytes)
            {
                throw new InvalidDataException("Protected session data has an invalid size.");
            }

            ciphertext = new byte[checked((int)stream.Length)];
            stream.ReadExactly(ciphertext);
            if (stream.ReadByte() != -1)
            {
                throw new InvalidDataException("Protected session data has an invalid size.");
            }

            ValidateDirectoryChain(Path.GetDirectoryName(_path)!);
            ValidateTargetPath(_path);
            return ciphertext;
        }
        catch
        {
            if (ciphertext is not null)
            {
                CryptographicOperations.ZeroMemory(ciphertext);
            }

            throw;
        }
    }

    private void WriteCiphertextAtomically(string directory, byte[] ciphertext)
    {
        var tempPath = Path.Combine(
            directory,
            $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
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

            ValidateDirectoryChain(directory);
            ValidateTargetPath(_path);
            ValidateTargetPath(tempPath);
            if (!File.Exists(tempPath))
            {
                throw new IOException("Temporary session file disappeared before commit.");
            }

            if (File.Exists(_path))
            {
                File.Replace(tempPath, _path, destinationBackupFileName: null);
            }
            else
            {
                File.Move(tempPath, _path);
            }
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    private string? PrepareStorageDirectory(bool createIfMissing)
    {
        var directory = Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException("Session path has no directory.");
        ValidateDirectoryChain(directory);

        if (createIfMissing)
        {
            Directory.CreateDirectory(directory);
        }
        else if (!Directory.Exists(directory))
        {
            return null;
        }

        ValidateDirectoryChain(directory);
        ValidateTargetPath(_path);
        return directory;
    }

    private static string ValidateStoragePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("Session path must be absolute.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);
        if (string.IsNullOrEmpty(Path.GetFileName(fullPath)))
        {
            throw new ArgumentException("Session path must identify a file.", nameof(path));
        }

        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException("Session path must have a directory.", nameof(path));
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
                throw new IOException("Session directory must not contain a reparse point.");
            }

            if ((attributes & FileAttributes.Directory) == 0)
            {
                throw new IOException("Session directory path contains a file.");
            }
        }
    }

    private static IEnumerable<string> EnumerateDirectoryChain(string directory)
    {
        var root = Path.GetPathRoot(directory);
        if (string.IsNullOrEmpty(root))
        {
            throw new IOException("Session directory has no filesystem root.");
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
            throw new IOException("Session file must not be a reparse point.");
        }

        if ((attributes & FileAttributes.Directory) != 0)
        {
            throw new IOException("Session path must identify a file.");
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

    private sealed class PersistedSession
    {
        internal PersistedSession(SessionData session)
        {
            Username = session.Username;
            UserId = session.UserId;
            SessionToken = session.SessionToken;
            MachineId = session.MachineId;
            LicenseId = session.LicenseId;
            MachineFingerprint = session.MachineFingerprint;
            LastServerTime = session.LastServerTime;
        }

        [JsonPropertyName("username")]
        public string Username { get; }

        [JsonPropertyName("user_id")]
        public string UserId { get; }

        [JsonPropertyName("session_token")]
        public string SessionToken { get; }

        [JsonPropertyName("machine_id")]
        public string MachineId { get; }

        [JsonPropertyName("license_id")]
        public string LicenseId { get; }

        [JsonPropertyName("machine_fingerprint")]
        public string MachineFingerprint { get; }

        [JsonPropertyName("last_server_time")]
        public DateTimeOffset LastServerTime { get; }
    }
}
