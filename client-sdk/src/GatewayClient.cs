using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal sealed class GatewayException : Exception
{
    internal GatewayException(string message, HttpStatusCode? statusCode = null)
        : base(message)
    {
        StatusCode = statusCode;
    }

    public HttpStatusCode? StatusCode { get; }
}

internal sealed class GatewayLoginResult
{
    internal GatewayLoginResult(
        string userId,
        string username,
        string sessionToken,
        DateTimeOffset serverTime)
    {
        UserId = userId;
        Username = username;
        SessionToken = sessionToken;
        ServerTime = serverTime;
    }

    public string UserId { get; }
    public string Username { get; }
    public string SessionToken { get; }
    public DateTimeOffset ServerTime { get; }

    public override string ToString()
    {
        return $"{nameof(GatewayLoginResult)} {{ UserId = {UserId}, Username = {Username}, "
            + $"SessionToken = <REDACTED>, ServerTime = {ServerTime:O} }}";
    }
}

internal sealed class GatewayActivationResult
{
    internal GatewayActivationResult(
        string userId,
        string licenseId,
        string machineId,
        string machineFingerprint,
        string plan,
        int price,
        DateTimeOffset? expiresAt,
        DateTimeOffset serverTime)
    {
        UserId = userId;
        LicenseId = licenseId;
        MachineId = machineId;
        MachineFingerprint = machineFingerprint;
        Plan = plan;
        Price = price;
        ExpiresAt = expiresAt;
        ServerTime = serverTime;
    }

    public string UserId { get; }
    public string LicenseId { get; }
    public string MachineId { get; }
    public string MachineFingerprint { get; }
    public string Plan { get; }
    public int Price { get; }
    public DateTimeOffset? ExpiresAt { get; }
    public DateTimeOffset ServerTime { get; }
}

internal sealed class GatewayLeaseResult
{
    internal GatewayLeaseResult(
        string machineFile,
        DateTimeOffset machineFileExpiresAt,
        int refreshAfterSeconds,
        string challenge,
        string manifestSha256,
        string bindingSha256,
        string plan,
        DateTimeOffset? businessExpiresAt,
        DateTimeOffset serverTime)
    {
        MachineFile = machineFile;
        MachineFileExpiresAt = machineFileExpiresAt;
        RefreshAfterSeconds = refreshAfterSeconds;
        Challenge = challenge;
        ManifestSha256 = manifestSha256;
        BindingSha256 = bindingSha256;
        Plan = plan;
        BusinessExpiresAt = businessExpiresAt;
        ServerTime = serverTime;
    }

    public string MachineFile { get; }
    public DateTimeOffset MachineFileExpiresAt { get; }
    public int RefreshAfterSeconds { get; }
    public string Challenge { get; }
    public string ManifestSha256 { get; }
    public string BindingSha256 { get; }
    public string Plan { get; }
    public DateTimeOffset? BusinessExpiresAt { get; }
    public DateTimeOffset ServerTime { get; }

    public override string ToString()
    {
        return $"{nameof(GatewayLeaseResult)} {{ MachineFile = <REDACTED>, "
            + $"MachineFileExpiresAt = {MachineFileExpiresAt:O}, Plan = {Plan} }}";
    }
}

internal sealed class GatewayLogoutResult
{
    internal GatewayLogoutResult(DateTimeOffset serverTime)
    {
        ServerTime = serverTime;
    }

    public DateTimeOffset ServerTime { get; }
}

internal sealed class GatewayClient : IDisposable
{
    private const string ProductCode = "DEMO-PRODUCT";
    private const int JsonResponseLimit = 32 * 1024;
    private const int MachineFileLimit = 1024 * 1024;
    private const int LeaseResponseLimit = MachineFileLimit + JsonResponseLimit;
    private const int MaximumTokenLength = 4096;
    private const int MaximumPasswordLength = 256;
    private const int MaximumCardKeyLength = 256;
    private const int RefreshAfterSeconds = 600;
    private const int MaximumMachineFileEnvelopeSeconds = 3700;

    private static readonly TimeSpan ProductionCallTimeout = TimeSpan.FromSeconds(8);

    private static readonly HashSet<string> AllowedComponentNames = new(StringComparer.Ordinal)
    {
        "smbios",
        "baseboard",
        "bios",
        "system_disk",
        "machine_guid",
        "device_key",
    };

    private static readonly string[] LoginResponseFields =
    [
        "ok",
        "message",
        "session_token",
        "user_id",
        "username",
        "server_time",
    ];

    private static readonly string[] ActivateResponseFields =
    [
        "ok",
        "message",
        "user_id",
        "license_id",
        "machine_id",
        "machine_fingerprint",
        "plan",
        "price",
        "expires_at",
        "server_time",
    ];

    private static readonly string[] LeaseResponseFields =
    [
        "ok",
        "message",
        "machine_file",
        "machine_file_expires_at",
        "refresh_after_seconds",
        "challenge",
        "manifest_sha256",
        "binding_sha256",
        "plan",
        "business_expires_at",
        "server_time",
    ];

    private static readonly string[] LogoutResponseFields =
    [
        "ok",
        "message",
        "server_time",
    ];

    private readonly HttpClient httpClient;
    private readonly string clientVersion;
    private readonly Uri loginEndpoint;
    private readonly Uri activateEndpoint;
    private readonly Uri leaseEndpoint;
    private readonly Uri logoutEndpoint;
    private readonly Func<int, MemoryStream> responseBufferFactory;
    private readonly bool ownsHttpClient;
    private readonly TimeSpan callTimeout;
    private readonly Action? beforeRequestConstruction;
    private readonly Action? afterResponseParsed;
    private int disposeState;

    internal GatewayClient(Uri gatewayBaseAddress, string clientVersion)
        : this(
            CreateProductionHttpClient(gatewayBaseAddress, clientVersion),
            clientVersion,
            ownsHttpClient: true,
            ProductionCallTimeout,
            responseBufferFactory: null,
            beforeRequestConstruction: null,
            afterResponseParsed: null)
    {
    }

    private GatewayClient(
        HttpClient httpClient,
        string clientVersion,
        bool ownsHttpClient,
        TimeSpan callTimeout,
        Func<int, MemoryStream>? responseBufferFactory,
        Action? beforeRequestConstruction,
        Action? afterResponseParsed)
    {
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        ValidateClientVersion(clientVersion);
        if (callTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(callTimeout));
        }

        var baseAddress = httpClient.BaseAddress;
        ValidateGatewayBaseAddress(baseAddress, nameof(httpClient));

        if (httpClient.DefaultRequestHeaders.Contains("Authorization"))
        {
            throw new ArgumentException(
                "HTTP client must not define a default authorization header.",
                nameof(httpClient));
        }

        this.clientVersion = clientVersion;
        this.ownsHttpClient = ownsHttpClient;
        this.callTimeout = callTimeout;
        this.beforeRequestConstruction = beforeRequestConstruction;
        this.afterResponseParsed = afterResponseParsed;
        this.responseBufferFactory = responseBufferFactory
            ?? (static capacity => new MemoryStream(capacity));
        var authority = baseAddress!.GetLeftPart(UriPartial.Authority);
        loginEndpoint = new Uri(authority + "/api/v2/login", UriKind.Absolute);
        activateEndpoint = new Uri(authority + "/api/v2/activate", UriKind.Absolute);
        leaseEndpoint = new Uri(authority + "/api/v2/lease", UriKind.Absolute);
        logoutEndpoint = new Uri(authority + "/api/v2/logout", UriKind.Absolute);
    }

    void IDisposable.Dispose()
    {
        if (ownsHttpClient && Interlocked.Exchange(ref disposeState, 1) == 0)
        {
            httpClient.Dispose();
        }
    }

    private static HttpClient CreateProductionHttpClient(
        Uri gatewayBaseAddress,
        string clientVersion)
    {
        ValidateClientVersion(clientVersion);
        ValidateGatewayBaseAddress(gatewayBaseAddress, nameof(gatewayBaseAddress));
        return new HttpClient(CreateProductionHandler(), disposeHandler: true)
        {
            BaseAddress = gatewayBaseAddress,
            Timeout = Timeout.InfiniteTimeSpan,
        };
    }

    private static HttpClientHandler CreateProductionHandler()
    {
        return new HttpClientHandler
        {
            AllowAutoRedirect = false,
        };
    }

    internal Task<GatewayLoginResult> LoginAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        return ExecuteWithDeadlineAsync(async operationToken =>
        {
            var normalizedUsername = AccountNaming.Normalize(username);
            ValidatePassword(password);
            var requestBody = BuildLoginRequest(normalizedUsername, password);
            var responseBody = await SendAsync(
                loginEndpoint,
                requestBody,
                bearerToken: null,
                isLease: false,
                operationToken).ConfigureAwait(false);

            try
            {
                operationToken.ThrowIfCancellationRequested();
                var result = ParseLoginResponse(responseBody, normalizedUsername);
                operationToken.ThrowIfCancellationRequested();
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(responseBody);
            }
        }, cancellationToken);
    }

    internal Task<GatewayActivationResult> ActivateAsync(
        string sessionToken,
        string expectedUserId,
        DeviceBinding deviceBinding,
        string? cardKey = null,
        CancellationToken cancellationToken = default)
    {
        return ExecuteWithDeadlineAsync(async operationToken =>
        {
            ValidateTokenArgument(sessionToken, nameof(sessionToken));
            ValidateIdArgument(expectedUserId, nameof(expectedUserId));
            ValidateDeviceBinding(deviceBinding, nameof(deviceBinding));
            var normalizedCardKey = NormalizeCardKey(cardKey);
            var requestBody = BuildActivateRequest(deviceBinding, normalizedCardKey);
            var responseBody = await SendAsync(
                activateEndpoint,
                requestBody,
                sessionToken,
                isLease: false,
                operationToken).ConfigureAwait(false);

            try
            {
                operationToken.ThrowIfCancellationRequested();
                var result = ParseActivateResponse(
                    responseBody,
                    expectedUserId,
                    normalizedCardKey.Length != 0);
                operationToken.ThrowIfCancellationRequested();
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(responseBody);
            }
        }, cancellationToken);
    }

    internal Task<GatewayLeaseResult> LeaseAsync(
        string sessionToken,
        string machineId,
        DeviceBinding deviceBinding,
        string manifestSha256,
        string challenge,
        CancellationToken cancellationToken = default)
    {
        return ExecuteWithDeadlineAsync(async operationToken =>
        {
            ValidateTokenArgument(sessionToken, nameof(sessionToken));
            ValidateIdArgument(machineId, nameof(machineId));
            ValidateDeviceBinding(deviceBinding, nameof(deviceBinding));
            ValidateSha256Argument(manifestSha256, nameof(manifestSha256));
            ValidateChallengeArgument(challenge, nameof(challenge));
            var requestBody = BuildLeaseRequest(
                machineId,
                deviceBinding,
                manifestSha256,
                challenge);
            var responseBody = await SendAsync(
                leaseEndpoint,
                requestBody,
                sessionToken,
                isLease: true,
                operationToken).ConfigureAwait(false);

            try
            {
                operationToken.ThrowIfCancellationRequested();
                var result = ParseLeaseResponse(responseBody, manifestSha256, challenge);
                operationToken.ThrowIfCancellationRequested();
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(responseBody);
            }
        }, cancellationToken);
    }

    internal Task<GatewayLogoutResult> LogoutAsync(
        string sessionToken,
        CancellationToken cancellationToken = default)
    {
        return ExecuteWithDeadlineAsync(async operationToken =>
        {
            ValidateTokenArgument(sessionToken, nameof(sessionToken));
            var responseBody = await SendAsync(
                logoutEndpoint,
                BuildLogoutRequest(),
                sessionToken,
                isLease: false,
                operationToken).ConfigureAwait(false);

            try
            {
                operationToken.ThrowIfCancellationRequested();
                var result = ParseLogoutResponse(responseBody);
                operationToken.ThrowIfCancellationRequested();
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(responseBody);
            }
        }, cancellationToken);
    }

    private async Task<T> ExecuteWithDeadlineAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        using var callCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        callCancellation.CancelAfter(callTimeout);

        try
        {
            callCancellation.Token.ThrowIfCancellationRequested();
            beforeRequestConstruction?.Invoke();
            callCancellation.Token.ThrowIfCancellationRequested();
            var result = await operation(callCancellation.Token).ConfigureAwait(false);
            afterResponseParsed?.Invoke();
            callCancellation.Token.ThrowIfCancellationRequested();
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw TimeoutFailure();
        }
        catch (GatewayException) when (
            callCancellation.IsCancellationRequested
            && !cancellationToken.IsCancellationRequested)
        {
            throw TimeoutFailure();
        }
    }

    private async Task<byte[]> SendAsync(
        Uri endpoint,
        byte[] requestBody,
        string? bearerToken,
        bool isLease,
        CancellationToken cancellationToken)
    {
        byte[]? responseBody = null;
        var responseBodyTransferred = false;

        try
        {
            using var request = new RedactedHttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = new ByteArrayContent(requestBody),
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
            {
                CharSet = "utf-8",
            };
            if (bearerToken is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
            }

            cancellationToken.ThrowIfCancellationRequested();
            using var response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();
            var statusCode = response.StatusCode;
            var isSuccess = (int)statusCode is >= 200 and <= 299;
            ValidateContentType(response.Content, isSuccess ? null : statusCode);
            var responseLimit = isSuccess && isLease
                ? LeaseResponseLimit
                : JsonResponseLimit;
            responseBody = await ReadLimitedAsync(
                response.Content,
                responseLimit,
                isSuccess ? null : statusCode,
                cancellationToken).ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();
            if (isSuccess)
            {
                responseBodyTransferred = true;
                return responseBody;
            }

            ValidateErrorResponse(responseBody, statusCode);
            cancellationToken.ThrowIfCancellationRequested();

            throw HttpStatusFailure(statusCode);
        }
        catch (HttpRequestException)
        {
            throw new GatewayException("The authorization gateway is unavailable.");
        }
        catch (IOException)
        {
            throw new GatewayException("The authorization gateway is unavailable.");
        }
        finally
        {
            if (!responseBodyTransferred && responseBody is not null)
            {
                CryptographicOperations.ZeroMemory(responseBody);
            }

            CryptographicOperations.ZeroMemory(requestBody);
        }
    }

    private async Task<byte[]> ReadLimitedAsync(
        HttpContent content,
        int maximumBytes,
        HttpStatusCode? statusCode,
        CancellationToken cancellationToken)
    {
        var contentLength = content.Headers.ContentLength;
        if (contentLength is < 0 || contentLength > maximumBytes)
        {
            throw InvalidResponse(statusCode);
        }

        var capacity = contentLength.HasValue
            ? checked((int)contentLength.Value)
            : Math.Min(maximumBytes, 8192);
        using var output = responseBufferFactory(capacity);
        await using var stream = await content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        var buffer = ArrayPool<byte>.Shared.Rent(8192);

        try
        {
            while (true)
            {
                var bytesRead = await stream.ReadAsync(buffer, cancellationToken)
                    .ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    break;
                }

                if (output.Length > maximumBytes - bytesRead)
                {
                    throw InvalidResponse(statusCode);
                }

                output.Write(buffer, 0, bytesRead);
            }

            return output.ToArray();
        }
        finally
        {
            if (output.TryGetBuffer(out var writtenBuffer) && writtenBuffer.Array is not null)
            {
                CryptographicOperations.ZeroMemory(
                    writtenBuffer.Array.AsSpan(writtenBuffer.Offset, checked((int)output.Length)));
            }

            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static GatewayLoginResult ParseLoginResponse(
        byte[] responseBody,
        string expectedUsername)
    {
        using var document = ParseJson(responseBody);
        var properties = ReadExactObject(document.RootElement, LoginResponseFields);
        RequireSuccessfulResponse(properties);
        var sessionToken = RequireString(properties, "session_token");
        var userId = RequireString(properties, "user_id");
        var username = RequireString(properties, "username");
        var serverTime = RequireTimestamp(properties, "server_time");

        if (!IsValidToken(sessionToken)
            || !IsValidId(userId)
            || !string.Equals(username, expectedUsername, StringComparison.Ordinal))
        {
            throw InvalidResponse();
        }

        return new GatewayLoginResult(userId, username, sessionToken, serverTime);
    }

    private static GatewayActivationResult ParseActivateResponse(
        byte[] responseBody,
        string expectedUserId,
        bool cardWasProvided)
    {
        using var document = ParseJson(responseBody);
        var properties = ReadKnownObject(document.RootElement, ActivateResponseFields);
        RequireFields(
            properties,
            "ok",
            "message",
            "user_id",
            "license_id",
            "machine_id",
            "machine_fingerprint",
            "plan",
            "server_time");
        RequireSuccessfulResponse(properties);
        var userId = RequireString(properties, "user_id");
        var licenseId = RequireString(properties, "license_id");
        var machineId = RequireString(properties, "machine_id");
        var machineFingerprint = RequireString(properties, "machine_fingerprint");
        var plan = RequireString(properties, "plan");
        var price = properties.ContainsKey("price")
            ? RequireInt32(properties, "price")
            : plan == "TRIAL"
                ? 0
                : throw InvalidResponse();
        var expiresText = properties.ContainsKey("expires_at")
            ? RequireString(properties, "expires_at", allowEmpty: true)
            : plan == "FOREVER"
                ? string.Empty
                : throw InvalidResponse();
        var serverTime = RequireTimestamp(properties, "server_time");

        if (!string.Equals(userId, expectedUserId, StringComparison.Ordinal)
            || !IsValidId(userId)
            || !IsValidId(licenseId)
            || !IsValidId(machineId)
            || !IsUppercaseSha256(machineFingerprint)
            || !IsValidPlanAndPrice(plan, price)
            || (cardWasProvided && plan == "TRIAL"))
        {
            throw InvalidResponse();
        }

        var expiresAt = ValidateBusinessExpiry(plan, expiresText, serverTime);
        return new GatewayActivationResult(
            userId,
            licenseId,
            machineId,
            machineFingerprint,
            plan,
            price,
            expiresAt,
            serverTime);
    }

    private static GatewayLeaseResult ParseLeaseResponse(
        byte[] responseBody,
        string expectedManifestSha256,
        string expectedChallenge)
    {
        using var document = ParseJson(responseBody);
        var properties = ReadKnownObject(document.RootElement, LeaseResponseFields);
        RequireFields(
            properties,
            "ok",
            "message",
            "machine_file",
            "machine_file_expires_at",
            "refresh_after_seconds",
            "challenge",
            "manifest_sha256",
            "binding_sha256",
            "plan",
            "server_time");
        RequireSuccessfulResponse(properties);
        var machineFile = RequireString(properties, "machine_file");
        var machineFileExpiresAt = RequireTimestamp(properties, "machine_file_expires_at");
        var refreshAfterSeconds = RequireInt32(properties, "refresh_after_seconds");
        var challenge = RequireString(properties, "challenge");
        var manifestSha256 = RequireString(properties, "manifest_sha256");
        var bindingSha256 = RequireString(properties, "binding_sha256");
        var plan = RequireString(properties, "plan");
        var businessExpiresText = properties.ContainsKey("business_expires_at")
            ? RequireString(properties, "business_expires_at", allowEmpty: true)
            : plan == "FOREVER"
                ? string.Empty
                : throw InvalidResponse();
        var serverTime = RequireTimestamp(properties, "server_time");

        if (Encoding.UTF8.GetByteCount(machineFile) > MachineFileLimit
            || refreshAfterSeconds != RefreshAfterSeconds
            || !string.Equals(challenge, expectedChallenge, StringComparison.Ordinal)
            || !string.Equals(manifestSha256, expectedManifestSha256, StringComparison.Ordinal)
            || !IsUppercaseSha256(bindingSha256)
            || !IsValidPlan(plan)
            || machineFileExpiresAt <= serverTime
            || machineFileExpiresAt - serverTime
                > TimeSpan.FromSeconds(MaximumMachineFileEnvelopeSeconds))
        {
            throw InvalidResponse();
        }

        var expectedBinding = ComputeLeaseBinding(machineFile, manifestSha256, challenge);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(bindingSha256),
                Encoding.ASCII.GetBytes(expectedBinding)))
        {
            throw InvalidResponse();
        }

        var businessExpiresAt = ValidateBusinessExpiry(
            plan,
            businessExpiresText,
            serverTime);
        return new GatewayLeaseResult(
            machineFile,
            machineFileExpiresAt,
            refreshAfterSeconds,
            challenge,
            manifestSha256,
            bindingSha256,
            plan,
            businessExpiresAt,
            serverTime);
    }

    private static GatewayLogoutResult ParseLogoutResponse(byte[] responseBody)
    {
        using var document = ParseJson(responseBody);
        var properties = ReadExactObject(document.RootElement, LogoutResponseFields);
        RequireSuccessfulResponse(properties);
        return new GatewayLogoutResult(RequireTimestamp(properties, "server_time"));
    }

    private static void ValidateErrorResponse(byte[] responseBody, HttpStatusCode statusCode)
    {
        using var document = ParseJson(responseBody, statusCode);
        var properties = ReadExactObject(
            document.RootElement,
            LogoutResponseFields,
            statusCode);
        if (properties["ok"].ValueKind != JsonValueKind.False)
        {
            throw InvalidResponse(statusCode);
        }

        _ = RequireString(properties, "message", statusCode: statusCode);
        _ = RequireTimestamp(properties, "server_time", statusCode);
    }

    private static JsonDocument ParseJson(
        byte[] responseBody,
        HttpStatusCode? statusCode = null)
    {
        try
        {
            return JsonDocument.Parse(
                responseBody,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 16,
                });
        }
        catch (JsonException)
        {
            throw InvalidResponse(statusCode);
        }
    }

    private static Dictionary<string, JsonElement> ReadExactObject(
        JsonElement root,
        IReadOnlyCollection<string> expectedFields,
        HttpStatusCode? statusCode = null)
    {
        var properties = ReadKnownObject(root, expectedFields, statusCode);
        if (properties.Count != expectedFields.Count)
        {
            throw InvalidResponse(statusCode);
        }

        return properties;
    }

    private static Dictionary<string, JsonElement> ReadKnownObject(
        JsonElement root,
        IReadOnlyCollection<string> allowedFields,
        HttpStatusCode? statusCode = null)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw InvalidResponse(statusCode);
        }

        var allowed = allowedFields.ToHashSet(StringComparer.Ordinal);
        var properties = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!allowed.Contains(property.Name)
                || !properties.TryAdd(property.Name, property.Value))
            {
                throw InvalidResponse(statusCode);
            }
        }

        return properties;
    }

    private static void RequireFields(
        IReadOnlyDictionary<string, JsonElement> properties,
        params string[] requiredFields)
    {
        foreach (var field in requiredFields)
        {
            if (!properties.ContainsKey(field))
            {
                throw InvalidResponse();
            }
        }
    }

    private static void RequireSuccessfulResponse(
        IReadOnlyDictionary<string, JsonElement> properties)
    {
        if (properties["ok"].ValueKind != JsonValueKind.True
            || !string.Equals(
                RequireString(properties, "message"),
                "ok",
                StringComparison.Ordinal))
        {
            throw InvalidResponse();
        }
    }

    private static string RequireString(
        IReadOnlyDictionary<string, JsonElement> properties,
        string name,
        bool allowEmpty = false,
        HttpStatusCode? statusCode = null)
    {
        var value = properties[name];
        if (value.ValueKind != JsonValueKind.String)
        {
            throw InvalidResponse(statusCode);
        }

        var text = value.GetString();
        if (text is null || (!allowEmpty && text.Length == 0))
        {
            throw InvalidResponse(statusCode);
        }

        return text;
    }

    private static int RequireInt32(
        IReadOnlyDictionary<string, JsonElement> properties,
        string name)
    {
        var value = properties[name];
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number))
        {
            throw InvalidResponse();
        }

        return number;
    }

    private static DateTimeOffset RequireTimestamp(
        IReadOnlyDictionary<string, JsonElement> properties,
        string name,
        HttpStatusCode? statusCode = null)
    {
        var text = RequireString(properties, name, statusCode: statusCode);
        if (!LooksLikeRfc3339(text)
            || !DateTimeOffset.TryParse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var timestamp))
        {
            throw InvalidResponse(statusCode);
        }

        return timestamp;
    }

    private static DateTimeOffset? ValidateBusinessExpiry(
        string plan,
        string expiresText,
        DateTimeOffset serverTime)
    {
        if (plan == "FOREVER")
        {
            if (expiresText.Length != 0)
            {
                throw InvalidResponse();
            }

            return null;
        }

        if (expiresText.Length == 0
            || !LooksLikeRfc3339(expiresText)
            || !DateTimeOffset.TryParse(
                expiresText,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var expiresAt)
            || expiresAt <= serverTime
            || expiresAt <= DateTimeOffset.UtcNow)
        {
            throw InvalidResponse();
        }

        return expiresAt;
    }

    private static void ValidateContentType(
        HttpContent content,
        HttpStatusCode? statusCode)
    {
        if (!string.Equals(
                content.Headers.ContentType?.MediaType,
                "application/json",
                StringComparison.OrdinalIgnoreCase))
        {
            throw InvalidResponse(statusCode);
        }
    }

    private byte[] BuildLoginRequest(string username, string password)
    {
        return BuildJson(writer =>
        {
            writer.WriteString("product", ProductCode);
            writer.WriteString("username", username);
            writer.WriteString("password", password);
            writer.WriteString("client_version", clientVersion);
        });
    }

    private byte[] BuildActivateRequest(DeviceBinding deviceBinding, string cardKey)
    {
        return BuildJson(writer =>
        {
            writer.WriteString("product", ProductCode);
            if (cardKey.Length != 0)
            {
                writer.WriteString("card_key", cardKey);
            }

            writer.WriteString("device_fingerprint", deviceBinding.Fingerprint);
            writer.WritePropertyName("components");
            writer.WriteStartObject();
            foreach (var component in deviceBinding.Components.OrderBy(
                         component => component.Key,
                         StringComparer.Ordinal))
            {
                writer.WriteString(component.Key, component.Value);
            }

            writer.WriteEndObject();
            writer.WriteString("client_version", clientVersion);
        });
    }

    private byte[] BuildLeaseRequest(
        string machineId,
        DeviceBinding deviceBinding,
        string manifestSha256,
        string challenge)
    {
        return BuildJson(writer =>
        {
            writer.WriteString("product", ProductCode);
            writer.WriteString("machine_id", machineId);
            writer.WriteString("device_fingerprint", deviceBinding.Fingerprint);
            writer.WritePropertyName("components");
            writer.WriteStartObject();
            foreach (var component in deviceBinding.Components.OrderBy(
                         component => component.Key,
                         StringComparer.Ordinal))
            {
                writer.WriteString(component.Key, component.Value);
            }

            writer.WriteEndObject();
            writer.WriteString("manifest_sha256", manifestSha256);
            writer.WriteString("challenge", challenge);
            writer.WriteString("client_version", clientVersion);
        });
    }

    private byte[] BuildLogoutRequest()
    {
        return BuildJson(writer => writer.WriteString("product", ProductCode));
    }

    private static byte[] BuildJson(Action<Utf8JsonWriter> writeProperties)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writeProperties(writer);
            writer.WriteEndObject();
        }

        var result = buffer.ToArray();
        if (buffer.TryGetBuffer(out var writtenBuffer) && writtenBuffer.Array is not null)
        {
            CryptographicOperations.ZeroMemory(
                writtenBuffer.Array.AsSpan(writtenBuffer.Offset, checked((int)buffer.Length)));
        }

        return result;
    }

    private static string ComputeLeaseBinding(
        string machineFile,
        string manifestSha256,
        string challenge)
    {
        var material = Encoding.UTF8.GetBytes(
            "LICENSE-AUTH-LEASE-V1\0" + machineFile + "\0" + manifestSha256 + "\0" + challenge);
        try
        {
            return Convert.ToHexString(SHA256.HashData(material));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
        }
    }

    private static void ValidateClientVersion(string clientVersion)
    {
        if (string.IsNullOrWhiteSpace(clientVersion)
            || clientVersion.Length > 64
            || clientVersion.Any(char.IsControl))
        {
            throw new ArgumentException("Client version is invalid.", nameof(clientVersion));
        }
    }

    private static void ValidateGatewayBaseAddress(Uri? gatewayBaseAddress, string parameterName)
    {
        if (gatewayBaseAddress is null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (!gatewayBaseAddress.IsAbsoluteUri
            || !string.Equals(
                gatewayBaseAddress.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(gatewayBaseAddress.UserInfo))
        {
            throw new ArgumentException("Gateway base address is invalid.", parameterName);
        }
    }

    private static void ValidatePassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (password.Length is 0 or > MaximumPasswordLength)
        {
            throw new ArgumentException("Password is invalid.", nameof(password));
        }
    }

    private static void ValidateTokenArgument(string token, string parameterName)
    {
        if (!IsValidToken(token))
        {
            throw new ArgumentException("Session token is invalid.", parameterName);
        }
    }

    private static bool IsValidToken(string? token)
    {
        return token is not null
            && token.Length is >= 1 and <= MaximumTokenLength
            && !token.Any(character => char.IsControl(character) || char.IsWhiteSpace(character));
    }

    private static void ValidateIdArgument(string value, string parameterName)
    {
        if (!IsValidId(value))
        {
            throw new ArgumentException("Identifier is invalid.", parameterName);
        }
    }

    private static bool IsValidId(string? value)
    {
        return value is not null
            && value.Length is >= 1 and <= 128
            && value.All(character => IsAsciiLetterOrDigit(character) || character is '_' or '-');
    }

    private static void ValidateSha256Argument(string value, string parameterName)
    {
        if (!IsUppercaseSha256(value))
        {
            throw new ArgumentException("SHA-256 value is invalid.", parameterName);
        }
    }

    private static bool IsUppercaseSha256(string? value)
    {
        return value is not null
            && value.Length == 64
            && value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
    }

    private static void ValidateChallengeArgument(string value, string parameterName)
    {
        if (value is null
            || value.Length is < 32 or > 128
            || !value.All(character =>
                IsAsciiLetterOrDigit(character) || character is '_' or '-'))
        {
            throw new ArgumentException("Lease challenge is invalid.", parameterName);
        }
    }

    private static void ValidateDeviceBinding(DeviceBinding binding, string parameterName)
    {
        if (binding is null
            || !IsUppercaseSha256(binding.Fingerprint)
            || binding.Components is null
            || binding.Components.Count is < 3 or > 6)
        {
            throw new ArgumentException("Device binding is invalid.", parameterName);
        }

        var uniqueHashes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var component in binding.Components)
        {
            if (!AllowedComponentNames.Contains(component.Key)
                || !IsUppercaseSha256(component.Value))
            {
                throw new ArgumentException("Device binding is invalid.", parameterName);
            }

            uniqueHashes.Add(component.Value);
        }

        if (uniqueHashes.Count < 3)
        {
            throw new ArgumentException("Device binding is invalid.", parameterName);
        }
    }

    private static string NormalizeCardKey(string? cardKey)
    {
        var normalized = (cardKey ?? string.Empty).Trim().ToUpperInvariant();
        if (normalized.Length == 0)
        {
            return string.Empty;
        }

        if (normalized.Length is < 4 or > MaximumCardKeyLength
            || !normalized.All(character =>
                character is >= 'A' and <= 'Z'
                or >= '0' and <= '9'
                or '-'))
        {
            throw new ArgumentException("Card key is invalid.", nameof(cardKey));
        }

        return normalized;
    }

    private static bool IsValidPlanAndPrice(string plan, int price)
    {
        return plan switch
        {
            "TRIAL" => price == 0,
            "YEAR" => price == 128,
            "FOREVER" => price == 288,
            _ => false,
        };
    }

    private static bool IsValidPlan(string plan)
    {
        return plan is "TRIAL" or "YEAR" or "FOREVER";
    }

    private static bool LooksLikeRfc3339(string value)
    {
        if (value.Length < 20
            || value[4] != '-'
            || value[7] != '-'
            || value[10] != 'T'
            || value[13] != ':'
            || value[16] != ':')
        {
            return false;
        }

        var zoneStart = value.EndsWith('Z')
            ? value.Length - 1
            : value.Length - 6;
        if (zoneStart < 19
            || (value[zoneStart] != 'Z'
                && (value[zoneStart] is not ('+' or '-')
                    || value.Length - zoneStart != 6
                    || value[zoneStart + 3] != ':')))
        {
            return false;
        }

        for (var index = 0; index < value.Length; index++)
        {
            if (index is 4 or 7 or 13 or 16
                || index == 10
                || index == zoneStart
                || (zoneStart != value.Length - 1 && index == zoneStart + 3))
            {
                continue;
            }

            if (index == 19 && zoneStart > 19)
            {
                if (value[index] != '.' || zoneStart - index is < 2 or > 10)
                {
                    return false;
                }

                continue;
            }

            if (value[index] is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAsciiLetterOrDigit(char character)
    {
        return character is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9';
    }

    private static GatewayException InvalidResponse(HttpStatusCode? statusCode = null)
    {
        return new GatewayException(
            "The authorization gateway returned an invalid response.",
            statusCode);
    }

    private static GatewayException TimeoutFailure()
    {
        return new GatewayException("The authorization gateway request timed out.");
    }

    private static GatewayException HttpStatusFailure(HttpStatusCode statusCode)
    {
        return new GatewayException(
            $"The authorization gateway returned HTTP {(int)statusCode}.",
            statusCode);
    }

    private sealed class RedactedHttpRequestMessage : HttpRequestMessage
    {
        internal RedactedHttpRequestMessage(HttpMethod method, Uri requestUri)
            : base(method, requestUri)
        {
        }

        public override string ToString()
        {
            return "Authorization gateway HTTP request (sensitive values redacted).";
        }
    }
}
