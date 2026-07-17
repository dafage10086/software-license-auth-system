using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

internal sealed record KeygenUser(
    string Id,
    string Email = "",
    string Customer = "",
    bool WasCreated = false,
    string? OwnerRequestId = null);

internal sealed record KeygenLicense(
    string Id,
    string Key,
    string Plan,
    int Price,
    string OwnerId,
    string ProductId,
    string PolicyId,
    string Status = "",
    DateTimeOffset? Expiry = null,
    int? DurationSeconds = null,
    DateTimeOffset? BusinessExpiresAt = null);

internal sealed class KeygenAdminException : Exception
{
    internal KeygenAdminException(string message)
        : base(message)
    {
    }

    private KeygenAdminException(
        string message,
        bool requestStateUnknown,
        bool commitStateUnknown,
        bool networkFailure)
        : base(message)
    {
        RequestStateUnknown = requestStateUnknown;
        CommitStateUnknown = commitStateUnknown;
        IsNetworkFailure = networkFailure;
    }

    internal KeygenAdminException(HttpStatusCode statusCode)
        : base($"Keygen administrator request failed with HTTP status {(int)statusCode}.")
    {
        StatusCode = statusCode;
    }

    internal HttpStatusCode? StatusCode { get; }

    internal bool CommitStateUnknown { get; }

    internal bool RequestStateUnknown { get; }

    internal bool IsNetworkFailure { get; }

    internal bool IsAuthenticationFailure =>
        StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden;

    internal static KeygenAdminException UncertainRequest(string message)
    {
        return new KeygenAdminException(
            message,
            requestStateUnknown: true,
            commitStateUnknown: false,
            networkFailure: true);
    }

    internal static KeygenAdminException UnknownCommit()
    {
        return new KeygenAdminException(
            "CommitStateUnknown: Keygen may have committed the operation; verify before retrying.",
            requestStateUnknown: false,
            commitStateUnknown: true,
            networkFailure: false);
    }

    internal static KeygenAdminException NetworkFailure(string message)
    {
        return new KeygenAdminException(
            message,
            requestStateUnknown: false,
            commitStateUnknown: false,
            networkFailure: true);
    }
}

internal sealed class KeygenAdminClient : IDisposable
{
    private const string JsonApiMediaType = "application/vnd.api+json";
    private const int MaxResponseBytes = 1024 * 1024;
    private const int MaxAdminTokenLength = 16 * 1024;
    private const int MaxPasswordLength = 4 * 1024;
    private const int MaxCustomerLength = 1024;
    private const int MachinePageSize = 100;
    private const int MaxMachinePages = 5;
    private const int MaxMachineCount = MachinePageSize * MaxMachinePages;
    private const string KeygenRequestHost = "keygen.license.invalid";
    private const string ForwardedProtoHeader = "X-Forwarded-Proto";
    private const int TrialDurationSeconds = 30 * 24 * 60 * 60;
    private const int YearDurationSeconds = 365 * 24 * 60 * 60;
    private static readonly TimeSpan ProductionTotalTimeout = TimeSpan.FromSeconds(8);
    private static readonly Regex ResourceIdPattern = new(
        "^[A-Za-z0-9_-]{1,128}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly string _accountId;
    private readonly string _adminToken;
    private readonly Uri _baseUri;
    private readonly string _foreverPolicyId;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly string _productId;
    private readonly string _trialPolicyId;
    private readonly TimeSpan _totalTimeout;
    private readonly string _yearPolicyId;

    internal KeygenAdminClient(
        OwnerConfig config,
        string adminToken)
        : this(
            CreateProductionHttpClient(config, adminToken),
            config,
            adminToken,
            ProductionTotalTimeout,
            ownsHttpClient: true)
    {
    }

    private KeygenAdminClient(
        HttpClient httpClient,
        OwnerConfig config,
        string adminToken,
        TimeSpan totalTimeout)
        : this(httpClient, config, adminToken, totalTimeout, ownsHttpClient: false)
    {
    }

    private KeygenAdminClient(
        HttpClient httpClient,
        OwnerConfig config,
        string adminToken,
        TimeSpan totalTimeout,
        bool ownsHttpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(config);
        ValidateAdminToken(adminToken);
        ValidateTotalTimeout(totalTimeout);
        ValidateResourceId(config.AccountId, nameof(config.AccountId));
        ValidateResourceId(config.ProductId, nameof(config.ProductId));
        ValidateResourceId(config.TrialPolicyId, nameof(config.TrialPolicyId));
        ValidateResourceId(config.YearPolicyId, nameof(config.YearPolicyId));
        ValidateResourceId(config.ForeverPolicyId, nameof(config.ForeverPolicyId));

        _httpClient = httpClient;
        _ownsHttpClient = ownsHttpClient;
        _baseUri = ValidateAndNormalizeBaseUri(config.AdminUrl);
        _adminToken = adminToken;
        _accountId = config.AccountId;
        _productId = config.ProductId;
        _trialPolicyId = config.TrialPolicyId;
        _yearPolicyId = config.YearPolicyId;
        _foreverPolicyId = config.ForeverPolicyId;
        _totalTimeout = totalTimeout;
    }

    internal TimeSpan TotalTimeout => _totalTimeout;

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }

    internal async Task<KeygenUser> FindOrCreateUserAsync(
        string username,
        string password,
        string customer,
        CancellationToken operationCancellationToken = default)
    {
        using var deadline = CreateDeadline(operationCancellationToken);
        var cancellationToken = deadline.Token;
        var email = AccountNaming.ToAccountEmail(username);
        ValidateSensitiveText(password, MaxPasswordLength, nameof(password));
        ValidateCustomerMetadata(customer);

        var existing = await FindUsersByEmailAsync(
            email,
            customer,
            cancellationToken);
        if (existing.Count == 1)
        {
            return existing[0];
        }

        if (existing.Count > 1)
        {
            throw AmbiguousResponse("user");
        }

        var ownerRequestId = Guid.NewGuid().ToString("N");
        var created = await TryCreateUserAsync(
            email,
            password,
            customer,
            ownerRequestId,
            cancellationToken);
        if (created is not null)
        {
            return created;
        }

        existing = await FindUsersByEmailAsync(
            email,
            customer,
            cancellationToken);
        if (existing.Count == 1)
        {
            return existing[0];
        }

        throw existing.Count > 1
            ? AmbiguousResponse("user")
            : InvalidResponse();
    }

    internal async Task<KeygenLicense> EnsureTrialAsync(
        KeygenUser user,
        CancellationToken operationCancellationToken = default)
    {
        using var deadline = CreateDeadline(operationCancellationToken);
        var cancellationToken = deadline.Token;
        ValidateUser(user);
        var existing = await FindLicensesAsync(
            user.Id,
            _trialPolicyId,
            "TRIAL",
            0,
            cancellationToken);
        if (existing.Count == 1)
        {
            return existing[0];
        }

        if (existing.Count > 1)
        {
            throw AmbiguousResponse("trial license");
        }

        var created = await TryCreateLicenseAsync(
            user.Id,
            _trialPolicyId,
            "TRIAL",
            0,
            allowConflict: true,
            ownerRequestId: null,
            cancellationToken);
        if (created is not null)
        {
            return created;
        }

        existing = await FindLicensesAsync(
            user.Id,
            _trialPolicyId,
            "TRIAL",
            0,
            cancellationToken);
        if (existing.Count == 1)
        {
            return existing[0];
        }

        throw existing.Count > 1
            ? AmbiguousResponse("trial license")
            : InvalidResponse();
    }

    internal async Task<KeygenLicense> IssuePaidAsync(
        KeygenUser user,
        string plan,
        CancellationToken operationCancellationToken = default)
    {
        using var deadline = CreateDeadline(operationCancellationToken);
        var cancellationToken = deadline.Token;
        ValidateUser(user);
        var (policyId, price) = plan switch
        {
            "YEAR" => (_yearPolicyId, 128),
            "FOREVER" => (_foreverPolicyId, 288),
            _ => throw new ArgumentException("Plan must be YEAR or FOREVER.", nameof(plan))
        };
        var ownerRequestId = Guid.NewGuid().ToString("N");

        return await TryCreateLicenseAsync(
                user.Id,
                policyId,
                plan,
                price,
                allowConflict: false,
                ownerRequestId,
                cancellationToken)
            ?? throw InvalidResponse();
    }

    internal async Task ResetPasswordAsync(
        KeygenUser user,
        string newPassword,
        CancellationToken operationCancellationToken = default)
    {
        using var deadline = CreateDeadline(operationCancellationToken);
        var cancellationToken = deadline.Token;
        ValidateUser(user);
        ValidateSensitiveText(newPassword, MaxPasswordLength, nameof(newPassword));
        try
        {
            await PatchPasswordOnceAsync(user.Id, newPassword, cancellationToken);
        }
        catch (KeygenAdminException error) when (error.RequestStateUnknown)
        {
            try
            {
                await PatchPasswordOnceAsync(user.Id, newPassword, cancellationToken);
            }
            catch (KeygenAdminException)
            {
                throw KeygenAdminException.UnknownCommit();
            }
        }
    }

    internal async Task<IReadOnlyList<string>> ListMachineIdsAsync(
        KeygenUser user,
        CancellationToken operationCancellationToken = default)
    {
        using var deadline = CreateDeadline(operationCancellationToken);
        var cancellationToken = deadline.Token;
        ValidateUser(user);
        var machineIds = new List<string>();
        var uniqueIds = new HashSet<string>(StringComparer.Ordinal);

        for (var pageNumber = 1; pageNumber <= MaxMachinePages; pageNumber++)
        {
            using var request = CreateRequest(
                HttpMethod.Get,
                UserMachinesUri(user.Id, pageNumber));
            using var response = await SendAsync(request, cancellationToken);
            EnsureSuccess(response);
            var document = await ReadJsonAsync<ResourceListDocument<MachineResource>>(
                response,
                cancellationToken);
            var resources = document.Data ?? throw InvalidResponse();
            if (resources.Count > MachinePageSize)
            {
                throw InvalidResponse();
            }

            foreach (var resource in resources)
            {
                if (!IsValidResourceId(resource.Id)
                    || !uniqueIds.Add(resource.Id!))
                {
                    throw InvalidResponse();
                }

                machineIds.Add(resource.Id!);
                if (machineIds.Count > MaxMachineCount)
                {
                    throw InvalidResponse();
                }
            }

            if (resources.Count < MachinePageSize)
            {
                return machineIds;
            }
        }

        throw InvalidResponse();
    }

    private async Task PatchPasswordOnceAsync(
        string userId,
        string newPassword,
        CancellationToken cancellationToken)
    {
        var payload = new
        {
            data = new
            {
                type = "users",
                id = userId,
                attributes = new
                {
                    password = newPassword
                }
            }
        };

        using var request = CreateJsonRequest(
            HttpMethod.Patch,
            UserUri(userId),
            payload);
        using var response = await SendAsync(request, cancellationToken);
        EnsureSuccess(response);
    }

    internal async Task RevokeMachineAsync(
        string machineId,
        CancellationToken operationCancellationToken = default)
    {
        using var deadline = CreateDeadline(operationCancellationToken);
        var cancellationToken = deadline.Token;
        ValidateResourceId(machineId, nameof(machineId));
        try
        {
            using var request = CreateRequest(HttpMethod.Delete, MachineUri(machineId));
            using var response = await SendAsync(request, cancellationToken);
            EnsureSuccess(response);
        }
        catch (KeygenAdminException error) when (error.RequestStateUnknown)
        {
            throw KeygenAdminException.UnknownCommit();
        }
    }

    private async Task<List<KeygenUser>> FindUsersByEmailAsync(
        string email,
        string fallbackCustomer,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(HttpMethod.Get, UsersUri(email));
        using var response = await SendAsync(request, cancellationToken);
        EnsureSuccess(response);
        var document = await ReadJsonAsync<ResourceListDocument<UserResource>>(
            response,
            cancellationToken);
        var resources = document.Data ?? throw InvalidResponse();
        if (resources.Count > 1)
        {
            throw AmbiguousResponse("user");
        }

        return resources
            .Select(resource => ParseUser(resource, email, fallbackCustomer))
            .ToList();
    }

    private async Task<KeygenUser?> TryCreateUserAsync(
        string email,
        string password,
        string customer,
        string ownerRequestId,
        CancellationToken cancellationToken)
    {
        var payload = new
        {
            data = new
            {
                type = "users",
                attributes = new
                {
                    email,
                    password,
                    metadata = new
                    {
                        customer,
                        ownerRequestId
                    }
                }
            }
        };

        try
        {
            using var request = CreateJsonRequest(HttpMethod.Post, UsersUri(), payload);
            using var response = await SendAsync(request, cancellationToken);
            if (response.StatusCode == HttpStatusCode.Conflict)
            {
                return null;
            }

            EnsureSuccess(response);
            try
            {
                var document = await ReadJsonAsync<ResourceDocument<UserResource>>(
                    response,
                    cancellationToken);
                var created = ParseUser(
                    document.Data ?? throw InvalidResponse(),
                    email,
                    customer);
                if (!string.Equals(
                    created.OwnerRequestId,
                    ownerRequestId,
                    StringComparison.Ordinal))
                {
                    return await RecoverCreatedUserAsync(
                        email,
                        customer,
                        ownerRequestId,
                        cancellationToken);
                }

                return created with { WasCreated = true };
            }
            catch (KeygenAdminException)
            {
                return await RecoverCreatedUserAsync(
                    email,
                    customer,
                    ownerRequestId,
                    cancellationToken);
            }
        }
        catch (KeygenAdminException error) when (error.RequestStateUnknown)
        {
            return await RecoverCreatedUserAsync(
                email,
                customer,
                ownerRequestId,
                cancellationToken);
        }
    }

    private async Task<KeygenUser> RecoverCreatedUserAsync(
        string email,
        string customer,
        string ownerRequestId,
        CancellationToken cancellationToken)
    {
        try
        {
            var users = await FindUsersByEmailAsync(
                email,
                customer,
                cancellationToken);
            if (users.Count == 1
                && string.Equals(
                    users[0].OwnerRequestId,
                    ownerRequestId,
                    StringComparison.Ordinal))
            {
                return users[0] with { WasCreated = true };
            }
        }
        catch (KeygenAdminException)
        {
        }

        throw KeygenAdminException.UnknownCommit();
    }

    private async Task<List<KeygenLicense>> FindLicensesAsync(
        string ownerId,
        string policyId,
        string plan,
        int price,
        CancellationToken cancellationToken)
    {
        var resources = await FindLicenseResourcesAsync(
            ownerId,
            policyId,
            cancellationToken);
        if (resources.Count > 1)
        {
            throw AmbiguousResponse("license");
        }

        return resources
            .Select(resource => ParseLicense(
                resource,
                ownerId,
                policyId,
                plan,
                price))
            .ToList();
    }

    private async Task<List<KeygenLicense>> FindLicensesByCorrelationAsync(
        string ownerId,
        string policyId,
        string plan,
        int price,
        string ownerRequestId,
        CancellationToken cancellationToken)
    {
        var resources = await FindLicenseResourcesAsync(
            ownerId,
            policyId,
            cancellationToken);
        var matches = resources
            .Where(resource => string.Equals(
                resource.Attributes?.Metadata?.OwnerRequestId,
                ownerRequestId,
                StringComparison.Ordinal))
            .ToList();
        if (matches.Count > 1)
        {
            throw AmbiguousResponse("license correlation");
        }

        return matches
            .Select(resource => ParseLicense(
                resource,
                ownerId,
                policyId,
                plan,
                price,
                ownerRequestId))
            .ToList();
    }

    private async Task<List<LicenseResource>> FindLicenseResourcesAsync(
        string ownerId,
        string policyId,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(
            HttpMethod.Get,
            LicensesUri(ownerId, policyId));
        using var response = await SendAsync(request, cancellationToken);
        EnsureSuccess(response);
        var document = await ReadJsonAsync<ResourceListDocument<LicenseResource>>(
            response,
            cancellationToken);
        return document.Data ?? throw InvalidResponse();
    }

    private async Task<KeygenLicense?> TryCreateLicenseAsync(
        string ownerId,
        string policyId,
        string plan,
        int price,
        bool allowConflict,
        string? ownerRequestId,
        CancellationToken cancellationToken)
    {
        var metadata = new Dictionary<string, object>
        {
            ["plan"] = plan,
            ["price"] = price
        };
        if (string.Equals(plan, "TRIAL", StringComparison.Ordinal))
        {
            metadata["durationSeconds"] = TrialDurationSeconds;
        }
        else if (string.Equals(plan, "YEAR", StringComparison.Ordinal))
        {
            metadata["durationSeconds"] = YearDurationSeconds;
        }

        if (ownerRequestId is not null)
        {
            metadata["ownerRequestId"] = ownerRequestId;
        }

        var payload = new
        {
            data = new
            {
                type = "licenses",
                attributes = new
                {
                    metadata
                },
                relationships = new
                {
                    policy = Relationship("policies", policyId),
                    owner = Relationship("users", ownerId)
                }
            }
        };

        try
        {
            using var request = CreateJsonRequest(HttpMethod.Post, LicensesUri(), payload);
            using var response = await SendAsync(request, cancellationToken);
            if (allowConflict && response.StatusCode == HttpStatusCode.Conflict)
            {
                return null;
            }

            EnsureSuccess(response);
            try
            {
                var document = await ReadJsonAsync<ResourceDocument<LicenseResource>>(
                    response,
                    cancellationToken);
                return ParseLicense(
                    document.Data ?? throw InvalidResponse(),
                    ownerId,
                    policyId,
                    plan,
                    price,
                    ownerRequestId);
            }
            catch (KeygenAdminException)
            {
                return await RecoverCreatedLicenseAsync(
                    ownerId,
                    policyId,
                    plan,
                    price,
                    ownerRequestId,
                    cancellationToken);
            }
        }
        catch (KeygenAdminException error) when (error.RequestStateUnknown)
        {
            return await RecoverCreatedLicenseAsync(
                ownerId,
                policyId,
                plan,
                price,
                ownerRequestId,
                cancellationToken);
        }
    }

    private async Task<KeygenLicense> RecoverCreatedLicenseAsync(
        string ownerId,
        string policyId,
        string plan,
        int price,
        string? ownerRequestId,
        CancellationToken cancellationToken)
    {
        try
        {
            var matches = ownerRequestId is null
                ? await FindLicensesAsync(
                    ownerId,
                    policyId,
                    plan,
                    price,
                    cancellationToken)
                : await FindLicensesByCorrelationAsync(
                    ownerId,
                    policyId,
                    plan,
                    price,
                    ownerRequestId,
                    cancellationToken);
            if (matches.Count == 1)
            {
                return matches[0];
            }
        }
        catch (KeygenAdminException)
        {
        }

        throw KeygenAdminException.UnknownCommit();
    }

    private static object Relationship(string type, string id)
    {
        return new
        {
            data = new
            {
                type,
                id
            }
        };
    }

    private KeygenUser ParseUser(
        UserResource resource,
        string? expectedEmail,
        string fallbackCustomer)
    {
        if (!string.Equals(resource.Type, "users", StringComparison.Ordinal)
            || !IsValidResourceId(resource.Id)
            || resource.Attributes is null
            || string.IsNullOrWhiteSpace(resource.Attributes.Email)
            || (expectedEmail is not null
                && !string.Equals(
                    resource.Attributes.Email,
                    expectedEmail,
                    StringComparison.Ordinal)))
        {
            throw InvalidResponse();
        }

        var customer = fallbackCustomer;
        string? ownerRequestId = null;
        if (resource.Attributes.Metadata is not null
            && resource.Attributes.Metadata.TryGetValue("customer", out var value))
        {
            if (value.ValueKind != JsonValueKind.String)
            {
                throw InvalidResponse();
            }

            customer = value.GetString() ?? string.Empty;
        }

        if (resource.Attributes.Metadata is not null
            && resource.Attributes.Metadata.TryGetValue(
                "ownerRequestId",
                out var ownerRequestValue))
        {
            if (ownerRequestValue.ValueKind != JsonValueKind.String)
            {
                throw InvalidResponse();
            }

            ownerRequestId = ownerRequestValue.GetString();
        }

        return new KeygenUser(
            resource.Id!,
            resource.Attributes.Email,
            customer,
            OwnerRequestId: ownerRequestId);
    }

    private KeygenLicense ParseLicense(
        LicenseResource resource,
        string expectedOwnerId,
        string expectedPolicyId,
        string expectedPlan,
        int expectedPrice,
        string? expectedOwnerRequestId = null)
    {
        var attributes = resource.Attributes;
        var metadata = attributes?.Metadata;
        var relationships = resource.Relationships;
        if (!string.Equals(resource.Type, "licenses", StringComparison.Ordinal)
            || !IsValidResourceId(resource.Id)
            || attributes is null
            || string.IsNullOrWhiteSpace(attributes.Key)
            || metadata is null
            || !string.Equals(attributes.Status, "ACTIVE", StringComparison.Ordinal)
            || (expectedOwnerRequestId is not null
                && !string.Equals(
                    metadata.OwnerRequestId,
                    expectedOwnerRequestId,
                    StringComparison.Ordinal))
            || !string.Equals(metadata.Plan, expectedPlan, StringComparison.Ordinal)
            || metadata.Price != expectedPrice
            || (string.Equals(expectedPlan, "TRIAL", StringComparison.Ordinal)
                && metadata.DurationSeconds != TrialDurationSeconds)
            || (string.Equals(expectedPlan, "YEAR", StringComparison.Ordinal)
                && metadata.DurationSeconds != YearDurationSeconds)
            || (string.Equals(expectedPlan, "FOREVER", StringComparison.Ordinal)
                && metadata.DurationSeconds is not null)
            || relationships is null
            || !MatchesRelationship(
                relationships.Owner,
                "users",
                expectedOwnerId)
            || !MatchesRelationship(
                relationships.Product,
                "products",
                _productId)
            || !MatchesRelationship(
                relationships.Policy,
                "policies",
                expectedPolicyId))
        {
            throw InvalidResponse();
        }

        var expiry = ParseOptionalKeygenTime(attributes.Expiry);
        var businessExpiresAt = ParseOptionalKeygenTime(metadata.BusinessExpiresAt);
        if (string.Equals(expectedPlan, "FOREVER", StringComparison.Ordinal)
            && (expiry is not null || businessExpiresAt is not null))
        {
            throw InvalidResponse();
        }

        var now = DateTimeOffset.UtcNow;
        if (!string.Equals(expectedPlan, "FOREVER", StringComparison.Ordinal)
            && ((expiry is not null && expiry <= now)
                || (businessExpiresAt is not null && businessExpiresAt <= now)))
        {
            throw InvalidResponse();
        }

        return new KeygenLicense(
            resource.Id!,
            attributes.Key,
            expectedPlan,
            expectedPrice,
            expectedOwnerId,
            _productId,
            expectedPolicyId,
            attributes.Status ?? string.Empty,
            expiry,
            metadata.DurationSeconds,
            businessExpiresAt);
    }

    private static DateTimeOffset? ParseOptionalKeygenTime(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (!DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out var parsed))
        {
            throw InvalidResponse();
        }

        return parsed.ToUniversalTime();
    }

    private static bool MatchesRelationship(
        RelationshipResource? relationship,
        string expectedType,
        string expectedId)
    {
        return relationship?.Data is not null
            && string.Equals(
                relationship.Data.Type,
                expectedType,
                StringComparison.Ordinal)
            && string.Equals(
                relationship.Data.Id,
                expectedId,
                StringComparison.Ordinal)
            && IsValidResourceId(relationship.Data.Id);
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, Uri uri)
    {
        var request = new HttpRequestMessage(method, uri);
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue(JsonApiMediaType));
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            _adminToken);
        if (IsLoopbackHttp(_baseUri))
        {
            request.Headers.Host = KeygenRequestHost;
            request.Headers.Add(ForwardedProtoHeader, Uri.UriSchemeHttps);
        }

        return request;
    }

    private HttpRequestMessage CreateJsonRequest<T>(
        HttpMethod method,
        Uri uri,
        T payload)
    {
        var request = CreateRequest(method, uri);
        request.Content = JsonContent.Create(
            payload,
            new MediaTypeHeaderValue(JsonApiMediaType),
            JsonOptions);
        return request;
    }

    private CancellationTokenSource CreateDeadline(
        CancellationToken operationCancellationToken)
    {
        var deadline = operationCancellationToken.CanBeCanceled
            ? CancellationTokenSource.CreateLinkedTokenSource(
                operationCancellationToken)
            : new CancellationTokenSource();
        deadline.CancelAfter(_totalTimeout);
        return deadline;
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        const string timeoutMessage = "Keygen administrator request timed out.";
        if (cancellationToken.IsCancellationRequested)
        {
            throw KeygenAdminException.NetworkFailure(timeoutMessage);
        }

        try
        {
            return await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw IsMutationRequest(request)
                ? KeygenAdminException.UncertainRequest(timeoutMessage)
                : KeygenAdminException.NetworkFailure(timeoutMessage);
        }
        catch (HttpRequestException)
        {
            const string message = "Keygen administrator service is unavailable.";
            throw IsMutationRequest(request)
                ? KeygenAdminException.UncertainRequest(message)
                : KeygenAdminException.NetworkFailure(message);
        }
    }

    private static bool IsMutationRequest(HttpRequestMessage request)
    {
        return request.Method == HttpMethod.Post
            || request.Method == HttpMethod.Patch
            || request.Method == HttpMethod.Delete;
    }

    private static void EnsureSuccess(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new KeygenAdminException(response.StatusCode);
        }
    }

    private static async Task<T> ReadJsonAsync<T>(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content is null
            || !string.Equals(
                response.Content.Headers.ContentType?.MediaType,
                JsonApiMediaType,
                StringComparison.OrdinalIgnoreCase))
        {
            throw InvalidResponse();
        }

        var payload = await ReadResponseBytesAsync(
            response.Content,
            cancellationToken);
        try
        {
            return JsonSerializer.Deserialize<T>(payload, JsonOptions)
                ?? throw InvalidResponse();
        }
        catch (JsonException)
        {
            throw InvalidResponse();
        }
        catch (NotSupportedException)
        {
            throw InvalidResponse();
        }
    }

    private static async Task<byte[]> ReadResponseBytesAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > MaxResponseBytes)
        {
            throw InvalidResponse();
        }

        try
        {
            await using var stream = await content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            while (true)
            {
                var count = await stream.ReadAsync(chunk, cancellationToken);
                if (count == 0)
                {
                    return buffer.ToArray();
                }

                if (buffer.Length + count > MaxResponseBytes)
                {
                    throw InvalidResponse();
                }

                buffer.Write(chunk, 0, count);
            }
        }
        catch (OperationCanceledException)
        {
            throw KeygenAdminException.NetworkFailure(
                "Keygen administrator request timed out.");
        }
        catch (HttpRequestException)
        {
            throw KeygenAdminException.NetworkFailure(
                "Keygen administrator service is unavailable.");
        }
        catch (IOException)
        {
            throw KeygenAdminException.NetworkFailure(
                "Keygen administrator service is unavailable.");
        }
    }

    private Uri UsersUri(string? email = null)
    {
        var query = email is null
            ? null
            : $"email={Uri.EscapeDataString(email)}";
        return AccountCollectionUri("users", query);
    }

    private Uri UserUri(string userId)
    {
        return AccountResourceUri("users", userId);
    }

    private Uri LicensesUri(string? ownerId = null, string? policyId = null)
    {
        var query = ownerId is null || policyId is null
            ? null
            : $"owner={Uri.EscapeDataString(ownerId)}&policy={Uri.EscapeDataString(policyId)}";
        return AccountCollectionUri("licenses", query);
    }

    private Uri MachineUri(string machineId)
    {
        return AccountResourceUri("machines", machineId);
    }

    private Uri UserMachinesUri(string userId, int pageNumber)
    {
        var builder = new UriBuilder(_baseUri)
        {
            Path = $"/v1/accounts/{_accountId}/users/{userId}/machines",
            Query = $"page[size]={MachinePageSize}&page[number]={pageNumber}"
        };
        return builder.Uri;
    }

    private Uri AccountCollectionUri(string resource, string? query)
    {
        var builder = new UriBuilder(_baseUri)
        {
            Path = $"/v1/accounts/{_accountId}/{resource}",
            Query = query ?? string.Empty
        };
        return builder.Uri;
    }

    private Uri AccountResourceUri(string resource, string resourceId)
    {
        var builder = new UriBuilder(_baseUri)
        {
            Path = $"/v1/accounts/{_accountId}/{resource}/{resourceId}",
            Query = string.Empty
        };
        return builder.Uri;
    }

    private static HttpClient CreateProductionHttpClient(
        OwnerConfig config,
        string adminToken)
    {
        ArgumentNullException.ThrowIfNull(config);
        ValidateAdminToken(adminToken);
        var baseUri = ValidateAndNormalizeBaseUri(config.AdminUrl);
        ValidateResourceId(config.AccountId, nameof(config.AccountId));
        ValidateResourceId(config.ProductId, nameof(config.ProductId));
        ValidateResourceId(config.TrialPolicyId, nameof(config.TrialPolicyId));
        ValidateResourceId(config.YearPolicyId, nameof(config.YearPolicyId));
        ValidateResourceId(config.ForeverPolicyId, nameof(config.ForeverPolicyId));

        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false
        };
        if (IsLoopbackHttp(baseUri))
        {
            handler.UseProxy = false;
        }

        return new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    private static Uri ValidateAndNormalizeBaseUri(Uri adminUrl)
    {
        ArgumentNullException.ThrowIfNull(adminUrl);
        if (!adminUrl.IsAbsoluteUri
            || !string.Equals(
                adminUrl.AbsoluteUri,
                OwnerConfig.RequiredAdminUrl,
                StringComparison.Ordinal))
        {
            throw new ArgumentException("Invalid administrator URL.", nameof(adminUrl));
        }

        return new Uri(OwnerConfig.RequiredAdminUrl, UriKind.Absolute);
    }

    private static bool IsLoopbackHttp(Uri uri)
    {
        return uri.IsLoopback
            && string.Equals(
                uri.Scheme,
                Uri.UriSchemeHttp,
                StringComparison.OrdinalIgnoreCase);
    }

    private static void ValidateAdminToken(string adminToken)
    {
        if (string.IsNullOrWhiteSpace(adminToken)
            || adminToken.Length > MaxAdminTokenLength
            || adminToken.Contains('\r')
            || adminToken.Contains('\n'))
        {
            throw new ArgumentException("Invalid administrator token.", nameof(adminToken));
        }
    }

    private static void ValidateUser(KeygenUser user)
    {
        ArgumentNullException.ThrowIfNull(user);
        ValidateResourceId(user.Id, nameof(user));
    }

    private static void ValidateTotalTimeout(TimeSpan totalTimeout)
    {
        if (totalTimeout <= TimeSpan.Zero
            || totalTimeout > ProductionTotalTimeout)
        {
            throw new ArgumentOutOfRangeException(
                nameof(totalTimeout),
                "Total timeout must be positive and no greater than eight seconds.");
        }
    }

    private static void ValidateResourceId(string? value, string parameterName)
    {
        if (!IsValidResourceId(value))
        {
            throw new ArgumentException(
                "Invalid Keygen resource identifier.",
                parameterName);
        }
    }

    internal static bool IsValidResourceId(string? value)
    {
        return value is not null && ResourceIdPattern.IsMatch(value);
    }

    private static void ValidateSensitiveText(
        string? value,
        int maximumLength,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
        {
            throw new ArgumentException("Invalid sensitive input.", parameterName);
        }
    }

    private static void ValidateCustomerMetadata(string? customer)
    {
        if (customer is null
            || customer.Length > MaxCustomerLength
            || (customer.Length > 0 && string.IsNullOrWhiteSpace(customer)))
        {
            throw new ArgumentException("Invalid customer metadata.", nameof(customer));
        }
    }

    private static KeygenAdminException InvalidResponse()
    {
        return new KeygenAdminException("Keygen returned an invalid response.");
    }

    private static KeygenAdminException AmbiguousResponse(string resource)
    {
        return new KeygenAdminException($"Keygen returned an ambiguous {resource} response.");
    }

    private sealed class ResourceDocument<T>
    {
        public T? Data { get; init; }
    }

    private sealed class ResourceListDocument<T>
    {
        public List<T>? Data { get; init; }
    }

    private sealed class UserResource
    {
        public string? Type { get; init; }

        public string? Id { get; init; }

        public UserAttributes? Attributes { get; init; }
    }

    private sealed class MachineResource
    {
        public string? Id { get; init; }
    }

    private sealed class UserAttributes
    {
        public string? Email { get; init; }

        public Dictionary<string, JsonElement>? Metadata { get; init; }
    }

    private sealed class LicenseResource
    {
        public string? Type { get; init; }

        public string? Id { get; init; }

        public LicenseAttributes? Attributes { get; init; }

        public LicenseRelationships? Relationships { get; init; }
    }

    private sealed class LicenseAttributes
    {
        public string? Key { get; init; }

        public string? Status { get; init; }

        public string? Expiry { get; init; }

        public LicenseMetadata? Metadata { get; init; }
    }

    private sealed class LicenseMetadata
    {
        public string? Plan { get; init; }

        public int? Price { get; init; }

        public int? DurationSeconds { get; init; }

        public string? BusinessExpiresAt { get; init; }

        public string? OwnerRequestId { get; init; }
    }

    private sealed class LicenseRelationships
    {
        public RelationshipResource? Owner { get; init; }

        public RelationshipResource? Product { get; init; }

        public RelationshipResource? Policy { get; init; }
    }

    private sealed class RelationshipResource
    {
        public ResourceIdentifier? Data { get; init; }
    }

    private sealed class ResourceIdentifier
    {
        public string? Type { get; init; }

        public string? Id { get; init; }
    }
}
