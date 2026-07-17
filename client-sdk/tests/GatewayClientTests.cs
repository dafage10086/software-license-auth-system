using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SoftwareLicenseAuth.Client.Tests;

public sealed class GatewayClientTests
{
    private const string BaseAddress = "https://gateway.example.test/ignored-prefix/";
    private const string ClientVersion = "2.0.0-test";
    private const string Username = "account.one";
    private const string UserId = "user_1";
    private const string LicenseId = "license_1";
    private const string MachineId = "machine_1";
    private const string MachineFingerprint =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    private const string SessionToken = "TEST_ONLY_SESSION_TOKEN_123";
    private const string Password = "TEST_ONLY_PASSWORD_456";
    private const string CardKey = "CARD-TEST-789";
    private const string ManifestSha256 =
        "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
    private const string Challenge = "challenge_ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";
    private const string ServerTime = "2099-01-01T00:00:00Z";
    private const string MachineFileExpiresAt = "2099-01-01T01:00:00Z";
    private const string BusinessExpiresAt = "2100-01-01T00:00:00Z";
    private const int JsonResponseLimit = 32 * 1024;
    private const int MachineFileLimit = 1024 * 1024;
    private const int LeaseResponseLimit = MachineFileLimit + JsonResponseLimit;

    [Fact]
    public void PublicSurface_ContainsOnlyFourFixedGatewayOperations()
    {
        var operations = typeof(GatewayClient)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(method =>
                method.DeclaringType == typeof(GatewayClient)
                && !method.IsPrivate
                && !method.IsSpecialName)
            .OrderBy(method => method.Name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            new[] { "ActivateAsync", "LeaseAsync", "LoginAsync", "LogoutAsync" },
            operations.Select(method => method.Name).ToArray());
        Assert.DoesNotContain(
            operations.SelectMany(method => method.GetParameters()),
            parameter => parameter.Name is "path" or "method" or "ttl" or "include");

        var constructors = typeof(GatewayClient).GetConstructors(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        var constructor = Assert.Single(constructors, candidate => !candidate.IsPrivate);
        Assert.Equal(
            new[] { typeof(Uri), typeof(string) },
            constructor.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        var testConstructor = Assert.Single(constructors, candidate => candidate.IsPrivate);
        Assert.Equal(
            new[]
            {
                typeof(HttpClient),
                typeof(string),
                typeof(bool),
                typeof(TimeSpan),
                typeof(Func<int, MemoryStream>),
                typeof(Action),
                typeof(Action),
            },
            testConstructor.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        Assert.Contains(typeof(IDisposable), typeof(GatewayClient).GetInterfaces());
        Assert.Null(typeof(GatewayClient).GetMethod(
            nameof(IDisposable.Dispose),
            BindingFlags.Instance | BindingFlags.Public));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("version\n2")]
    public void Constructor_RejectsInvalidClientVersion(string clientVersion)
    {
        Assert.Throws<ArgumentException>(() =>
            new GatewayClient(new Uri(BaseAddress), clientVersion));
    }

    [Fact]
    public void Constructor_RejectsClientVersionLongerThanSixtyFourCharacters()
    {
        Assert.Throws<ArgumentException>(() =>
            new GatewayClient(new Uri(BaseAddress), new string('v', 65)));
    }

    [Theory]
    [InlineData("http://nonloopback.example.test/gateway/")]
    [InlineData("https://user:password@gateway.example.test/gateway/")]
    [InlineData("/relative/gateway/")]
    public void ProductionConstructor_RejectsNonHttpsUserInfoOrRelativeBaseAddress(string value)
    {
        var gatewayBaseAddress = new Uri(value, UriKind.RelativeOrAbsolute);

        Assert.Throws<ArgumentException>(() =>
            new GatewayClient(gatewayBaseAddress, ClientVersion));
    }

    [Fact]
    public void ProductionTransport_DisablesRedirectsUsesInfiniteTimeoutAndIgnoresBasePath()
    {
        var handlerFactory = Assert.Single(
            typeof(GatewayClient).GetMethods(BindingFlags.Static | BindingFlags.NonPublic),
            method => method.Name == "CreateProductionHandler");
        Assert.True(handlerFactory.IsPrivate);
        using var handler = Assert.IsType<HttpClientHandler>(handlerFactory.Invoke(null, null));
        Assert.False(handler.AllowAutoRedirect);

        var client = new GatewayClient(new Uri(BaseAddress), ClientVersion);
        var httpClientField = typeof(GatewayClient).GetField(
            "httpClient",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(httpClientField);
        var productionHttpClient = Assert.IsType<HttpClient>(httpClientField.GetValue(client));
        var loginEndpointField = typeof(GatewayClient).GetField(
            "loginEndpoint",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(loginEndpointField);

        try
        {
            Assert.Equal(Timeout.InfiniteTimeSpan, productionHttpClient.Timeout);
            Assert.Equal(
                "https://gateway.example.test/api/v2/login",
                Assert.IsType<Uri>(loginEndpointField.GetValue(client)).AbsoluteUri);
        }
        finally
        {
            productionHttpClient.Dispose();
        }
    }

    [Fact]
    public void Dispose_ReleasesOwnedProductionHttpClientAndIsIdempotent()
    {
        var client = new GatewayClient(new Uri(BaseAddress), ClientVersion);
        var httpClientField = typeof(GatewayClient).GetField(
            "httpClient",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(httpClientField);
        var productionHttpClient = Assert.IsType<HttpClient>(httpClientField.GetValue(client));
        Assert.IsAssignableFrom<IDisposable>(client);

        ((IDisposable)client).Dispose();
        ((IDisposable)client).Dispose();

        Assert.Throws<ObjectDisposedException>(() => productionHttpClient.CancelPendingRequests());
    }

    [Fact]
    public void Dispose_DoesNotReleaseInjectedTestHttpClientAndIsIdempotent()
    {
        var handler = new DisposalTrackingHandler();
        using var injectedHttpClient = NewHttpClient(handler);
        var client = NewClient(injectedHttpClient);
        Assert.IsAssignableFrom<IDisposable>(client);

        ((IDisposable)client).Dispose();
        ((IDisposable)client).Dispose();

        Assert.Equal(0, handler.DisposeCount);
        injectedHttpClient.CancelPendingRequests();
        injectedHttpClient.Dispose();
        Assert.Equal(1, handler.DisposeCount);
    }

    [Fact]
    public async Task LoginAsync_SendsExactFixedRequestAndNormalizesUsername()
    {
        var handler = new StubHandler(async (request, cancellationToken) =>
        {
            await AssertRequestAsync(request, "/api/v2/login", cancellationToken);
            Assert.False(request.Headers.Contains("Authorization"));
            Assert.Null(request.Headers.Authorization);
            AssertRequestToStringRedacts(request, Password);

            using var document = await ReadRequestJsonAsync(request, cancellationToken);
            AssertPropertyNames(
                document.RootElement,
                "product",
                "username",
                "password",
                "client_version");
            Assert.Equal("DEMO-PRODUCT", document.RootElement.GetProperty("product").GetString());
            Assert.Equal(Username, document.RootElement.GetProperty("username").GetString());
            Assert.Equal(Password, document.RootElement.GetProperty("password").GetString());
            Assert.Equal(ClientVersion, document.RootElement.GetProperty("client_version").GetString());
            return JsonResponse(ValidLoginJson());
        });
        var client = NewClient(handler);

        var result = await client.LoginAsync("  Account.One  ", Password);

        Assert.Equal(UserId, result.UserId);
        Assert.Equal(Username, result.Username);
        Assert.Equal(SessionToken, result.SessionToken);
        Assert.Equal(ParseTime(ServerTime), result.ServerTime);
        Assert.DoesNotContain(SessionToken, result.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task ActivateAsync_SendsExactFixedRequestAndBearerHeader()
    {
        var binding = ValidBinding();
        var handler = new StubHandler(async (request, cancellationToken) =>
        {
            await AssertRequestAsync(request, "/api/v2/activate", cancellationToken);
            AssertBearer(request, SessionToken);
            AssertRequestToStringRedacts(request, SessionToken, CardKey);

            using var document = await ReadRequestJsonAsync(request, cancellationToken);
            AssertPropertyNames(
                document.RootElement,
                "product",
                "card_key",
                "device_fingerprint",
                "components",
                "client_version");
            Assert.Equal("DEMO-PRODUCT", document.RootElement.GetProperty("product").GetString());
            Assert.Equal(CardKey, document.RootElement.GetProperty("card_key").GetString());
            Assert.Equal(binding.Fingerprint, document.RootElement.GetProperty("device_fingerprint").GetString());
            Assert.Equal(ClientVersion, document.RootElement.GetProperty("client_version").GetString());
            AssertComponents(document.RootElement.GetProperty("components"), binding.Components);
            Assert.DoesNotContain("token", document.RootElement.EnumerateObject().Select(property => property.Name));
            return JsonResponse(ValidActivateJson());
        });
        var client = NewClient(handler);

        var result = await client.ActivateAsync(
            SessionToken,
            UserId,
            binding,
            "  card-test-789  ");

        Assert.Equal(UserId, result.UserId);
        Assert.Equal(LicenseId, result.LicenseId);
        Assert.Equal(MachineId, result.MachineId);
        Assert.Equal(MachineFingerprint, result.MachineFingerprint);
        Assert.Equal("YEAR", result.Plan);
        Assert.Equal(128, result.Price);
        Assert.Equal(ParseTime(BusinessExpiresAt), result.ExpiresAt);
        Assert.Equal(ParseTime(ServerTime), result.ServerTime);
    }

    [Fact]
    public async Task ActivateAsync_OmitsEmptyCardKey()
    {
        var handler = new StubHandler(async (request, cancellationToken) =>
        {
            using var document = await ReadRequestJsonAsync(request, cancellationToken);
            AssertPropertyNames(
                document.RootElement,
                "product",
                "device_fingerprint",
                "components",
                "client_version");
            return JsonResponse(ValidActivateJson(
                plan: "TRIAL",
                price: 0,
                expiresAt: BusinessExpiresAt));
        });
        var client = NewClient(handler);

        var result = await client.ActivateAsync(SessionToken, UserId, ValidBinding(), "   ");

        Assert.Equal("TRIAL", result.Plan);
        Assert.Equal(0, result.Price);
    }

    [Theory]
    [InlineData("YEAR", 128, BusinessExpiresAt)]
    [InlineData("FOREVER", 288, "")]
    public async Task ActivateAsync_NoCardRecoveryAcceptsBoundPaidPlan(
        string plan,
        int price,
        string expiresAt)
    {
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(
            ValidActivateJson(plan: plan, price: price, expiresAt: expiresAt)))));

        var result = await client.ActivateAsync(
            SessionToken,
            UserId,
            ValidBinding());

        Assert.Equal(plan, result.Plan);
        Assert.Equal(price, result.Price);
    }

    [Fact]
    public async Task ActivateAsync_TrialResponseMayOmitZeroPrice()
    {
        var json = ValidActivateJson(
            plan: "TRIAL",
            price: 0,
            expiresAt: BusinessExpiresAt);
        Assert.DoesNotContain("\"price\"", json, StringComparison.Ordinal);
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));

        var result = await client.ActivateAsync(
            SessionToken,
            UserId,
            ValidBinding());

        Assert.Equal("TRIAL", result.Plan);
        Assert.Equal(0, result.Price);
        Assert.Equal(ParseTime(BusinessExpiresAt), result.ExpiresAt);
    }

    [Fact]
    public async Task ActivateAsync_ForeverResponseMayOmitEmptyExpiresAt()
    {
        var json = ValidActivateJson(
            plan: "FOREVER",
            price: 288,
            expiresAt: string.Empty);
        Assert.DoesNotContain("\"expires_at\"", json, StringComparison.Ordinal);
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));

        var result = await client.ActivateAsync(
            SessionToken,
            UserId,
            ValidBinding(),
            CardKey);

        Assert.Equal("FOREVER", result.Plan);
        Assert.Equal(288, result.Price);
        Assert.Null(result.ExpiresAt);
    }

    [Fact]
    public async Task LeaseAsync_SendsExactFixedRequestWithHashedComponents()
    {
        var binding = ValidBinding();
        const string rawHardwareMarker = "RAW-HARDWARE-MUST-NOT-BE-SENT";
        Assert.DoesNotContain(rawHardwareMarker, binding.Components.Values);
        var machineFile = "machine/signed-certificate";
        var handler = new StubHandler(async (request, cancellationToken) =>
        {
            await AssertRequestAsync(request, "/api/v2/lease", cancellationToken);
            AssertBearer(request, SessionToken);
            AssertRequestToStringRedacts(request, SessionToken);

            using var document = await ReadRequestJsonAsync(request, cancellationToken);
            AssertPropertyNames(
                document.RootElement,
                "product",
                "machine_id",
                "device_fingerprint",
                "components",
                "manifest_sha256",
                "challenge",
                "client_version");
            Assert.Equal("DEMO-PRODUCT", document.RootElement.GetProperty("product").GetString());
            Assert.Equal(MachineId, document.RootElement.GetProperty("machine_id").GetString());
            Assert.Equal(binding.Fingerprint, document.RootElement.GetProperty("device_fingerprint").GetString());
            AssertComponents(document.RootElement.GetProperty("components"), binding.Components);
            Assert.Equal(ManifestSha256, document.RootElement.GetProperty("manifest_sha256").GetString());
            Assert.Equal(Challenge, document.RootElement.GetProperty("challenge").GetString());
            Assert.Equal(ClientVersion, document.RootElement.GetProperty("client_version").GetString());
            Assert.DoesNotContain(rawHardwareMarker, Encoding.UTF8.GetString(
                await request.Content!.ReadAsByteArrayAsync(cancellationToken)), StringComparison.Ordinal);
            return JsonResponse(ValidLeaseJson(machineFile));
        });
        var client = NewClient(handler);

        var result = await client.LeaseAsync(
            SessionToken,
            MachineId,
            binding,
            ManifestSha256,
            Challenge);

        Assert.Equal(machineFile, result.MachineFile);
        Assert.Equal(ParseTime(MachineFileExpiresAt), result.MachineFileExpiresAt);
        Assert.Equal(600, result.RefreshAfterSeconds);
        Assert.Equal(Challenge, result.Challenge);
        Assert.Equal(ManifestSha256, result.ManifestSha256);
        Assert.Equal(ComputeBinding(machineFile, ManifestSha256, Challenge), result.BindingSha256);
        Assert.Equal("YEAR", result.Plan);
        Assert.Equal(ParseTime(BusinessExpiresAt), result.BusinessExpiresAt);
        Assert.Equal(ParseTime(ServerTime), result.ServerTime);
        Assert.DoesNotContain(machineFile, result.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task LeaseAsync_ForeverResponseMayOmitEmptyBusinessExpiresAt()
    {
        const string machineFile = "machine/forever-signed-certificate";
        var json = ValidLeaseJson(
            machineFile,
            plan: "FOREVER",
            businessExpiresAt: string.Empty);
        Assert.DoesNotContain("\"business_expires_at\"", json, StringComparison.Ordinal);
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));

        var result = await client.LeaseAsync(
            SessionToken,
            MachineId,
            ValidBinding(),
            ManifestSha256,
            Challenge);

        Assert.Equal("FOREVER", result.Plan);
        Assert.Null(result.BusinessExpiresAt);
    }

    [Fact]
    public async Task LeaseAsync_DoesNotUseLocalClockAsUnsignedOuterExpiryAuthority()
    {
        const string machineFile = "machine/clock-skew-signed-certificate";
        const string pastServerTime = "2000-01-01T00:00:00Z";
        const string pastOuterExpiry = "2000-01-01T01:00:00Z";
        var json = ValidLeaseJson(
            machineFile,
            machineFileExpiresAt: pastOuterExpiry,
            plan: "FOREVER",
            businessExpiresAt: string.Empty,
            serverTime: pastServerTime);
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));

        var result = await client.LeaseAsync(
            SessionToken,
            MachineId,
            ValidBinding(),
            ManifestSha256,
            Challenge);

        Assert.Equal(ParseTime(pastServerTime), result.ServerTime);
        Assert.Equal(ParseTime(pastOuterExpiry), result.MachineFileExpiresAt);
    }

    [Fact]
    public async Task LogoutAsync_SendsOnlyProductAndBearerHeader()
    {
        var handler = new StubHandler(async (request, cancellationToken) =>
        {
            await AssertRequestAsync(request, "/api/v2/logout", cancellationToken);
            AssertBearer(request, SessionToken);
            AssertRequestToStringRedacts(request, SessionToken);
            using var document = await ReadRequestJsonAsync(request, cancellationToken);
            AssertPropertyNames(document.RootElement, "product");
            Assert.Equal("DEMO-PRODUCT", document.RootElement.GetProperty("product").GetString());
            return JsonResponse(ValidLogoutJson());
        });
        var client = NewClient(handler);

        var result = await client.LogoutAsync(SessionToken);

        Assert.Equal(ParseTime(ServerTime), result.ServerTime);
    }

    [Theory]
    [MemberData(nameof(InvalidTokens))]
    public async Task AuthenticatedOperations_RejectInvalidTokensBeforeSending(string token)
    {
        var handler = new StubHandler((_, _) => throw new Xunit.Sdk.XunitException(
            "Invalid token reached the HTTP handler."));
        var client = NewClient(handler);

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => client.LogoutAsync(token));

        Assert.Equal(0, handler.CallCount);
        if (!string.IsNullOrWhiteSpace(token))
        {
            Assert.DoesNotContain(token, exception.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task ActivateAsync_ValidatesComponentDictionaryBeforeSending()
    {
        var invalidBinding = new DeviceBinding(
            new string('F', 64),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["smbios"] = new string('A', 64),
                ["baseboard"] = new string('A', 64),
                ["raw_serial"] = new string('C', 64),
            });
        var handler = new StubHandler((_, _) => throw new Xunit.Sdk.XunitException(
            "Invalid binding reached the HTTP handler."));
        var client = NewClient(handler);

        await Assert.ThrowsAsync<ArgumentException>(() => client.ActivateAsync(
            SessionToken,
            UserId,
            invalidBinding));

        Assert.Equal(0, handler.CallCount);
    }

    [Theory]
    [InlineData("machine.invalid", ManifestSha256, Challenge)]
    [InlineData(MachineId, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Challenge)]
    [InlineData(MachineId, ManifestSha256, "too_short")]
    public async Task LeaseAsync_RejectsInvalidIdentifiersBeforeSending(
        string machineId,
        string manifestSha256,
        string challenge)
    {
        var handler = new StubHandler((_, _) => throw new Xunit.Sdk.XunitException(
            "Invalid lease input reached the HTTP handler."));
        var client = NewClient(handler);

        await Assert.ThrowsAsync<ArgumentException>(() => client.LeaseAsync(
            SessionToken,
            machineId,
            ValidBinding(),
            manifestSha256,
            challenge));

        Assert.Equal(0, handler.CallCount);
    }

    [Theory]
    [InlineData("challenge", ManifestSha256, null)]
    [InlineData("manifest", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", null)]
    [InlineData("binding", ManifestSha256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task LeaseAsync_RejectsChallengeManifestOrBindingMismatch(
        string mismatch,
        string responseManifest,
        string? responseBinding)
    {
        var responseChallenge = mismatch == "challenge"
            ? "different_ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789"
            : Challenge;
        const string machineFile = "machine/signed-certificate";
        responseBinding ??= mismatch == "binding"
            ? new string('A', 64)
            : ComputeBinding(machineFile, responseManifest, responseChallenge);
        var handler = new StubHandler((_, _) => Task.FromResult(JsonResponse(ValidLeaseJson(
            machineFile,
            challenge: responseChallenge,
            manifestSha256: responseManifest,
            bindingSha256: responseBinding))));
        var client = NewClient(handler);

        await Assert.ThrowsAsync<GatewayException>(() => client.LeaseAsync(
            SessionToken,
            MachineId,
            ValidBinding(),
            ManifestSha256,
            Challenge));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task LoginAsync_RejectsResponseOverThirtyTwoKiBBeforeParsing(bool contentLengthKnown)
    {
        var content = contentLengthKnown
            ? (HttpContent)new DeclaredLengthContent(JsonResponseLimit + 1)
            : new ChunkedContent(new byte[JsonResponseLimit + 1]);
        var handler = new StubHandler((_, _) => Task.FromResult(Response(content)));
        var client = NewClient(handler);

        await Assert.ThrowsAsync<GatewayException>(() => client.LoginAsync(Username, Password));

        if (content is DeclaredLengthContent declared)
        {
            Assert.False(declared.WasRead);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task LeaseAsync_RejectsTotalResponseOverLeaseLimitBeforeParsing(bool contentLengthKnown)
    {
        var content = contentLengthKnown
            ? (HttpContent)new DeclaredLengthContent(LeaseResponseLimit + 1L)
            : new ChunkedContent(new byte[LeaseResponseLimit + 1]);
        var handler = new StubHandler((_, _) => Task.FromResult(Response(content)));
        var client = NewClient(handler);

        await Assert.ThrowsAsync<GatewayException>(() => client.LeaseAsync(
            SessionToken,
            MachineId,
            ValidBinding(),
            ManifestSha256,
            Challenge));

        if (content is DeclaredLengthContent declared)
        {
            Assert.False(declared.WasRead);
        }
    }

    [Fact]
    public async Task LeaseAsync_RejectsMachineFileWhoseUtf8EncodingExceedsOneMiB()
    {
        var oversizedMachineFile = new string('m', MachineFileLimit + 1);
        var handler = new StubHandler((_, _) => Task.FromResult(
            JsonResponse(ValidLeaseJson(oversizedMachineFile))));
        var client = NewClient(handler);

        await Assert.ThrowsAsync<GatewayException>(() => client.LeaseAsync(
            SessionToken,
            MachineId,
            ValidBinding(),
            ManifestSha256,
            Challenge));
    }

    [Fact]
    public async Task ReadLimitedAsync_ZeroesWrittenResponseBufferOnSuccess()
    {
        var buffers = new TrackingResponseBufferFactory();
        var client = NewClient(
            new StubHandler((_, _) => Task.FromResult(JsonResponse(ValidLoginJson()))),
            buffers.Create);

        _ = await client.LoginAsync(Username, Password);

        buffers.AssertWrittenBytesWereCleared();
    }

    [Fact]
    public async Task ReadLimitedAsync_ZeroesWrittenResponseBufferOnStreamingOverflow()
    {
        var buffers = new TrackingResponseBufferFactory();
        var oversizedBody = Enumerable.Repeat((byte)0x5a, JsonResponseLimit + 1).ToArray();
        var client = NewClient(
            new StubHandler((_, _) => Task.FromResult(Response(new ChunkedContent(oversizedBody)))),
            buffers.Create);

        await Assert.ThrowsAsync<GatewayException>(() => client.LoginAsync(Username, Password));

        buffers.AssertWrittenBytesWereCleared();
    }

    [Fact]
    public async Task ReadLimitedAsync_ZeroesWrittenResponseBufferWhenStreamThrowsIOException()
    {
        var buffers = new TrackingResponseBufferFactory();
        var client = NewClient(
            new StubHandler((_, _) => Task.FromResult(Response(
                new PartialReadContent(Encoding.UTF8.GetBytes("SENSITIVE-PARTIAL-RESPONSE"),
                    PartialReadFailure.IOException)))),
            buffers.Create);

        await Assert.ThrowsAsync<GatewayException>(() => client.LoginAsync(Username, Password));

        buffers.AssertWrittenBytesWereCleared();
    }

    [Fact]
    public async Task ReadLimitedAsync_ZeroesWrittenResponseBufferWhenCallerCancelsRead()
    {
        var buffers = new TrackingResponseBufferFactory();
        var client = NewClient(
            new StubHandler((_, _) => Task.FromResult(Response(
                new PartialReadContent(Encoding.UTF8.GetBytes("SENSITIVE-CANCELED-RESPONSE"),
                    PartialReadFailure.WaitForCancellation)))),
            buffers.Create);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(75));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.LoginAsync(Username, Password, cancellation.Token));

        buffers.AssertWrittenBytesWereCleared();
    }

    [Fact]
    public async Task SendAsync_ZeroesUntransferredToArrayCopyWhenCallerCancelsAtEof()
    {
        var buffers = new TrackingResponseBufferFactory();
        using var cancellation = new CancellationTokenSource();
        var sensitiveJson = Encoding.UTF8.GetBytes(ValidLoginJson());
        var client = NewClient(
            new StubHandler((_, _) => Task.FromResult(Response(
                new CancelOnEofContent(sensitiveJson, cancellation.Cancel)))),
            buffers.Create);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.LoginAsync(Username, Password, cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        buffers.AssertWrittenBytesWereCleared();
        buffers.AssertReturnedCopyWasCleared();
    }

    [Fact]
    public async Task CallTimeout_IsSingleEightSecondBudgetAcrossHeadersAndBody()
    {
        var validBody = Encoding.UTF8.GetBytes(ValidLoginJson());
        var handler = new StubHandler(async (_, cancellationToken) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(4.5), cancellationToken);
            return Response(new DelayedContent(validBody, TimeSpan.FromSeconds(4.5)));
        });
        var client = NewClient(handler);
        var stopwatch = Stopwatch.StartNew();

        var exception = await Assert.ThrowsAsync<GatewayException>(() =>
            client.LoginAsync(Username, Password));

        stopwatch.Stop();
        Assert.InRange(stopwatch.Elapsed, TimeSpan.FromSeconds(7), TimeSpan.FromSeconds(10));
        Assert.Contains("timed out", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public async Task CallDeadline_StartsBeforeRequestConstructionAndUsesCumulativeBudget()
    {
        var handler = new StubHandler(async (_, cancellationToken) =>
        {
            await Task.Delay(TimeSpan.FromMilliseconds(200), cancellationToken);
            return JsonResponse(ValidLoginJson());
        });
        var client = NewClient(
            handler,
            callTimeout: TimeSpan.FromMilliseconds(200),
            beforeRequestConstruction: () => Thread.Sleep(TimeSpan.FromMilliseconds(120)));

        var exception = await Assert.ThrowsAsync<GatewayException>(() =>
            client.LoginAsync(Username, Password));

        Assert.Equal(1, handler.CallCount);
        Assert.Contains("timed out", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public async Task CallDeadline_IsCheckedAfterLeaseParsingAndBindingValidation()
    {
        const string machineFile = "machine/deadline-signed-certificate";
        var client = NewClient(
            new StubHandler((_, _) => Task.FromResult(JsonResponse(ValidLeaseJson(machineFile)))),
            callTimeout: TimeSpan.FromMilliseconds(50),
            afterResponseParsed: () => Thread.Sleep(TimeSpan.FromMilliseconds(250)));

        var exception = await Assert.ThrowsAsync<GatewayException>(() => client.LeaseAsync(
            SessionToken,
            MachineId,
            ValidBinding(),
            ManifestSha256,
            Challenge));

        Assert.Contains("timed out", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public async Task CallerCancellationAfterParsingPreservesCallerCancellationToken()
    {
        using var cancellation = new CancellationTokenSource();
        var client = NewClient(
            new StubHandler((_, _) => Task.FromResult(JsonResponse(ValidLoginJson()))),
            callTimeout: TimeSpan.FromSeconds(1),
            afterResponseParsed: cancellation.Cancel);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.LoginAsync(Username, Password, cancellation.Token));

        Assert.IsNotType<GatewayException>(exception);
        Assert.Equal(cancellation.Token, exception.CancellationToken);
    }

    [Fact]
    public async Task CallerCancellation_RemainsOperationCanceledException()
    {
        var handler = new StubHandler(async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("Unreachable.");
        });
        var client = NewClient(handler);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(75));

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.LoginAsync(Username, Password, cancellation.Token));

        Assert.IsNotType<GatewayException>(exception);
        Assert.True(cancellation.IsCancellationRequested);
    }

    [Theory]
    [InlineData("{\"ok\":true,\"message\":\"ok\",\"session_token\":\"TEST_ONLY_SESSION_TOKEN_123\",\"user_id\":\"user_1\",\"username\":\"account.one\",\"server_time\":\"2099-01-01T00:00:00Z\",\"unknown\":1}")]
    [InlineData("{\"ok\":true,\"ok\":true,\"message\":\"ok\",\"session_token\":\"TEST_ONLY_SESSION_TOKEN_123\",\"user_id\":\"user_1\",\"username\":\"account.one\",\"server_time\":\"2099-01-01T00:00:00Z\"}")]
    [InlineData("{\"ok\":true,\"message\":\"ok\",\"user_id\":\"user_1\",\"username\":\"account.one\",\"server_time\":\"2099-01-01T00:00:00Z\"}")]
    [InlineData("{\"ok\":\"true\",\"message\":\"ok\",\"session_token\":\"TEST_ONLY_SESSION_TOKEN_123\",\"user_id\":\"user_1\",\"username\":\"account.one\",\"server_time\":\"2099-01-01T00:00:00Z\"}")]
    [InlineData("{\"ok\":true,\"message\":\"ok\",\"session_token\":\"TEST_ONLY_SESSION_TOKEN_123\",\"user_id\":\"user_1\",\"username\":\"account.one\",\"server_time\":\"2099-01-01T00:00:00Z\"} {}")]
    public async Task LoginAsync_RejectsUnknownDuplicateMissingWrongTypeOrMultipleJson(string json)
    {
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));

        await Assert.ThrowsAsync<GatewayException>(() => client.LoginAsync(Username, Password));
    }

    [Fact]
    public async Task LoginAsync_RejectsUsernameMismatchAndInvalidOutputToken()
    {
        var mismatched = ValidLoginJson(username: "other.user");
        var invalidToken = ValidLoginJson(token: "invalid token");

        foreach (var json in new[] { mismatched, invalidToken })
        {
            var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));
            await Assert.ThrowsAsync<GatewayException>(() => client.LoginAsync(Username, Password));
        }
    }

    [Theory]
    [InlineData("other_user", LicenseId, MachineId, "YEAR", 128, BusinessExpiresAt)]
    [InlineData(UserId, "license.invalid", MachineId, "YEAR", 128, BusinessExpiresAt)]
    [InlineData(UserId, LicenseId, "machine.invalid", "YEAR", 128, BusinessExpiresAt)]
    [InlineData(UserId, LicenseId, MachineId, "YEAR", 0, BusinessExpiresAt)]
    [InlineData(UserId, LicenseId, MachineId, "UNKNOWN", 128, BusinessExpiresAt)]
    [InlineData(UserId, LicenseId, MachineId, "TRIAL", 0, "")]
    [InlineData(UserId, LicenseId, MachineId, "FOREVER", 288, BusinessExpiresAt)]
    public async Task ActivateAsync_RejectsInvalidIdentityPlanPriceOrExpiry(
        string responseUserId,
        string licenseId,
        string machineId,
        string plan,
        int price,
        string expiresAt)
    {
        var json = ValidActivateJson(
            userId: responseUserId,
            licenseId: licenseId,
            machineId: machineId,
            plan: plan,
            price: price,
            expiresAt: expiresAt);
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));

        await Assert.ThrowsAsync<GatewayException>(() => client.ActivateAsync(
            SessionToken,
            UserId,
            ValidBinding(),
            CardKey));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
    [InlineData("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFG")]
    public async Task ActivateAsync_RejectsMissingOrInvalidMachineFingerprint(
        string? machineFingerprint)
    {
        var json = ValidActivateJson(machineFingerprint: machineFingerprint);
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));

        await Assert.ThrowsAsync<GatewayException>(() => client.ActivateAsync(
            SessionToken,
            UserId,
            ValidBinding(),
            CardKey));
    }

    [Theory]
    [InlineData(599, MachineFileExpiresAt, "YEAR", BusinessExpiresAt)]
    [InlineData(600, "2099-01-01T00:00:00Z", "YEAR", BusinessExpiresAt)]
    [InlineData(600, "2099-01-01T01:01:41Z", "YEAR", BusinessExpiresAt)]
    [InlineData(600, MachineFileExpiresAt, "YEAR", "")]
    [InlineData(600, MachineFileExpiresAt, "FOREVER", BusinessExpiresAt)]
    [InlineData(600, MachineFileExpiresAt, "UNKNOWN", BusinessExpiresAt)]
    public async Task LeaseAsync_RejectsInvalidEnvelopeRefreshOrBusinessExpiry(
        int refreshAfterSeconds,
        string machineFileExpiresAt,
        string plan,
        string businessExpiresAt)
    {
        const string machineFile = "machine/signed-certificate";
        var json = ValidLeaseJson(
            machineFile,
            refreshAfterSeconds: refreshAfterSeconds,
            machineFileExpiresAt: machineFileExpiresAt,
            plan: plan,
            businessExpiresAt: businessExpiresAt);
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));

        await Assert.ThrowsAsync<GatewayException>(() => client.LeaseAsync(
            SessionToken,
            MachineId,
            ValidBinding(),
            ManifestSha256,
            Challenge));
    }

    [Fact]
    public async Task LeaseAsync_RejectsUnsignedFallbackResponseField()
    {
        var json = ValidLeaseJson("machine/signed-certificate");
        json = json[..^1] + ",\"unsigned_machine_file\":\"fallback\"}";
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));

        await Assert.ThrowsAsync<GatewayException>(() => client.LeaseAsync(
            SessionToken,
            MachineId,
            ValidBinding(),
            ManifestSha256,
            Challenge));
    }

    [Fact]
    public async Task Responses_RequireApplicationJson()
    {
        var content = new StringContent(ValidLoginJson(), Encoding.UTF8, "text/plain");
        var client = NewClient(new StubHandler((_, _) => Task.FromResult(Response(content))));

        await Assert.ThrowsAsync<GatewayException>(() => client.LoginAsync(Username, Password));
    }

    [Fact]
    public async Task HttpFailure_IsSanitizedAndDoesNotLeakPasswordOrUpstreamMessage()
    {
        const string upstreamMarker = "UPSTREAM-PRIVATE-MESSAGE-123";
        var handler = new StubHandler((_, _) => Task.FromResult(JsonResponse(
            $"{{\"ok\":false,\"message\":\"{upstreamMarker} {Password}\",\"server_time\":\"{ServerTime}\"}}",
            HttpStatusCode.Unauthorized)));
        var client = NewClient(handler);

        var exception = await Assert.ThrowsAsync<GatewayException>(() =>
            client.LoginAsync(Username, Password));

        Assert.Equal(HttpStatusCode.Unauthorized, exception.StatusCode);
        Assert.DoesNotContain(Password, exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(upstreamMarker, exception.ToString(), StringComparison.Ordinal);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public async Task AuthenticatedHttpFailure_DoesNotLeakTokenCardOrPayload()
    {
        const string upstreamMarker = "UPSTREAM-CARD-FAILURE-PAYLOAD-456";
        var handler = new StubHandler((request, _) =>
        {
            AssertBearer(request, SessionToken);
            return Task.FromResult(JsonResponse(
                $"{{\"ok\":false,\"message\":\"{upstreamMarker} {SessionToken} {CardKey}\",\"server_time\":\"{ServerTime}\"}}",
                HttpStatusCode.Forbidden));
        });
        var client = NewClient(handler);

        var exception = await Assert.ThrowsAsync<GatewayException>(() => client.ActivateAsync(
            SessionToken,
            UserId,
            ValidBinding(),
            CardKey));

        Assert.Equal(HttpStatusCode.Forbidden, exception.StatusCode);
        Assert.DoesNotContain(SessionToken, exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(CardKey, exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(upstreamMarker, exception.ToString(), StringComparison.Ordinal);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public async Task LoginAsync_TemporaryRedirectIsNotFollowedAndDoesNotLeakPassword()
    {
        var redirectTarget = new Uri("https://redirect-target.example.test/capture-login");
        var requestedUris = new List<Uri>();
        var handler = new StubHandler((request, _) =>
        {
            requestedUris.Add(request.RequestUri!);
            var response = JsonResponse(
                $"{{\"ok\":false,\"message\":\"redirect login\",\"server_time\":\"{ServerTime}\"}}",
                HttpStatusCode.TemporaryRedirect);
            response.Headers.Location = redirectTarget;
            return Task.FromResult(response);
        });
        var client = NewClient(handler);

        var exception = await Assert.ThrowsAsync<GatewayException>(() =>
            client.LoginAsync(Username, Password));

        Assert.Equal(HttpStatusCode.TemporaryRedirect, exception.StatusCode);
        Assert.Equal(new[] { new Uri("https://gateway.example.test/api/v2/login") }, requestedUris);
        Assert.DoesNotContain(Password, exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(redirectTarget.AbsoluteUri, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task LogoutAsync_PermanentRedirectIsNotFollowedAndDoesNotLeakBearerToken()
    {
        var redirectTarget = new Uri("https://redirect-target.example.test/capture-token");
        var requestedUris = new List<Uri>();
        var handler = new StubHandler((request, _) =>
        {
            requestedUris.Add(request.RequestUri!);
            var response = JsonResponse(
                $"{{\"ok\":false,\"message\":\"redirect logout\",\"server_time\":\"{ServerTime}\"}}",
                HttpStatusCode.PermanentRedirect);
            response.Headers.Location = redirectTarget;
            return Task.FromResult(response);
        });
        var client = NewClient(handler);

        var exception = await Assert.ThrowsAsync<GatewayException>(() =>
            client.LogoutAsync(SessionToken));

        Assert.Equal(HttpStatusCode.PermanentRedirect, exception.StatusCode);
        Assert.Equal(new[] { new Uri("https://gateway.example.test/api/v2/logout") }, requestedUris);
        Assert.DoesNotContain(SessionToken, exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(redirectTarget.AbsoluteUri, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task NetworkFailure_IsSanitizedWithoutInnerException()
    {
        const string networkMarker = "NETWORK-INTERNAL-DETAIL-789";
        var handler = new StubHandler((_, _) => throw new HttpRequestException(
            networkMarker,
            new SocketException((int)SocketError.ConnectionRefused)));
        var client = NewClient(handler);

        var exception = await Assert.ThrowsAsync<GatewayException>(() =>
            client.LoginAsync(Username, Password));

        Assert.DoesNotContain(networkMarker, exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Password, exception.ToString(), StringComparison.Ordinal);
        Assert.Null(exception.InnerException);
        Assert.Null(exception.StatusCode);
    }

    [Fact]
    public async Task LogoutAsync_RequiresTrueOkAndValidServerTime()
    {
        foreach (var json in new[]
                 {
                     $"{{\"ok\":false,\"message\":\"ok\",\"server_time\":\"{ServerTime}\"}}",
                     "{\"ok\":true,\"message\":\"ok\",\"server_time\":\"not-a-time\"}",
                 })
        {
            var client = NewClient(new StubHandler((_, _) => Task.FromResult(JsonResponse(json))));
            await Assert.ThrowsAsync<GatewayException>(() => client.LogoutAsync(SessionToken));
        }
    }

    public static IEnumerable<object[]> InvalidTokens()
    {
        yield return new object[] { string.Empty };
        yield return new object[] { "   " };
        yield return new object[] { "token with space" };
        yield return new object[] { "token\twith-control" };
        yield return new object[] { "token\u0001with-control" };
        yield return new object[] { new string('t', 4097) };
    }

    private static GatewayClient NewClient(
        HttpMessageHandler handler,
        Func<int, MemoryStream>? responseBufferFactory = null,
        TimeSpan? callTimeout = null,
        Action? beforeRequestConstruction = null,
        Action? afterResponseParsed = null)
    {
        return NewClient(
            NewHttpClient(handler),
            responseBufferFactory,
            callTimeout,
            beforeRequestConstruction,
            afterResponseParsed);
    }

    private static GatewayClient NewClient(
        HttpClient httpClient,
        Func<int, MemoryStream>? responseBufferFactory = null,
        TimeSpan? callTimeout = null,
        Action? beforeRequestConstruction = null,
        Action? afterResponseParsed = null)
    {
        var constructor = typeof(GatewayClient).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            [
                typeof(HttpClient),
                typeof(string),
                typeof(bool),
                typeof(TimeSpan),
                typeof(Func<int, MemoryStream>),
                typeof(Action),
                typeof(Action),
            ],
            modifiers: null);
        Assert.NotNull(constructor);
        Assert.True(constructor.IsPrivate);
        return Assert.IsType<GatewayClient>(constructor.Invoke(
            [
                httpClient,
                ClientVersion,
                false,
                callTimeout ?? TimeSpan.FromSeconds(8),
                responseBufferFactory,
                beforeRequestConstruction,
                afterResponseParsed,
            ]));
    }

    private static HttpClient NewHttpClient(HttpMessageHandler handler)
    {
        return new HttpClient(handler)
        {
            BaseAddress = new Uri(BaseAddress),
            Timeout = Timeout.InfiniteTimeSpan,
        };
    }

    private static DeviceBinding ValidBinding()
    {
        return new DeviceBinding(
            new string('F', 64),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["smbios"] = new string('A', 64),
                ["baseboard"] = new string('B', 64),
                ["bios"] = new string('C', 64),
                ["device_key"] = new string('D', 64),
            });
    }

    private static async Task AssertRequestAsync(
        HttpRequestMessage request,
        string expectedPath,
        CancellationToken cancellationToken)
    {
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.NotNull(request.RequestUri);
        Assert.True(request.RequestUri!.IsAbsoluteUri);
        Assert.Equal("https://gateway.example.test" + expectedPath, request.RequestUri.AbsoluteUri);
        Assert.Equal(string.Empty, request.RequestUri.Query);
        Assert.NotNull(request.Content);
        Assert.Equal("application/json", request.Content!.Headers.ContentType?.MediaType);
        _ = await request.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    private static void AssertBearer(HttpRequestMessage request, string expectedToken)
    {
        Assert.NotNull(request.Headers.Authorization);
        Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        Assert.Equal(expectedToken, request.Headers.Authorization.Parameter);
        Assert.Single(request.Headers.GetValues("Authorization"));
    }

    private static void AssertRequestToStringRedacts(
        HttpRequestMessage request,
        params string[] sensitiveValues)
    {
        var text = request.ToString();
        foreach (var sensitiveValue in sensitiveValues)
        {
            Assert.DoesNotContain(sensitiveValue, text, StringComparison.Ordinal);
        }
    }

    private static async Task<JsonDocument> ReadRequestJsonAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Assert.NotNull(request.Content);
        var bytes = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
        return JsonDocument.Parse(bytes);
    }

    private static void AssertPropertyNames(JsonElement element, params string[] expected)
    {
        Assert.Equal(JsonValueKind.Object, element.ValueKind);
        Assert.Equal(expected, element.EnumerateObject().Select(property => property.Name).ToArray());
    }

    private static void AssertComponents(
        JsonElement element,
        IReadOnlyDictionary<string, string> expected)
    {
        Assert.Equal(JsonValueKind.Object, element.ValueKind);
        var actual = element.EnumerateObject().ToDictionary(
            property => property.Name,
            property => property.Value.GetString()!,
            StringComparer.Ordinal);
        Assert.Equal(expected.Count, actual.Count);
        foreach (var component in expected)
        {
            Assert.True(actual.TryGetValue(component.Key, out var hash));
            Assert.Equal(component.Value, hash);
        }
    }

    private static HttpResponseMessage JsonResponse(
        string json,
        HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        return Response(
            new StringContent(json, Encoding.UTF8, "application/json"),
            statusCode);
    }

    private static HttpResponseMessage Response(
        HttpContent content,
        HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        return new HttpResponseMessage(statusCode) { Content = content };
    }

    private static string ValidLoginJson(
        string username = Username,
        string token = SessionToken)
    {
        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["ok"] = true,
            ["message"] = "ok",
            ["session_token"] = token,
            ["user_id"] = UserId,
            ["username"] = username,
            ["server_time"] = ServerTime,
        });
    }

    private static string ValidActivateJson(
        string userId = UserId,
        string licenseId = LicenseId,
        string machineId = MachineId,
        string? machineFingerprint = MachineFingerprint,
        string plan = "YEAR",
        int price = 128,
        string expiresAt = BusinessExpiresAt)
    {
        var response = new Dictionary<string, object?>
        {
            ["ok"] = true,
            ["message"] = "ok",
            ["user_id"] = userId,
            ["license_id"] = licenseId,
            ["machine_id"] = machineId,
            ["plan"] = plan,
        };
        if (machineFingerprint is not null)
        {
            response["machine_fingerprint"] = machineFingerprint;
        }
        if (price != 0)
        {
            response["price"] = price;
        }

        if (expiresAt.Length != 0)
        {
            response["expires_at"] = expiresAt;
        }

        response["server_time"] = ServerTime;
        return JsonSerializer.Serialize(response);
    }

    private static string ValidLeaseJson(
        string machineFile,
        int refreshAfterSeconds = 600,
        string challenge = Challenge,
        string manifestSha256 = ManifestSha256,
        string? bindingSha256 = null,
        string machineFileExpiresAt = MachineFileExpiresAt,
        string plan = "YEAR",
        string businessExpiresAt = BusinessExpiresAt,
        string serverTime = ServerTime)
    {
        bindingSha256 ??= ComputeBinding(machineFile, manifestSha256, challenge);
        var response = new Dictionary<string, object?>
        {
            ["ok"] = true,
            ["message"] = "ok",
            ["machine_file"] = machineFile,
            ["machine_file_expires_at"] = machineFileExpiresAt,
            ["refresh_after_seconds"] = refreshAfterSeconds,
            ["challenge"] = challenge,
            ["manifest_sha256"] = manifestSha256,
            ["binding_sha256"] = bindingSha256,
            ["plan"] = plan,
        };
        if (businessExpiresAt.Length != 0)
        {
            response["business_expires_at"] = businessExpiresAt;
        }

        response["server_time"] = serverTime;
        return JsonSerializer.Serialize(response);
    }

    private static string ValidLogoutJson()
    {
        return $"{{\"ok\":true,\"message\":\"ok\",\"server_time\":\"{ServerTime}\"}}";
    }

    private static string ComputeBinding(
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

    private static DateTimeOffset ParseTime(string value)
    {
        return DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
    }

    private sealed class TrackingResponseBufferFactory
    {
        private TrackingMemoryStream? lastBuffer;

        internal MemoryStream Create(int capacity)
        {
            lastBuffer = new TrackingMemoryStream(capacity);
            return lastBuffer;
        }

        internal void AssertWrittenBytesWereCleared()
        {
            Assert.NotNull(lastBuffer);
            Assert.True(lastBuffer.WrittenLength > 0);
            Assert.All(
                lastBuffer.BackingBuffer
                    .Skip(lastBuffer.BackingOffset)
                    .Take(lastBuffer.WrittenLength),
                value => Assert.Equal((byte)0, value));
        }

        internal void AssertReturnedCopyWasCleared()
        {
            Assert.NotNull(lastBuffer);
            Assert.NotNull(lastBuffer.ReturnedCopy);
            Assert.NotEmpty(lastBuffer.ReturnedCopy);
            Assert.All(lastBuffer.ReturnedCopy, value => Assert.Equal((byte)0, value));
        }
    }

    private sealed class TrackingMemoryStream : MemoryStream
    {
        internal TrackingMemoryStream(int capacity)
            : base(capacity)
        {
        }

        internal byte[] BackingBuffer { get; private set; } = [];
        internal int BackingOffset { get; private set; }
        internal int WrittenLength { get; private set; }
        internal byte[] ReturnedCopy { get; private set; } = [];

        public override byte[] ToArray()
        {
            ReturnedCopy = base.ToArray();
            return ReturnedCopy;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && TryGetBuffer(out var backing) && backing.Array is not null)
            {
                BackingBuffer = backing.Array;
                BackingOffset = backing.Offset;
                WrittenLength = checked((int)Length);
            }

            base.Dispose(disposing);
        }
    }

    private enum PartialReadFailure
    {
        IOException,
        WaitForCancellation,
    }

    private sealed class CancelOnEofContent : HttpContent
    {
        private readonly byte[] bytes;
        private readonly Action cancelAtEof;

        internal CancelOnEofContent(byte[] bytes, Action cancelAtEof)
        {
            this.bytes = bytes;
            this.cancelAtEof = cancelAtEof;
            Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            throw new NotSupportedException();
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            return Task.FromResult<Stream>(new CancelOnEofStream(bytes, cancelAtEof));
        }

        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return CreateContentReadStreamAsync();
        }
    }

    private sealed class CancelOnEofStream : Stream
    {
        private readonly byte[] bytes;
        private readonly Action cancelAtEof;
        private int offset;
        private bool canceled;

        internal CancelOnEofStream(byte[] bytes, Action cancelAtEof)
        {
            this.bytes = bytes;
            this.cancelAtEof = cancelAtEof;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int bufferOffset, int count)
        {
            return ReadCore(buffer.AsSpan(bufferOffset, count));
        }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int bufferOffset,
            int count,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(ReadCore(buffer.AsSpan(bufferOffset, count)));
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(ReadCore(buffer.Span));
        }

        public override long Seek(long streamOffset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int bufferOffset, int count)
        {
            throw new NotSupportedException();
        }

        private int ReadCore(Span<byte> destination)
        {
            if (offset < bytes.Length)
            {
                var bytesToCopy = Math.Min(destination.Length, bytes.Length - offset);
                bytes.AsSpan(offset, bytesToCopy).CopyTo(destination);
                offset += bytesToCopy;
                return bytesToCopy;
            }

            if (!canceled)
            {
                canceled = true;
                cancelAtEof();
            }

            return 0;
        }
    }

    private sealed class PartialReadContent : HttpContent
    {
        private readonly byte[] firstChunk;
        private readonly PartialReadFailure failure;

        internal PartialReadContent(byte[] firstChunk, PartialReadFailure failure)
        {
            this.firstChunk = firstChunk;
            this.failure = failure;
            Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            throw new NotSupportedException();
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            return Task.FromResult<Stream>(new PartialReadStream(firstChunk, failure));
        }

        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return CreateContentReadStreamAsync();
        }
    }

    private sealed class PartialReadStream : Stream
    {
        private readonly byte[] firstChunk;
        private readonly PartialReadFailure failure;
        private bool deliveredFirstChunk;

        internal PartialReadStream(byte[] firstChunk, PartialReadFailure failure)
        {
            this.firstChunk = firstChunk;
            this.failure = failure;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!deliveredFirstChunk)
            {
                deliveredFirstChunk = true;
                var bytesToCopy = Math.Min(count, firstChunk.Length);
                firstChunk.AsSpan(0, bytesToCopy).CopyTo(buffer.AsSpan(offset, bytesToCopy));
                return bytesToCopy;
            }

            throw new IOException("Synthetic response stream failure.");
        }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            return ReadCoreAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            return ReadCoreAsync(buffer, cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        private async ValueTask<int> ReadCoreAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken)
        {
            if (!deliveredFirstChunk)
            {
                deliveredFirstChunk = true;
                var bytesToCopy = Math.Min(buffer.Length, firstChunk.Length);
                firstChunk.AsMemory(0, bytesToCopy).CopyTo(buffer);
                return bytesToCopy;
            }

            if (failure == PartialReadFailure.IOException)
            {
                throw new IOException("Synthetic response stream failure.");
            }

            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send;

        internal StubHandler(
            Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send)
        {
            this.send = send;
        }

        internal int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return send(request, cancellationToken);
        }
    }

    private sealed class DisposalTrackingHandler : HttpMessageHandler
    {
        internal int DisposeCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("No request is expected in this ownership test.");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeCount++;
            }

            base.Dispose(disposing);
        }
    }

    private sealed class DeclaredLengthContent : HttpContent
    {
        private readonly long declaredLength;

        internal DeclaredLengthContent(long declaredLength)
        {
            this.declaredLength = declaredLength;
            Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        internal bool WasRead { get; private set; }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            WasRead = true;
            return Task.CompletedTask;
        }

        protected override bool TryComputeLength(out long length)
        {
            length = declaredLength;
            return true;
        }
    }

    private sealed class ChunkedContent : HttpContent
    {
        private readonly byte[] bytes;

        internal ChunkedContent(byte[] bytes)
        {
            this.bytes = bytes;
            Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            return stream.WriteAsync(bytes).AsTask();
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            return Task.FromResult<Stream>(new MemoryStream(bytes, writable: false));
        }

        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return CreateContentReadStreamAsync();
        }
    }

    private sealed class DelayedContent : HttpContent
    {
        private readonly byte[] bytes;
        private readonly TimeSpan delay;

        internal DelayedContent(byte[] bytes, TimeSpan delay)
        {
            this.bytes = bytes;
            this.delay = delay;
            Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        protected override async Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context)
        {
            await Task.Delay(delay);
            await stream.WriteAsync(bytes);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            return Task.FromResult<Stream>(new DelayedReadStream(bytes, delay));
        }

        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return CreateContentReadStreamAsync();
        }
    }

    private sealed class DelayedReadStream : Stream
    {
        private readonly MemoryStream source;
        private readonly TimeSpan delay;
        private bool delayed;

        internal DelayedReadStream(byte[] bytes, TimeSpan delay)
        {
            source = new MemoryStream(bytes, writable: false);
            this.delay = delay;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return source.Read(buffer, offset, count);
        }

        public override async Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            await DelayOnceAsync(cancellationToken);
            return await source.ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await DelayOnceAsync(cancellationToken);
            return await source.ReadAsync(buffer, cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                source.Dispose();
            }

            base.Dispose(disposing);
        }

        private async Task DelayOnceAsync(CancellationToken cancellationToken)
        {
            if (delayed)
            {
                return;
            }

            delayed = true;
            await Task.Delay(delay, cancellationToken);
        }
    }
}
