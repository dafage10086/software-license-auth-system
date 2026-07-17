using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SoftwareLicenseAuth.Admin.Tests;

public sealed class KeygenAdminClientTests
{
    private const string AdminBaseUrl = "http://127.0.0.1:18788/";
    private const string JsonApiMediaType = "application/vnd.api+json";
    private const string FakeAdminToken = "FAKE_ADMIN_TOKEN_FOR_TESTS_ONLY";
    private const string FakePassword = "FAKE_INITIAL_PASSWORD_FOR_TESTS_ONLY";
    private const string FakeNewPassword = "FAKE_NEW_PASSWORD_FOR_TESTS_ONLY";
    private const string FakeCustomer = "FAKE_CUSTOMER_FOR_TESTS_ONLY";
    private const string AccountId = "account-test";
    private const string ProductId = "product-test";
    private const string TrialPolicyId = "policy-trial";
    private const string YearPolicyId = "policy-year";
    private const string ForeverPolicyId = "policy-forever";
    private const string UserId = "user-1";
    private const int TrialDurationSeconds = 30 * 24 * 60 * 60;
    private const int YearDurationSeconds = 365 * 24 * 60 * 60;

    [Fact]
    public async Task CliPasswordReset_RealClientCreatesMissingUserWithExplicitEmptyCustomer()
    {
        var handler = new FakeHandler((request, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, UserList()),
            1 => JsonResponse(
                HttpStatusCode.Created,
                UserDocument(UserResource(
                    customer: string.Empty,
                    ownerRequestId: TryGetOwnerRequestId(request)))),
            2 => new HttpResponseMessage(HttpStatusCode.NoContent),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var operations = new ClientOperations(CreateClient(httpClient));
        var workflow = new OwnerWorkflow(operations, () => FakeNewPassword);

        var result = await workflow.ResetPasswordForCliAsync("customer.one");

        Assert.True(result.Succeeded);
        Assert.True(workflow.SelectedUser?.WasCreated);
        Assert.Equal(
            [HttpMethod.Get, HttpMethod.Post, HttpMethod.Patch],
            handler.Requests.Select(request => request.Method).ToArray());
        using var payload = JsonDocument.Parse(
            Assert.IsType<string>(handler.Requests[1].Body));
        Assert.Equal(
            string.Empty,
            payload.RootElement
                .GetProperty("data")
                .GetProperty("attributes")
                .GetProperty("metadata")
                .GetProperty("customer")
                .GetString());
    }

    [Fact]
    public async Task FindOrCreateUserAsync_QueriesExactMappedEmailAndReturnsSingleUser()
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            UserList(UserResource())));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var user = await client.FindOrCreateUserAsync(
            " Customer.One ",
            FakePassword,
            FakeCustomer);

        Assert.Equal(UserId, user.Id);
        Assert.Equal("customer.one@accounts.license.invalid", user.Email);
        Assert.Equal(FakeCustomer, user.Customer);
        Assert.False(user.WasCreated);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal($"/v1/accounts/{AccountId}/users", request.RawPath);
        Assert.Equal(
            "email=customer.one%40accounts.license.invalid",
            request.RawQuery);
        Assert.Null(request.Body);
        Assert.Null(request.ContentType);
        AssertJsonApiHeaders(request);
    }

    [Fact]
    public async Task FindOrCreateUserAsync_CreatesAllowListedJsonApiUserWhenLookupIsEmpty()
    {
        var handler = new FakeHandler((request, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, UserList()),
            1 => JsonResponse(
                HttpStatusCode.Created,
                UserDocument(UserResource(
                    ownerRequestId: TryGetOwnerRequestId(request)))),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var user = await client.FindOrCreateUserAsync(
            "Customer.One",
            FakePassword,
            FakeCustomer);

        Assert.Equal(UserId, user.Id);
        Assert.True(user.WasCreated);
        Assert.Equal(2, handler.Requests.Count);
        var create = handler.Requests[1];
        Assert.Equal(HttpMethod.Post, create.Method);
        Assert.Equal($"/v1/accounts/{AccountId}/users", create.RawPath);
        Assert.Equal(string.Empty, create.RawQuery);
        AssertJsonBodyRequest(create);

        using var payload = JsonDocument.Parse(Assert.IsType<string>(create.Body));
        var data = payload.RootElement.GetProperty("data");
        AssertPropertyNames(data, "attributes", "type");
        Assert.Equal("users", data.GetProperty("type").GetString());
        var attributes = data.GetProperty("attributes");
        AssertPropertyNames(attributes, "email", "metadata", "password");
        Assert.Equal(
            "customer.one@accounts.license.invalid",
            attributes.GetProperty("email").GetString());
        Assert.Equal(FakePassword, attributes.GetProperty("password").GetString());
        var metadata = attributes.GetProperty("metadata");
        AssertPropertyNames(metadata, "customer", "ownerRequestId");
        Assert.Equal(FakeCustomer, metadata.GetProperty("customer").GetString());
        Assert.Matches(
            "^[a-f0-9]{32}$",
            metadata.GetProperty("ownerRequestId").GetString());
    }

    [Fact]
    public async Task UserCorrelation_CreateSendsAndAcceptsMatchingOwnerRequestId()
    {
        string? ownerRequestId = null;
        var handler = new FakeHandler((request, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, UserList()),
            1 => JsonResponse(
                HttpStatusCode.Created,
                UserDocument(UserResource(
                    ownerRequestId: ownerRequestId = TryGetOwnerRequestId(request)))),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var user = await client.FindOrCreateUserAsync(
            "customer.one",
            FakePassword,
            FakeCustomer);

        Assert.True(user.WasCreated);
        Assert.Matches("^[a-f0-9]{32}$", ownerRequestId);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task UserCorrelation_DirectMismatchRecoversOnlyMatchingQueriedUser()
    {
        string? ownerRequestId = null;
        var handler = new FakeHandler((request, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, UserList()),
            1 => JsonResponse(
                HttpStatusCode.Created,
                UserDocument(UserResource(
                    id: "user-direct-mismatch",
                    ownerRequestId: CaptureOwnerRequestId(
                        request,
                        value => ownerRequestId = value,
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")))),
            2 => JsonResponse(
                HttpStatusCode.OK,
                UserList(UserResource(
                    id: "user-correlated",
                    ownerRequestId: ownerRequestId))),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var user = await client.FindOrCreateUserAsync(
            "customer.one",
            FakePassword,
            FakeCustomer);

        Assert.Equal("user-correlated", user.Id);
        Assert.True(user.WasCreated);
        Assert.Equal(
            [HttpMethod.Get, HttpMethod.Post, HttpMethod.Get],
            handler.Requests.Select(request => request.Method).ToArray());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    public async Task UserCorrelation_UncertainCreateRejectsConcurrentUnrelatedUser(
        string? concurrentOwnerRequestId)
    {
        var handler = new FakeHandler((request, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, UserList()),
            1 => ThrowAfterCapturingOwnerRequestId(request),
            2 => JsonResponse(
                HttpStatusCode.OK,
                UserList(UserResource(ownerRequestId: concurrentOwnerRequestId))),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var error = await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.FindOrCreateUserAsync(
                "customer.one",
                FakePassword,
                FakeCustomer));

        Assert.Contains("CommitStateUnknown", error.Message, StringComparison.Ordinal);
        Assert.Equal(
            [HttpMethod.Get, HttpMethod.Post, HttpMethod.Get],
            handler.Requests.Select(request => request.Method).ToArray());
    }

    [Fact]
    public async Task CommitRecovery_UserCreateRecoversAfterCommittedBodyReadFailure()
    {
        string? ownerRequestId = null;
        var handler = new FakeHandler((request, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, UserList()),
            1 => CaptureUserCorrelationAndFailBody(
                request,
                value => ownerRequestId = value),
            2 => JsonResponse(
                HttpStatusCode.OK,
                UserList(UserResource(ownerRequestId: ownerRequestId))),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var user = await client.FindOrCreateUserAsync(
            "customer.one",
            FakePassword,
            FakeCustomer);

        Assert.Equal(UserId, user.Id);
        Assert.True(user.WasCreated);
        Assert.Equal(
            [HttpMethod.Get, HttpMethod.Post, HttpMethod.Get],
            handler.Requests.Select(request => request.Method).ToArray());
        Assert.Equal(handler.Requests[0].RawQuery, handler.Requests[2].RawQuery);
    }

    [Fact]
    public async Task FindOrCreateUserAsync_RequeriesAfterCreateConflict()
    {
        var handler = new FakeHandler((_, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, UserList()),
            1 => JsonResponse(
                HttpStatusCode.Conflict,
                new { errors = new[] { new { detail = "duplicate" } } }),
            2 => JsonResponse(HttpStatusCode.OK, UserList(UserResource())),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var user = await client.FindOrCreateUserAsync(
            "customer.one",
            FakePassword,
            FakeCustomer);

        Assert.Equal(UserId, user.Id);
        Assert.False(user.WasCreated);
        Assert.Equal(3, handler.Requests.Count);
        Assert.Equal(
            new[] { HttpMethod.Get, HttpMethod.Post, HttpMethod.Get },
            handler.Requests.Select(request => request.Method).ToArray());
        Assert.Equal(
            handler.Requests[0].RawQuery,
            handler.Requests[2].RawQuery);
    }

    [Fact]
    public async Task FindOrCreateUserAsync_RejectsAmbiguousExactMatches()
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            UserList(
                UserResource(id: "user-1"),
                UserResource(id: "user-2"))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.FindOrCreateUserAsync(
                "customer.one",
                FakePassword,
                FakeCustomer));

        Assert.Single(handler.Requests);
    }

    [Theory]
    [InlineData("licenses", "user-1", "customer.one@accounts.license.invalid")]
    [InlineData("users", "bad/user", "customer.one@accounts.license.invalid")]
    [InlineData("users", "user-1", "other@accounts.license.invalid")]
    public async Task FindOrCreateUserAsync_FailsClosedForInvalidUserResources(
        string type,
        string id,
        string email)
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            UserList(UserResource(type: type, id: id, email: email))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.FindOrCreateUserAsync(
                "customer.one",
                FakePassword,
                FakeCustomer));
    }

    [Fact]
    public async Task EnsureTrialAsync_CreatesExactlyOneOwnedTrialAcrossRepeatedCalls()
    {
        var trialResource = LicenseResource(
            id: "license-trial",
            key: "FAKE-TRIAL-LICENSE",
            plan: "TRIAL",
            price: 0,
            policyId: TrialPolicyId);
        var handler = new FakeHandler((_, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, LicenseList()),
            1 => JsonResponse(HttpStatusCode.Created, LicenseDocument(trialResource)),
            2 => JsonResponse(HttpStatusCode.OK, LicenseList(trialResource)),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);
        var user = TestUser();

        var first = await client.EnsureTrialAsync(user);
        var second = await client.EnsureTrialAsync(user);

        Assert.Equal(first, second);
        Assert.Equal("license-trial", first.Id);
        Assert.Equal("TRIAL", first.Plan);
        Assert.Equal(0, first.Price);
        Assert.Equal(UserId, first.OwnerId);
        Assert.Equal(ProductId, first.ProductId);
        Assert.Equal(TrialPolicyId, first.PolicyId);
        Assert.Equal(3, handler.Requests.Count);
        Assert.Single(handler.Requests, request => request.Method == HttpMethod.Post);

        foreach (var lookup in handler.Requests.Where(request => request.Method == HttpMethod.Get))
        {
            Assert.Equal($"/v1/accounts/{AccountId}/licenses", lookup.RawPath);
            Assert.Equal(
                $"owner={UserId}&policy={TrialPolicyId}",
                lookup.RawQuery);
            AssertJsonApiHeaders(lookup);
        }

        var create = handler.Requests.Single(request => request.Method == HttpMethod.Post);
        Assert.Equal($"/v1/accounts/{AccountId}/licenses", create.RawPath);
        Assert.Equal(string.Empty, create.RawQuery);
        AssertJsonBodyRequest(create);
        AssertLicenseCreatePayload(
            Assert.IsType<string>(create.Body),
            "TRIAL",
            0,
            TrialPolicyId,
            TrialDurationSeconds);
    }

    [Fact]
    public async Task LicenseContract_TrialCreateUsesExactDurationMetadata()
    {
        var trial = LicenseResource(durationSeconds: TrialDurationSeconds);
        var handler = new FakeHandler((_, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, LicenseList()),
            1 => JsonResponse(HttpStatusCode.Created, LicenseDocument(trial)),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var license = await client.EnsureTrialAsync(TestUser());

        Assert.Equal(TrialDurationSeconds, license.DurationSeconds);
        using var payload = JsonDocument.Parse(
            Assert.IsType<string>(handler.Requests[1].Body));
        Assert.Equal(
            TrialDurationSeconds,
            payload.RootElement
                .GetProperty("data")
                .GetProperty("attributes")
                .GetProperty("metadata")
                .GetProperty("durationSeconds")
                .GetInt32());
    }

    [Theory]
    [InlineData(null)]
    [InlineData(TrialDurationSeconds - 1)]
    [InlineData(TrialDurationSeconds + 1)]
    public async Task LicenseContract_TrialResponseRequiresExactDuration(
        int? durationSeconds)
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            LicenseList(LicenseResource(
                durationSeconds: durationSeconds,
                omitDurationSeconds: durationSeconds is null))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.EnsureTrialAsync(TestUser()));
    }

    [Fact]
    public async Task LicenseContract_RejectsNonActiveStatus()
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            LicenseList(LicenseResource(status: "SUSPENDED"))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.EnsureTrialAsync(TestUser()));
    }

    [Fact]
    public async Task LicenseContract_UnactivatedTrialAllowsNullExpiry()
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            LicenseList(LicenseResource())));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var license = await client.EnsureTrialAsync(TestUser());

        Assert.Null(license.Expiry);
        Assert.Null(license.BusinessExpiresAt);
        Assert.Equal(TrialDurationSeconds, license.DurationSeconds);
    }

    [Fact]
    public async Task EnsureTrialAsync_RequeriesOnceAfterCreateConflictAndReturnsOneTrial()
    {
        var trial = LicenseResource(id: "trial-after-conflict");
        var handler = new FakeHandler((_, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, LicenseList()),
            1 => JsonResponse(
                HttpStatusCode.Conflict,
                new { errors = new[] { new { detail = "duplicate" } } }),
            2 => JsonResponse(HttpStatusCode.OK, LicenseList(trial)),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var license = await client.EnsureTrialAsync(TestUser());

        Assert.Equal("trial-after-conflict", license.Id);
        Assert.Equal(3, handler.Requests.Count);
        Assert.Single(handler.Requests, request => request.Method == HttpMethod.Post);
        Assert.Equal(
            new[] { HttpMethod.Get, HttpMethod.Post, HttpMethod.Get },
            handler.Requests.Select(request => request.Method).ToArray());
        Assert.Equal(
            $"owner={UserId}&policy={TrialPolicyId}",
            handler.Requests[2].RawQuery);
    }

    [Fact]
    public async Task CommitRecovery_TrialCreateRecoversAfterCommittedBodyReadFailure()
    {
        var trial = LicenseResource(id: "trial-recovered");
        var handler = new FakeHandler((_, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, LicenseList()),
            1 => BodyReadFailureResponse(HttpStatusCode.Created),
            2 => JsonResponse(HttpStatusCode.OK, LicenseList(trial)),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var license = await client.EnsureTrialAsync(TestUser());

        Assert.Equal("trial-recovered", license.Id);
        Assert.Equal(
            [HttpMethod.Get, HttpMethod.Post, HttpMethod.Get],
            handler.Requests.Select(request => request.Method).ToArray());
        Assert.Equal(handler.Requests[0].RawQuery, handler.Requests[2].RawQuery);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public async Task EnsureTrialAsync_RejectsUnsafeRequeryAfterCreateConflict(
        int requeryMatchCount)
    {
        var matches = Enumerable.Range(1, requeryMatchCount)
            .Select(index => LicenseResource(id: $"trial-{index}"))
            .ToArray();
        var handler = new FakeHandler((_, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, LicenseList()),
            1 => JsonResponse(
                HttpStatusCode.Conflict,
                new { errors = new[] { new { detail = "duplicate" } } }),
            2 => JsonResponse(HttpStatusCode.OK, LicenseList(matches)),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.EnsureTrialAsync(TestUser()));

        Assert.Equal(3, handler.Requests.Count);
        Assert.Single(handler.Requests, request => request.Method == HttpMethod.Post);
        Assert.Equal(
            new[] { HttpMethod.Get, HttpMethod.Post, HttpMethod.Get },
            handler.Requests.Select(request => request.Method).ToArray());
    }

    [Fact]
    public async Task EnsureTrialAsync_RejectsMultipleMatchingTrials()
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            LicenseList(
                LicenseResource(id: "trial-1"),
                LicenseResource(id: "trial-2"))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.EnsureTrialAsync(TestUser()));

        Assert.Single(handler.Requests);
    }

    [Theory]
    [InlineData("other-user", ProductId, TrialPolicyId, "users", "products", "policies")]
    [InlineData(UserId, "other-product", TrialPolicyId, "users", "products", "policies")]
    [InlineData(UserId, ProductId, "other-policy", "users", "products", "policies")]
    [InlineData(UserId, ProductId, TrialPolicyId, "licenses", "products", "policies")]
    [InlineData(UserId, ProductId, TrialPolicyId, "users", "licenses", "policies")]
    [InlineData(UserId, ProductId, TrialPolicyId, "users", "products", "licenses")]
    public async Task EnsureTrialAsync_FailsClosedForMismatchedRelationships(
        string ownerId,
        string productId,
        string policyId,
        string ownerType,
        string productType,
        string policyType)
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            LicenseList(LicenseResource(
                ownerId: ownerId,
                productId: productId,
                policyId: policyId,
                ownerType: ownerType,
                productType: productType,
                policyType: policyType))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.EnsureTrialAsync(TestUser()));
    }

    [Theory]
    [InlineData("YEAR", 128, YearPolicyId, YearDurationSeconds)]
    [InlineData("FOREVER", 288, ForeverPolicyId, null)]
    public async Task IssuePaidAsync_UsesExactPolicyOwnershipAndMetadata(
        string plan,
        int price,
        string policyId,
        int? expectedDurationSeconds)
    {
        const string yearExpiry = "2027-07-15T00:00:00Z";
        const string yearBusinessExpiry = "2027-07-14T23:59:59Z";
        var handler = new FakeHandler((request, _, _) => JsonResponse(
            HttpStatusCode.Created,
            LicenseDocument(LicenseResource(
                id: $"license-{plan.ToLowerInvariant()}",
                key: $"FAKE-{plan}-LICENSE",
                plan: plan,
                price: price,
                policyId: policyId,
                durationSeconds: expectedDurationSeconds,
                expiry: plan == "YEAR" ? yearExpiry : null,
                businessExpiresAt: plan == "YEAR" ? yearBusinessExpiry : null,
                ownerRequestId: TryGetPaidOwnerRequestId(request)))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var license = await client.IssuePaidAsync(TestUser(), plan);

        Assert.Equal(plan, license.Plan);
        Assert.Equal(price, license.Price);
        Assert.Equal(UserId, license.OwnerId);
        Assert.Equal(ProductId, license.ProductId);
        Assert.Equal(policyId, license.PolicyId);
        Assert.Equal(expectedDurationSeconds, license.DurationSeconds);
        if (plan == "YEAR")
        {
            Assert.Equal(
                DateTimeOffset.Parse(yearExpiry).ToUniversalTime(),
                license.Expiry);
            Assert.Equal(
                DateTimeOffset.Parse(yearBusinessExpiry).ToUniversalTime(),
                license.BusinessExpiresAt);
        }
        else
        {
            Assert.Null(license.Expiry);
            Assert.Null(license.BusinessExpiresAt);
        }

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal($"/v1/accounts/{AccountId}/licenses", request.RawPath);
        Assert.Equal(string.Empty, request.RawQuery);
        AssertJsonBodyRequest(request);
        AssertLicenseCreatePayload(
            Assert.IsType<string>(request.Body),
            plan,
            price,
            policyId,
            expectedDurationSeconds);
    }

    [Fact]
    public async Task CommitRecovery_PaidCreateRecoversOnlyExactCorrelationAfterBodyReadFailure()
    {
        string? correlationId = null;
        var handler = new FakeHandler((request, index, _) => index switch
        {
            0 => CapturePaidCorrelationAndFailBody(request, value => correlationId = value),
            1 => JsonResponse(
                HttpStatusCode.OK,
                LicenseList(
                    LicenseResource(
                        id: "license-old",
                        key: "FAKE-OLD-LICENSE",
                        plan: "YEAR",
                        price: 128,
                        policyId: YearPolicyId,
                        durationSeconds: YearDurationSeconds,
                        ownerRequestId: "old-request"),
                    LicenseResource(
                        id: "license-recovered",
                        key: "FAKE-RECOVERED-LICENSE",
                        plan: "YEAR",
                        price: 128,
                        policyId: YearPolicyId,
                        durationSeconds: YearDurationSeconds,
                        ownerRequestId: correlationId ?? "missing-request"))),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var license = await client.IssuePaidAsync(TestUser(), "YEAR");

        Assert.Equal("license-recovered", license.Id);
        Assert.Equal("FAKE-RECOVERED-LICENSE", license.Key);
        Assert.Matches("^[a-f0-9]{32}$", correlationId);
        Assert.Equal([HttpMethod.Post, HttpMethod.Get],
            handler.Requests.Select(request => request.Method).ToArray());
        Assert.Equal(
            $"owner={UserId}&policy={YearPolicyId}",
            handler.Requests[1].RawQuery);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    public async Task PaidCorrelation_DirectMismatchRecoversMatchingQueriedLicense(
        string? directOwnerRequestId)
    {
        string? ownerRequestId = null;
        var handler = new FakeHandler((request, index, _) =>
        {
            if (index == 0)
            {
                ownerRequestId = TryGetPaidOwnerRequestId(request);
                return JsonResponse(
                    HttpStatusCode.Created,
                    LicenseDocument(LicenseResource(
                        id: "license-direct-unrelated",
                        key: "FAKE-DIRECT-UNRELATED-LICENSE",
                        plan: "YEAR",
                        price: 128,
                        policyId: YearPolicyId,
                        durationSeconds: YearDurationSeconds,
                        ownerRequestId: directOwnerRequestId)));
            }

            if (index == 1)
            {
                return JsonResponse(
                    HttpStatusCode.OK,
                    LicenseList(LicenseResource(
                        id: "license-correlated",
                        key: "FAKE-CORRELATED-LICENSE",
                        plan: "YEAR",
                        price: 128,
                        policyId: YearPolicyId,
                        durationSeconds: YearDurationSeconds,
                        ownerRequestId: ownerRequestId)));
            }

            throw new InvalidOperationException("Unexpected fake request.");
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var license = await client.IssuePaidAsync(TestUser(), "YEAR");

        Assert.Equal("license-correlated", license.Id);
        Assert.Equal("FAKE-CORRELATED-LICENSE", license.Key);
        Assert.Matches("^[a-f0-9]{32}$", ownerRequestId);
        Assert.Equal([HttpMethod.Post, HttpMethod.Get],
            handler.Requests.Select(request => request.Method).ToArray());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    public async Task PaidCorrelation_DirectMismatchWithoutQueriedMatchReturnsUnknown(
        string? directOwnerRequestId)
    {
        var handler = new FakeHandler((request, index, _) => index switch
        {
            0 => JsonResponse(
                HttpStatusCode.Created,
                LicenseDocument(LicenseResource(
                    id: "license-direct-unrelated",
                    key: "FAKE-DIRECT-UNRELATED-LICENSE",
                    plan: "YEAR",
                    price: 128,
                    policyId: YearPolicyId,
                    durationSeconds: YearDurationSeconds,
                    ownerRequestId: CapturePaidOwnerRequestId(
                        request,
                        directOwnerRequestId)))),
            1 => JsonResponse(
                HttpStatusCode.OK,
                LicenseList(LicenseResource(
                    id: "license-old",
                    key: "FAKE-OLD-LICENSE",
                    plan: "YEAR",
                    price: 128,
                    policyId: YearPolicyId,
                    durationSeconds: YearDurationSeconds,
                    ownerRequestId: "cccccccccccccccccccccccccccccccc"))),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var error = await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.IssuePaidAsync(TestUser(), "YEAR"));

        Assert.Contains("CommitStateUnknown", error.Message, StringComparison.Ordinal);
        Assert.Equal([HttpMethod.Post, HttpMethod.Get],
            handler.Requests.Select(request => request.Method).ToArray());
    }

    [Fact]
    public async Task LicenseContract_UnactivatedYearAllowsNullExpiry()
    {
        var handler = new FakeHandler((request, _, _) => JsonResponse(
            HttpStatusCode.Created,
            LicenseDocument(LicenseResource(
                plan: "YEAR",
                price: 128,
                policyId: YearPolicyId,
                durationSeconds: YearDurationSeconds,
                ownerRequestId: TryGetPaidOwnerRequestId(request)))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var license = await client.IssuePaidAsync(TestUser(), "YEAR");

        Assert.Null(license.Expiry);
        Assert.Null(license.BusinessExpiresAt);
        Assert.Equal(YearDurationSeconds, license.DurationSeconds);
    }

    [Theory]
    [InlineData("expiry")]
    [InlineData("businessExpiresAt")]
    public async Task LicenseContract_RejectsExpiredFiniteTerm(string expiredField)
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.Created,
            LicenseDocument(LicenseResource(
                plan: "YEAR",
                price: 128,
                policyId: YearPolicyId,
                durationSeconds: YearDurationSeconds,
                expiry: expiredField == "expiry" ? "2000-01-01T00:00:00Z" : null,
                businessExpiresAt: expiredField == "businessExpiresAt"
                    ? "2000-01-01T00:00:00Z"
                    : null))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.IssuePaidAsync(TestUser(), "YEAR"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(31535999)]
    [InlineData(31536001)]
    public async Task IssuePaidAsync_RejectsYearResponseWithoutExactDuration(
        int? durationSeconds)
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.Created,
            LicenseDocument(LicenseResource(
                id: "license-year",
                key: "FAKE-YEAR-LICENSE",
                plan: "YEAR",
                price: 128,
                policyId: YearPolicyId,
                durationSeconds: durationSeconds))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.IssuePaidAsync(TestUser(), "YEAR"));
    }

    [Theory]
    [InlineData("durationSeconds")]
    [InlineData("expiry")]
    [InlineData("businessExpiresAt")]
    public async Task IssuePaidAsync_RejectsForeverResponseWithAnyTerm(string term)
    {
        var resource = term switch
        {
            "durationSeconds" => LicenseResource(
                id: "license-forever",
                plan: "FOREVER",
                price: 288,
                policyId: ForeverPolicyId,
                durationSeconds: 1),
            "expiry" => LicenseResource(
                id: "license-forever",
                plan: "FOREVER",
                price: 288,
                policyId: ForeverPolicyId,
                expiry: "2099-01-01T00:00:00Z"),
            "businessExpiresAt" => LicenseResource(
                id: "license-forever",
                plan: "FOREVER",
                price: 288,
                policyId: ForeverPolicyId,
                businessExpiresAt: "2099-01-01T00:00:00Z"),
            _ => throw new InvalidOperationException("Unexpected test term.")
        };
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.Created,
            LicenseDocument(resource)));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.IssuePaidAsync(TestUser(), "FOREVER"));
    }

    [Theory]
    [InlineData("TRIAL")]
    [InlineData("year")]
    [InlineData(" YEAR ")]
    [InlineData("FOREVER/../../users")]
    public async Task IssuePaidAsync_RejectsUnsupportedOrInjectedPlanBeforeSending(string plan)
    {
        var handler = new FakeHandler(NoRequestExpected);
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.IssuePaidAsync(TestUser(), plan));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ResetPasswordAsync_PatchesOnlyTheExactUserResource()
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            UserDocument(UserResource())));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await client.ResetPasswordAsync(TestUser(), FakeNewPassword);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Patch, request.Method);
        Assert.Equal($"/v1/accounts/{AccountId}/users/{UserId}", request.RawPath);
        Assert.Equal(string.Empty, request.RawQuery);
        AssertJsonBodyRequest(request);
        using var payload = JsonDocument.Parse(Assert.IsType<string>(request.Body));
        var data = payload.RootElement.GetProperty("data");
        AssertPropertyNames(data, "attributes", "id", "type");
        Assert.Equal("users", data.GetProperty("type").GetString());
        Assert.Equal(UserId, data.GetProperty("id").GetString());
        var attributes = data.GetProperty("attributes");
        AssertPropertyNames(attributes, "password");
        Assert.Equal(FakeNewPassword, attributes.GetProperty("password").GetString());
    }

    [Fact]
    public async Task CommitRecovery_PasswordConfirmsFromTwoXxHeadersWithoutReadingBody()
    {
        var handler = new FakeHandler((_, _, _) =>
            BodyReadFailureResponse(HttpStatusCode.OK));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await client.ResetPasswordAsync(TestUser(), FakeNewPassword);

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task CommitRecovery_PasswordRetriesUncertainSendOnceWithSamePassword()
    {
        var handler = new FakeHandler((_, index, _) => index switch
        {
            0 => throw new HttpRequestException("Simulated lost response."),
            1 => new HttpResponseMessage(HttpStatusCode.NoContent),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await client.ResetPasswordAsync(TestUser(), FakeNewPassword);

        Assert.Equal(2, handler.Requests.Count);
        Assert.All(handler.Requests, request => Assert.Equal(HttpMethod.Patch, request.Method));
        Assert.Equal(handler.Requests[0].Body, handler.Requests[1].Body);
    }

    [Fact]
    public async Task CommitRecovery_PasswordReturnsUnknownAfterTwoUncertainSends()
    {
        var handler = new FakeHandler(
            new Func<CapturedRequest, int, CancellationToken, HttpResponseMessage>(
                (_, _, _) =>
                    throw new HttpRequestException("Simulated lost response.")));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var error = await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.ResetPasswordAsync(TestUser(), FakeNewPassword));

        Assert.Contains("CommitStateUnknown", error.Message, StringComparison.Ordinal);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(handler.Requests[0].Body, handler.Requests[1].Body);
    }

    [Theory]
    [InlineData("paid")]
    [InlineData("reset")]
    [InlineData("revoke")]
    public async Task Mutation_PreCanceledBeforeHandlerRecords_IsOrdinaryTimeout(
        string operation)
    {
        var handler = new CancellationBeforeRecordingHandler();
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Task ExecuteAsync() => operation switch
        {
            "paid" => client.IssuePaidAsync(TestUser(), "YEAR", cancellation.Token),
            "reset" => client.ResetPasswordAsync(
                TestUser(),
                FakeNewPassword,
                cancellation.Token),
            _ => client.RevokeMachineAsync("machine-1", cancellation.Token)
        };

        var error = await Assert.ThrowsAsync<KeygenAdminException>(ExecuteAsync);

        Assert.Equal(0, handler.RecordedRequests);
        Assert.False(error.RequestStateUnknown);
        Assert.False(error.CommitStateUnknown);
    }

    [Theory]
    [InlineData("trial")]
    [InlineData("paid")]
    public async Task Workflow_PreCanceledAfterNewUserCreation_ReturnsPartialWithPasswordOnce(
        string stage)
    {
        var handler = new CancellationBeforeRecordingHandler();
        using var httpClient = new HttpClient(handler);
        using var operations = new PreCanceledWorkflowOperations(
            CreateClient(httpClient),
            wasCreated: true,
            stage);
        var workflow = new OwnerWorkflow(
            operations,
            () => FakeNewPassword,
            TimeSpan.FromMilliseconds(50));

        var result = await workflow.IssueLicenseForCliAsync("customer.one", "year");

        Assert.False(result.Succeeded);
        Assert.True(result.IsPartialSuccess);
        Assert.False(result.IsCommitStateUnknown);
        Assert.Equal(
            1,
            result.Output.Split(FakeNewPassword, StringSplitOptions.None).Length - 1);
        Assert.Equal(0, handler.RecordedRequests);
    }

    [Fact]
    public async Task Workflow_PreCanceledPaidForExistingUser_ReturnsOrdinaryFailure()
    {
        var handler = new CancellationBeforeRecordingHandler();
        using var httpClient = new HttpClient(handler);
        using var operations = new PreCanceledWorkflowOperations(
            CreateClient(httpClient),
            wasCreated: false,
            "paid");
        var workflow = new OwnerWorkflow(
            operations,
            () => FakeNewPassword,
            TimeSpan.FromMilliseconds(50));

        var result = await workflow.IssueLicenseForCliAsync("customer.one", "year");

        Assert.False(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.False(result.IsCommitStateUnknown);
        Assert.DoesNotContain(FakeNewPassword, result.Output, StringComparison.Ordinal);
        Assert.Equal(0, handler.RecordedRequests);
    }

    [Fact]
    public async Task Workflow_PreCanceledRevokeWithZeroSend_ReturnsOrdinaryFailure()
    {
        var handler = new CancellationBeforeRecordingHandler();
        using var httpClient = new HttpClient(handler);
        using var operations = new PreCanceledWorkflowOperations(
            CreateClient(httpClient),
            wasCreated: false,
            "revoke");
        var workflow = new OwnerWorkflow(
            operations,
            () => FakePassword,
            TimeSpan.FromMilliseconds(50));

        var result = await workflow.RevokeMachineAsync("machine-1");

        Assert.False(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.False(result.IsCommitStateUnknown);
        Assert.Equal(0, handler.RecordedRequests);
    }

    [Fact]
    public async Task CommitRecovery_WorkflowDoesNotClaimUnknownPasswordSucceeded()
    {
        var handler = new FakeHandler((_, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, UserList(UserResource())),
            1 or 2 => throw new HttpRequestException("Simulated lost response."),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        using var operations = new ClientOperations(CreateClient(httpClient));
        var workflow = new OwnerWorkflow(operations, () => FakeNewPassword);

        var result = await workflow.ResetPasswordForCliAsync("customer.one");

        Assert.False(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Contains("CommitStateUnknown", result.Output, StringComparison.Ordinal);
        Assert.Equal(
            0,
            result.Output.Split(FakeNewPassword, StringSplitOptions.None).Length - 1);
        var unknownProperty = typeof(OwnerOperationResult).GetProperty(
            "IsCommitStateUnknown",
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        Assert.NotNull(unknownProperty);
        Assert.True(Assert.IsType<bool>(unknownProperty.GetValue(result)));
    }

    [Fact]
    public async Task ListMachineIdsAsync_UsesSelectedUserRelationshipRouteAndParsesOnlyIds()
    {
        const string sensitiveFingerprint = "RAW-HARDWARE-FINGERPRINT-MUST-NOT-LEAK";
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            MachineList(
                MachineResource("machine-1", sensitiveFingerprint),
                MachineResource("machine-2", sensitiveFingerprint))));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var machineIds = await client.ListMachineIdsAsync(TestUser());

        Assert.Equal(["machine-1", "machine-2"], machineIds);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(
            $"/v1/accounts/{AccountId}/users/{UserId}/machines",
            request.RawPath);
        Assert.Equal("page[size]=100&page[number]=1", request.RawQuery);
        Assert.Null(request.Body);
        AssertJsonApiHeaders(request);
        Assert.DoesNotContain(
            sensitiveFingerprint,
            string.Join(Environment.NewLine, machineIds),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListMachineIdsAsync_PaginatesFixedSizePagesWithOneSharedDeadline()
    {
        var firstPage = Enumerable.Range(0, 100)
            .Select(index => MachineResource($"machine-{index:D3}"))
            .ToArray();
        var handler = new FakeHandler((_, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, MachineList(firstPage)),
            1 => JsonResponse(
                HttpStatusCode.OK,
                MachineList(MachineResource("machine-100"))),
            _ => throw new InvalidOperationException("Unexpected machine page request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var machineIds = await client.ListMachineIdsAsync(TestUser());

        Assert.Equal(101, machineIds.Count);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal("page[size]=100&page[number]=1", handler.Requests[0].RawQuery);
        Assert.Equal("page[size]=100&page[number]=2", handler.Requests[1].RawQuery);
    }

    [Fact]
    public async Task ListMachineIdsAsync_RejectsOversizedOrDuplicateMachineCollections()
    {
        var oversized = Enumerable.Range(0, 101)
            .Select(index => MachineResource($"machine-{index:D3}"))
            .ToArray();
        var responses = new[]
        {
            MachineList(oversized),
            MachineList(MachineResource("machine-1"), MachineResource("machine-1"))
        };

        foreach (var response in responses)
        {
            var handler = new FakeHandler((_, _, _) =>
                JsonResponse(HttpStatusCode.OK, response));
            using var httpClient = new HttpClient(handler);
            var client = CreateClient(httpClient);

            await Assert.ThrowsAsync<KeygenAdminException>(() =>
                client.ListMachineIdsAsync(TestUser()));

            Assert.Single(handler.Requests);
        }
    }

    [Fact]
    public async Task RevokeMachineAsync_DeletesOnlyTheExactMachineResource()
    {
        var handler = new FakeHandler((_, _, _) =>
            new HttpResponseMessage(HttpStatusCode.NoContent));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        await client.RevokeMachineAsync("machine-1");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal($"/v1/accounts/{AccountId}/machines/machine-1", request.RawPath);
        Assert.Equal(string.Empty, request.RawQuery);
        Assert.Null(request.Body);
        Assert.Null(request.ContentType);
        AssertJsonApiHeaders(request);
    }

    [Fact]
    public async Task RevokeContract_TwoXxHeadersCompleteWithoutReadingHangingBody()
    {
        var handler = new FakeHandler((_, _, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new DelayedJsonContent("{}", TimeSpan.FromSeconds(2))
            });
        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var client = CreateClient(httpClient, TimeSpan.FromMilliseconds(250));
        var stopwatch = Stopwatch.StartNew();

        await client.RevokeMachineAsync("machine-1");

        stopwatch.Stop();
        Assert.InRange(
            stopwatch.Elapsed,
            TimeSpan.Zero,
            TimeSpan.FromSeconds(1));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task RevokeContract_LostResponseReturnsUnknownAndCliExitFour()
    {
        var handler = new FakeHandler(
            new Func<CapturedRequest, int, CancellationToken, HttpResponseMessage>(
                (_, _, _) =>
                    throw new HttpRequestException("Simulated lost response.")));
        using var httpClient = new HttpClient(handler);
        var operations = new ClientOperations(CreateClient(httpClient));
        var cli = new OwnerCli(
            () => operations,
            () => FakeAdminToken,
            _ => { },
            () => FakePassword);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await cli.RunAsync(
            ["machine-revoke", "machine-1"],
            output,
            error);

        Assert.Equal(4, exitCode);
        Assert.Contains("CommitStateUnknown", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(FakePassword, output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(FakeAdminToken, output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ResourceIds_AreValidatedBeforePathConstruction()
    {
        var handler = new FakeHandler(NoRequestExpected);
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);
        var invalidUser = new KeygenUser(
            "user-1/../../licenses",
            "customer.one@accounts.license.invalid",
            FakeCustomer);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.EnsureTrialAsync(invalidUser));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ResetPasswordAsync(invalidUser, FakeNewPassword));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RevokeMachineAsync("machine-1?include=owner"));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public void Constructor_RejectsInjectedConfigIdBeforeSending()
    {
        var handler = new FakeHandler(NoRequestExpected);
        using var httpClient = new HttpClient(handler);
        var config = LoadConfig(accountId: "account-test/../../other");

        Assert.Throws<ArgumentException>(() =>
            CreateClient(httpClient, config: config));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public void ProductionConstructor_UsesFixedEightSecondTotalTimeout()
    {
        var client = CreateProductionClient(LoadConfig());

        try
        {
            Assert.Equal(TimeSpan.FromSeconds(8), client.TotalTimeout);
        }
        finally
        {
            DisposeIfSupported(client);
        }
    }

    [Fact]
    public void TransportContract_InjectedHttpClientConstructorsArePrivate()
    {
        var injectedConstructors = typeof(KeygenAdminClient)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(constructor => constructor
                .GetParameters()
                .Any(parameter => parameter.ParameterType == typeof(HttpClient)))
            .ToArray();

        Assert.NotEmpty(injectedConstructors);
        Assert.All(injectedConstructors, constructor => Assert.True(constructor.IsPrivate));
    }

    [Fact]
    public void TransportContract_ProductionConstructorUsesOnlyFixedTunnelUrl()
    {
        var config = LoadConfig();
        var client = CreateProductionClient(config);

        try
        {
            Assert.Equal(
                new Uri(AdminBaseUrl),
                GetPrivateField<Uri>(client, "_baseUri"));
        }
        finally
        {
            DisposeIfSupported(client);
        }
    }

    [Fact]
    public async Task TransportContract_LoopbackHttpRequestsUseFixedKeygenProxyHeaders()
    {
        var handler = new FakeHandler((_, _, _) => JsonResponse(
            HttpStatusCode.OK,
            UserList(UserResource())));
        using var httpClient = new HttpClient(handler);
        var config = LoadConfig();
        var client = CreateClient(httpClient, config: config);

        _ = await client.FindOrCreateUserAsync(
            "customer.one",
            FakePassword,
            FakeCustomer);

        var request = Assert.Single(handler.Requests);
        Assert.Equal("127.0.0.1:18788", request.Uri.Authority);
        Assert.Equal("keygen.license.invalid", request.Host);
        Assert.Equal(["https"], request.ForwardedProto);
    }

    [Fact]
    public void OwnerRuntime_ConfigLoaderAllowsOnlyFixedTunnelUrl()
    {
        using var directory = new TemporaryDirectory();
        var path = WriteDefaultConfig(directory, AdminBaseUrl);

        var config = OwnerRuntime.LoadConfigForOperations(path);

        Assert.Equal(new Uri(AdminBaseUrl), config.AdminUrl);
    }

    [Theory]
    [InlineData("http://127.0.0.1:18788")]
    [InlineData("http://localhost:18788/")]
    [InlineData("http://127.0.0.1:18789/")]
    [InlineData("https://license-admin.example.invalid/")]
    public void OwnerRuntime_ConfigLoaderRejectsEveryOtherUrl(string adminBaseUrl)
    {
        using var directory = new TemporaryDirectory();
        var path = WriteDefaultConfig(directory, adminBaseUrl);

        Assert.Throws<InvalidDataException>(() =>
            OwnerRuntime.LoadConfigForOperations(path));
    }

    [Fact]
    public void TransportContract_ProductionHandlerDisablesAutomaticRedirects()
    {
        var client = CreateProductionClient(LoadConfig());
        try
        {
            var httpClient = GetPrivateField<HttpClient>(client, "_httpClient");
            var handler = GetPrivateField<HttpMessageHandler>(httpClient, "_handler");
            var productionHandler = Assert.IsType<HttpClientHandler>(handler);

            Assert.False(productionHandler.AllowAutoRedirect);
        }
        finally
        {
            DisposeIfSupported(client);
        }
    }

    [Fact]
    public void TransportContract_FixedTunnelProductionHandlerDisablesProxy()
    {
        var config = LoadConfig();
        var client = CreateProductionClient(config);
        try
        {
            var httpClient = GetPrivateField<HttpClient>(client, "_httpClient");
            var handler = GetPrivateField<HttpMessageHandler>(httpClient, "_handler");
            var productionHandler = Assert.IsType<HttpClientHandler>(handler);

            Assert.False(productionHandler.UseProxy);
        }
        finally
        {
            DisposeIfSupported(client);
        }
    }

    [Fact]
    public async Task TransportContract_OperationsDisposeOwnedHttpClient()
    {
        var operations = CreateProductionOperations(LoadConfig());
        var client = GetPrivateField<KeygenAdminClient>(operations, "_client");
        var httpClient = GetPrivateField<HttpClient>(client, "_httpClient");

        operations.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            httpClient.GetAsync("https://license-admin.example.invalid/unused"));
    }

    [Fact]
    public async Task NonSuccessResponses_AreSanitizedWithoutSecretsOrUpstreamBody()
    {
        const string upstreamOnlySecret = "UPSTREAM_BODY_SECRET_FOR_TESTS_ONLY";
        var handler = new FakeHandler((_, index, _) => index switch
        {
            0 => JsonResponse(HttpStatusCode.OK, UserList()),
            1 => JsonResponse(
                HttpStatusCode.ServiceUnavailable,
                new
                {
                    errors = new[]
                    {
                        new
                        {
                            detail = string.Join(
                                " ",
                                FakeAdminToken,
                                FakePassword,
                                FakeCustomer,
                                upstreamOnlySecret)
                        }
                    }
                }),
            _ => throw new InvalidOperationException("Unexpected fake request.")
        });
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var error = await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.FindOrCreateUserAsync(
                "customer.one",
                FakePassword,
                FakeCustomer));

        var rendered = error.ToString();
        Assert.Contains("503", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(FakeAdminToken, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(FakePassword, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(FakeCustomer, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(upstreamOnlySecret, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(FakeAdminToken, handler.Requests[1].Body, StringComparison.Ordinal);
        Assert.DoesNotContain(FakeAdminToken, handler.Requests[1].Uri.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SuccessfulResponseOverFixedLimit_IsRejected()
    {
        var oversizedBody = "{\"data\":[]}" + new string(' ', 1024 * 1024);
        var handler = new FakeHandler((_, _, _) => RawJsonResponse(
            HttpStatusCode.OK,
            oversizedBody));
        using var httpClient = new HttpClient(handler);
        var client = CreateClient(httpClient);

        var error = await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.FindOrCreateUserAsync(
                "customer.one",
                FakePassword,
                FakeCustomer));

        Assert.DoesNotContain(oversizedBody, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Request_UsesFixedTimeoutAndReturnsSanitizedFailure()
    {
        var totalTimeout = TimeSpan.FromMilliseconds(250);
        var handler = new FakeHandler(async (_, _, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return JsonResponse(HttpStatusCode.OK, UserList());
        });
        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var client = CreateClient(httpClient, totalTimeout);
        var stopwatch = Stopwatch.StartNew();

        var error = await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.FindOrCreateUserAsync(
                "customer.one",
                FakePassword,
                FakeCustomer));

        stopwatch.Stop();
        Assert.InRange(
            stopwatch.Elapsed,
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(3));
        var rendered = error.ToString();
        Assert.DoesNotContain(FakeAdminToken, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(FakePassword, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(FakeCustomer, rendered, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WorkflowDeadline_KeygenClientLinksCallerCancellation()
    {
        var handler = new FakeHandler(async (_, _, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return JsonResponse(HttpStatusCode.OK, UserList());
        });
        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var client = CreateClient(httpClient);
        using var operationCancellation = new CancellationTokenSource(
            TimeSpan.FromMilliseconds(200));
        var stopwatch = Stopwatch.StartNew();

        var error = await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.FindOrCreateUserAsync(
                "customer.one",
                FakePassword,
                FakeCustomer,
                operationCancellation.Token));

        stopwatch.Stop();
        Assert.Equal("Keygen administrator request timed out.", error.Message);
        Assert.InRange(
            stopwatch.Elapsed,
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(2));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ResponseBodyRead_UsesTheSameFixedTimeout()
    {
        var totalTimeout = TimeSpan.FromMilliseconds(250);
        var handler = new FakeHandler((_, _, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new DelayedJsonContent("{}", TimeSpan.FromSeconds(1))
            });
        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var client = CreateClient(httpClient, totalTimeout);
        var stopwatch = Stopwatch.StartNew();

        await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.FindOrCreateUserAsync(
                "customer.one",
                FakePassword,
                FakeCustomer));

        stopwatch.Stop();
        Assert.InRange(
            stopwatch.Elapsed,
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task ResponseHeadersAndBody_ShareOneTotalTimeout()
    {
        var totalTimeout = TimeSpan.FromMilliseconds(400);
        var phaseDelay = TimeSpan.FromMilliseconds(250);
        var validUserList = JsonSerializer.Serialize(UserList(UserResource()));
        var handler = new FakeHandler(async (_, _, cancellationToken) =>
        {
            await Task.Delay(phaseDelay, cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new DelayedJsonContent(validUserList, phaseDelay)
            };
        });
        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var client = CreateClient(httpClient, totalTimeout);
        var stopwatch = Stopwatch.StartNew();

        var error = await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.FindOrCreateUserAsync(
                "customer.one",
                FakePassword,
                FakeCustomer));

        stopwatch.Stop();
        Assert.Equal("Keygen administrator request timed out.", error.Message);
        Assert.InRange(
            stopwatch.Elapsed,
            TimeSpan.FromMilliseconds(300),
            TimeSpan.FromSeconds(3));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task DeadlineContract_FindOrCreateSharesBudgetAcrossGetAndPost()
    {
        var totalTimeout = TimeSpan.FromMilliseconds(1000);
        var lookupDelay = TimeSpan.FromMilliseconds(200);
        var mutationDelay = TimeSpan.FromMilliseconds(900);
        var handler = new FakeHandler(async (_, index, cancellationToken) =>
        {
            await Task.Delay(
                index == 0 ? lookupDelay : mutationDelay,
                cancellationToken);
            return index switch
            {
                0 => JsonResponse(HttpStatusCode.OK, UserList()),
                1 => JsonResponse(
                    HttpStatusCode.Created,
                    UserDocument(UserResource())),
                _ => throw new InvalidOperationException("Unexpected fake request.")
            };
        });
        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var client = CreateClient(httpClient, totalTimeout);

        var error = await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.FindOrCreateUserAsync(
                "customer.one",
                FakePassword,
                FakeCustomer));

        Assert.Contains("CommitStateUnknown", error.Message, StringComparison.Ordinal);
        Assert.Equal(
            [HttpMethod.Get, HttpMethod.Post],
            handler.Requests.Select(request => request.Method).ToArray());
    }

    [Fact]
    public async Task DeadlineContract_EnsureTrialSharesBudgetAcrossGetAndPost()
    {
        var totalTimeout = TimeSpan.FromMilliseconds(1000);
        var lookupDelay = TimeSpan.FromMilliseconds(200);
        var mutationDelay = TimeSpan.FromMilliseconds(900);
        var handler = new FakeHandler(async (_, index, cancellationToken) =>
        {
            await Task.Delay(
                index == 0 ? lookupDelay : mutationDelay,
                cancellationToken);
            return index switch
            {
                0 => JsonResponse(HttpStatusCode.OK, LicenseList()),
                1 => JsonResponse(
                    HttpStatusCode.Created,
                    LicenseDocument(LicenseResource())),
                _ => throw new InvalidOperationException("Unexpected fake request.")
            };
        });
        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var client = CreateClient(httpClient, totalTimeout);

        var error = await Assert.ThrowsAsync<KeygenAdminException>(() =>
            client.EnsureTrialAsync(TestUser()));

        Assert.Contains("CommitStateUnknown", error.Message, StringComparison.Ordinal);
        Assert.Equal(
            [HttpMethod.Get, HttpMethod.Post],
            handler.Requests.Select(request => request.Method).ToArray());
    }

    private static KeygenAdminClient CreateClient(
        HttpClient httpClient,
        TimeSpan? totalTimeout = null,
        OwnerConfig? config = null)
    {
        var constructor = typeof(KeygenAdminClient).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            [typeof(HttpClient), typeof(OwnerConfig), typeof(string), typeof(TimeSpan)],
            modifiers: null);
        Assert.NotNull(constructor);
        return InvokeConstructor<KeygenAdminClient>(
            constructor,
            [
                httpClient,
                config ?? LoadConfig(),
                FakeAdminToken,
                totalTimeout ?? TimeSpan.FromSeconds(8)
            ]);
    }

    private static KeygenAdminClient CreateProductionClient(OwnerConfig config)
    {
        var constructor = typeof(KeygenAdminClient).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            [typeof(OwnerConfig), typeof(string)],
            modifiers: null);
        Assert.NotNull(constructor);
        return InvokeConstructor<KeygenAdminClient>(
            constructor,
            [config, FakeAdminToken]);
    }

    private static KeygenAdminOperations CreateProductionOperations(OwnerConfig config)
    {
        var constructor = typeof(KeygenAdminOperations).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            [typeof(OwnerConfig), typeof(string)],
            modifiers: null);
        Assert.NotNull(constructor);
        return InvokeConstructor<KeygenAdminOperations>(
            constructor,
            [config, FakeAdminToken]);
    }

    private static T InvokeConstructor<T>(ConstructorInfo constructor, object?[] arguments)
    {
        try
        {
            return (T)constructor.Invoke(arguments);
        }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
            throw;
        }
    }

    private static T GetPrivateField<T>(object instance, string fieldName)
    {
        for (var type = instance.GetType(); type is not null; type = type.BaseType)
        {
            var field = type.GetField(
                fieldName,
                BindingFlags.Instance | BindingFlags.NonPublic);
            if (field is not null)
            {
                return Assert.IsAssignableFrom<T>(field.GetValue(instance));
            }
        }

        throw new InvalidOperationException($"Private field '{fieldName}' was not found.");
    }

    private static void DisposeIfSupported(object instance)
    {
        if (instance is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }

    private static OwnerConfig LoadConfig(
        string accountId = AccountId,
        string productId = ProductId,
        string trialPolicyId = TrialPolicyId,
        string yearPolicyId = YearPolicyId,
        string foreverPolicyId = ForeverPolicyId,
        string adminBaseUrl = AdminBaseUrl)
    {
        using var directory = new TemporaryDirectory();
        var json = JsonSerializer.Serialize(new
        {
            admin_url = adminBaseUrl,
            account_id = accountId,
            product_id = productId,
            trial_policy_id = trialPolicyId,
            year_policy_id = yearPolicyId,
            forever_policy_id = foreverPolicyId
        });
        var path = directory.WriteFile("admin-config.json", json);
        return OwnerConfig.Load(path);
    }

    private static string WriteDefaultConfig(
        TemporaryDirectory directory,
        string adminBaseUrl)
    {
        var json = JsonSerializer.Serialize(new
        {
            admin_url = adminBaseUrl,
            account_id = AccountId,
            product_id = ProductId,
            trial_policy_id = TrialPolicyId,
            year_policy_id = YearPolicyId,
            forever_policy_id = ForeverPolicyId
        });
        return directory.WriteFile("admin-config.json", json);
    }

    private static KeygenUser TestUser()
    {
        return new KeygenUser(
            UserId,
            "customer.one@accounts.license.invalid",
            FakeCustomer);
    }

    private static void AssertJsonApiHeaders(CapturedRequest request)
    {
        Assert.Equal("Bearer", request.Authorization?.Scheme);
        Assert.Equal(FakeAdminToken, request.Authorization?.Parameter);
        Assert.Contains(JsonApiMediaType, request.Accept);
        Assert.DoesNotContain(FakeAdminToken, request.Uri.AbsoluteUri, StringComparison.Ordinal);
        Assert.DoesNotContain(FakeAdminToken, request.Body ?? string.Empty, StringComparison.Ordinal);
    }

    private static void AssertJsonBodyRequest(CapturedRequest request)
    {
        AssertJsonApiHeaders(request);
        Assert.Equal(JsonApiMediaType, request.ContentType);
        Assert.NotNull(request.Body);
    }

    private static void AssertLicenseCreatePayload(
        string body,
        string plan,
        int price,
        string policyId,
        int? durationSeconds = null)
    {
        using var payload = JsonDocument.Parse(body);
        var data = payload.RootElement.GetProperty("data");
        AssertPropertyNames(data, "attributes", "relationships", "type");
        Assert.Equal("licenses", data.GetProperty("type").GetString());

        var attributes = data.GetProperty("attributes");
        AssertPropertyNames(attributes, "metadata");
        Assert.False(attributes.TryGetProperty("expiry", out _));
        var metadata = attributes.GetProperty("metadata");
        var expectedMetadata = new List<string> { "plan", "price" };
        if (durationSeconds is not null)
        {
            expectedMetadata.Add("durationSeconds");
        }

        if (!string.Equals(plan, "TRIAL", StringComparison.Ordinal))
        {
            expectedMetadata.Add("ownerRequestId");
        }

        AssertPropertyNames(metadata, expectedMetadata.ToArray());
        Assert.Equal(plan, metadata.GetProperty("plan").GetString());
        Assert.Equal(price, metadata.GetProperty("price").GetInt32());
        if (durationSeconds is not null)
        {
            Assert.Equal(
                durationSeconds.Value,
                metadata.GetProperty("durationSeconds").GetInt32());
        }

        if (!string.Equals(plan, "TRIAL", StringComparison.Ordinal))
        {
            Assert.Matches(
                "^[a-f0-9]{32}$",
                metadata.GetProperty("ownerRequestId").GetString());
        }

        Assert.False(metadata.TryGetProperty("businessExpiresAt", out _));

        var relationships = data.GetProperty("relationships");
        AssertPropertyNames(relationships, "owner", "policy");
        AssertRelationship(relationships, "owner", "users", UserId);
        AssertRelationship(relationships, "policy", "policies", policyId);
    }

    private static void AssertRelationship(
        JsonElement relationships,
        string name,
        string type,
        string id)
    {
        var relationship = relationships.GetProperty(name);
        AssertPropertyNames(relationship, "data");
        var data = relationship.GetProperty("data");
        AssertPropertyNames(data, "id", "type");
        Assert.Equal(type, data.GetProperty("type").GetString());
        Assert.Equal(id, data.GetProperty("id").GetString());
    }

    private static void AssertPropertyNames(JsonElement element, params string[] expected)
    {
        var actual = element.EnumerateObject()
            .Select(property => property.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(expected.Order(StringComparer.Ordinal).ToArray(), actual);
    }

    private static object UserResource(
        string type = "users",
        string id = UserId,
        string email = "customer.one@accounts.license.invalid",
        string customer = FakeCustomer,
        string? ownerRequestId = null)
    {
        var metadata = new Dictionary<string, object?>
        {
            ["customer"] = customer
        };
        if (ownerRequestId is not null)
        {
            metadata["ownerRequestId"] = ownerRequestId;
        }

        return new
        {
            type,
            id,
            attributes = new
            {
                email,
                metadata
            }
        };
    }

    private static object UserList(params object[] resources)
    {
        return new { data = resources };
    }

    private static object UserDocument(object resource)
    {
        return new { data = resource };
    }

    private static object MachineResource(
        string id,
        string fingerprint = "TEST-FINGERPRINT-IGNORED")
    {
        return new
        {
            type = "machines",
            id,
            attributes = new
            {
                fingerprint,
                name = "ignored-machine-name"
            }
        };
    }

    private static object MachineList(params object[] resources)
    {
        return new { data = resources };
    }

    private static object LicenseResource(
        string type = "licenses",
        string id = "license-trial",
        string key = "FAKE-TRIAL-LICENSE",
        string plan = "TRIAL",
        int price = 0,
        string ownerId = UserId,
        string productId = ProductId,
        string policyId = TrialPolicyId,
        string ownerType = "users",
        string productType = "products",
        string policyType = "policies",
        int? durationSeconds = null,
        string? expiry = null,
        string? businessExpiresAt = null,
        string status = "ACTIVE",
        bool omitDurationSeconds = false,
        string? ownerRequestId = null)
    {
        if (!omitDurationSeconds
            && durationSeconds is null
            && string.Equals(plan, "TRIAL", StringComparison.Ordinal))
        {
            durationSeconds = TrialDurationSeconds;
        }

        var metadata = new Dictionary<string, object?>
        {
            ["plan"] = plan,
            ["price"] = price
        };
        if (durationSeconds is not null)
        {
            metadata["durationSeconds"] = durationSeconds.Value;
        }

        if (businessExpiresAt is not null)
        {
            metadata["businessExpiresAt"] = businessExpiresAt;
        }

        if (ownerRequestId is not null)
        {
            metadata["ownerRequestId"] = ownerRequestId;
        }

        var attributes = new Dictionary<string, object?>
        {
            ["key"] = key,
            ["status"] = status,
            ["metadata"] = metadata
        };
        if (expiry is not null)
        {
            attributes["expiry"] = expiry;
        }

        return new
        {
            type,
            id,
            attributes,
            relationships = new
            {
                owner = new
                {
                    data = new { type = ownerType, id = ownerId }
                },
                product = new
                {
                    data = new { type = productType, id = productId }
                },
                policy = new
                {
                    data = new { type = policyType, id = policyId }
                }
            }
        };
    }

    private static object LicenseList(params object[] resources)
    {
        return new { data = resources };
    }

    private static object LicenseDocument(object resource)
    {
        return new { data = resource };
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode status, object document)
    {
        return RawJsonResponse(status, JsonSerializer.Serialize(document));
    }

    private static HttpResponseMessage CapturePaidCorrelationAndFailBody(
        CapturedRequest request,
        Action<string?> capture)
    {
        using var payload = JsonDocument.Parse(Assert.IsType<string>(request.Body));
        var metadata = payload.RootElement
            .GetProperty("data")
            .GetProperty("attributes")
            .GetProperty("metadata");
        capture(metadata.TryGetProperty("ownerRequestId", out var value)
            ? value.GetString()
            : null);
        return BodyReadFailureResponse(HttpStatusCode.Created);
    }

    private static string? TryGetPaidOwnerRequestId(CapturedRequest request)
    {
        using var payload = JsonDocument.Parse(Assert.IsType<string>(request.Body));
        var metadata = payload.RootElement
            .GetProperty("data")
            .GetProperty("attributes")
            .GetProperty("metadata");
        return metadata.TryGetProperty("ownerRequestId", out var value)
            ? value.GetString()
            : null;
    }

    private static string? CapturePaidOwnerRequestId(
        CapturedRequest request,
        string? responseOwnerRequestId)
    {
        _ = TryGetPaidOwnerRequestId(request);
        return responseOwnerRequestId;
    }

    private static HttpResponseMessage CaptureUserCorrelationAndFailBody(
        CapturedRequest request,
        Action<string?> capture)
    {
        capture(TryGetOwnerRequestId(request));
        return BodyReadFailureResponse(HttpStatusCode.Created);
    }

    private static string? TryGetOwnerRequestId(CapturedRequest request)
    {
        using var payload = JsonDocument.Parse(Assert.IsType<string>(request.Body));
        var metadata = payload.RootElement
            .GetProperty("data")
            .GetProperty("attributes")
            .GetProperty("metadata");
        return metadata.TryGetProperty("ownerRequestId", out var value)
            ? value.GetString()
            : null;
    }

    private static string CaptureOwnerRequestId(
        CapturedRequest request,
        Action<string?> capture,
        string responseOwnerRequestId)
    {
        capture(TryGetOwnerRequestId(request));
        return responseOwnerRequestId;
    }

    private static HttpResponseMessage ThrowAfterCapturingOwnerRequestId(
        CapturedRequest request)
    {
        _ = TryGetOwnerRequestId(request);
        throw new HttpRequestException("Simulated lost response.");
    }

    private static HttpResponseMessage BodyReadFailureResponse(HttpStatusCode status)
    {
        return new HttpResponseMessage(status)
        {
            Content = new DelayedJsonContent(
                "{}",
                TimeSpan.Zero,
                failOnRead: true)
        };
    }

    private static HttpResponseMessage NoRequestExpected(
        CapturedRequest _,
        int __,
        CancellationToken ___)
    {
        throw new InvalidOperationException("No request was expected.");
    }

    private static HttpResponseMessage RawJsonResponse(HttpStatusCode status, string body)
    {
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, JsonApiMediaType)
        };
    }

    private sealed record CapturedRequest(
        HttpMethod Method,
        Uri Uri,
        string RawPath,
        string RawQuery,
        string? Host,
        string[] ForwardedProto,
        AuthenticationHeaderValue? Authorization,
        string[] Accept,
        string? ContentType,
        string? Body);

    private sealed class DelayedJsonContent : HttpContent
    {
        private readonly TimeSpan _delay;
        private readonly bool _failOnRead;
        private readonly byte[] _payload;

        internal DelayedJsonContent(
            string payload,
            TimeSpan delay,
            bool failOnRead = false)
        {
            _payload = Encoding.UTF8.GetBytes(payload);
            _delay = delay;
            _failOnRead = failOnRead;
            Headers.ContentType = new MediaTypeHeaderValue(JsonApiMediaType);
        }

        protected override Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context)
        {
            throw new NotSupportedException();
        }

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            return Task.FromResult<Stream>(
                new DelayedReadStream(_payload, _delay, _failOnRead));
        }

        protected override Task<Stream> CreateContentReadStreamAsync(
            CancellationToken cancellationToken)
        {
            return Task.FromResult<Stream>(
                new DelayedReadStream(_payload, _delay, _failOnRead));
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class DelayedReadStream : Stream
    {
        private readonly TimeSpan _delay;
        private readonly bool _failOnRead;
        private readonly byte[] _payload;
        private bool _delayCompleted;
        private int _position;

        internal DelayedReadStream(
            byte[] payload,
            TimeSpan delay,
            bool failOnRead)
        {
            _payload = payload;
            _delay = delay;
            _failOnRead = failOnRead;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => _payload.Length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadAsync(buffer, offset, count).GetAwaiter().GetResult();
        }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (_failOnRead)
            {
                throw new HttpRequestException("Simulated response body read failure.");
            }

            if (!_delayCompleted)
            {
                await Task.Delay(_delay, cancellationToken);
                _delayCompleted = true;
            }

            var count = Math.Min(buffer.Length, _payload.Length - _position);
            if (count == 0)
            {
                return 0;
            }

            _payload.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return count;
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
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<CapturedRequest, int, CancellationToken, Task<HttpResponseMessage>>
            _responseFactory;

        internal FakeHandler(
            Func<CapturedRequest, int, CancellationToken, HttpResponseMessage> responseFactory)
            : this((request, index, cancellationToken) =>
                Task.FromResult(responseFactory(request, index, cancellationToken)))
        {
        }

        internal FakeHandler(
            Func<CapturedRequest, int, CancellationToken, Task<HttpResponseMessage>> responseFactory)
        {
            _responseFactory = responseFactory;
        }

        internal List<CapturedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var uri = request.RequestUri
                ?? throw new InvalidOperationException("Fake request URI was missing.");
            var body = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            var forwardedProto = request.Headers.TryGetValues(
                "X-Forwarded-Proto",
                out var forwardedProtoValues)
                ? forwardedProtoValues.ToArray()
                : [];
            var captured = new CapturedRequest(
                request.Method,
                uri,
                uri.AbsolutePath,
                uri.GetComponents(UriComponents.Query, UriFormat.UriEscaped),
                request.Headers.Host,
                forwardedProto,
                request.Headers.Authorization,
                request.Headers.Accept.Select(value => value.MediaType ?? string.Empty).ToArray(),
                request.Content?.Headers.ContentType?.MediaType,
                body);
            Requests.Add(captured);
            return await _responseFactory(captured, Requests.Count - 1, cancellationToken);
        }
    }

    private sealed class CancellationBeforeRecordingHandler : HttpMessageHandler
    {
        internal int RecordedRequests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RecordedRequests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        }
    }

    private sealed class PreCanceledWorkflowOperations : IKeygenAdminOperations
    {
        private readonly KeygenAdminClient _client;
        private readonly string _stage;
        private readonly bool _wasCreated;

        internal PreCanceledWorkflowOperations(
            KeygenAdminClient client,
            bool wasCreated,
            string stage)
        {
            _client = client;
            _wasCreated = wasCreated;
            _stage = stage;
        }

        public Task<KeygenUser> FindOrCreateUserAsync(
            string username,
            string password,
            string customer,
            CancellationToken cancellationToken)
        {
            if (_stage == "trial" || (_stage == "paid" && !_wasCreated))
            {
                WaitUntilCanceled(cancellationToken);
            }

            return Task.FromResult(TestUser() with { WasCreated = _wasCreated });
        }

        public Task<KeygenLicense> EnsureTrialAsync(
            KeygenUser user,
            CancellationToken cancellationToken)
        {
            if (_stage == "paid" && _wasCreated)
            {
                WaitUntilCanceled(cancellationToken);
                return Task.FromResult(new KeygenLicense(
                    "trial-boundary",
                    "TRIAL-LICENSE-BOUNDARY-TEST",
                    "TRIAL",
                    0,
                    user.Id,
                    ProductId,
                    TrialPolicyId));
            }

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
            WaitUntilCanceled(cancellationToken);
            return _client.RevokeMachineAsync(machineId, cancellationToken);
        }

        public void Dispose()
        {
            _client.Dispose();
        }

        private static void WaitUntilCanceled(CancellationToken cancellationToken)
        {
            if (!cancellationToken.WaitHandle.WaitOne(TimeSpan.FromSeconds(2)))
            {
                throw new InvalidOperationException("Workflow deadline did not cancel.");
            }
        }
    }

    private sealed class ClientOperations : IKeygenAdminOperations
    {
        private readonly KeygenAdminClient _client;

        internal ClientOperations(KeygenAdminClient client)
        {
            _client = client;
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
}
