using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SoftwareLicenseAuth.Client.Tests;

public sealed class HardwareFingerprintTests
{
    private const string ProductCode = "DEMO-PRODUCT";

    [Fact]
    public void WindowsHardwareSource_FiltersEveryWmiCandidateBeforeStableSelection()
    {
        var backend = new FakeWindowsHardwareBackend
        {
            WmiValues = [" UNKNOWN ", " z-valid-serial ", " a-valid-serial "],
        };

        var value = new WindowsHardwareSource(backend).GetSmbiosUuid();

        Assert.Equal("AVALIDSERIAL", value);
        Assert.Equal(
            ("SELECT UUID FROM Win32_ComputerSystemProduct", "UUID"),
            Assert.Single(backend.WmiRequests));
    }

    [Fact]
    public void WindowsHardwareSource_UsesTheSameSelectionForDiskAndRegistryCandidates()
    {
        var backend = new FakeWindowsHardwareBackend
        {
            SystemDiskSerials = ["DEFAULT STRING", " z-disk ", " a-disk "],
            MachineGuids = ["00000000-0000-0000-0000-000000000000", " z-guid ", " a-guid "],
        };
        var source = new WindowsHardwareSource(backend);

        Assert.Equal("ADISK", source.GetSystemDiskSerial());
        Assert.Equal("AGUID", source.GetMachineGuid());
        Assert.Equal(1, backend.SystemDiskReadCount);
        Assert.Equal(1, backend.MachineGuidReadCount);
    }

    [Fact]
    public void WindowsHardwareSource_ReplacesBackendExceptionWithGenericError()
    {
        const string rawMarker = "RAW-SERIAL-IN-BACKEND-EXCEPTION-7119";
        var backend = new FakeWindowsHardwareBackend
        {
            WmiException = new ManagementException(rawMarker),
        };

        var exception = Assert.Throws<HardwareSourceUnavailableException>(
            () => new WindowsHardwareSource(backend).GetSmbiosUuid());

        Assert.Equal("Hardware source is unavailable.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.False(exception.ToString().Contains(rawMarker, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void WindowsHardwareSource_ReplacesInteropInvalidCastWithGenericError()
    {
        const string rawMarker = "RAW-WMI-INVALID-CAST-2491";
        var backend = new FakeWindowsHardwareBackend
        {
            WmiException = new InvalidCastException(rawMarker),
        };

        var exception = Assert.Throws<HardwareSourceUnavailableException>(
            () => new WindowsHardwareSource(backend).GetSmbiosUuid());

        Assert.Equal("Hardware source is unavailable.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain(rawMarker, exception.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void WindowsHardwareSource_DoesNotSwallowUnexpectedBackendException()
    {
        var unexpected = new ArgumentException("Unexpected backend programming error.");
        var backend = new FakeWindowsHardwareBackend
        {
            WmiException = unexpected,
        };

        var exception = Assert.Throws<ArgumentException>(
            () => new WindowsHardwareSource(backend).GetSmbiosUuid());

        Assert.Same(unexpected, exception);
    }

    [Fact]
    public void CngDeviceKeyProvider_UsesFixedUserScopedNonExportableP256PlatformKey()
    {
        var publicKeyBlob = Encoding.UTF8.GetBytes("INTERNAL-ECC-PUBLIC-BLOB-4815");
        var expectedSha256 = SHA256.HashData(publicKeyBlob);
        var backend = new FakeCngKeyBackend(publicKeyBlob);

        var result = new CngDeviceKeyProvider(backend).GetOrCreatePublicKeySha256();

        Assert.Equal(expectedSha256, result);
        Assert.Equal(SHA256.HashSizeInBytes, result.Length);
        var configuration = Assert.Single(backend.Configurations);
        Assert.Equal("DEMO-PRODUCT.DeviceKey.P256.v1", configuration.KeyName);
        Assert.Equal("Microsoft Platform Crypto Provider", configuration.Provider.Provider);
        Assert.Equal(CngAlgorithm.ECDsaP256.Algorithm, configuration.Algorithm.Algorithm);
        Assert.Equal(CngKeyCreationOptions.None, configuration.CreationOptions);
        Assert.Equal(CngKeyOpenOptions.None, configuration.OpenOptions);
        Assert.Equal(CngExportPolicies.None, configuration.ExportPolicy);
        Assert.Equal(CngKeyUsages.Signing, configuration.KeyUsage);
        Assert.NotNull(backend.LastReturnedBlob);
        Assert.All(backend.LastReturnedBlob!, value => Assert.Equal((byte)0, value));
    }

    [Fact]
    public void CngDeviceKeyProvider_FallsBackOnlyWhenPlatformProviderIsUnavailable()
    {
        var publicKeyBlob = Encoding.UTF8.GetBytes("SOFTWARE-ECC-PUBLIC-BLOB-9274");
        var backend = new FakeCngKeyBackend(publicKeyBlob)
        {
            PlatformException = new CngProviderUnavailableException(
                "Platform provider is unavailable."),
        };

        var result = new CngDeviceKeyProvider(backend).GetOrCreatePublicKeySha256();

        Assert.Equal(SHA256.HashData(publicKeyBlob), result);
        Assert.Equal(
            new[]
            {
                "Microsoft Platform Crypto Provider",
                "Microsoft Software Key Storage Provider",
            },
            backend.Configurations.Select(configuration => configuration.Provider.Provider));
    }

    [Fact]
    public void CngDeviceKeyProvider_ReplacesBackendExceptionsWithGenericError()
    {
        const string rawMarker = "RAW-CNG-BACKEND-EXCEPTION-6631";
        var backend = new FakeCngKeyBackend([1, 2, 3])
        {
            PlatformException = new CryptographicException(rawMarker),
        };

        var exception = Assert.Throws<CryptographicException>(
            () => new CngDeviceKeyProvider(backend).GetOrCreatePublicKeySha256());

        Assert.Equal("Device key is unavailable.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.False(exception.ToString().Contains(rawMarker, StringComparison.OrdinalIgnoreCase));
        Assert.Equal("Microsoft Platform Crypto Provider", Assert.Single(backend.Configurations).Provider.Provider);
    }

    [Fact]
    public void CngDeviceKeyProvider_DoesNotFallbackAfterPlatformPermissionFailure()
    {
        const string rawMarker = "RAW-CNG-PERMISSION-ERROR-8824";
        var backend = new FakeCngKeyBackend([1, 2, 3])
        {
            PlatformException = new UnauthorizedAccessException(rawMarker),
        };

        var exception = Assert.Throws<CryptographicException>(
            () => new CngDeviceKeyProvider(backend).GetOrCreatePublicKeySha256());

        Assert.Equal("Device key is unavailable.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.False(exception.ToString().Contains(rawMarker, StringComparison.OrdinalIgnoreCase));
        Assert.Equal("Microsoft Platform Crypto Provider", Assert.Single(backend.Configurations).Provider.Provider);
    }

    [Fact]
    public void CngDeviceKeyProvider_DoesNotFallbackAfterPlatformNotSupportedException()
    {
        const string rawMarker = "RAW-PLATFORM-NOT-SUPPORTED-5174";
        var backend = new FakeCngKeyBackend([1, 2, 3])
        {
            PlatformException = new PlatformNotSupportedException(rawMarker),
        };

        var exception = Assert.Throws<CryptographicException>(
            () => new CngDeviceKeyProvider(backend).GetOrCreatePublicKeySha256());

        Assert.Equal("Device key is unavailable.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.False(exception.ToString().Contains(rawMarker, StringComparison.OrdinalIgnoreCase));
        Assert.Equal("Microsoft Platform Crypto Provider", Assert.Single(backend.Configurations).Provider.Provider);
    }

    [Theory]
    [InlineData(unchecked((int)0x80090013))]
    [InlineData(unchecked((int)0x80090017))]
    [InlineData(unchecked((int)0x8009001E))]
    [InlineData(unchecked((int)0x80090029))]
    public void CngErrorClassifier_RecognizesOnlyExplicitProviderUnavailableErrors(int hresult)
    {
        Assert.True(CngErrorClassifier.IsProviderUnavailable(new CryptographicException(hresult)));
    }

    [Theory]
    [InlineData(unchecked((int)0x80090010))]
    [InlineData(unchecked((int)0x8009001D))]
    [InlineData(unchecked((int)0x80090032))]
    public void CngErrorClassifier_DoesNotClassifyPermissionDamageOrValidationAsUnavailable(int hresult)
    {
        Assert.False(CngErrorClassifier.IsProviderUnavailable(new CryptographicException(hresult)));
    }

    [Fact]
    public void CngErrorClassifier_DoesNotClassifyExceptionsWithoutWhitelistedHResult()
    {
        Assert.False(CngErrorClassifier.IsProviderUnavailable(new PlatformNotSupportedException()));
        Assert.False(CngErrorClassifier.IsProviderUnavailable(new NotSupportedException()));
        Assert.False(CngErrorClassifier.IsProviderUnavailable(new CryptographicException()));
    }

    [Fact]
    public void WindowsCngKeyBackend_OpensExistingKeyWithoutExistsProbe()
    {
        var operations = new FakeCngKeyOperations();
        operations.OpenReturns(ValidCngMaterial());

        var result = new WindowsCngKeyBackend(operations)
            .GetOrCreatePublicKeyBlob(TestCngConfiguration());

        Assert.Equal(new byte[] { 11, 22, 33, 44 }, result);
        Assert.Equal(new[] { "Open" }, operations.Calls);
    }

    [Fact]
    public void WindowsCngKeyBackend_AcceptsGenericEcdsaNameForVerifiedP256Blob()
    {
        var operations = new FakeCngKeyOperations();
        var blob = P256PublicBlob();
        operations.OpenReturns(new CngPublicKeyMaterial(
            blob,
            new CngAlgorithm("ECDSA"),
            CngExportPolicies.None,
            CngKeyUsages.Signing));

        var result = new WindowsCngKeyBackend(operations)
            .GetOrCreatePublicKeyBlob(TestCngConfiguration());

        Assert.Equal(blob, result);
    }

    [Fact]
    public void WindowsCngKeyBackend_RejectsGenericEcdsaNameWithoutVerifiedP256Blob()
    {
        var operations = new FakeCngKeyOperations();
        operations.OpenReturns(new CngPublicKeyMaterial(
            new byte[72],
            new CngAlgorithm("ECDSA"),
            CngExportPolicies.None,
            CngKeyUsages.Signing));

        Assert.Throws<CryptographicException>(() =>
            new WindowsCngKeyBackend(operations)
                .GetOrCreatePublicKeyBlob(TestCngConfiguration()));
    }

    [Fact]
    public void WindowsCngKeyBackend_CreatesAfterOpenReportsMissingKey()
    {
        var operations = new FakeCngKeyOperations();
        operations.OpenThrows(new CngKeyNotFoundException());
        operations.CreateReturns(ValidCngMaterial());

        new WindowsCngKeyBackend(operations)
            .GetOrCreatePublicKeyBlob(TestCngConfiguration());

        Assert.Equal(new[] { "Open", "Create" }, operations.Calls);
    }

    [Fact]
    public void WindowsCngKeyBackend_RetriesOpenOnceAfterConcurrentCreate()
    {
        var operations = new FakeCngKeyOperations();
        operations.OpenThrows(new CngKeyNotFoundException());
        operations.CreateThrows(new CngKeyAlreadyExistsException());
        operations.OpenReturns(ValidCngMaterial());

        new WindowsCngKeyBackend(operations)
            .GetOrCreatePublicKeyBlob(TestCngConfiguration());

        Assert.Equal(new[] { "Open", "Create", "Open" }, operations.Calls);
    }

    [Fact]
    public void WindowsCngKeyBackend_DoesNotLoopWhenConcurrentRetryStillCannotOpen()
    {
        var operations = new FakeCngKeyOperations();
        operations.OpenThrows(new CngKeyNotFoundException());
        operations.CreateThrows(new CngKeyAlreadyExistsException());
        operations.OpenThrows(new CngKeyNotFoundException());

        Assert.Throws<CngKeyNotFoundException>(() =>
            new WindowsCngKeyBackend(operations)
                .GetOrCreatePublicKeyBlob(TestCngConfiguration()));
        Assert.Equal(new[] { "Open", "Create", "Open" }, operations.Calls);
    }

    [Fact]
    public void CreateBinding_NormalizesWhitespaceSeparatorsAndCaseBeforeHashing()
    {
        var source = ValidSource();
        source.SmbiosUuid = "  ab-cd : ef_12/34\\56\t\r\n";

        var binding = CreateFingerprint(source).CreateBinding();

        Assert.Equal(ExpectedComponentHash("smbios", "ABCDEF123456"), binding.Components["smbios"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \t\r\n ")]
    [InlineData("UNKNOWN")]
    [InlineData("UNKNOWN!")]
    [InlineData(" default string ")]
    [InlineData("To Be Filled By O.E.M.")]
    [InlineData("SYSTEM SERIAL NUMBER")]
    [InlineData("NONE")]
    [InlineData("N/A")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("00:00:00:00")]
    [InlineData("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")]
    public void CreateBinding_FiltersPlaceholderPhysicalValues(string? placeholder)
    {
        var source = new FakeHardwareSource
        {
            SmbiosUuid = placeholder,
            BaseboardSerial = "board-1",
            BiosSerial = "bios-1",
            SystemDiskSerial = "disk-1",
            MachineGuid = null,
        };

        var binding = CreateFingerprint(source).CreateBinding();

        Assert.DoesNotContain("smbios", binding.Components.Keys);
        Assert.Equal(
            new[] { "baseboard", "bios", "device_key", "system_disk" },
            binding.Components.Keys.OrderBy(name => name, StringComparer.Ordinal));
    }

    [Fact]
    public void CreateBinding_DoesNotCountRepeatedNormalizedRawValuesAsSeparateFactors()
    {
        var source = new FakeHardwareSource
        {
            SmbiosUuid = "repeated-serial",
            BaseboardSerial = " repeated serial ",
            BiosSerial = "REPEATED_SERIAL",
            SystemDiskSerial = "unique-disk",
        };

        var exception = Assert.Throws<InvalidOperationException>(
            () => CreateFingerprint(source).CreateBinding());

        Assert.Equal("Hardware identity is unavailable. Contact the administrator.", exception.Message);
    }

    [Fact]
    public void CreateBinding_UsesComponentSpecificHashDomains()
    {
        var source = new FakeHardwareSource
        {
            SmbiosUuid = "smbios-value",
            BaseboardSerial = "baseboard-value",
            BiosSerial = "bios-value",
        };

        var binding = CreateFingerprint(source).CreateBinding();

        Assert.Equal(ExpectedComponentHash("smbios", "SMBIOSVALUE"), binding.Components["smbios"]);
        Assert.Equal(ExpectedComponentHash("baseboard", "BASEBOARDVALUE"), binding.Components["baseboard"]);
        Assert.Equal(ExpectedComponentHash("bios", "BIOSVALUE"), binding.Components["bios"]);
        Assert.NotEqual(binding.Components["smbios"], binding.Components["baseboard"]);
    }

    [Fact]
    public void CreateBinding_RejectsFewerThanThreePhysicalFactorsWithoutLeakingRawValues()
    {
        const string rawSmbios = "RAW-SMBIOS-SECRET-7812";
        const string rawBaseboard = "RAW-BOARD-SECRET-9934";
        var source = new FakeHardwareSource
        {
            SmbiosUuid = rawSmbios,
            BaseboardSerial = rawBaseboard,
            BiosSerial = "UNKNOWN",
            SystemDiskSerial = "0000-0000",
            MachineGuid = null,
        };

        var exception = Assert.Throws<InvalidOperationException>(() => CreateFingerprint(source).CreateBinding());

        Assert.Equal("Hardware identity is unavailable. Contact the administrator.", exception.Message);
        Assert.False(exception.ToString().Contains(rawSmbios, StringComparison.OrdinalIgnoreCase));
        Assert.False(exception.ToString().Contains(rawBaseboard, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CreateBinding_SortsPhysicalComponentsByNameForStableFingerprint()
    {
        var binding = CreateFingerprint(ValidSource()).CreateBinding();

        Assert.Equal(ExpectedFingerprint(binding.Components), binding.Fingerprint);
        Assert.Equal(CreateFingerprint(ValidSource()).CreateBinding().Fingerprint, binding.Fingerprint);
    }

    [Fact]
    public void MatchesPhysicalMajority_AcceptsOneChangedPhysicalFactor()
    {
        var bound = CreateFingerprint(ValidSource()).CreateBinding();
        var changedSource = ValidSource();
        changedSource.BiosSerial = "replacement-bios";
        var candidate = CreateFingerprint(changedSource).CreateBinding();

        Assert.True(HardwareFingerprint.MatchesPhysicalMajority(bound, candidate));
    }

    [Fact]
    public void MatchesPhysicalMajority_RejectsAChangedMajority()
    {
        var bound = CreateFingerprint(ValidSource()).CreateBinding();
        var changedSource = ValidSource();
        changedSource.SmbiosUuid = "replacement-smbios";
        changedSource.BaseboardSerial = "replacement-board";
        changedSource.BiosSerial = "replacement-bios";
        var candidate = CreateFingerprint(changedSource).CreateBinding();

        Assert.False(HardwareFingerprint.MatchesPhysicalMajority(bound, candidate));
    }

    [Fact]
    public void MatchesPhysicalMajority_CountsMissingBoundComponentsAsMismatches()
    {
        var bound = CreateFingerprint(ValidSource()).CreateBinding();
        var candidateSource = new FakeHardwareSource
        {
            SmbiosUuid = "smbios-1",
            BaseboardSerial = "board-1",
            BiosSerial = "different-bios",
        };
        var candidate = CreateFingerprint(candidateSource).CreateBinding();

        Assert.False(HardwareFingerprint.MatchesPhysicalMajority(bound, candidate));
    }

    [Fact]
    public void MatchesPhysicalMajority_RejectsBoundWithFewerThanThreeLegalPhysicalComponents()
    {
        var valid = ThreePhysicalFactorBinding();
        var malformedComponents = valid.Components.ToDictionary(
            component => component.Key,
            component => component.Value,
            StringComparer.Ordinal);
        malformedComponents["bios"] = "not-a-sha256";
        var malformedBound = new DeviceBinding(valid.Fingerprint, malformedComponents);

        Assert.False(HardwareFingerprint.MatchesPhysicalMajority(malformedBound, valid));
    }

    [Fact]
    public void MatchesPhysicalMajority_RejectsCandidateWithFewerThanThreeLegalPhysicalComponents()
    {
        var bound = ThreePhysicalFactorBinding();
        var malformedComponents = bound.Components.ToDictionary(
            component => component.Key,
            component => component.Value,
            StringComparer.Ordinal);
        malformedComponents["bios"] = "not-a-sha256";
        var malformedCandidate = new DeviceBinding(bound.Fingerprint, malformedComponents);

        Assert.False(HardwareFingerprint.MatchesPhysicalMajority(bound, malformedCandidate));
    }

    [Fact]
    public void CreateBinding_DeviceKeyChangeDoesNotChangeMainFingerprintOrPhysicalMajority()
    {
        var first = CreateFingerprint(ValidSource(), SHA256.HashData([1, 2, 3, 4])).CreateBinding();
        var second = CreateFingerprint(ValidSource(), SHA256.HashData([9, 8, 7, 6])).CreateBinding();

        Assert.Equal(first.Fingerprint, second.Fingerprint);
        Assert.NotEqual(first.Components["device_key"], second.Components["device_key"]);
        Assert.True(HardwareFingerprint.MatchesPhysicalMajority(first, second));
    }

    [Fact]
    public void CreateBinding_DomainSeparatesThePublicKeySha256()
    {
        var publicKeySha256 = SHA256.HashData([41, 42, 43, 44]);

        var binding = CreateFingerprint(ValidSource(), publicKeySha256).CreateBinding();

        Assert.Equal(
            ExpectedComponentHash("device_key", publicKeySha256),
            binding.Components["device_key"]);
    }

    [Fact]
    public void CreateBinding_RejectsDeviceKeyValuesThatAreNotSha256Length()
    {
        var fingerprint = new HardwareFingerprint(
            ValidSource(),
            new FakeDeviceKeyProvider([1, 2, 3, 4]));

        var exception = Assert.Throws<InvalidOperationException>(fingerprint.CreateBinding);

        Assert.Equal("Device identity is unavailable. Contact the administrator.", exception.Message);
    }

    [Fact]
    public void CreateBinding_ExposesOnlyAllowedNamesAndUppercaseSha256WithoutRawValues()
    {
        const string rawMarker = "Raw-Serial-Marker-52918";
        var source = ValidSource();
        source.SystemDiskSerial = rawMarker;

        var binding = CreateFingerprint(source).CreateBinding();
        var observable = binding.Fingerprint
            + binding
            + string.Join("", binding.Components.Select(pair => pair.Key + pair.Value));

        Assert.Equal(
            new[] { "baseboard", "bios", "device_key", "machine_guid", "smbios", "system_disk" },
            binding.Components.Keys.OrderBy(name => name, StringComparer.Ordinal));
        Assert.Matches("^[0-9A-F]{64}$", binding.Fingerprint);
        Assert.All(binding.Components.Values, value => Assert.Matches("^[0-9A-F]{64}$", value));
        Assert.False(observable.Contains(rawMarker, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CreateBinding_ReplacesHardwareSourceExceptionWithoutRawLeakage()
    {
        const string rawMarker = "RAW-HARDWARE-SOURCE-EXCEPTION-3182";
        var fingerprint = new HardwareFingerprint(
            new ThrowingHardwareSource(new HardwareSourceUnavailableException(rawMarker)),
            new FakeDeviceKeyProvider(SHA256.HashData([1, 2, 3])));

        var exception = Assert.Throws<InvalidOperationException>(fingerprint.CreateBinding);

        Assert.Equal("Hardware identity is unavailable. Contact the administrator.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.False(exception.ToString().Contains(rawMarker, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CreateBinding_ReplacesDeviceProviderExceptionWithoutRawLeakage()
    {
        const string rawMarker = "RAW-DEVICE-PROVIDER-EXCEPTION-5793";
        var fingerprint = new HardwareFingerprint(
            ValidSource(),
            new ThrowingDeviceKeyProvider(new CryptographicException(rawMarker)));

        var exception = Assert.Throws<InvalidOperationException>(fingerprint.CreateBinding);

        Assert.Equal("Device identity is unavailable. Contact the administrator.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.False(exception.ToString().Contains(rawMarker, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CreateBinding_DoesNotSwallowUnexpectedHardwareSourceException()
    {
        var unexpected = new InvalidOperationException("Unexpected source programming error.");
        var fingerprint = new HardwareFingerprint(
            new ThrowingHardwareSource(unexpected),
            new FakeDeviceKeyProvider(SHA256.HashData([1, 2, 3])));

        var exception = Assert.Throws<InvalidOperationException>(fingerprint.CreateBinding);

        Assert.Same(unexpected, exception);
    }

    [Fact]
    public void CreateBinding_DoesNotSwallowUnexpectedDeviceProviderException()
    {
        var unexpected = new InvalidOperationException("Unexpected provider programming error.");
        var fingerprint = new HardwareFingerprint(
            ValidSource(),
            new ThrowingDeviceKeyProvider(unexpected));

        var exception = Assert.Throws<InvalidOperationException>(fingerprint.CreateBinding);

        Assert.Same(unexpected, exception);
    }

    [Fact]
    public void DeviceBinding_SystemTextJsonSerializationContainsNoRawHardwareOrPublicKeyBlob()
    {
        const string rawSerial = "RAW-SERIAL-FOR-JSON-8642";
        const string rawPublicKeyBlob = "RAW-PUBLIC-KEY-BLOB-FOR-JSON-1075";
        var source = ValidSource();
        source.SystemDiskSerial = rawSerial;
        var publicKeySha256 = SHA256.HashData(Encoding.UTF8.GetBytes(rawPublicKeyBlob));

        var binding = CreateFingerprint(source, publicKeySha256).CreateBinding();
        var json = JsonSerializer.Serialize(binding);

        Assert.Contains(binding.Fingerprint, json, StringComparison.Ordinal);
        Assert.False(json.Contains(rawSerial, StringComparison.OrdinalIgnoreCase));
        Assert.False(json.Contains(rawPublicKeyBlob, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DeviceBinding_DefensivelyCopiesAndFreezesComponents()
    {
        var originalHash = new string('A', 64);
        var mutableComponents = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["smbios"] = originalHash,
        };
        var binding = new DeviceBinding(new string('B', 64), mutableComponents);

        mutableComponents["smbios"] = new string('C', 64);
        mutableComponents["bios"] = new string('D', 64);

        Assert.Equal(originalHash, binding.Components["smbios"]);
        Assert.DoesNotContain("bios", binding.Components.Keys);
        var exposedDictionary = Assert.IsAssignableFrom<IDictionary<string, string>>(binding.Components);
        Assert.Throws<NotSupportedException>(
            () => exposedDictionary.Add("baseboard", new string('E', 64)));
    }

    [Fact]
    public void DeviceBinding_ComponentsIsGetterOnlyAcrossRecordCopyPaths()
    {
        var componentsProperty = typeof(DeviceBinding).GetProperty(nameof(DeviceBinding.Components));
        Assert.NotNull(componentsProperty);
        Assert.Null(componentsProperty!.GetSetMethod(nonPublic: true));

        var mutableComponents = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["smbios"] = new string('A', 64),
        };
        var binding = new DeviceBinding(new string('B', 64), mutableComponents);
        var copy = binding with { Fingerprint = new string('C', 64) };
        mutableComponents["smbios"] = new string('D', 64);

        Assert.Equal(new string('A', 64), binding.Components["smbios"]);
        Assert.Equal(new string('A', 64), copy.Components["smbios"]);
        var (fingerprint, copiedComponents) = copy;
        Assert.Equal(copy.Fingerprint, fingerprint);
        Assert.Same(copy.Components, copiedComponents);
    }

    private static HardwareFingerprint CreateFingerprint(
        FakeHardwareSource source,
        byte[]? publicKeySha256 = null)
    {
        return new HardwareFingerprint(
            source,
            new FakeDeviceKeyProvider(publicKeySha256 ?? SHA256.HashData([10, 20, 30, 40])));
    }

    private static FakeHardwareSource ValidSource()
    {
        return new FakeHardwareSource
        {
            SmbiosUuid = "smbios-1",
            BaseboardSerial = "board-1",
            BiosSerial = "bios-1",
            SystemDiskSerial = "disk-1",
            MachineGuid = "machine-guid-1",
        };
    }

    private static DeviceBinding ThreePhysicalFactorBinding()
    {
        return CreateFingerprint(new FakeHardwareSource
        {
            SmbiosUuid = "smbios-1",
            BaseboardSerial = "board-1",
            BiosSerial = "bios-1",
        }).CreateBinding();
    }

    private static CngKeyConfiguration TestCngConfiguration()
    {
        return new CngKeyConfiguration(
            "DEMO-PRODUCT.DeviceKey.P256.v1",
            new CngProvider("Test Provider"),
            CngAlgorithm.ECDsaP256,
            CngKeyCreationOptions.None,
            CngKeyOpenOptions.None,
            CngExportPolicies.None,
            CngKeyUsages.Signing);
    }

    private static CngPublicKeyMaterial ValidCngMaterial()
    {
        return new CngPublicKeyMaterial(
            [11, 22, 33, 44],
            CngAlgorithm.ECDsaP256,
            CngExportPolicies.None,
            CngKeyUsages.Signing);
    }

    private static byte[] P256PublicBlob()
    {
        var blob = new byte[72];
        BitConverter.GetBytes(0x31534345u).CopyTo(blob, 0);
        BitConverter.GetBytes(32u).CopyTo(blob, 4);
        return blob;
    }

    private static string ExpectedComponentHash(string componentName, string normalizedValue)
    {
        return ExpectedComponentHash(componentName, Encoding.UTF8.GetBytes(normalizedValue));
    }

    private static string ExpectedComponentHash(string componentName, byte[] value)
    {
        var prefix = Encoding.UTF8.GetBytes(ProductCode + "\0" + componentName + "\0");
        return Convert.ToHexString(SHA256.HashData([.. prefix, .. value]));
    }

    private static string ExpectedFingerprint(IReadOnlyDictionary<string, string> components)
    {
        var material = new StringBuilder(ProductCode + "\0fingerprint\0");
        foreach (var component in components
                     .Where(pair => pair.Key != "device_key")
                     .OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            material.Append(component.Key).Append('\0').Append(component.Value).Append('\0');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material.ToString())));
    }

    private sealed class FakeHardwareSource : IHardwareSource
    {
        internal string? SmbiosUuid { get; set; }
        internal string? BaseboardSerial { get; set; }
        internal string? BiosSerial { get; set; }
        internal string? SystemDiskSerial { get; set; }
        internal string? MachineGuid { get; set; }

        public string? GetSmbiosUuid() => SmbiosUuid;
        public string? GetBaseboardSerial() => BaseboardSerial;
        public string? GetBiosSerial() => BiosSerial;
        public string? GetSystemDiskSerial() => SystemDiskSerial;
        public string? GetMachineGuid() => MachineGuid;
    }

    private sealed class FakeWindowsHardwareBackend : IWindowsHardwareBackend
    {
        internal IReadOnlyList<string?> WmiValues { get; set; } = [];
        internal IReadOnlyList<string?> SystemDiskSerials { get; set; } = [];
        internal IReadOnlyList<string?> MachineGuids { get; set; } = [];
        internal Exception? WmiException { get; set; }
        internal List<(string Query, string PropertyName)> WmiRequests { get; } = [];
        internal int SystemDiskReadCount { get; private set; }
        internal int MachineGuidReadCount { get; private set; }

        public IReadOnlyList<string?> ReadWmiValues(string query, string propertyName)
        {
            WmiRequests.Add((query, propertyName));
            if (WmiException is not null)
            {
                throw WmiException;
            }

            return WmiValues;
        }

        public IReadOnlyList<string?> ReadSystemDiskSerials()
        {
            SystemDiskReadCount++;
            return SystemDiskSerials;
        }

        public IReadOnlyList<string?> ReadMachineGuids()
        {
            MachineGuidReadCount++;
            return MachineGuids;
        }
    }

    private sealed class FakeCngKeyBackend : ICngKeyBackend
    {
        private readonly byte[] publicKeyBlob;

        internal FakeCngKeyBackend(byte[] publicKeyBlob)
        {
            this.publicKeyBlob = (byte[])publicKeyBlob.Clone();
        }

        internal Exception? PlatformException { get; set; }
        internal Exception? SoftwareException { get; set; }
        internal List<CngKeyConfiguration> Configurations { get; } = [];
        internal byte[]? LastReturnedBlob { get; private set; }

        public byte[] GetOrCreatePublicKeyBlob(CngKeyConfiguration configuration)
        {
            Configurations.Add(configuration);
            var failure = configuration.Provider.Provider == "Microsoft Platform Crypto Provider"
                ? PlatformException
                : SoftwareException;
            if (failure is not null)
            {
                throw failure;
            }

            LastReturnedBlob = (byte[])publicKeyBlob.Clone();
            return LastReturnedBlob;
        }
    }

    private sealed class FakeCngKeyOperations : ICngKeyOperations
    {
        private readonly Queue<object> openSteps = [];
        private readonly Queue<object> createSteps = [];

        internal List<string> Calls { get; } = [];

        internal void OpenReturns(CngPublicKeyMaterial material) => openSteps.Enqueue(material);
        internal void OpenThrows(Exception exception) => openSteps.Enqueue(exception);
        internal void CreateReturns(CngPublicKeyMaterial material) => createSteps.Enqueue(material);
        internal void CreateThrows(Exception exception) => createSteps.Enqueue(exception);

        public CngPublicKeyMaterial Open(CngKeyConfiguration configuration)
        {
            Calls.Add("Open");
            return Execute(openSteps);
        }

        public CngPublicKeyMaterial Create(CngKeyConfiguration configuration)
        {
            Calls.Add("Create");
            return Execute(createSteps);
        }

        private static CngPublicKeyMaterial Execute(Queue<object> steps)
        {
            var step = steps.Dequeue();
            if (step is Exception exception)
            {
                throw exception;
            }

            return (CngPublicKeyMaterial)step;
        }
    }

    private sealed class ThrowingHardwareSource : IHardwareSource
    {
        private readonly Exception exception;

        internal ThrowingHardwareSource(Exception exception)
        {
            this.exception = exception;
        }

        public string? GetSmbiosUuid() => throw exception;
        public string? GetBaseboardSerial() => throw exception;
        public string? GetBiosSerial() => throw exception;
        public string? GetSystemDiskSerial() => throw exception;
        public string? GetMachineGuid() => throw exception;
    }

    private sealed class ThrowingDeviceKeyProvider : IDeviceKeyProvider
    {
        private readonly Exception exception;

        internal ThrowingDeviceKeyProvider(Exception exception)
        {
            this.exception = exception;
        }

        public byte[] GetOrCreatePublicKeySha256()
        {
            throw exception;
        }
    }

    private sealed class FakeDeviceKeyProvider : IDeviceKeyProvider
    {
        private readonly byte[] publicKeySha256;

        internal FakeDeviceKeyProvider(byte[] publicKeySha256)
        {
            this.publicKeySha256 = publicKeySha256;
        }

        public byte[] GetOrCreatePublicKeySha256()
        {
            return (byte[])publicKeySha256.Clone();
        }
    }
}
