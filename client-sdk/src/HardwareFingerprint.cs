using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

internal sealed record DeviceBinding
{
    internal DeviceBinding(
        string fingerprint,
        IReadOnlyDictionary<string, string> components)
    {
        ArgumentNullException.ThrowIfNull(fingerprint);
        ArgumentNullException.ThrowIfNull(components);

        Fingerprint = fingerprint;
        Components = new ReadOnlyDictionary<string, string>(
            components.ToDictionary(
                component => component.Key,
                component => component.Value,
                StringComparer.Ordinal));
    }

    public string Fingerprint { get; init; }
    public IReadOnlyDictionary<string, string> Components { get; }

    public void Deconstruct(
        out string fingerprint,
        out IReadOnlyDictionary<string, string> components)
    {
        fingerprint = Fingerprint;
        components = Components;
    }
}

internal interface IHardwareSource
{
    string? GetSmbiosUuid();
    string? GetBaseboardSerial();
    string? GetBiosSerial();
    string? GetSystemDiskSerial();
    string? GetMachineGuid();
}

internal sealed class HardwareSourceUnavailableException : InvalidOperationException
{
    internal HardwareSourceUnavailableException(string message)
        : base(message)
    {
    }
}

internal interface IDeviceKeyProvider
{
    byte[] GetOrCreatePublicKeySha256();
}

internal sealed class HardwareFingerprint
{
    private const string ProductCode = "DEMO-PRODUCT";
    private const string HardwareUnavailableMessage =
        "Hardware identity is unavailable. Contact the administrator.";
    private const string DeviceUnavailableMessage =
        "Device identity is unavailable. Contact the administrator.";

    private static readonly (string Name, Func<IHardwareSource, string?> Read)[] PhysicalComponents =
    [
        ("smbios", source => source.GetSmbiosUuid()),
        ("baseboard", source => source.GetBaseboardSerial()),
        ("bios", source => source.GetBiosSerial()),
        ("system_disk", source => source.GetSystemDiskSerial()),
        ("machine_guid", source => source.GetMachineGuid()),
    ];

    private static readonly HashSet<string> PhysicalComponentNames =
        PhysicalComponents.Select(component => component.Name).ToHashSet(StringComparer.Ordinal);

    private static readonly HashSet<string> PlaceholderValues = new(StringComparer.Ordinal)
    {
        "UNKNOWN",
        "UNKNOWN!",
        "DEFAULTSTRING",
        "TOBEFILLEDBYOEM",
        "SYSTEMSERIALNUMBER",
        "NONE",
        "NA",
    };

    private readonly IHardwareSource hardwareSource;
    private readonly IDeviceKeyProvider deviceKeyProvider;

    internal HardwareFingerprint(
        IHardwareSource hardwareSource,
        IDeviceKeyProvider deviceKeyProvider)
    {
        this.hardwareSource = hardwareSource ?? throw new ArgumentNullException(nameof(hardwareSource));
        this.deviceKeyProvider = deviceKeyProvider ?? throw new ArgumentNullException(nameof(deviceKeyProvider));
    }

    internal DeviceBinding CreateBinding()
    {
        var components = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var normalizedPhysicalValues = new HashSet<string>(StringComparer.Ordinal);

        foreach (var component in PhysicalComponents)
        {
            string? normalizedValue;
            try
            {
                normalizedValue = Normalize(component.Read(hardwareSource));
            }
            catch (HardwareSourceUnavailableException)
            {
                normalizedValue = null;
            }

            if (normalizedValue is not null && normalizedPhysicalValues.Add(normalizedValue))
            {
                components[component.Name] = HashComponent(
                    component.Name,
                    Encoding.UTF8.GetBytes(normalizedValue));
            }
        }

        if (components.Count < 3)
        {
            throw new InvalidOperationException(HardwareUnavailableMessage);
        }

        byte[] publicKeySha256;
        try
        {
            publicKeySha256 = deviceKeyProvider.GetOrCreatePublicKeySha256();
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException(DeviceUnavailableMessage);
        }
        catch (UnauthorizedAccessException)
        {
            throw new InvalidOperationException(DeviceUnavailableMessage);
        }

        if (publicKeySha256 is null || publicKeySha256.Length != SHA256.HashSizeInBytes)
        {
            throw new InvalidOperationException(DeviceUnavailableMessage);
        }

        components["device_key"] = HashComponent("device_key", publicKeySha256);
        var readOnlyComponents = new ReadOnlyDictionary<string, string>(components);
        return new DeviceBinding(ComputeFingerprint(readOnlyComponents), readOnlyComponents);
    }

    internal static bool MatchesPhysicalMajority(DeviceBinding bound, DeviceBinding candidate)
    {
        ArgumentNullException.ThrowIfNull(bound);
        ArgumentNullException.ThrowIfNull(candidate);

        var boundPhysicalComponents = LegalPhysicalComponents(bound);
        var candidatePhysicalComponents = LegalPhysicalComponents(candidate);
        if (boundPhysicalComponents.Count < 3 || candidatePhysicalComponents.Count < 3)
        {
            return false;
        }

        var matchCount = boundPhysicalComponents.Count(component =>
            candidatePhysicalComponents.TryGetValue(component.Key, out var candidateValue)
            && string.Equals(component.Value, candidateValue, StringComparison.Ordinal));
        return matchCount >= (boundPhysicalComponents.Count / 2) + 1;
    }

    private static IReadOnlyDictionary<string, string> LegalPhysicalComponents(DeviceBinding binding)
    {
        return binding.Components
            .Where(component =>
                PhysicalComponentNames.Contains(component.Key)
                && IsUppercaseSha256(component.Value))
            .ToDictionary(component => component.Key, component => component.Value, StringComparer.Ordinal);
    }

    private static bool IsUppercaseSha256(string value)
    {
        return value.Length == 64
            && value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
    }

    internal static string? Normalize(string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return null;
        }

        var normalized = new StringBuilder(rawValue.Length);
        foreach (var character in rawValue)
        {
            if (char.IsWhiteSpace(character) || IsCommonSeparator(character))
            {
                continue;
            }

            normalized.Append(char.ToUpperInvariant(character));
        }

        var value = normalized.ToString();
        if (value.Length == 0
            || PlaceholderValues.Contains(value)
            || value.All(character => character == '0')
            || value.All(character => character == 'F'))
        {
            return null;
        }

        return value;
    }

    private static bool IsCommonSeparator(char character)
    {
        return character is '-' or ':' or '.' or '_' or '/' or '\\'
            or '{' or '}' or '(' or ')' or '[' or ']';
    }

    private static string HashComponent(string componentName, ReadOnlySpan<byte> value)
    {
        var domain = Encoding.UTF8.GetBytes(ProductCode + "\0" + componentName + "\0");
        var material = new byte[domain.Length + value.Length];
        domain.CopyTo(material, 0);
        value.CopyTo(material.AsSpan(domain.Length));
        return Convert.ToHexString(SHA256.HashData(material));
    }

    private static string ComputeFingerprint(IReadOnlyDictionary<string, string> components)
    {
        var material = new StringBuilder(ProductCode + "\0fingerprint\0");
        foreach (var component in components
                     .Where(component => PhysicalComponentNames.Contains(component.Key))
                     .OrderBy(component => component.Key, StringComparer.Ordinal))
        {
            material.Append(component.Key).Append('\0').Append(component.Value).Append('\0');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material.ToString())));
    }
}

internal interface IWindowsHardwareBackend
{
    IReadOnlyList<string?> ReadWmiValues(string query, string propertyName);
    IReadOnlyList<string?> ReadSystemDiskSerials();
    IReadOnlyList<string?> ReadMachineGuids();
}

internal sealed class WindowsHardwareSource : IHardwareSource
{
    private const string SourceUnavailableMessage = "Hardware source is unavailable.";
    private readonly IWindowsHardwareBackend backend;

    internal WindowsHardwareSource()
        : this(new WindowsHardwareBackend())
    {
    }

    internal WindowsHardwareSource(IWindowsHardwareBackend backend)
    {
        this.backend = backend ?? throw new ArgumentNullException(nameof(backend));
    }

    public string? GetSmbiosUuid()
    {
        return SelectStableValue(
            () => backend.ReadWmiValues(
                "SELECT UUID FROM Win32_ComputerSystemProduct",
                "UUID"));
    }

    public string? GetBaseboardSerial()
    {
        return SelectStableValue(
            () => backend.ReadWmiValues(
                "SELECT SerialNumber FROM Win32_BaseBoard",
                "SerialNumber"));
    }

    public string? GetBiosSerial()
    {
        return SelectStableValue(
            () => backend.ReadWmiValues(
                "SELECT SerialNumber FROM Win32_BIOS",
                "SerialNumber"));
    }

    public string? GetSystemDiskSerial()
    {
        return SelectStableValue(backend.ReadSystemDiskSerials);
    }

    public string? GetMachineGuid()
    {
        return SelectStableValue(backend.ReadMachineGuids);
    }

    private static string? SelectStableValue(Func<IReadOnlyList<string?>> readCandidates)
    {
        try
        {
            return readCandidates()
                .Select(HardwareFingerprint.Normalize)
                .Where(value => value is not null)
                .OrderBy(value => value, StringComparer.Ordinal)
                .FirstOrDefault();
        }
        catch (Exception exception) when (
            exception is ManagementException
                or COMException
                or InvalidCastException
                or UnauthorizedAccessException
                or SecurityException
                or IOException
                or PlatformNotSupportedException)
        {
            throw new HardwareSourceUnavailableException(SourceUnavailableMessage);
        }
    }
}

internal sealed class WindowsHardwareBackend : IWindowsHardwareBackend
{
    public IReadOnlyList<string?> ReadWmiValues(string query, string propertyName)
    {
        var values = new List<string?>();
        using var searcher = new ManagementObjectSearcher(query);
        using var results = searcher.Get();
        foreach (ManagementObject result in results)
        {
            using (result)
            {
                values.Add(Convert.ToString(result[propertyName], CultureInfo.InvariantCulture));
            }
        }

        return values;
    }

    public IReadOnlyList<string?> ReadSystemDiskSerials()
    {
        var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var root = Path.GetPathRoot(systemDirectory);
        var deviceId = root?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return [];
        }

        var serials = new List<string?>();
        using var logicalDisk = new ManagementObject($"Win32_LogicalDisk.DeviceID=\"{deviceId}\"");
        logicalDisk.Get();
        using var partitions = logicalDisk.GetRelated("Win32_DiskPartition");
        foreach (ManagementObject partition in partitions)
        {
            using (partition)
            using (var diskDrives = partition.GetRelated("Win32_DiskDrive"))
            {
                foreach (ManagementObject diskDrive in diskDrives)
                {
                    using (diskDrive)
                    {
                        serials.Add(Convert.ToString(
                            diskDrive["SerialNumber"],
                            CultureInfo.InvariantCulture));
                    }
                }
            }
        }

        return serials;
    }

    public IReadOnlyList<string?> ReadMachineGuids()
    {
        var values = new List<string?>();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = localMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", writable: false);
                values.Add(key?.GetValue(
                    "MachineGuid",
                    defaultValue: null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames) as string);
            }
            catch (UnauthorizedAccessException)
            {
                // Try the alternate registry view.
            }
            catch (SecurityException)
            {
                // Try the alternate registry view.
            }
            catch (IOException)
            {
                // Try the alternate registry view.
            }
            catch (PlatformNotSupportedException)
            {
                // Try the alternate registry view.
            }
        }

        return values;
    }
}

internal sealed class CngProviderUnavailableException : CryptographicException
{
    internal CngProviderUnavailableException(string message)
        : base(message)
    {
    }
}

internal sealed class CngKeyNotFoundException : CryptographicException
{
    internal CngKeyNotFoundException()
        : base("Device key was not found.")
    {
    }
}

internal sealed class CngKeyAlreadyExistsException : CryptographicException
{
    internal CngKeyAlreadyExistsException()
        : base("Device key already exists.")
    {
    }
}

internal static class CngErrorClassifier
{
    private static readonly HashSet<int> ProviderUnavailableErrors =
    [
        unchecked((int)0x80090013), // NTE_BAD_PROVIDER
        unchecked((int)0x80090017), // NTE_PROV_TYPE_NOT_DEF
        unchecked((int)0x8009001E), // NTE_PROV_DLL_NOT_FOUND
        unchecked((int)0x80090029), // NTE_NOT_SUPPORTED
    ];

    private static readonly HashSet<int> KeyNotFoundErrors =
    [
        unchecked((int)0x8009000D), // NTE_NO_KEY
        unchecked((int)0x80090011), // NTE_NOT_FOUND
        unchecked((int)0x80090016), // NTE_BAD_KEYSET
    ];

    internal static bool IsProviderUnavailable(Exception exception)
    {
        return exception is CryptographicException cryptographicException
            && ProviderUnavailableErrors.Contains(cryptographicException.HResult);
    }

    internal static bool IsKeyNotFound(CryptographicException exception)
    {
        return KeyNotFoundErrors.Contains(exception.HResult);
    }

    internal static bool IsKeyAlreadyExists(CryptographicException exception)
    {
        return exception.HResult == unchecked((int)0x8009000F); // NTE_EXISTS
    }
}

internal sealed record CngKeyConfiguration(
    string KeyName,
    CngProvider Provider,
    CngAlgorithm Algorithm,
    CngKeyCreationOptions CreationOptions,
    CngKeyOpenOptions OpenOptions,
    CngExportPolicies ExportPolicy,
    CngKeyUsages KeyUsage);

internal interface ICngKeyBackend
{
    byte[] GetOrCreatePublicKeyBlob(CngKeyConfiguration configuration);
}

internal sealed record CngPublicKeyMaterial(
    byte[] PublicKeyBlob,
    CngAlgorithm Algorithm,
    CngExportPolicies ExportPolicy,
    CngKeyUsages KeyUsage);

internal interface ICngKeyOperations
{
    CngPublicKeyMaterial Open(CngKeyConfiguration configuration);
    CngPublicKeyMaterial Create(CngKeyConfiguration configuration);
}

internal sealed class CngDeviceKeyProvider : IDeviceKeyProvider
{
    private const string KeyName = "DEMO-PRODUCT.DeviceKey.P256.v1";
    private static readonly CngKeyConfiguration[] Configurations =
    [
        CreateConfiguration(new CngProvider("Microsoft Platform Crypto Provider")),
        CreateConfiguration(CngProvider.MicrosoftSoftwareKeyStorageProvider),
    ];

    private readonly ICngKeyBackend backend;

    internal CngDeviceKeyProvider()
        : this(new WindowsCngKeyBackend())
    {
    }

    internal CngDeviceKeyProvider(ICngKeyBackend backend)
    {
        this.backend = backend ?? throw new ArgumentNullException(nameof(backend));
    }

    public byte[] GetOrCreatePublicKeySha256()
    {
        try
        {
            return HashPublicKey(Configurations[0]);
        }
        catch (CngProviderUnavailableException)
        {
            // Only an explicitly unavailable Platform provider permits the software fallback.
        }
        catch (CryptographicException)
        {
            throw DeviceKeyUnavailable();
        }
        catch (UnauthorizedAccessException)
        {
            throw DeviceKeyUnavailable();
        }
        catch (PlatformNotSupportedException)
        {
            throw DeviceKeyUnavailable();
        }

        try
        {
            return HashPublicKey(Configurations[1]);
        }
        catch (CryptographicException)
        {
            throw DeviceKeyUnavailable();
        }
        catch (UnauthorizedAccessException)
        {
            throw DeviceKeyUnavailable();
        }
        catch (PlatformNotSupportedException)
        {
            throw DeviceKeyUnavailable();
        }
    }

    private byte[] HashPublicKey(CngKeyConfiguration configuration)
    {
        byte[]? publicKeyBlob = null;
        try
        {
            publicKeyBlob = backend.GetOrCreatePublicKeyBlob(configuration);
            if (publicKeyBlob is null || publicKeyBlob.Length == 0)
            {
                throw new CryptographicException("Device public key is unavailable.");
            }

            return SHA256.HashData(publicKeyBlob);
        }
        finally
        {
            if (publicKeyBlob is not null)
            {
                CryptographicOperations.ZeroMemory(publicKeyBlob);
            }
        }
    }

    private static CryptographicException DeviceKeyUnavailable()
    {
        return new CryptographicException("Device key is unavailable.");
    }

    private static CngKeyConfiguration CreateConfiguration(CngProvider provider)
    {
        return new CngKeyConfiguration(
            KeyName,
            provider,
            CngAlgorithm.ECDsaP256,
            CngKeyCreationOptions.None,
            CngKeyOpenOptions.None,
            CngExportPolicies.None,
            CngKeyUsages.Signing);
    }
}

internal sealed class WindowsCngKeyBackend : ICngKeyBackend
{
    private readonly ICngKeyOperations operations;

    internal WindowsCngKeyBackend()
        : this(new WindowsCngKeyOperations())
    {
    }

    internal WindowsCngKeyBackend(ICngKeyOperations operations)
    {
        this.operations = operations ?? throw new ArgumentNullException(nameof(operations));
    }

    public byte[] GetOrCreatePublicKeyBlob(CngKeyConfiguration configuration)
    {
        CngPublicKeyMaterial material;
        try
        {
            material = operations.Open(configuration);
        }
        catch (CngKeyNotFoundException)
        {
            try
            {
                material = operations.Create(configuration);
            }
            catch (CngKeyAlreadyExistsException)
            {
                material = operations.Open(configuration);
            }
        }

        if (!MatchesExpectedAlgorithm(material, configuration)
            || material.ExportPolicy != configuration.ExportPolicy
            || (material.KeyUsage & configuration.KeyUsage) != configuration.KeyUsage
            || material.PublicKeyBlob.Length == 0)
        {
            throw new CryptographicException("Device key configuration is invalid.");
        }

        return material.PublicKeyBlob;
    }

    private static bool MatchesExpectedAlgorithm(
        CngPublicKeyMaterial material,
        CngKeyConfiguration configuration)
    {
        if (material.Algorithm.Equals(configuration.Algorithm))
        {
            return true;
        }

        const uint ecdsaPublicP256Magic = 0x31534345;
        const int p256CoordinateBytes = 32;
        var blob = material.PublicKeyBlob;
        return configuration.Algorithm.Equals(CngAlgorithm.ECDsaP256)
            && string.Equals(material.Algorithm.Algorithm, "ECDSA", StringComparison.Ordinal)
            && blob.Length == 8 + (2 * p256CoordinateBytes)
            && BinaryPrimitives.ReadUInt32LittleEndian(blob) == ecdsaPublicP256Magic
            && BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(4)) == p256CoordinateBytes;
    }
}

internal sealed class WindowsCngKeyOperations : ICngKeyOperations
{
    public CngPublicKeyMaterial Open(CngKeyConfiguration configuration)
    {
        try
        {
            using var key = CngKey.Open(
                configuration.KeyName,
                configuration.Provider,
                configuration.OpenOptions);
            return ReadMaterial(key);
        }
        catch (CryptographicException exception) when (CngErrorClassifier.IsProviderUnavailable(exception))
        {
            throw new CngProviderUnavailableException("CNG provider is unavailable.");
        }
        catch (CryptographicException exception) when (CngErrorClassifier.IsKeyNotFound(exception))
        {
            throw new CngKeyNotFoundException();
        }
    }

    public CngPublicKeyMaterial Create(CngKeyConfiguration configuration)
    {
        var creationParameters = new CngKeyCreationParameters
        {
            Provider = configuration.Provider,
            ExportPolicy = configuration.ExportPolicy,
            KeyCreationOptions = configuration.CreationOptions,
            KeyUsage = configuration.KeyUsage,
        };

        try
        {
            using var key = CngKey.Create(
                configuration.Algorithm,
                configuration.KeyName,
                creationParameters);
            return ReadMaterial(key);
        }
        catch (CryptographicException exception) when (CngErrorClassifier.IsProviderUnavailable(exception))
        {
            throw new CngProviderUnavailableException("CNG provider is unavailable.");
        }
        catch (CryptographicException exception) when (CngErrorClassifier.IsKeyAlreadyExists(exception))
        {
            throw new CngKeyAlreadyExistsException();
        }
    }

    private static CngPublicKeyMaterial ReadMaterial(CngKey key)
    {
        return new CngPublicKeyMaterial(
            key.Export(CngKeyBlobFormat.EccPublicBlob),
            key.Algorithm,
            key.ExportPolicy,
            key.KeyUsage);
    }
}
