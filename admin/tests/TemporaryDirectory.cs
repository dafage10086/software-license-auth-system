namespace SoftwareLicenseAuth.Admin.Tests;

internal sealed class TemporaryDirectory : IDisposable
{
    internal TemporaryDirectory()
    {
        Path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "SoftwareLicenseAuth.Admin.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    private string Path { get; }

    internal string GetPath(string fileName)
    {
        return System.IO.Path.Combine(Path, fileName);
    }

    internal string WriteFile(string fileName, string contents)
    {
        var path = GetPath(fileName);
        File.WriteAllText(path, contents);
        return path;
    }

    public void Dispose()
    {
        Directory.Delete(Path, recursive: true);
    }
}
