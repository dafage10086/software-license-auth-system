using System.Drawing;
using System.Security.Cryptography;
using SoftwareLicenseAuth.Client;

namespace SoftwareLicenseAuth.Demo;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new DemoForm());
    }
}

internal sealed class DemoForm : Form
{
    private readonly Button activateButton = new();
    private readonly TextBox licenseKeyText = new();
    private readonly Button loginButton = new();
    private readonly Button logoutButton = new();
    private readonly TextBox passwordText = new();
    private readonly Button refreshButton = new();
    private readonly TextBox resultText = new();
    private readonly Label statusLabel = new();
    private readonly TextBox usernameText = new();
    private LicenseAuthClient? client;

    internal DemoForm()
    {
        Text = "Software License Auth - Demo";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        ClientSize = new Size(720, 430);
        Font = new Font("Segoe UI", 9F);

        Controls.Add(LabelAt("Username", 24, 27, 90));
        PlaceTextBox(usernameText, 120, 22, 260);
        Controls.Add(LabelAt("Password", 24, 69, 90));
        PlaceTextBox(passwordText, 120, 64, 260);
        passwordText.UseSystemPasswordChar = true;
        Controls.Add(LabelAt("License key", 24, 111, 90));
        PlaceTextBox(licenseKeyText, 120, 106, 420);

        ConfigureButton(loginButton, "Login", 410, 21, LoginButton_Click);
        ConfigureButton(activateButton, "Activate", 550, 105, ActivateButton_Click);
        ConfigureButton(refreshButton, "Refresh", 410, 63, RefreshButton_Click);
        ConfigureButton(logoutButton, "Logout", 550, 63, LogoutButton_Click);

        resultText.SetBounds(24, 166, 672, 190);
        resultText.Multiline = true;
        resultText.ReadOnly = true;
        resultText.ScrollBars = ScrollBars.Vertical;
        resultText.Font = new Font("Consolas", 9F);
        Controls.Add(resultText);

        statusLabel.SetBounds(24, 374, 672, 32);
        statusLabel.ForeColor = Color.FromArgb(40, 90, 55);
        Controls.Add(statusLabel);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            client?.Dispose();
        }

        base.Dispose(disposing);
    }

    private async void LoginButton_Click(object? sender, EventArgs e)
    {
        await RunAuthorizationAsync(() => GetClient().LoginAsync(
            usernameText.Text,
            passwordText.Text));
    }

    private async void ActivateButton_Click(object? sender, EventArgs e)
    {
        await RunAuthorizationAsync(() => GetClient().ActivateAsync(licenseKeyText.Text));
    }

    private async void RefreshButton_Click(object? sender, EventArgs e)
    {
        await RunAuthorizationAsync(() => GetClient().RefreshAsync());
    }

    private async void LogoutButton_Click(object? sender, EventArgs e)
    {
        await RunCommandAsync(async () =>
        {
            await GetClient().LogoutAsync();
            resultText.Clear();
            statusLabel.Text = "SIGNED OUT";
        });
    }

    private async Task RunAuthorizationAsync(Func<Task<LicenseAuthorization>> operation)
    {
        await RunCommandAsync(async () =>
        {
            var authorization = await operation();
            resultText.Text = string.Join(
                Environment.NewLine,
                $"State: {authorization.State}",
                $"Plan: {authorization.Plan ?? "-"}",
                $"Machine: {authorization.MachineId}",
                $"Lease expires: {authorization.ExpiresAt:O}");
            statusLabel.Text = authorization.State;
        });
    }

    private async Task RunCommandAsync(Func<Task> operation)
    {
        SetActionsEnabled(false);
        statusLabel.Text = "WORKING";
        try
        {
            await operation();
        }
        catch (ArgumentException)
        {
            statusLabel.Text = "INVALID INPUT";
        }
        catch (OperationCanceledException)
        {
            statusLabel.Text = "CANCELED";
        }
        catch (LicenseAuthException error)
        {
            statusLabel.Text = error.Message;
        }
        catch
        {
            statusLabel.Text = "License authorization failed.";
        }
        finally
        {
            passwordText.Clear();
            SetActionsEnabled(true);
        }
    }

    private LicenseAuthClient GetClient()
    {
        return client ??= new LicenseAuthClient(ComputeManifestSha256());
    }

    private static string ComputeManifestSha256()
    {
        using var stream = File.OpenRead(Application.ExecutablePath);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private void SetActionsEnabled(bool enabled)
    {
        loginButton.Enabled = enabled;
        activateButton.Enabled = enabled;
        refreshButton.Enabled = enabled;
        logoutButton.Enabled = enabled;
    }

    private void ConfigureButton(
        Button button,
        string text,
        int left,
        int top,
        EventHandler handler)
    {
        button.SetBounds(left, top, 120, 32);
        button.Text = text;
        button.Click += handler;
        Controls.Add(button);
    }

    private static Label LabelAt(string text, int left, int top, int width)
    {
        return new Label
        {
            AutoSize = false,
            Text = text,
            TextAlign = ContentAlignment.MiddleLeft,
            Bounds = new Rectangle(left, top, width, 24)
        };
    }

    private void PlaceTextBox(TextBox textBox, int left, int top, int width)
    {
        textBox.SetBounds(left, top, width, 28);
        Controls.Add(textBox);
    }
}
