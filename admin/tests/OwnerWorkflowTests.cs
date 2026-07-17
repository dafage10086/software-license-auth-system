using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Xunit;

namespace SoftwareLicenseAuth.Admin.Tests;

public sealed class OwnerWorkflowTests
{
    private const string StrongPassword = "Abcdefghijk123456789_-XY";
    private const string ResetPassword = "ResetPassword567890_-AbCdE";
    private const string SensitiveCustomer = "customer-private-payload";
    private const string SensitiveToken = "admin-token-must-not-leak";

    private static readonly string ProgramSourcePath = Path.GetFullPath(
        Path.Combine(
            AppContext.BaseDirectory,
            "..",
            "..",
            "..",
            "..",
            "src",
            "Program.cs"));

    [Fact]
    public void ProgramSource_DoesNotContainLegacyOfflineCardGeneration()
    {
        var source = File.ReadAllText(ProgramSourcePath);
        var forbiddenMarkers = new[]
        {
            "HMACSHA256",
            "SecretBase64",
            "QL21",
            "ComputeMachineCode",
            "SignText",
            "TryGenerate",
            "生成卡密",
            "机器码应为 16 位"
        };

        foreach (var marker in forbiddenMarkers)
        {
            Assert.False(
                source.Contains(marker, StringComparison.Ordinal),
                $"Program.cs still contains forbidden legacy marker '{marker}'.");
        }
    }

    [Fact]
    public void ProgramReflection_DoesNotExposeLegacyGeneratorsOrSharedSecretFields()
    {
        var methods = typeof(Program)
            .GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            .Select(method => method.Name)
            .ToArray();
        var fields = typeof(Program)
            .GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            .Select(field => field.Name)
            .ToArray();

        Assert.DoesNotContain("ComputeMachineCode", methods);
        Assert.DoesNotContain("SignText", methods);
        Assert.DoesNotContain("TryGenerate", methods);
        Assert.DoesNotContain(
            fields,
            name => name.Contains("secret", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task LegacyMachineCommand_IsRejectedWithoutReturningMachineCode()
    {
        var originalOut = Console.Out;
        var originalError = Console.Error;
        using var output = new StringWriter();
        using var error = new StringWriter();

        try
        {
            Console.SetOut(output);
            Console.SetError(error);

            var exitCode = await InvokeProgramMainAsync(["machine"]);

            Assert.NotEqual(0, exitCode);
            Assert.False(
                Regex.IsMatch(output.ToString().Trim(), "^[A-F0-9]{16}$"),
                "The removed machine-code command still returned a legacy machine code.");
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }
    }

    [Fact]
    public void GeneratePassword_ReturnsHighEntropyBase64UrlValues()
    {
        var generated = Enumerable.Range(0, 64)
            .Select(_ => OwnerPasswordGenerator.Generate())
            .ToArray();

        Assert.Equal(generated.Length, generated.Distinct(StringComparer.Ordinal).Count());
        Assert.All(generated, password =>
        {
            Assert.True(password.Length >= 20);
            Assert.Matches("^[A-Za-z0-9_-]+$", password);
        });
    }

    [Fact]
    public async Task CreateAccount_ExistingUserNeverDisplaysCandidatePassword()
    {
        var admin = new FakeAdminOperations();
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.CreateAccountAsync(" Customer.One ", SensitiveCustomer);

        Assert.True(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(
            ["find:customer.one", "trial:user-123"],
            admin.Calls);
        Assert.Equal(StrongPassword, admin.LastPassword);
        Assert.Equal(SensitiveCustomer, admin.LastCustomer);
        Assert.Contains("customer.one", result.Output, StringComparison.Ordinal);
        Assert.Contains("user-123", result.Output, StringComparison.Ordinal);
        Assert.Contains("TRIAL", result.Output, StringComparison.Ordinal);
        Assert.Contains("账号已存在", result.Output, StringComparison.Ordinal);
        Assert.Equal(0, Count(result.Output, StrongPassword));
    }

    [Fact]
    public async Task CreateAccount_CreatedUserDisplaysInitialPasswordExactlyOnce()
    {
        var admin = new FakeAdminOperations { WasCreated = true };
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);

        Assert.True(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(
            ["find:customer.one", "trial:user-123"],
            admin.Calls);
        Assert.Contains("账号创建成功", result.Output, StringComparison.Ordinal);
        Assert.Equal(1, Count(result.Output, StrongPassword));
    }

    [Fact]
    public async Task CreateAccount_BlankCustomerIsRejectedBeforeAdminCall()
    {
        var admin = new FakeAdminOperations();
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.CreateAccountAsync("customer.one", "   ");

        Assert.False(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Null(workflow.SelectedUser);
        Assert.Empty(admin.Calls);
        Assert.DoesNotContain(StrongPassword, result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAccount_CreatedThenTrialFailsReturnsSanitizedPartialSuccessWithPassword()
    {
        var admin = FailingAdmin(wasCreated: true, failureAt: "trial");
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);

        Assert.False(result.Succeeded);
        Assert.True(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(
            ["find:customer.one", "trial:user-123"],
            admin.Calls);
        Assert.Contains("部分成功", result.Output, StringComparison.Ordinal);
        Assert.Contains("试用授权失败", result.Output, StringComparison.Ordinal);
        Assert.Equal(1, Count(result.Output, StrongPassword));
        AssertSanitized(result.Output);
    }

    [Fact]
    public async Task CreateAccount_ExistingThenTrialFailsRetainsSelectionForIssueAndReset()
    {
        var admin = FailingAdmin(wasCreated: false, failureAt: "trial");
        var workflow = CreateWorkflow(admin, StrongPassword, ResetPassword);

        var result = await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);

        Assert.False(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(0, Count(result.Output, StrongPassword));
        AssertSanitized(result.Output);

        var issue = await workflow.IssueSelectedLicenseAsync("year");
        var reset = await workflow.ResetSelectedPasswordAsync();

        Assert.True(issue.Succeeded);
        Assert.True(reset.Succeeded);
        Assert.Equal(
            [
                "find:customer.one",
                "trial:user-123",
                "issue:user-123:YEAR",
                "reset:user-123"
            ],
            admin.Calls);
    }

    [Fact]
    public async Task SelectedAccount_IsRequiredForGuiIssueAndReset()
    {
        var admin = new FakeAdminOperations();
        var workflow = CreateWorkflow(admin, StrongPassword, ResetPassword);

        var issue = await workflow.IssueSelectedLicenseAsync("year");
        var reset = await workflow.ResetSelectedPasswordAsync();

        Assert.False(issue.Succeeded);
        Assert.False(reset.Succeeded);
        Assert.Empty(admin.Calls);
        Assert.DoesNotContain(StrongPassword, issue.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(ResetPassword, reset.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SelectedAccount_IssueAndResetReuseSuccessfulSelectionWithoutCreatingAnotherUser()
    {
        var admin = new FakeAdminOperations();
        var workflow = CreateWorkflow(admin, StrongPassword, ResetPassword);
        await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);
        admin.Calls.Clear();

        var issue = await workflow.IssueSelectedLicenseAsync("forever");
        var reset = await workflow.ResetSelectedPasswordAsync();

        Assert.True(issue.Succeeded);
        Assert.True(reset.Succeeded);
        Assert.Equal(
            ["issue:user-123:FOREVER", "reset:user-123"],
            admin.Calls);
        Assert.Equal(ResetPassword, admin.LastPassword);
        Assert.Contains(admin.PaidLicense.Key, issue.Output, StringComparison.Ordinal);
        Assert.Contains("FOREVER", issue.Output, StringComparison.Ordinal);
        Assert.Contains("288", issue.Output, StringComparison.Ordinal);
        Assert.Contains("永久", issue.Output, StringComparison.Ordinal);
        Assert.Equal(1, Count(reset.Output, ResetPassword));
    }

    [Fact]
    public async Task LicenseContract_UnactivatedYearShowsFirstActivationTermNotForever()
    {
        var admin = new FakeAdminOperations { PaidLicenseIsUnactivated = true };
        var workflow = CreateWorkflow(admin, StrongPassword);
        await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);

        var result = await workflow.IssueSelectedLicenseAsync("year");

        Assert.True(result.Succeeded);
        Assert.Contains("365", result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("永久", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CliLicenseIssue_ExistingUserNeverDisplaysCandidatePassword()
    {
        var admin = new FakeAdminOperations();
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.IssueLicenseForCliAsync("customer.one", "year");

        Assert.True(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Equal(
            ["find:customer.one", "issue:user-123:YEAR"],
            admin.Calls);
        Assert.Equal(StrongPassword, admin.LastPassword);
        Assert.Contains(admin.PaidLicense.Key, result.Output, StringComparison.Ordinal);
        Assert.Contains("YEAR", result.Output, StringComparison.Ordinal);
        Assert.Contains("128", result.Output, StringComparison.Ordinal);
        Assert.Contains("2031-02-03", result.Output, StringComparison.Ordinal);
        Assert.Equal(0, Count(result.Output, StrongPassword));
    }

    [Fact]
    public async Task CliLicenseIssue_CreatedUserEnsuresTrialAndDisplaysInitialPasswordOnce()
    {
        var admin = new FakeAdminOperations { WasCreated = true };
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.IssueLicenseForCliAsync("customer.one", "year");

        Assert.True(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(
            ["find:customer.one", "trial:user-123", "issue:user-123:YEAR"],
            admin.Calls);
        Assert.Equal(1, Count(result.Output, StrongPassword));
    }

    [Fact]
    public async Task CliLicenseIssue_CreatedThenTrialFailsReturnsPartialWithoutIssuingPaid()
    {
        var admin = FailingAdmin(wasCreated: true, failureAt: "trial");
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.IssueLicenseForCliAsync("customer.one", "year");

        Assert.False(result.Succeeded);
        Assert.True(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(
            ["find:customer.one", "trial:user-123"],
            admin.Calls);
        Assert.Contains("试用授权失败", result.Output, StringComparison.Ordinal);
        Assert.Equal(1, Count(result.Output, StrongPassword));
        AssertSanitized(result.Output);
    }

    [Fact]
    public async Task CliLicenseIssue_CreatedThenPaidIssueFailsReturnsPartialWithPassword()
    {
        var admin = FailingAdmin(wasCreated: true, failureAt: "issue");
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.IssueLicenseForCliAsync("customer.one", "year");

        Assert.False(result.Succeeded);
        Assert.True(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(
            ["find:customer.one", "trial:user-123", "issue:user-123:YEAR"],
            admin.Calls);
        Assert.Contains("付费授权失败", result.Output, StringComparison.Ordinal);
        Assert.Equal(1, Count(result.Output, StrongPassword));
        AssertSanitized(result.Output);
    }

    [Fact]
    public async Task CliLicenseIssue_ExistingThenPaidIssueFailsDoesNotDisplayCandidatePassword()
    {
        var admin = FailingAdmin(wasCreated: false, failureAt: "issue");
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.IssueLicenseForCliAsync("customer.one", "year");

        Assert.False(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(0, Count(result.Output, StrongPassword));
        AssertSanitized(result.Output);
    }

    [Fact]
    public async Task CliPasswordReset_GeneratesLocallyThenFindsAndResetsTheAccount()
    {
        var admin = new FakeAdminOperations();
        var workflow = CreateWorkflow(admin, ResetPassword);

        var result = await workflow.ResetPasswordForCliAsync("customer.one");

        Assert.True(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Equal(
            ["find:customer.one", "reset:user-123"],
            admin.Calls);
        Assert.Equal(ResetPassword, admin.LastPassword);
        Assert.Equal(1, Count(result.Output, ResetPassword));
    }

    [Fact]
    public async Task CliPasswordReset_CreatedUserDisplaysFinalPasswordOnceAfterResetSucceeds()
    {
        var admin = new FakeAdminOperations { WasCreated = true };
        var workflow = CreateWorkflow(admin, ResetPassword);

        var result = await workflow.ResetPasswordForCliAsync("customer.one");

        Assert.True(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(
            ["find:customer.one", "reset:user-123"],
            admin.Calls);
        Assert.Equal(1, Count(result.Output, ResetPassword));
    }

    [Fact]
    public async Task CliPasswordReset_CreatedThenResetFailsReturnsPartialWithValidInitialPassword()
    {
        var admin = FailingAdmin(wasCreated: true, failureAt: "reset");
        var workflow = CreateWorkflow(admin, ResetPassword);

        var result = await workflow.ResetPasswordForCliAsync("customer.one");

        Assert.False(result.Succeeded);
        Assert.True(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(
            ["find:customer.one", "reset:user-123"],
            admin.Calls);
        Assert.Contains("密码重置失败", result.Output, StringComparison.Ordinal);
        Assert.Equal(1, Count(result.Output, ResetPassword));
        AssertSanitized(result.Output);
    }

    [Fact]
    public async Task CliPasswordReset_ExistingThenResetFailsDoesNotDisplayCandidatePassword()
    {
        var admin = FailingAdmin(wasCreated: false, failureAt: "reset");
        var workflow = CreateWorkflow(admin, ResetPassword);

        var result = await workflow.ResetPasswordForCliAsync("customer.one");

        Assert.False(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.Equal(admin.User, workflow.SelectedUser);
        Assert.Equal(0, Count(result.Output, ResetPassword));
        AssertSanitized(result.Output);
    }

    [Theory]
    [InlineData("account", "trial")]
    [InlineData("issue", "issue")]
    [InlineData("reset", "reset")]
    public async Task CommitStateUnknown_WorkflowsNeverReturnCandidatePassword(
        string operation,
        string failureAt)
    {
        var admin = new FakeAdminOperations
        {
            WasCreated = true,
            FailureAt = failureAt,
            Failure = KeygenAdminException.UnknownCommit()
        };
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = operation switch
        {
            "account" => await workflow.CreateAccountAsync(
                "customer.one",
                SensitiveCustomer),
            "issue" => await workflow.IssueLicenseForCliAsync(
                "customer.one",
                "year"),
            _ => await workflow.ResetPasswordForCliAsync("customer.one")
        };

        Assert.False(result.Succeeded);
        Assert.False(result.IsPartialSuccess);
        Assert.True(result.IsCommitStateUnknown);
        Assert.Contains("CommitStateUnknown", result.Output, StringComparison.Ordinal);
        Assert.Equal(0, Count(result.Output, StrongPassword));
    }

    [Fact]
    public async Task CommitStateUnknown_SelectedPasswordResetNeverReturnsNewPassword()
    {
        var admin = new FakeAdminOperations
        {
            FailureAt = "reset",
            Failure = KeygenAdminException.UnknownCommit()
        };
        var workflow = CreateWorkflow(admin, StrongPassword, ResetPassword);
        await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);

        var result = await workflow.ResetSelectedPasswordAsync();

        Assert.True(result.IsCommitStateUnknown);
        Assert.Equal(0, Count(result.Output, ResetPassword));
    }

    [Fact]
    public async Task CommitStateUnknown_CliReturnsExitFourWithoutPassword()
    {
        var admin = new FakeAdminOperations
        {
            WasCreated = true,
            FailureAt = "reset",
            Failure = KeygenAdminException.UnknownCommit()
        };
        var cli = CreateCli(admin, [], ResetPassword);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await cli.RunAsync(
            ["password-reset", "customer.one"],
            output,
            error);

        Assert.Equal(4, exitCode);
        Assert.Contains("CommitStateUnknown", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, Count(output.ToString(), ResetPassword));
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task WorkflowDeadline_ExistingLookupAndPaidShareOneBudget()
    {
        var admin = new DeadlineAdminOperations(
            wasCreated: false,
            phaseDelay: TimeSpan.FromMilliseconds(180));
        var workflow = CreateWorkflowWithTimeout(
            admin,
            TimeSpan.FromMilliseconds(300),
            StrongPassword);

        var result = await workflow.IssueLicenseForCliAsync(
            "customer.one",
            "year");

        Assert.False(result.Succeeded);
        Assert.True(result.IsCommitStateUnknown);
        Assert.Equal(["find", "issue"], admin.Calls);
        Assert.Equal(["find"], admin.CompletedCalls);
        Assert.All(
            admin.Tokens,
            token => Assert.Equal(admin.Tokens[0], token));
        Assert.Equal(0, Count(result.Output, StrongPassword));
    }

    [Fact]
    public async Task WorkflowDeadline_NewUserLookupTrialAndPaidShareOneBudget()
    {
        var admin = new DeadlineAdminOperations(
            wasCreated: true,
            phaseDelay: TimeSpan.FromMilliseconds(110));
        var workflow = CreateWorkflowWithTimeout(
            admin,
            TimeSpan.FromMilliseconds(300),
            StrongPassword);

        var result = await workflow.IssueLicenseForCliAsync(
            "customer.one",
            "year");

        Assert.False(result.Succeeded);
        Assert.True(result.IsCommitStateUnknown);
        Assert.Equal(["find", "trial", "issue"], admin.Calls);
        Assert.Equal(["find", "trial"], admin.CompletedCalls);
        Assert.All(
            admin.Tokens,
            token => Assert.Equal(admin.Tokens[0], token));
        Assert.Equal(0, Count(result.Output, StrongPassword));
    }

    [Fact]
    public void CommitStateUnknown_GuiClearsInitialPasswordControl()
    {
        using var form = new OwnerAdminForm(CreateRuntime(), () => StrongPassword);
        var passwordField = typeof(OwnerAdminForm).GetField(
            "_initialPasswordText",
            BindingFlags.Instance | BindingFlags.NonPublic);
        var showResult = typeof(OwnerAdminForm).GetMethod(
            "ShowResult",
            BindingFlags.Instance | BindingFlags.NonPublic);
        var passwordText = Assert.IsType<TextBox>(passwordField?.GetValue(form));
        Assert.NotNull(showResult);
        passwordText.Text = StrongPassword;

        showResult.Invoke(
            form,
            [OwnerOperationResult.CommitStateUnknown("CommitStateUnknown: verify remotely.")]);

        Assert.Equal(string.Empty, passwordText.Text);
    }

    [Fact]
    public void AdminForm_PasswordVisibilityToggleKeepsGeneratedPasswordReadOnly()
    {
        Exception? failure = null;
        var firstText = string.Empty;
        var secondText = string.Empty;
        var firstButtonText = string.Empty;
        var secondButtonText = string.Empty;
        var firstUsesPasswordChar = true;
        var secondUsesPasswordChar = false;
        var remainedReadOnly = false;
        var thread = new Thread(() =>
        {
            try
            {
                using var form = new OwnerAdminForm(
                    CreateRuntime(),
                    () => StrongPassword,
                    new FakeClipboard());
                var passwordText = GetPrivateField<TextBox>(form, "_initialPasswordText");
                var toggle = form.Controls.OfType<Button>()
                    .Single(button => button.Text == "显示密码");
                form.Show();
                Application.DoEvents();
                passwordText.Text = StrongPassword;

                Click(toggle);
                Application.DoEvents();
                firstText = passwordText.Text;
                firstButtonText = toggle.Text;
                firstUsesPasswordChar = passwordText.UseSystemPasswordChar;

                Click(toggle);
                Application.DoEvents();
                secondText = passwordText.Text;
                secondButtonText = toggle.Text;
                secondUsesPasswordChar = passwordText.UseSystemPasswordChar;
                remainedReadOnly = passwordText.ReadOnly;
            }
            catch (Exception error)
            {
                failure = error;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        Assert.True(thread.Join(TimeSpan.FromSeconds(10)));
        Assert.Null(failure);
        Assert.True(remainedReadOnly);
        Assert.False(firstUsesPasswordChar);
        Assert.Equal(StrongPassword, firstText);
        Assert.Equal("隐藏密码", firstButtonText);
        Assert.True(secondUsesPasswordChar);
        Assert.Equal(StrongPassword, secondText);
        Assert.Equal("显示密码", secondButtonText);
    }

    [Fact]
    public void AdminForm_CopyPasswordUsesInjectedClipboardWithoutMutatingPassword()
    {
        var clipboard = new FakeClipboard();
        using var form = new OwnerAdminForm(
            CreateRuntime(),
            () => StrongPassword,
            clipboard);
        var passwordText = GetPrivateField<TextBox>(form, "_initialPasswordText");
        var copy = form.Controls.OfType<Button>()
            .Single(button => button.Text == "复制密码");
        passwordText.Text = StrongPassword;

        Click(copy);

        Assert.Equal([StrongPassword], clipboard.CopiedValues);
        Assert.Equal(StrongPassword, passwordText.Text);
        Assert.True(passwordText.ReadOnly);
    }

    [Fact]
    public void AdminForm_ResultTextHasAccessibleName()
    {
        using var form = new OwnerAdminForm(
            CreateRuntime(),
            () => StrongPassword,
            new FakeClipboard());
        var resultText = GetPrivateField<TextBox>(form, "_resultText");

        Assert.Equal("操作结果：", resultText.AccessibleName);
    }

    [Fact]
    public void WindowsOwnerClipboard_UsesBoundedFrameworkRetry()
    {
        object? copiedValue = null;
        var copy = false;
        var retryTimes = 0;
        var retryDelay = 0;
        var calls = 0;
        var clipboard = new WindowsOwnerClipboard(
            (value, persistAfterExit, retries, delay) =>
            {
                calls++;
                copiedValue = value;
                copy = persistAfterExit;
                retryTimes = retries;
                retryDelay = delay;
            });

        clipboard.SetText(StrongPassword);

        Assert.Equal(1, calls);
        Assert.Equal(StrongPassword, copiedValue);
        Assert.True(copy);
        Assert.Equal(50, retryTimes);
        Assert.Equal(100, retryDelay);
    }

    [Fact]
    public void ApplicationEntryPoint_IsStaForWindowsClipboard()
    {
        var entryPoint = typeof(OwnerAdminForm).Assembly.EntryPoint;

        Assert.NotNull(entryPoint);
        Assert.Contains(
            entryPoint.GetCustomAttributesData(),
            attribute => attribute.AttributeType == typeof(STAThreadAttribute));
    }

    [Theory]
    [InlineData(true, "管理员令牌状态：已安全保存")]
    [InlineData(false, "管理员令牌状态：尚未配置")]
    public void AdminForm_ShowsSavedTokenStatusWithoutRefillingToken(
        bool hasSavedToken,
        string expectedStatus)
    {
        using var form = new OwnerAdminForm(
            CreateRuntime(hasSavedToken),
            () => StrongPassword,
            new FakeClipboard());
        var tokenText = GetPrivateField<TextBox>(form, "_tokenText");
        var tokenState = GetPrivateField<Label>(form, "_tokenStateLabel");

        Assert.Equal(string.Empty, tokenText.Text);
        Assert.Equal(expectedStatus, tokenState.Text);
        Assert.DoesNotContain(SensitiveToken, tokenState.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void AdminForm_BlankTokenSaveIsRejectedWithoutCallingSaverOrLosingSavedStatus()
    {
        var savedTokens = new List<string>();
        using var form = new OwnerAdminForm(
            CreateRuntime(hasSavedToken: true, savedTokens.Add),
            () => StrongPassword,
            new FakeClipboard());
        var tokenText = GetPrivateField<TextBox>(form, "_tokenText");
        var tokenState = GetPrivateField<Label>(form, "_tokenStateLabel");
        var status = GetPrivateField<Label>(form, "_statusLabel");
        var save = form.Controls.OfType<Button>()
            .Single(button => button.Text == "保存令牌");
        tokenText.Text = "   \t";

        Click(save);

        Assert.Empty(savedTokens);
        Assert.Equal("管理员令牌状态：已安全保存", tokenState.Text);
        Assert.Contains("不能为空", status.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RevokeMachine_ReturnsOnlyFixedSuccessText()
    {
        var admin = new FakeAdminOperations();
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.RevokeMachineAsync("machine-123");

        Assert.True(result.Succeeded);
        Assert.Equal(["revoke:machine-123"], admin.Calls);
        Assert.Equal("机器解绑成功。", result.Output);
        Assert.DoesNotContain("machine-123", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task QueryMachines_RequiresPreviouslySelectedAccount()
    {
        var admin = new FakeAdminOperations
        {
            MachineIds = ["machine-1"]
        };
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.QuerySelectedMachinesAsync();

        Assert.False(result.Succeeded);
        Assert.Equal(OwnerWorkflow.MachineQueryFailure, result.Output);
        Assert.DoesNotContain(admin.Calls, call => call.StartsWith("machines:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task QueryMachines_SingleMachineReturnsIdForAutoFill()
    {
        var admin = new FakeAdminOperations
        {
            MachineIds = ["machine-1"]
        };
        var workflow = CreateWorkflow(admin, StrongPassword);
        _ = await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);

        var result = await workflow.QuerySelectedMachinesAsync();

        Assert.True(result.Succeeded);
        Assert.Equal("machine-1", result.MachineIdToFill);
        Assert.Equal(1, Count(result.Output, "machine-1"));
        Assert.Contains("machines:user-123", admin.Calls);
    }

    [Fact]
    public async Task QueryMachines_MultipleMachinesListsIdsWithoutAutoFillOrFingerprint()
    {
        var admin = new FakeAdminOperations
        {
            MachineIds = ["machine-2", "machine-1"]
        };
        var workflow = CreateWorkflow(admin, StrongPassword);
        _ = await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);

        var result = await workflow.QuerySelectedMachinesAsync();

        Assert.True(result.Succeeded);
        Assert.Null(result.MachineIdToFill);
        Assert.Contains("machine-1", result.Output, StringComparison.Ordinal);
        Assert.Contains("machine-2", result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("fingerprint", result.Output, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("machine-1,machine-2")]
    [InlineData("machine-1 machine-2")]
    [InlineData("machine-1\nmachine-2")]
    public async Task RevokeMachine_RejectsCombinedIdsBeforeAdminCall(string machineIds)
    {
        var admin = new FakeAdminOperations();
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.RevokeMachineAsync(machineIds);

        Assert.False(result.Succeeded);
        Assert.Equal(OwnerWorkflow.RevokeFailure, result.Output);
        Assert.DoesNotContain(admin.Calls, call => call.StartsWith("revoke:", StringComparison.Ordinal));
    }

    [Fact]
    public void AdminForm_MachineQueryResultAutoFillsOnlySingleMachine()
    {
        using var form = new OwnerAdminForm(
            CreateRuntime(),
            () => StrongPassword,
            new FakeClipboard());
        var machineText = GetPrivateField<TextBox>(form, "_machineText");
        var showQueryResult = typeof(OwnerAdminForm).GetMethod(
            "ShowMachineQueryResult",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(showQueryResult);

        showQueryResult.Invoke(
            form,
            [OwnerOperationResult.Success("机器 ID: machine-1", "machine-1")]);
        Assert.Equal("machine-1", machineText.Text);

        showQueryResult.Invoke(
            form,
            [OwnerOperationResult.Success("machine-1\nmachine-2")]);
        Assert.Equal(string.Empty, machineText.Text);
    }

    [Theory]
    [InlineData("account")]
    [InlineData("issue")]
    [InlineData("reset")]
    [InlineData("revoke")]
    public async Task WorkflowFailures_ReturnOnlyFixedSanitizedChineseMessage(string operation)
    {
        var admin = new FakeAdminOperations
        {
            Failure = new InvalidOperationException(
                $"upstream={SensitiveCustomer}; password={StrongPassword}; token={SensitiveToken}")
        };
        var workflow = CreateWorkflow(admin, StrongPassword);

        OwnerOperationResult result;
        switch (operation)
        {
            case "account":
                result = await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);
                break;
            case "issue":
                result = await workflow.IssueLicenseForCliAsync("customer.one", "year");
                break;
            case "reset":
                result = await workflow.ResetPasswordForCliAsync("customer.one");
                break;
            default:
                result = await workflow.RevokeMachineAsync("machine-123");
                break;
        }

        Assert.False(result.Succeeded);
        Assert.StartsWith(ExpectedFailurePrefix(operation), result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(SensitiveCustomer, result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(StrongPassword, result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(SensitiveToken, result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("upstream", result.Output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WorkflowNetworkFailure_ReturnsDedicatedFixedSanitizedMessage()
    {
        var admin = new FakeAdminOperations
        {
            Failure = KeygenAdminException.NetworkFailure(
                $"upstream={SensitiveCustomer}; password={StrongPassword}; token={SensitiveToken}")
        };
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);

        Assert.False(result.Succeeded);
        Assert.Equal(OwnerFailureMessages.NetworkFailure, result.Output);
        Assert.NotEqual(OwnerWorkflow.AccountFailure, result.Output);
        AssertSanitized(result.Output);
        Assert.DoesNotContain(StrongPassword, result.Output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task WorkflowAuthenticationFailure_ReturnsDedicatedFixedSanitizedMessage(
        HttpStatusCode statusCode)
    {
        var admin = new FakeAdminOperations
        {
            Failure = new KeygenAdminException(statusCode)
        };
        var workflow = CreateWorkflow(admin, StrongPassword);

        var result = await workflow.CreateAccountAsync("customer.one", SensitiveCustomer);

        Assert.False(result.Succeeded);
        Assert.Equal(
            "管理员令牌无效或已失效，请重新保存管理员令牌后重试。",
            result.Output);
        AssertSanitized(result.Output);
        Assert.DoesNotContain(StrongPassword, result.Output, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(AuthenticationFailureWorkflows))]
    public async Task EveryGuiAndCliWorkflow_AuthenticationFailureNeverUsesBusinessFailure(
        string operation,
        HttpStatusCode statusCode)
    {
        var admin = new FakeAdminOperations();
        var workflow = CreateWorkflow(admin, StrongPassword, ResetPassword);
        if (operation is "issue-selected" or "reset-selected" or "query")
        {
            var selection = await workflow.CreateAccountAsync(
                "customer.one",
                SensitiveCustomer);
            Assert.True(selection.Succeeded);
            admin.Calls.Clear();
        }

        admin.Failure = new KeygenAdminException(statusCode);
        admin.FailureAt = operation switch
        {
            "account" => "find",
            "account-trial" => "trial",
            "issue-cli" or "issue-selected" => "issue",
            "reset-cli" or "reset-selected" => "reset",
            "revoke" => "revoke",
            _ => "machines"
        };

        var result = operation switch
        {
            "account" or "account-trial" => await workflow.CreateAccountAsync(
                "customer.one",
                SensitiveCustomer),
            "issue-cli" => await workflow.IssueLicenseForCliAsync("customer.one", "year"),
            "reset-cli" => await workflow.ResetPasswordForCliAsync("customer.one"),
            "issue-selected" => await workflow.IssueSelectedLicenseAsync("year"),
            "reset-selected" => await workflow.ResetSelectedPasswordAsync(),
            "revoke" => await workflow.RevokeMachineAsync("machine-123"),
            _ => await workflow.QuerySelectedMachinesAsync()
        };

        Assert.False(result.Succeeded);
        Assert.Equal(OwnerFailureMessages.InvalidAdminCredential, result.Output);
        AssertSanitized(result.Output);
    }

    public static TheoryData<string, HttpStatusCode> AuthenticationFailureWorkflows
    {
        get
        {
            var data = new TheoryData<string, HttpStatusCode>();
            foreach (var operation in new[]
            {
                "account",
                "account-trial",
                "issue-cli",
                "reset-cli",
                "issue-selected",
                "reset-selected",
                "revoke",
                "query"
            })
            {
                data.Add(operation, HttpStatusCode.Unauthorized);
                data.Add(operation, HttpStatusCode.Forbidden);
            }

            return data;
        }
    }

    [Fact]
    public void InfrastructureFailureMessages_AreFixedDistinctAndSanitized()
    {
        var messages = new[]
        {
            OwnerFailureMessages.MissingAdminCredential,
            OwnerFailureMessages.InvalidAdminCredential,
            OwnerFailureMessages.TunnelConfigurationIncomplete,
            OwnerFailureMessages.TunnelConnectionFailed,
            OwnerFailureMessages.NetworkFailure
        };

        Assert.Equal(messages.Length, messages.Distinct(StringComparer.Ordinal).Count());
        Assert.All(messages, message =>
        {
            Assert.DoesNotContain(SensitiveToken, message, StringComparison.Ordinal);
            Assert.DoesNotContain(StrongPassword, message, StringComparison.Ordinal);
            Assert.DoesNotContain(SensitiveCustomer, message, StringComparison.Ordinal);
        });
    }

    [Theory]
    [MemberData(nameof(ValidCliCommands))]
    public async Task Cli_ExecutesOnlyThePlannedCommands(
        string[] args,
        string expectedCall,
        string expectedOutput)
    {
        var admin = new FakeAdminOperations();
        var savedTokens = new List<string>();
        var cli = CreateCli(admin, savedTokens, StrongPassword, ResetPassword);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await cli.RunAsync(args, output, error);

        Assert.Equal(0, exitCode);
        Assert.Contains(expectedCall, admin.Calls);
        Assert.Contains(expectedOutput, output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    public static TheoryData<string[], string, string> ValidCliCommands => new()
    {
        { ["account-create", "customer.one", "Customer One"], "trial:user-123", "TRIAL" },
        { ["license-issue", "customer.one", "year"], "issue:user-123:YEAR", "LICENSE-KEY-TEST" },
        { ["license-issue", "customer.one", "forever"], "issue:user-123:FOREVER", "FOREVER" },
        { ["password-reset", "customer.one"], "reset:user-123", StrongPassword },
        { ["machine-revoke", "machine-123"], "revoke:machine-123", "机器解绑成功" }
    };

    [Theory]
    [MemberData(nameof(InvalidCliArguments))]
    public async Task Cli_RejectsUnknownMissingAndExtraArgumentsWithoutEchoingThem(string[] args)
    {
        const string forbiddenArgument = "DO-NOT-ECHO-PASSWORD-TOKEN-CARD-KEY";
        var admin = new FakeAdminOperations();
        var factoryCalls = 0;
        var cli = new OwnerCli(
            () =>
            {
                factoryCalls++;
                return admin;
            },
            () => SensitiveToken,
            _ => { },
            () => StrongPassword);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await cli.RunAsync(args, output, error);

        Assert.NotEqual(0, exitCode);
        Assert.Equal(0, factoryCalls);
        Assert.Empty(admin.Calls);
        Assert.DoesNotContain(forbiddenArgument, output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(forbiddenArgument, error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(SensitiveToken, output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(SensitiveToken, error.ToString(), StringComparison.Ordinal);
    }

    public static TheoryData<string[]> InvalidCliArguments => new()
    {
        { [] },
        { ["machine"] },
        { ["year", "ABCD1234EF567890"] },
        { ["forever", "*"] },
        { ["unknown", "DO-NOT-ECHO-PASSWORD-TOKEN-CARD-KEY"] },
        { ["account-create", "customer.one"] },
        { ["account-create", "customer.one", "customer", "DO-NOT-ECHO-PASSWORD-TOKEN-CARD-KEY"] },
        { ["license-issue", "customer.one"] },
        { ["license-issue", "customer.one", "monthly"] },
        { ["license-issue", "customer.one", "year", "DO-NOT-ECHO-PASSWORD-TOKEN-CARD-KEY"] },
        { ["password-reset"] },
        { ["password-reset", "customer.one", "DO-NOT-ECHO-PASSWORD-TOKEN-CARD-KEY"] },
        { ["machine-revoke"] },
        { ["machine-revoke", "machine-123", "DO-NOT-ECHO-PASSWORD-TOKEN-CARD-KEY"] },
        { ["token-set", "DO-NOT-ECHO-PASSWORD-TOKEN-CARD-KEY"] },
        { ["help", "DO-NOT-ECHO-PASSWORD-TOKEN-CARD-KEY"] }
    };

    [Theory]
    [InlineData("help")]
    [InlineData("-h")]
    [InlineData("--help")]
    public async Task Cli_HelpListsOnlyApprovedCommands(string helpArgument)
    {
        var admin = new FakeAdminOperations();
        var cli = CreateCli(admin, [], StrongPassword);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await cli.RunAsync([helpArgument], output, error);

        Assert.Equal(0, exitCode);
        Assert.Empty(admin.Calls);
        var text = output.ToString();
        Assert.Contains("account-create <username> <customer>", text, StringComparison.Ordinal);
        Assert.Contains("license-issue <username> year|forever", text, StringComparison.Ordinal);
        Assert.Contains("password-reset <username>", text, StringComparison.Ordinal);
        Assert.Contains("machine-revoke <machine-id>", text, StringComparison.Ordinal);
        Assert.Contains("token-set", text, StringComparison.Ordinal);
        Assert.DoesNotContain("SecretBase64", text, StringComparison.Ordinal);
        Assert.DoesNotContain("QL21", text, StringComparison.Ordinal);
        Assert.DoesNotContain("<机器码>", text, StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task CliTokenSet_ReadsSecretOutOfBandSavesItAndNeverPrintsIt()
    {
        var admin = new FakeAdminOperations();
        var savedTokens = new List<string>();
        var cli = CreateCli(admin, savedTokens, StrongPassword);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await cli.RunAsync(["token-set"], output, error);

        Assert.Equal(0, exitCode);
        Assert.Equal([SensitiveToken], savedTokens);
        Assert.Empty(admin.Calls);
        Assert.DoesNotContain(SensitiveToken, output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(SensitiveToken, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cli_DisposesAdminOperationsAfterEveryCommand()
    {
        var admin = new FakeAdminOperations();
        var cli = CreateCli(admin, [], StrongPassword);

        var exitCode = await cli.RunAsync(
            ["machine-revoke", "machine-123"],
            TextWriter.Null,
            TextWriter.Null);

        Assert.Equal(0, exitCode);
        Assert.True(admin.IsDisposed);
    }

    [Fact]
    public async Task Cli_RuntimeFailureIsSanitizedAndDoesNotEchoArguments()
    {
        var cli = new OwnerCli(
            () => throw new InvalidOperationException(
                $"config payload {SensitiveCustomer}; token {SensitiveToken}"),
            () => SensitiveToken,
            _ => { },
            () => StrongPassword);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await cli.RunAsync(
            ["account-create", "customer.one", SensitiveCustomer],
            output,
            error);

        Assert.NotEqual(0, exitCode);
        Assert.Equal(string.Empty, output.ToString());
        Assert.DoesNotContain(SensitiveCustomer, error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(SensitiveToken, error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(StrongPassword, error.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("account-create", "trial")]
    [InlineData("license-issue", "issue")]
    [InlineData("password-reset", "reset")]
    public async Task Cli_PartialSuccessWritesResultOnceAndReturnsDedicatedNonzeroCode(
        string command,
        string failureAt)
    {
        var admin = FailingAdmin(wasCreated: true, failureAt);
        var cli = CreateCli(admin, [], StrongPassword);
        var args = command switch
        {
            "account-create" => new[] { command, "customer.one", "Customer One" },
            "license-issue" => new[] { command, "customer.one", "year" },
            _ => new[] { command, "customer.one" }
        };
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await cli.RunAsync(args, output, error);

        Assert.Equal(3, exitCode);
        Assert.Contains("部分成功", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, Count(output.ToString(), StrongPassword));
        Assert.Equal(string.Empty, error.ToString());
        Assert.True(admin.IsDisposed);
    }

    [Fact]
    public void Runtime_UsesOnlyFixedBaseDirectoryOwnerConfigPath()
    {
        Assert.Equal(
            Path.Combine(AppContext.BaseDirectory, "admin-config.json"),
            OwnerRuntime.ConfigPath);
    }

    [Fact]
    public void ProgramSource_ContainsRequiredAdminFormAndAsyncSafetyContract()
    {
        var source = File.ReadAllText(ProgramSourcePath);
        var requiredLabels = new[]
        {
            "账号：",
            "客户：",
            "初始密码：",
            "年卡",
            "永久",
            "创建账号",
            "签发授权",
            "重置密码",
            "机器 ID：",
            "查询机器",
            "解绑机器",
            "管理员令牌：",
            "保存令牌",
            "复制结果",
            "清空"
        };

        foreach (var label in requiredLabels)
        {
            Assert.True(
                source.Contains(label, StringComparison.Ordinal),
                $"Program.cs is missing required form text '{label}'.");
        }

        Assert.True(source.Contains("UseSystemPasswordChar = true", StringComparison.Ordinal));
        Assert.True(source.Contains("RandomNumberGenerator.GetBytes", StringComparison.Ordinal));
        Assert.False(source.Contains(".Result", StringComparison.Ordinal));
        Assert.Empty(Regex.Matches(source, "Clipboard\\.SetText").Cast<Match>());
        Assert.Single(Regex.Matches(source, "Clipboard\\.SetDataObject").Cast<Match>());
        Assert.True(source.Contains("IOwnerClipboard", StringComparison.Ordinal));
        Assert.InRange(OwnerAdminForm.FormWidth, 1, 900);
        Assert.InRange(OwnerAdminForm.FormHeight, 1, 700);
    }

    private static OwnerWorkflow CreateWorkflow(
        FakeAdminOperations admin,
        params string[] passwords)
    {
        var queue = new Queue<string>(passwords);
        return new OwnerWorkflow(admin, () => queue.Dequeue());
    }

    private static OwnerRuntime CreateRuntime(
        bool hasSavedToken = false,
        Action<string>? tokenSaver = null)
    {
        return new OwnerRuntime(
            () => hasSavedToken,
            tokenSaver ?? (_ => { }));
    }

    private static OwnerWorkflow CreateWorkflowWithTimeout(
        IKeygenAdminOperations admin,
        TimeSpan timeout,
        params string[] passwords)
    {
        var queue = new Queue<string>(passwords);
        Func<string> passwordFactory = () => queue.Dequeue();
        var constructor = typeof(OwnerWorkflow).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            [typeof(IKeygenAdminOperations), typeof(Func<string>), typeof(TimeSpan)],
            modifiers: null);
        return constructor is null
            ? new OwnerWorkflow(admin, passwordFactory)
            : Assert.IsType<OwnerWorkflow>(constructor.Invoke(
                [admin, passwordFactory, timeout]));
    }

    private static OwnerCli CreateCli(
        FakeAdminOperations admin,
        List<string> savedTokens,
        params string[] passwords)
    {
        var queue = new Queue<string>(passwords);
        return new OwnerCli(
            () => admin,
            () => SensitiveToken,
            savedTokens.Add,
            () => queue.Dequeue());
    }

    private static int Count(string value, string expected)
    {
        return Regex.Matches(value, Regex.Escape(expected)).Count;
    }

    private static void Click(Button button)
    {
        var onClick = typeof(Button).GetMethod(
            "OnClick",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(onClick);
        onClick.Invoke(button, [EventArgs.Empty]);
    }

    private static T GetPrivateField<T>(object instance, string fieldName)
    {
        var field = instance.GetType().GetField(
            fieldName,
            BindingFlags.Instance | BindingFlags.NonPublic);
        return Assert.IsType<T>(field?.GetValue(instance));
    }

    private static FakeAdminOperations FailingAdmin(
        bool wasCreated,
        string failureAt)
    {
        return new FakeAdminOperations
        {
            WasCreated = wasCreated,
            FailureAt = failureAt,
            Failure = new InvalidOperationException(
                $"upstream={SensitiveCustomer}; password={StrongPassword}; token={SensitiveToken}")
        };
    }

    private static void AssertSanitized(string output)
    {
        Assert.DoesNotContain(SensitiveCustomer, output, StringComparison.Ordinal);
        Assert.DoesNotContain(SensitiveToken, output, StringComparison.Ordinal);
        Assert.DoesNotContain("upstream", output, StringComparison.OrdinalIgnoreCase);
    }

    private static string ExpectedFailurePrefix(string operation)
    {
        return operation switch
        {
            "account" => "账号创建失败",
            "issue" => "授权失败",
            "reset" => "密码重置失败",
            _ => "机器解绑失败"
        };
    }

    private static async Task<int> InvokeProgramMainAsync(string[] args)
    {
        var main = typeof(Program).GetMethod(
            "Main",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Program.Main was not found.");
        var result = main.Invoke(null, [args]);
        return result switch
        {
            int exitCode => exitCode,
            Task<int> task => await task,
            _ => throw new InvalidOperationException("Program.Main has an unsupported return type.")
        };
    }

    private sealed class FakeAdminOperations : IKeygenAdminOperations
    {
        internal KeygenUser User => new(
            "user-123",
            "customer.one@accounts.license.invalid",
            SensitiveCustomer,
            WasCreated);

        internal KeygenLicense TrialLicense { get; } = new(
            "trial-123",
            "TRIAL-LICENSE-TEST",
            "TRIAL",
            0,
            "user-123",
            "product-123",
            "policy-trial");

        internal KeygenLicense PaidLicense { get; } = new(
            "license-123",
            "LICENSE-KEY-TEST",
            "YEAR",
            128,
            "user-123",
            "product-123",
            "policy-year",
            "ACTIVE",
            new DateTimeOffset(2031, 2, 3, 4, 5, 6, TimeSpan.Zero),
            365 * 24 * 60 * 60,
            new DateTimeOffset(2031, 2, 3, 4, 5, 6, TimeSpan.Zero));

        internal List<string> Calls { get; } = [];
        internal Exception? Failure { get; set; }
        internal string? FailureAt { get; set; }
        internal bool IsDisposed { get; private set; }
        internal string LastCustomer { get; private set; } = string.Empty;
        internal string LastPassword { get; private set; } = string.Empty;
        internal bool PaidLicenseIsUnactivated { get; init; }
        internal IReadOnlyList<string> MachineIds { get; init; } = [];
        internal bool WasCreated { get; init; }

        public Task<KeygenUser> FindOrCreateUserAsync(
            string username,
            string password,
            string customer,
            CancellationToken cancellationToken)
        {
            Calls.Add($"find:{username}");
            LastPassword = password;
            LastCustomer = customer;
            ThrowIfConfigured("find");
            return Task.FromResult(User);
        }

        public Task<KeygenLicense> EnsureTrialAsync(
            KeygenUser user,
            CancellationToken cancellationToken)
        {
            Calls.Add($"trial:{user.Id}");
            ThrowIfConfigured("trial");
            return Task.FromResult(TrialLicense);
        }

        public Task<KeygenLicense> IssuePaidAsync(
            KeygenUser user,
            string plan,
            CancellationToken cancellationToken)
        {
            Calls.Add($"issue:{user.Id}:{plan}");
            ThrowIfConfigured("issue");
            return Task.FromResult(PaidLicense with
            {
                Plan = plan,
                Price = plan == "YEAR" ? 128 : 288,
                BusinessExpiresAt = plan == "YEAR" && !PaidLicenseIsUnactivated
                    ? PaidLicense.BusinessExpiresAt
                    : null,
                Expiry = plan == "YEAR" && !PaidLicenseIsUnactivated
                    ? PaidLicense.Expiry
                    : null
            });
        }

        public Task ResetPasswordAsync(
            KeygenUser user,
            string newPassword,
            CancellationToken cancellationToken)
        {
            Calls.Add($"reset:{user.Id}");
            LastPassword = newPassword;
            ThrowIfConfigured("reset");
            return Task.CompletedTask;
        }

        public Task RevokeMachineAsync(
            string machineId,
            CancellationToken cancellationToken)
        {
            Calls.Add($"revoke:{machineId}");
            ThrowIfConfigured("revoke");
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<string>> ListMachineIdsAsync(
            KeygenUser user,
            CancellationToken cancellationToken)
        {
            Calls.Add($"machines:{user.Id}");
            ThrowIfConfigured("machines");
            return Task.FromResult(MachineIds);
        }

        public void Dispose()
        {
            IsDisposed = true;
        }

        private void ThrowIfConfigured(string operation)
        {
            if (Failure is not null
                && (FailureAt is null
                    || string.Equals(FailureAt, operation, StringComparison.Ordinal)))
            {
                throw Failure;
            }
        }
    }

    private sealed class FakeClipboard : IOwnerClipboard
    {
        internal List<string> CopiedValues { get; } = [];

        public void SetText(string text)
        {
            CopiedValues.Add(text);
        }
    }

    private sealed class DeadlineAdminOperations : IKeygenAdminOperations
    {
        private readonly TimeSpan _phaseDelay;
        private readonly bool _wasCreated;

        internal DeadlineAdminOperations(bool wasCreated, TimeSpan phaseDelay)
        {
            _wasCreated = wasCreated;
            _phaseDelay = phaseDelay;
        }

        internal List<string> Calls { get; } = [];
        internal List<string> CompletedCalls { get; } = [];
        internal List<CancellationToken> Tokens { get; } = [];

        public async Task<KeygenUser> FindOrCreateUserAsync(
            string username,
            string password,
            string customer,
            CancellationToken cancellationToken)
        {
            Calls.Add("find");
            Tokens.Add(cancellationToken);
            await Task.Delay(_phaseDelay, cancellationToken);
            CompletedCalls.Add("find");
            return new KeygenUser(
                "deadline-user",
                "customer.one@accounts.license.invalid",
                customer,
                _wasCreated);
        }

        public async Task<KeygenLicense> EnsureTrialAsync(
            KeygenUser user,
            CancellationToken cancellationToken)
        {
            Calls.Add("trial");
            Tokens.Add(cancellationToken);
            await DelayMutationAsync(cancellationToken);
            CompletedCalls.Add("trial");
            return new KeygenLicense(
                "deadline-trial",
                "DEADLINE-TRIAL-LICENSE",
                "TRIAL",
                0,
                user.Id,
                "product-123",
                "policy-trial");
        }

        public async Task<KeygenLicense> IssuePaidAsync(
            KeygenUser user,
            string plan,
            CancellationToken cancellationToken)
        {
            Calls.Add("issue");
            Tokens.Add(cancellationToken);
            await DelayMutationAsync(cancellationToken);
            CompletedCalls.Add("issue");
            return new KeygenLicense(
                "deadline-paid",
                "DEADLINE-PAID-LICENSE",
                plan,
                128,
                user.Id,
                "product-123",
                "policy-year");
        }

        public Task ResetPasswordAsync(
            KeygenUser user,
            string newPassword,
            CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<string>> ListMachineIdsAsync(
            KeygenUser user,
            CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task RevokeMachineAsync(
            string machineId,
            CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public void Dispose()
        {
        }

        private async Task DelayMutationAsync(CancellationToken cancellationToken)
        {
            try
            {
                await Task.Delay(_phaseDelay, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw KeygenAdminException.UnknownCommit();
            }
        }
    }
}
