namespace FileEncryptor.App.Services;

public static class PasswordAdvisor
{
    public static (int score, string guidance) Evaluate(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return (0, "Use at least 12 characters including upper/lowercase, numbers, and symbols.");
        }

        var score = 0;
        if (password.Length >= 12) score++;
        if (password.Length >= 16) score++;
        if (password.Any(char.IsLower) && password.Any(char.IsUpper)) score++;
        if (password.Any(char.IsDigit)) score++;
        if (password.Any(ch => !char.IsLetterOrDigit(ch))) score++;

        var guidance = score switch
        {
            <= 1 => "Weak: Increase length and mix character types.",
            2 or 3 => "Fair: Add symbols and more length for better security.",
            4 => "Strong: Good complexity. Consider a passphrase for memorability.",
            _ => "Very strong: Excellent passphrase quality."
        };

        return (score, guidance);
    }

    public static bool IsWeak(string password) => Evaluate(password).score <= 2;
}
