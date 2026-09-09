using System;
using System.Net.Mail;
using System.Net.Mime;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace Client_app.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(
            string toEmail,
            string subject,
            string body,
            bool isHtml = false,
            string? inlineImagePath = null,
            string? inlineImageContentId = null)
        {
            try
            {
                var smtpHost = _configuration["Smtp:Host"];
                
                if (!int.TryParse(_configuration["Smtp:Port"], out int smtpPort))
                {
                    smtpPort = 587;
                }

                var smtpUser = _configuration["Smtp:Username"] ?? _configuration["Smtp:User"];
                var smtpPass = _configuration["Smtp:Password"] ?? _configuration["Smtp:Pass"];

                if (string.IsNullOrEmpty(smtpHost) || string.IsNullOrEmpty(smtpUser) || string.IsNullOrEmpty(smtpPass) || smtpPass.Contains("your-"))
                {
                    Console.WriteLine($"[EMAIL SKIPPED] SMTP not configured. Intended for: {toEmail}");
                    return;
                }

                using var client = new SmtpClient(smtpHost, smtpPort)
                {
                    UseDefaultCredentials = false,
                    Credentials = new System.Net.NetworkCredential(smtpUser, smtpPass),
                    EnableSsl = true
                };

                using var mailMessage = new MailMessage { Subject = subject, Body = body, IsBodyHtml = isHtml };
                mailMessage.From = new MailAddress(smtpUser, "PLV BlockGO");
                mailMessage.To.Add(toEmail);

                if (isHtml &&
                    !string.IsNullOrWhiteSpace(inlineImagePath) &&
                    System.IO.File.Exists(inlineImagePath) &&
                    new System.IO.FileInfo(inlineImagePath).Length > 0)
                {
                    var contentId = (inlineImageContentId ?? "plv-logo").Trim('<', '>');
                    var htmlView = AlternateView.CreateAlternateViewFromString(body, null, MediaTypeNames.Text.Html);
                    var logo = new LinkedResource(inlineImagePath, MediaTypeNames.Image.Png)
                    {
                        ContentId = contentId,
                        TransferEncoding = TransferEncoding.Base64
                    };
                    logo.ContentType.Name = System.IO.Path.GetFileName(inlineImagePath);
                    logo.ContentLink = new Uri($"cid:{contentId}");
                    htmlView.LinkedResources.Add(logo);
                    mailMessage.Body = string.Empty;
                    mailMessage.IsBodyHtml = false;
                    mailMessage.AlternateViews.Add(htmlView);
                }

                await client.SendMailAsync(mailMessage);
                Console.WriteLine($"[EMAIL SENT] Successfully sent email to {toEmail} with subject '{subject}'");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[EMAIL ERROR] Failed to send email to {toEmail}: {ex.Message}");
            }
        }
    }
}
