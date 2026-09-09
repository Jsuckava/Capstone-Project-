using System.Threading.Tasks;

namespace Client_app.Services
{
    public interface IEmailService
    {
        Task SendEmailAsync(
            string toEmail,
            string subject,
            string body,
            bool isHtml = false,
            string? inlineImagePath = null,
            string? inlineImageContentId = null);
    }
}
