using Mailjet.Client;
using Mailjet.Client.Resources;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Services
{
    public class MailJetEmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;
        private MailJetOptions _mailJetOptions;

        public MailJetEmailSender(IConfiguration configuration)
        {
            _configuration = configuration;            
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            _mailJetOptions = _configuration.GetSection("MailJet").Get<MailJetOptions>();

            var client = new MailjetClient(_mailJetOptions.ApiKey, _mailJetOptions.SecretKey);            

            var request = new MailjetRequest
            {
                Resource = Send.Resource
            }
            .Property(Send.FromEmail, "minhvuhoangnguyen@hotmail.com")
            .Property(Send.FromName, "Minh")
            .Property(Send.Subject, subject)
            .Property(Send.HtmlPart, htmlMessage)
            .Property(Send.Recipients, new JArray
            {
                new JObject
                {
                    {"Email", email }
                }
            });

            await client.PostAsync(request);
        }
    }
}

