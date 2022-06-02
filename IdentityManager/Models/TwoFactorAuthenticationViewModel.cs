namespace IdentityManager.Models
{
    public class TwoFactorAuthenticationViewModel
    {                
        public string Code { get; set; } // use to login
        public string Token { get; set; } // use to register
        public string QrCodeUrl { get; set; }
    }
}
