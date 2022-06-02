using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

// This is ASP net core Web MVC
// This is server side rendering !!!
namespace IdentityManager.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly UrlEncoder _urlEncoder;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender, UrlEncoder urlEncoder)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _urlEncoder = urlEncoder;
        }

        public IActionResult Index()
        {
            return View();
        }

        // Fetch the Register page to client side
        [HttpGet]
        public async Task<IActionResult> Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            var registerViewModel = new RegisterViewModel();
            return View(registerViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl ??= Url.Content("~/");

            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name };

                var result = await _userManager.CreateAsync(user, model.Password);

                if(result.Succeeded)
                {
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code }, protocol: HttpContext.Request.Scheme);

                    await _emailSender.SendEmailAsync(model.Email, "Confirm your account - Identity Manager", "Please confirm your account by clicking here: <a href=\"" + callbackUrl + "\">link</a>");


                    await _signInManager.SignInAsync(user, isPersistent: false);
                    //return RedirectToAction("Index", "Home"); // Index action, inside Home Controller
                    return LocalRedirect(returnUrl);
                }

                AddErrors(result);
            }

            return View(model);            
        }


        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null) return View("Error");

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null) return View("Error");

            var result = await _userManager.ConfirmEmailAsync(user, code);

            return View(result.Succeeded ? "ConfirmEmail" : "Error"); ;
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction(nameof(Index), "Home");
        }

        // Fetch the Register page to client side
        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl ??= Url.Content("~/");

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);

                
                if (result.Succeeded)
                {
                    //return RedirectToAction("Index", "Home"); // Index action, inside Home Controller
                    return LocalRedirect(returnUrl);
                }
                else if(result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnUrl, model.RememberMe });
                }
                else if(result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt");
                    return View(model);
                }
                
            }

            return View(model);
        }

        // Fetch the Register page to client side
        [HttpGet]
        public IActionResult ForgotPassword()
        {            
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {           
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirmation");
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);

                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code }, protocol: HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(model.Email, "Reset Password - Identity Manager", "Please reset your password by clicking here: <a href=\"" + callbackUrl + "\">link</a>");

                return RedirectToAction("ForgotPasswordConfirmation");
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }


        // Fetch the Register page to client side
        [HttpGet]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ResetPasswordConfirmation");
                }

                // code is null !!!

                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

                if (result.Succeeded)
                {
                    return RedirectToAction("ResetPasswordConfirmation");

                }

                AddErrors(result);
            }

            return View();
        }

        // need view for ResetPasswordConfirmation !!!
        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // request redirect to the external provider
            var authenticationSchema = Url.Action("ExternalLoginCallBack", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, authenticationSchema);

            // I don't know this user, Please redirect him to facebook login !!!
            // This essentially redirects user to external login provider - which in our case is facebook !!!

            // once login successfully, it will redirect us back to the url inside the authenticationSchema !!! - which is ExternalLoginCallback
            return Challenge(properties, provider);
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {            
            returnUrl ??= Url.Content("~/");

            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return View(nameof(Login));
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();

            if(info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // sign in user with external provider
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);

            if(result.Succeeded)
            {
                // update any authentication token
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);                

                return LocalRedirect(returnUrl);
            } 
            else if(result.RequiresTwoFactor)
            {
                return RedirectToAction("VerifyAuthenticatorCode", new { returnUrl });
            }
            else
            {
                // user does not have an account ===> ask them to create one
                ViewData["returnUrl"] = returnUrl;
                ViewData["ProviderDisplayName"] = info.ProviderDisplayName;

                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var name = info.Principal.FindFirstValue(ClaimTypes.Name);

                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email, Name = name });
            }            
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl ??= Url.Content("~/");

            if (ModelState.IsValid)
            {
                var info = await _signInManager.GetExternalLoginInfoAsync();

                if(info == null)
                {
                    return View("Error");
                }

                var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name };
                var result = await _userManager.CreateAsync(user);

                if(result.Succeeded)
                {
                    result = await _userManager.AddLoginAsync(user, info);

                    if(result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        await _signInManager.UpdateExternalAuthenticationTokensAsync(info);

                        return LocalRedirect(returnUrl);
                    }
                }

                AddErrors(result);
            }

            ViewData["returnUrl"] = returnUrl;

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator()
        {
            // 2: secret or token key
            // 1: email address
            // 0: issuer name - anything we want
            var authenticatorUrlFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);

            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var authenticatorUri = string.Format(authenticatorUrlFormat, _urlEncoder.Encode("IdentityManager"), _urlEncoder.Encode(user.Email), token);

            var model = new TwoFactorAuthenticationViewModel() { Token = token, QrCodeUrl = authenticatorUri };

            return View(model);
        }

        [HttpGet]
        public IActionResult AuthenticatiorConfirmation()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);

                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true); 
                }
                else
                {
                    ModelState.AddModelError("Verify", "Your two factor auth code could not be validated");
                    return View(model);
                }

            }

            return RedirectToAction(nameof(AuthenticatiorConfirmation));
        }

        [HttpGet]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if(user == null)
            {
                return View("Error");
            }

            ViewData["returnUrl"] = returnUrl;

            return View(new VerifyAuthenticatorViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel model)
        {
            ViewData["returnUrl"] = model.ReturnUrl;
            model.ReturnUrl ??= Url.Content("~/");
            

            if (ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient: false);

            if(result.Succeeded) return LocalRedirect(model.ReturnUrl);            

            if(result.IsLockedOut) return View("Lockout");

            ModelState.AddModelError(string.Empty, "Invalid code");
            return View(model);
        }


        [HttpGet]
        public async Task<IActionResult> RemoveAuthenticator()
        {           
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, false);

            return RedirectToAction(nameof(Index), "Home");
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
