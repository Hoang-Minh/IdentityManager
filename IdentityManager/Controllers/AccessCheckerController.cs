using IdentityManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

// This is ASP net core Web MVC
// This is server side rendering !!!
namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly UrlEncoder _urlEncoder;

        public AccessCheckerController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender, UrlEncoder urlEncoder, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _urlEncoder = urlEncoder;
            _roleManager = roleManager;
        }

        public IActionResult AllAccess()
        {
            return View();
        }

        public IActionResult AuthorizedAccess()
        {
            return View();
        }

        [Authorize(Roles = "User")]
        public IActionResult UserAccess()
        {
            return View();
        }

        [Authorize(Policy = "Admin")] // match with policy defined in Startup.cs
        public IActionResult AdminAccess()
        {
            return View();
        }

        // Accessible by Admin users with a claim of create to be true
        [Authorize(Policy = "Admin_CreateAccess")]
        public IActionResult Admin_CreateAccess()
        {
            return View();
        }

        // Accessible by Admin users with a claim of create edit and delete (AND NOT OR) to be true
        [Authorize(Policy = "Admin_Create_Edit_DeleteAccess")]
        public IActionResult Admin_Create_Edit_DeleteAccess()
        {
            return View();
        }

        // Accessible by Admin users with a claim of create edit and delete (AND NOT OR) OR if the user is super admin
        [Authorize(Roles = "Admin_Create_Edit_DeleteAccess_OR_SuperAdmin")]
        public IActionResult Admin_Create_Edit_DeleteAccess_OR_SuperAdmin()
        {
            return View();
        }

        // User AND Admin
        [Authorize(Policy = "AdminAndUser")]        
        public IActionResult UserANDAdminAccess()
        {
            return View();
        }

        [Authorize(Roles = "User,Admin")] // User OR Admin
        public IActionResult UserORAdminAccess()
        {
            return View();
        }

        [Authorize(Policy = "AdminWithMoreThan1000Days")]
        public IActionResult OnlyWithMinh()
        {
            return View();
        }

        [Authorize(Policy = "FirstNameAuth")]
        public IActionResult FirstNameAuth()
        {
            return View();
        }
    }
}
