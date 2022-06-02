using IdentityManager.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _applicationDbContext;
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(ApplicationDbContext applicationDbContext, UserManager<IdentityUser> userManager)
        {
            _applicationDbContext = applicationDbContext;
            _userManager = userManager;
        }

        

        public IActionResult Index()
        {
            var userList = _applicationDbContext.ApplicationUser.ToList();
            var userRole = _applicationDbContext.UserRoles.ToList();
            var roles = _applicationDbContext.Roles.ToList();


            foreach(var user in userList)
            {
                var role = userRole.FirstOrDefault(x => x.UserId == user.Id);

                if(role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(x => x.Id == role.RoleId).Name;
                }


            }

            return View(userList);
        }
    }
}
