using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;

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

        
        [HttpGet]
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

        [HttpGet]
        public IActionResult Edit(string userId)
        {
            var user = _applicationDbContext.ApplicationUser.FirstOrDefault(x => x.Id == userId); // get current user
            if (user == null) return NotFound();

            var userRoles = _applicationDbContext.UserRoles.ToList(); // list of users with role
                                                                      
            var roles = _applicationDbContext.Roles.ToList(); // list of roles

            var role = userRoles.FirstOrDefault(x => x.UserId == user.Id); // find role of the current user

            if(role != null) // user has been assigned role before
            {
                user.RoleId = roles.FirstOrDefault(x => x.Id == role.RoleId).Id; // assign to pass to front end
            }

            // populate list

            user.RoleList = _applicationDbContext.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });
            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(ApplicationUser user)
        {
            if(ModelState.IsValid)
            {
                var userFromDb = _applicationDbContext.ApplicationUser.FirstOrDefault(x => x.Id == user.Id); // get current user
                if (userFromDb == null) return NotFound();

                var userRole = _applicationDbContext.UserRoles.FirstOrDefault(x => x.UserId == userFromDb.Id);

                if (userRole != null)
                {
                    var previousRoleName = _applicationDbContext.Roles.Where(x => x.Id == userRole.RoleId).Select(y => y.Name).FirstOrDefault();

                    await _userManager.RemoveFromRoleAsync(userFromDb, previousRoleName); // remove old role              
                }

                await _userManager.AddToRoleAsync(userFromDb, _applicationDbContext.Roles.FirstOrDefault(x => x.Id == user.RoleId).Name);

                userFromDb.Name = user.Name;
                _applicationDbContext.SaveChanges();

                TempData[SD.Success] = "User has been edited successfully";

                return RedirectToAction(nameof(Index));
            }

            user.RoleList = _applicationDbContext.Roles.Select(x => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = x.Name,
                Value = x.Id
            });

            return View(user);            
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult LockUnlock(string userId)
        {
            var userFromDb = _applicationDbContext.ApplicationUser.FirstOrDefault(x => x.Id == userId);

            if (userFromDb == null) return NotFound();

            if(userFromDb.LockoutEnd != null && userFromDb.LockoutEnd > DateTime.Now)
            {
                // user is lock and will remained lock until the lock out end time
                // clicking this will unlock
                userFromDb.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User unlocked successfully";
            }
            else
            {
                userFromDb.LockoutEnd = DateTime.Now.AddYears(100);
                TempData[SD.Success] = "User locked successfully";
            }
            _applicationDbContext.SaveChanges();
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult DeleteUser(string userId)
        {
            var userFromDb = _applicationDbContext.ApplicationUser.FirstOrDefault(x => x.Id == userId);

            if (userFromDb == null) return NotFound();

            _applicationDbContext.Remove(userFromDb);
            _applicationDbContext.SaveChanges();

            return RedirectToAction(nameof(Index));
        }
    }
}
