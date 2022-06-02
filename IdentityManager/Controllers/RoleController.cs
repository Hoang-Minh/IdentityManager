using IdentityManager.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Controllers
{
    public class RoleController : Controller
    {
        private readonly ApplicationDbContext _applicationDbContext;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(ApplicationDbContext applicationDbContext, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _applicationDbContext = applicationDbContext;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public IActionResult Index()
        {
            var roles = _applicationDbContext.Roles.ToList();


            return View(roles);
        }

        [HttpGet]
        public IActionResult Upsert(string id)
        {
            if(string.IsNullOrEmpty(id))
            {
                return View();
            }
            else
            {
                // update
                var objFromDb = _applicationDbContext.Roles.FirstOrDefault(u => u.Id == id);
                return View(objFromDb);
            }            
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole roleObj)
        {
            if (await _roleManager.RoleExistsAsync(roleObj.Name))
            {
                // error
                TempData[SD.Error] = "Role already exists";
                return RedirectToAction(nameof(Index));
            }
            else if(string.IsNullOrEmpty(roleObj.Id))
            {
                // create
                await _roleManager.CreateAsync(new IdentityRole { Name = roleObj.Name });
                TempData[SD.Success] = "Role created successfully";
            }
            else
            {
                // update
                var objRoleFromDb = _roleManager.Roles.FirstOrDefault(x => x.Id == roleObj.Id);

                if(objRoleFromDb == null)
                {                   
                    TempData[SD.Error] = "Role not found";
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    objRoleFromDb.Name = roleObj.Name;
                    objRoleFromDb.NormalizedName = roleObj.Name.ToUpper();

                    await _roleManager.UpdateAsync(objRoleFromDb);

                    TempData[SD.Success] = "Role updated successfully";
                }
                
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var objRoleFromDb = _roleManager.Roles.FirstOrDefault(x => x.Id == id);
            var userRolesForThisRole = _applicationDbContext.UserRoles.Where(x => x.RoleId == id);

            if(userRolesForThisRole.Any())
            {
                TempData[SD.Error] = "Cannot delete this role. There are users assigned to this role";
                return RedirectToAction(nameof(Index));
            }

            if(objRoleFromDb == null)
            {
                TempData[SD.Error] = "Role Not Found";
                return RedirectToAction(nameof(Index));
            }

            await _roleManager.DeleteAsync(objRoleFromDb);

            TempData[SD.Error] = "Role deleted successfully";
            
            return RedirectToAction(nameof(Index));
        }
    }
}
