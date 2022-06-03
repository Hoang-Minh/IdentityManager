using IdentityManager.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityManager.Authorize
{
    public class FirstNameAuthHandler : AuthorizationHandler<FirstNameAuthRequirement>
    {
        public UserManager<IdentityUser> _userManager { get; set; }
        public ApplicationDbContext _context { get; set; }


        public FirstNameAuthHandler(UserManager<IdentityUser> userManager, ApplicationDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, FirstNameAuthRequirement requirement)
        {
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            var user = _context.ApplicationUsers.FirstOrDefault(x => x.Id == userId);
            var claims = await _userManager.GetClaimsAsync(user);
            var claim = claims.FirstOrDefault(x => x.Type == "FirstName");

            if(claim != null && claim.Value.ToLower().Contains(requirement.Name.ToLower()))
            {
                context.Succeed(requirement);
                return;
            }

            return;

        }
    }
}
