using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace IdentityManager.Authorize
{
    // combine requirement and authorization handler together !!! so we do not need to configure service in the Startup.cs
    public class OnlySuperAdminChecker : AuthorizationHandler<OnlySuperAdminChecker>, IAuthorizationRequirement
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OnlySuperAdminChecker requirement)
        {
            if(context.User.IsInRole("SuperAdmin"))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            return Task.CompletedTask;
        }
    }
}
