using System.Collections.Generic;
using System.Security.Claims;

namespace IdentityManager.Data
{
    public static class ClaimStore
    {
        public static List<Claim> ClaimList = new()
        {
            new Claim("Create", "Create"),
            new Claim("Edit", "Edit"),
            new Claim("Delete", "Delete")
        };
    }
}
