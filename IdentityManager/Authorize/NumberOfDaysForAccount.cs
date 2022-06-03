using IdentityManager.Data;
using System;
using System.Linq;

namespace IdentityManager.Authorize
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly ApplicationDbContext _context;

        public NumberOfDaysForAccount(ApplicationDbContext context)
        {
            _context = context;
        }

        public int Get(string userId)
        {
            var user = _context.ApplicationUsers.FirstOrDefault(x => x.Id == userId);

            if (user != null && user.DateCreated != System.DateTime.MinValue) return (DateTime.Today - user.DateCreated).Days;

            return 0;
        }
    }
}
