using System;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace PhilaGov.Common.Authentication.Models
{
    public partial class campaignfinanceContext : IdentityDbContext
    {
        public campaignfinanceContext()
        {
        }

        public campaignfinanceContext(DbContextOptions<campaignfinanceContext> options)
            : base(options)
        {
        }


        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }
    }
}
