using BankOfDotNet.Data.Entity;
using BankOfDotNet.Data.Log;
using IdentiyServerCustom.Data.Entity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading.Tasks;


namespace IdentiyServerCustom.Data
{
    public class IS4DbContext : IdentityDbContext<ApplicationUser>
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public IS4DbContext(DbContextOptions<IS4DbContext> options, IHttpContextAccessor _httpContextAccessor) :
            base(options)
        {
            this._httpContextAccessor = _httpContextAccessor;
        }
        #region Identity Server
        public DbSet<IdentiyUserLog> IdentiyUserLogs { get; set; }
        #endregion

        #region Settings Configs
        public override int SaveChanges()
        {
            AddTimestamps();
            return base.SaveChanges();
        }

        public async Task<int> SaveChangesAsync()
        {
            AddTimestamps();
            return await base.SaveChangesAsync();
        }

        private void AddTimestamps()
        {

            var entities = ChangeTracker.Entries().Where(x => x.Entity is Base && (x.State == EntityState.Added || x.State == EntityState.Modified));

            var currentUsername = !string.IsNullOrEmpty(_httpContextAccessor?.HttpContext?.User?.Identity?.Name)
                ? _httpContextAccessor.HttpContext.User.Identity.Name
                : "Anonymous";

            foreach (var entity in entities)
            {
                if (entity.State == EntityState.Added)
                {
                    ((Base)entity.Entity).CreatedAt = DateTime.Now.AddHours(-12);
                    //((Base)entity.Entity).CreatedBy = currentUsername;
                }
                else
                {
                    //entity.Property("createdAt").IsModified = false;
                    //entity.Property("createdBy").IsModified = false;
                    ((Base)entity.Entity).UpdatedAt = DateTime.Now.AddHours(-12);
                    //((Base)entity.Entity).UpdatedBy = currentUsername;
                }

            }
        }
        #endregion
    }
}
