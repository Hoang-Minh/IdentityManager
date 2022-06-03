using IdentityManager.Authorize;
using IdentityManager.Data;
using IdentityManager.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;

namespace IdentityManager
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(Configuration.GetConnectionString("IdentityManagerConnection")));
            services.AddTransient<IEmailSender, MailJetEmailSender>();
            services.AddIdentity<IdentityUser, IdentityRole>(opt =>
            {
                opt.Password.RequiredLength = 5;
                opt.Password.RequireDigit = true;
                opt.Password.RequireUppercase = true;

                // These 2 things below goes in hand. if user fails to login, he will be locked out in 30 mins
                opt.Lockout.MaxFailedAccessAttempts = 2;
                opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);

            }).AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders()
                .AddDefaultUI(); // use the identity default path or we can explicily set in the ConfigureApplicationCookie


            services.AddAuthentication().AddFacebook(options =>
            {
                options.AppId = "760133122002531";
                options.AppSecret = "09e909f641da99ea4eaeaab67abcd010";
            });

            //services.ConfigureApplicationCookie(opt =>
            //{
            //    opt.AccessDeniedPath = new Microsoft.AspNetCore.Http.PathString("/Home/AccessDenied");
            //});

            services.AddAuthorization(opts =>
            {
                opts.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
                opts.AddPolicy("AdminAndUser", policy => policy.RequireRole("Admin").RequireRole("User"));
                opts.AddPolicy("Admin_CreateAccess", policy => policy.RequireRole("Admin").RequireClaim("Create", "True")); // claim type is not case sensitive, however, claim value is case sensitive !!!
                // Create is claim type while True is claim value
                opts.AddPolicy("Admin_Create_Edit_DeleteAccess", policy => policy.RequireRole("Admin")
                .RequireClaim("Create", "True")
                .RequireClaim("Edit", "True")
                .RequireClaim("Delete", "True"));                           

                opts.AddPolicy("Admin_Create_Edit_DeleteAccess_OR_SuperAdmin", policy => policy.RequireAssertion(context =>
                AuthorizeAdminWithClaimsOrSuperAdmin(context)));

                opts.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements.Add(new OnlySuperAdminChecker()));

                opts.AddPolicy("AdminWithMoreThan1000Days", policy => policy.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000))); // add requirement in add policy

                opts.AddPolicy("FirstNameAuth", policy => policy.Requirements.Add(new FirstNameAuthRequirement("Billy")));
            });
            services.AddScoped<IAuthorizationHandler, AdminWithMoreThan1000DaysHandler>(); // add requirement handler in here !!!
            services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();

            // account created over 1000 days
            services.AddControllersWithViews();
            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }

        private bool AuthorizeAdminWithClaimsOrSuperAdmin(AuthorizationHandlerContext context)
        {
            return (context.User.IsInRole("Admin") && context.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
                        && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
                        && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
                    ) || context.User.IsInRole("SuperAdmin");
        }
    }
}
