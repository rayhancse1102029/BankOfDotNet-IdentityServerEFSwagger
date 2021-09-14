using BankOfDotNet.API.Data.Log;
using BankOfDotNet.Data.Entity;
using BankOfDotNet.Services.Jwt;
using IdentiyServerCustom.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentiyServerCustom.Services.Jwt
{
    public class TokenService : ITokenService
    {
        private readonly IServiceScopeFactory scopeFactory;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public TokenService(IServiceScopeFactory scopeFactory, IHttpContextAccessor _httpContextAccessor)
        {
            this.scopeFactory = scopeFactory;
            this._httpContextAccessor = _httpContextAccessor;
        }

        public string BuildToken(string key, string issuer, ApplicationUser user)
        {
            var claims = new[] {
                new Claim(ClaimTypes.Name, user.UserName),
                //new Claim(ClaimTypes.Role, user.nam),
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            var tokenDescriptor = new JwtSecurityToken(issuer, issuer, claims,
                expires: DateTime.Now.AddMinutes(60), signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

        public string GenerateJSONWebToken(string key, string issuer, ApplicationUser user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.SerialNumber, user.EmployeeCode == null ? "9876543210" : user.EmployeeCode),
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(issuer, issuer, claims,
              expires: DateTime.Now.AddHours(6).AddMinutes(2),
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        public async Task<bool> IsTokenValid(string key, string issuer, string token)
        {
            IdentiyUserLog log = new IdentiyUserLog();
            try
            {
                var request = _httpContextAccessor.HttpContext;
                var headers =  _httpContextAccessor.HttpContext.Request.Headers;


                //log = new IdentiyUserLog
                //{
                //    Method = request.Request.Method,
                //    Host = request.Request.Host.Value,
                //    Path = request.Request.Path.Value,
                //    Protocol = request.Request.Protocol,
                //    PathBase = request.Request.PathBase,
                //    IsHttps = request.Request.IsHttps,
                //    Language = headers.Where(x => x.Key == "Accept-Language").FirstOrDefault().Value.FirstOrDefault().ToString(),
                //    Authorization = headers.Where(x => x.Key == "Authorization").FirstOrDefault().Value.FirstOrDefault().ToString(),
                //    ReferUrl = headers.Where(x => x.Key == "Referer").FirstOrDefault().Value.FirstOrDefault().ToString(),
                //    Agent = headers.Where(x => x.Key == "User-Agent").FirstOrDefault().Value.FirstOrDefault().ToString(),
                //    RequestDevice = headers.Where(x => x.Key == "sec-ch-ua").FirstOrDefault().Value.FirstOrDefault().ToString(),
                //    RequestMobileDevice = headers.Where(x => x.Key == "sec-ch-ua-mobile").FirstOrDefault().Value.FirstOrDefault().ToString(),
                //    OS = headers.Where(x => x.Key == "sec-ch-ua-platform").FirstOrDefault().Value.FirstOrDefault().ToString(),
                //    FetchSite = headers.Where(x => x.Key == "sec-fetch-site").FirstOrDefault().Value.FirstOrDefault().ToString(),
                //    FetchMode = headers.Where(x => x.Key == "sec-fetch-mode").FirstOrDefault().Value.FirstOrDefault().ToString(),
                //    IpAddress = _httpContextAccessor.HttpContext.Connection.RemoteIpAddress.ToString(),
                //    CreatedAt = DateTime.Now,
                //    UpdatedAt = null,
                //    Status = 1

                //};

                var mySecret = Encoding.UTF8.GetBytes(key);
                var mySecurityKey = new SymmetricSecurityKey(mySecret);

                var deSerializeToken = new JwtSecurityToken(token);
                var claims = deSerializeToken.Claims;

                if (claims != null && claims.Any())
                {
                    ApplicationUser user = new ApplicationUser();
                    string username = claims.First().Value;
                    //DateTime expiredDateTime = Convert.ToDateTime(deSerializeToken.ValidTo.Date.Date + " " + deSerializeToken.ValidTo.TimeOfDay);

                    using (var scope = scopeFactory.CreateScope())
                    {
                        var db = scope.ServiceProvider.GetRequiredService<IS4DbContext>();
                        user = await db.Users.Where(x => x.UserName == username).FirstOrDefaultAsync();
                        log.UserId = user.Id;
                        log.UserName = user.UserName;
                        log.CreatedBy = user.UserName;

                        if (user.IsVerified == false || user.IsActive == false)
                        {
                            log.Status = 0;
                            return false;
                        }
                        else if (!string.IsNullOrEmpty(user.UserName))
                        {
                            var tokenHandler = new JwtSecurityTokenHandler();
                            try
                            {

                                tokenHandler.ValidateToken(token, new TokenValidationParameters
                                {
                                    //RequireExpirationTime = true,
                                    //RequireSignedTokens = true,
                                    //RequireAudience = true,
                                    //SaveSigninToken = false,
                                    //ValidateActor = false,
                                    //ValidateAudience = true,
                                    //ValidateIssuer = true,
                                    //ValidateIssuerSigningKey = true,
                                    //ValidateLifetime = true,
                                    //ValidateTokenReplay = false,

                                    //ValidIssuer = issuer,
                                    //ValidAudience = issuer,
                                    //IssuerSigningKey = mySecurityKey,
                                    ValidateIssuerSigningKey = true,
                                    ValidateIssuer = true,
                                    ValidateAudience = true,
                                    ValidIssuer = issuer,
                                    ValidAudience = issuer,
                                    IssuerSigningKey = mySecurityKey,
                                    LifetimeValidator = LifetimeValidator

                                }, out SecurityToken validatedToken);
                            }
                            catch
                            {
                                log.Status = 0;
                                return false;
                            }
                        }
                        else
                        {
                            log.Status = 0;
                            return false;
                        }
                    }
                }
                else
                {
                    log.Status = 0;
                    return false;
                }
            }
            catch (Exception)
            {
                log.Status = 0;
                return false;
            }

            using (var scope = scopeFactory.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<IS4DbContext>();
                await db.IdentiyUserLogs.AddAsync(log);
                await db.SaveChangesAsync();              
            }

            return true;
        }

        private bool LifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken token, TokenValidationParameters @params)
        {
            if (expires != null)
            {
                if (expires > DateTime.Now)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
            
        }


    }

}
