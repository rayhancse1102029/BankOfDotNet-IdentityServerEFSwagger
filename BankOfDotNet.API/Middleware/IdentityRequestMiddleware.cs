using BankOfDotNet.Services.Jwt;
using IdentiyServerCustom.Services.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BankOfDotNet.Middleware
{
    public class IdentityRequestMiddleware
    {
        private readonly ILogger<IdentityRequestMiddleware> _logger;
        private readonly ITokenService _tokenService;
        private readonly IConfiguration _config;
        private readonly RequestDelegate _next;

        public IdentityRequestMiddleware(
            ILogger<IdentityRequestMiddleware> logger,
            ITokenService _tokenService,
            IConfiguration _config,
            RequestDelegate _next)
        {
            _logger = logger;
            this._tokenService = _tokenService;
            this._config = _config;
            this._next = _next;
        }

        public async Task Invoke(HttpContext httpContext)
        {

            string path = httpContext.Request.Path.Value;


            if (path.ToLower() == "/" || path.ToLower() == "/swagger/index.html" || path.ToLower() == "/swagger/v1/swagger.json" || path.ToLower() == "/register" || path.ToLower() == "/login")
            {
                await _next(httpContext);
            }
            else
            {
                string token = httpContext.Session.GetString("Authorization");

                if (token == null)
                {
                    httpContext.Response.StatusCode = 400; //Bad Request
                    httpContext.Response.ContentType = "UnAuthorize";
                    await httpContext.Response.WriteAsync("User Key is missing");
                    return;
                }

                bool isValidToken = await _tokenService.IsTokenValid(_config["Jwt:Key"].ToString(), _config["Jwt:Issuer"].ToString(), token);
                //bool isValidToken = true;
                if (isValidToken)
                {
                    await _next(httpContext);
                }
                else
                {
                    httpContext.Response.StatusCode = 400; //Bad Request
                    httpContext.Response.ContentType = "UnAuthorize";
                    await httpContext.Response.WriteAsync("User Key is missing");
                    return;
                }
            }
        }
    }
}
