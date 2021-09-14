using BankOfDotNet.Data.Entity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BankOfDotNet.Services.Jwt
{
    public interface ITokenService
    {   
        string BuildToken(string key, string issuer, ApplicationUser user);
        string GenerateJSONWebToken(string key, string issuer, ApplicationUser user);
        Task<bool> IsTokenValid(string key, string issuer, string token);
    }
}
