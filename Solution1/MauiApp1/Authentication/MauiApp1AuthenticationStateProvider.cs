using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MauiApp1.Authentication
{
    public class MauiApp1AuthenticationStateProvider : AuthenticationStateProvider
    {
        private MauiApp1TokenService _tokenService { get; init; }
        private AuthenticationState _authenticationStateAnonymous { get; init; }
        public MauiApp1AuthenticationStateProvider(MauiApp1TokenService tokenService)
        {
            _tokenService = tokenService;
            _authenticationStateAnonymous = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {

            var token = await _tokenService.GetToken("token");

            if (string.IsNullOrWhiteSpace(token))
            {
                return _authenticationStateAnonymous;
            }

            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(jwt!.Claims, "jwtAuthType")));
        }
        public void NotifyLogin(string token)
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var authState = Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(jwt!.Claims, "jwtAuthType"))));
            NotifyAuthenticationStateChanged(authState);
        }
        public void NotifyLogout()
        {
            var authState = Task.FromResult(_authenticationStateAnonymous);
            NotifyAuthenticationStateChanged(authState);
        }

    }
}
