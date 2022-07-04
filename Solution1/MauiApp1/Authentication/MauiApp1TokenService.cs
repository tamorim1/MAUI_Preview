using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MauiApp1.Authentication
{
 
    public class MauiApp1TokenService
    {
        private IJSRuntime _jSRuntime { get; init; }
        
        public MauiApp1TokenService(IJSRuntime jSRuntime)
        {
            _jSRuntime = jSRuntime;
        }


        public async Task<string> GetToken(string key)
        {
            
            //var module = await _jSRuntime.InvokeAsync<IJSObjectReference>("import", "./khronos-app/khronos-app.js");
            //descriptografar o token
            //var token = await module.InvokeAsync<string>("getItemLocalStorage", key);

            //await module.DisposeAsync();

            var token = await SecureStorage.GetAsync(key);

            return token;
        }

        public async Task SetToken(string key, string value)
        {
            //var module = await _jSRuntime.InvokeAsync<IJSObjectReference>("import", "./khronos-app/khronos-app.js");
            //await module.InvokeVoidAsync("setItemLocalStorage", new object[] { key, value });

            //await module.DisposeAsync();

            await SecureStorage.SetAsync(key, value);
        }

        public async Task RemoveToken(string key)
        {
            //var module = await _jSRuntime.InvokeAsync<IJSObjectReference>("import", "./khronos-app/khronos-app.js");
            //await module.InvokeVoidAsync("removeItemLocalStorage", key);

            //await module.DisposeAsync();

            SecureStorage.Remove(key);
            await Task.CompletedTask;
        }

        public async Task<bool> TokenNeedsRefresh()
        {
            var token = await GetToken("token");
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var authenticationState = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(jwt!.Claims, "jwtAuthType")));

            var exp = authenticationState.User!.FindFirst(c => c.Type.Equals("exp"))!.Value;
            var expTime = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(exp));
            var timeUTC = DateTime.UtcNow;
            var diff = expTime - timeUTC;

            return diff.TotalSeconds <= 30 ? true : false;
        }

    }
}
