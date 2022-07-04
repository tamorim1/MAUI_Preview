using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using Org.Apache.Http.Client;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace MauiApp1.Authentication
{
    public class MauiApp1AuthenticationService
    {
        private JsonSerializerOptions _jsonSerializerOptions { get; set; } = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        private AuthenticationStateProvider _authenticationStateProvider { get; init; }
        private IHttpClientFactory _httpClientFactory { get; init; }
        public MauiApp1TokenService TokenService { get; init; }

        public MauiApp1AuthenticationService(IHttpClientFactory httpClientFactory,
                                            AuthenticationStateProvider authenticationStateProvider,
                                            MauiApp1TokenService tokenService)
        {
            _httpClientFactory = httpClientFactory;
            _authenticationStateProvider = authenticationStateProvider;
            TokenService = tokenService;

        }

        public async Task<AuthenticationResponseDTO> Login(LoginDTO loginDTO)
        {
            try
            {
                var httpClient = _httpClientFactory.CreateClient("AUTH_API");
                var response = await httpClient.PostAsJsonAsync("auth/login", loginDTO, _jsonSerializerOptions, default);
                var authenticationResponse = await response.Content.ReadFromJsonAsync<AuthenticationResponseDTO>(_jsonSerializerOptions, default);
                if (!response.IsSuccessStatusCode)
                {
                    return authenticationResponse!;
                }

                //criptografar o token
                await TokenService.SetToken("token", authenticationResponse!.Token!);
                await TokenService.SetToken("refreshToken", authenticationResponse!.RefreshToken!);

                ((MauiApp1AuthenticationStateProvider)_authenticationStateProvider).NotifyLogin(authenticationResponse!.Token!);

                return authenticationResponse;
            }
            catch (Exception ex)
            {

                return new AuthenticationResponseDTO()
                {
                    Result = false,
                    Errors = new List<object>() { ex.Message }
                };
            }

        }
        public async Task<AuthenticationResponseDTO> Refresh()
        {
            try
            {

                var token = await TokenService.GetToken("token");
                var refreshToken = await TokenService.GetToken("refreshToken");


                var httpClient = _httpClientFactory.CreateClient("AUTH_API");
                var response = await httpClient.PostAsJsonAsync("auth/refresh", new RefreshDTO() { Token = token, RefreshToken = refreshToken }, _jsonSerializerOptions, default);
                var authenticationResponse = await response.Content.ReadFromJsonAsync<AuthenticationResponseDTO>(_jsonSerializerOptions, default);

                if (!response.IsSuccessStatusCode)
                {
                    return authenticationResponse!;
                }

                await TokenService.SetToken("token", authenticationResponse!.Token!);
                await TokenService.SetToken("refreshToken", authenticationResponse!.RefreshToken!);

                return authenticationResponse;

            }
            catch (Exception ex)
            {
                return new AuthenticationResponseDTO()
                {
                    Result = false,
                    Errors = new List<object>() { ex.Message }
                };
            }
        }

        public async Task<AuthenticationResponseDTO> Logout(bool requestLogout = true)
        {
            var result = new AuthenticationResponseDTO();

            if (requestLogout)
            {
                var httpClient = _httpClientFactory.CreateClient("AUTH_API");
                try
                {
                    if(await TokenService.TokenNeedsRefresh())
                    {
                        var authenticationResponse = await Refresh();
                        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authenticationResponse.Token);
                    }
                    else
                    {
                        var token = await TokenService.GetToken("token");
                        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    }
                    var response = await httpClient.PostAsJsonAsync("auth/logout", new { }, default);
                }
                catch (Exception ex)
                {
                    result.Errors = new List<object>() { ex.Message };
                }
            }

            await TokenService.RemoveToken("token");
            await TokenService.RemoveToken("refreshToken");

            ((MauiApp1AuthenticationStateProvider)_authenticationStateProvider).NotifyLogout();
            

            return result;
        }

    }

}
