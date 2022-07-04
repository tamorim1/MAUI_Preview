using Java.Security;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace MauiApp1.Authentication
{
    public class MauiApp1RefreshTokenHandler : DelegatingHandler
    {
        private MauiApp1AuthenticationService _authenticationService { get; init; }
        public MauiApp1RefreshTokenHandler(MauiApp1AuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }


        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, 
                                                                    CancellationToken cancellationToken)
        {
            
            if (await _authenticationService.TokenService.TokenNeedsRefresh())
            {
                var response = await _authenticationService.Refresh();

                if (!response.Result)
                {
                    _ = await _authenticationService.Logout(false);

                    CancellationTokenSource.CreateLinkedTokenSource(cancellationToken).Cancel();
                }
                else
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", response.Token);
                }

            }
            else
            {
                var token = await _authenticationService.TokenService.GetToken("token");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            }

            //resetar o timer do serviço singleton ou worker

            return await base.SendAsync(request, cancellationToken);
        }
    }
}
