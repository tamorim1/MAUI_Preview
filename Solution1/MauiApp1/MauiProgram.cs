using MauiApp1.Authentication;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebView.Maui;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Maui.Controls.Hosting;
using Microsoft.Maui.Hosting;
using Syncfusion.Blazor;
using Microsoft.Maui.LifecycleEvents;

namespace MauiApp1
{
    public static class MauiProgram
    {
        public static MauiApp CreateMauiApp()
        {
            Syncfusion.Licensing.SyncfusionLicenseProvider.RegisterLicense("NjU0OTk4QDMyMzAyZTMxMmUzMEp4dVJNWHQ1SkkxNHNhM2FLTDl6OG1zUFUrQ29FeHdDWDJjS2hVOURMeEk9");
            var builder = MauiApp.CreateBuilder();
            builder.UseMauiApp<App>().ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
            });
            builder.Services.AddSyncfusionBlazor();
            builder.Services.AddMauiBlazorWebView();
#if DEBUG
		    builder.Services.AddBlazorWebViewDeveloperTools();
#endif
            builder.Services.AddAuthorizationCore();
            

            builder.Services.AddHttpClient("API", c =>
            {
                c.BaseAddress = new Uri(Configuration.APIUrl);
                c.Timeout = TimeSpan.FromSeconds(15);
            }).AddHttpMessageHandler<MauiApp1RefreshTokenHandler>();

            builder.Services.AddHttpClient("AUTH_API", c =>
            {
                c.BaseAddress = new Uri(Configuration.APIUrl);
                c.Timeout = TimeSpan.FromSeconds(15);
            });

            builder.ConfigureLifecycleEvents(ev =>
            {
#if ANDROID
                ev.AddAndroid(android => android
                    .OnStart( async (activity) =>
                    {
                        var service = builder.Services.BuildServiceProvider().GetRequiredService<MauiApp1WorkerService>();
                        await service.StartAsync(default);
                    })
                    .OnStop( async (activity) =>
                    {
                        var service = builder.Services.BuildServiceProvider().GetRequiredService<MauiApp1WorkerService>();
                        await service.StopAsync(default);
                    }));
#endif
            });

            //builder.Services.AddHostedService<MauiApp1WorkerService>();
            builder.Services.AddSingleton<MauiApp1WorkerService>();

            builder.Services.AddSingleton<Khronos.Base.Frontend.Web.Shared.KhronosToast.KhronosToastService>();
            builder.Services.AddSingleton<Khronos.Base.Frontend.Web.Shared.KhronosDialog.KhronosDialogService>();

            builder.Services.AddScoped<AuthenticationStateProvider, MauiApp1AuthenticationStateProvider>();
            builder.Services.AddScoped<MauiApp1AuthenticationService>();
            builder.Services.AddScoped<MauiApp1TokenService>();          
            builder.Services.AddScoped<MauiApp1RefreshTokenHandler>();
            //está falhando, futuramente ver se corrigiu
            //builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("API"));

            builder.Services.AddScoped(typeof(Khronos.Base.Frontend.Web.Shared.KhronosAdaptor.KhronosAdaptor<>));


            return builder.Build();
        }
    }

    //não funciona em ihostedservice 
    //implementar depois um serviço de fundo para android com notificações
    public class MauiApp1WorkerService : IHostedService, IAsyncDisposable
    {
        private IServiceScopeFactory _serviceScopeFactory { get; init; }
        private Timer? _timer { get; set; }
        private HubConnection _hubConnection { get; init; }
        public MauiApp1WorkerService(IServiceScopeFactory serviceScopeFactory)
        {
            _serviceScopeFactory = serviceScopeFactory;
            _hubConnection = new HubConnectionBuilder().WithUrl(new Uri($"{Configuration.APIUrl}/hubs/sync"))
                                                       .Build();
            _hubConnection.Closed += async (error) =>
            {
                await Task.Delay(5000);
                await _hubConnection.StartAsync();
            };

            _hubConnection.On<List<MauiApp1.Pages.Empresas.EmpresasTableDTO>>("ResponseEmpresasSelect", ResponseEmpresasSelect);
        }

        public Task ResponseEmpresasSelect(List<MauiApp1.Pages.Empresas.EmpresasTableDTO> empresasTableDTOs)
        {
            var e = empresasTableDTOs;
            return Task.CompletedTask;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            try
            {
                await _hubConnection.StartAsync(cancellationToken);
            }
            catch (Exception ex)
            {

            }
            _timer = new(async (o) => { await ExecuteAsync(cancellationToken); },
                        null,
                        0,
                        (int)TimeSpan.FromSeconds(60).TotalMilliseconds);
        }

        private async Task ExecuteAsync(CancellationToken cancellationToken)
        {
            try
            {
                if(_hubConnection.State != HubConnectionState.Connected)
                {
                    await _hubConnection.StartAsync();
                }

                await _hubConnection.InvokeAsync("RequestEmpresasSelect", cancellationToken);

            }
            catch (Exception ex)
            {

            }
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            _timer?.Change(Timeout.Infinite, 0);
            await _hubConnection.StopAsync(cancellationToken);
        }

        public void AlterTime(bool execute, int interval)
        {
            if (execute)
            {
                _timer?.Change(0, (int)TimeSpan.FromSeconds(interval).TotalMilliseconds);
            }
            else
            {
                _timer?.Change(Timeout.Infinite, 0);
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_timer is IAsyncDisposable timer)
            {
                await timer.DisposeAsync();
            }

            _timer = null;
            await _hubConnection.DisposeAsync();
        }
    }
}