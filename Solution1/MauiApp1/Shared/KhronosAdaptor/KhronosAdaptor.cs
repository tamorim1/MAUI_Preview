using Khronos.Base.Frontend.Web.Shared.KhronosToast;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Syncfusion.Blazor;
using Syncfusion.Blazor.Data;
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using MauiApp1.Entities;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.SignalR.Client;
using System.Threading;

namespace Khronos.Base.Frontend.Web.Shared.KhronosAdaptor
{
    public class KhronosAdaptor<TDTO> : DataAdaptor
    {

        private KhronosToastService _toastService { get; init; }
        private IHttpClientFactory _httpClientFactory { get; init; }

        public KhronosAdaptor(IHttpClientFactory httpClientFactory,
                             KhronosToastService toastService)
        {

            _httpClientFactory = httpClientFactory;
            _toastService = toastService;
        }

        public override async Task<object> ReadAsync(DataManagerRequest dataManagerRequest, string key = null)
        {

            try
            {
                using (var dbConntext = new MauiApp1DbContext())
                {
                    //dbConntext.EmpresasTable.Add(new()
                    //{
                    //    Id = Guid.NewGuid(),
                    //    CodigoEmpresa = 3,
                    //    NomeEmpresa = "TESTE SQLITE",
                    //    Ativo = true
                    //});

                    //dbConntext.SaveChanges();
                    var e = dbConntext.EmpresasTable.First();
                };
            }
            catch (Exception ex)
            {
                await _toastService.ToastShow("Error", ex.Message, "error", 5000);
            }
            
            try
            {
                //modo single channel
                var hubConnection = new HubConnectionBuilder().WithUrl(new Uri($"{MauiApp1.Configuration.APIUrl}/hubs/sync"))
                                                              .Build();
                await hubConnection.StartAsync();

                var response = await hubConnection.InvokeAsync<List<MauiApp1.Pages.Empresas.EmpresasTableDTO>>("RequestEmpresasSelect1");

                await hubConnection.StopAsync();

                await hubConnection.DisposeAsync();
            }
            catch (Exception ex)
            {

                await _toastService.ToastShow("Error", ex.Message, "error", 5000);
            }

            try
            {
                var httpClient = _httpClientFactory.CreateClient("API");
                var results = await httpClient.GetFromJsonAsync<List<TDTO>>("/empresas/select",default);

                var dataResult = new DataResult();

                dataResult.Result = results;

                if (dataManagerRequest.RequiresCounts)
                {
                    dataResult.Count = results!.Count;
                }

                return dataManagerRequest.RequiresCounts ? dataResult : dataResult.Result!;


            }
            catch (Exception ex)
            {
                
                await _toastService.ToastShow("Error", ex.Message, "error", 5000);
                return new DataResult() { Result = null, Count = 0 };
            }

            

        }


    }
}
