using System;
using System.Threading.Tasks;

namespace Khronos.Base.Frontend.Web.Shared.KhronosDialog
{
    public class KhronosDialogService
    {
        public event Func<string, string, Func<Task>,Task>? OnDialogShow;

        public async Task DialogShow(string header, string content, Func<Task> OnOk)
        {
            await OnDialogShow?.Invoke(header, content, OnOk)!;

        }
    }
}
