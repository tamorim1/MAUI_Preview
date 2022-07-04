using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Khronos.Base.Frontend.Web.Shared.KhronosToast
{
    public class KhronosToastService
    {
        public event Func<string, string,string,int, Task>? OnToastShow;

        public async Task ToastShow(string title, string content, string type, int timeout)
        {
            await OnToastShow?.Invoke(title, content,type,timeout)!;

        }
    }
}
