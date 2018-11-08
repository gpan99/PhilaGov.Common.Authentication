using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PhilaGov.Common.Authentication.Services
{
   
    public class MethodResult
    {
       public bool Success { get; set; }

        public string Error { get; set; }

        public List<string> ErrorList { get; set; }
    }

    public class MethodResult<T> : MethodResult
    {
        public T Data { get; set; }
    }

    // extension class if needed to extend results
    public static class MethodResultExtensions
    {
       //sample method.. not for any use.  
        public static void  AdditionalInfo(this MethodResult methodResult)
        {

        }
    }

}
