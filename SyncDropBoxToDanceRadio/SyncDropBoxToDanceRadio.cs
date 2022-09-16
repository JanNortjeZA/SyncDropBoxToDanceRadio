using System;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Storage.Blob;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Extensions.Logging;
using SyncDropBoxToDanceRadio;


namespace SyncDropBoxToDanceRadio
{
    public class SyncDropBoxToDanceRadio
    {
        public  IProgram _program;
      //  private readonly ILogger<SyncDropBoxToDanceRadio> _log;
        //private readonly IInstantSMS _instantSMS;

        //public SyncDropBoxToDanceRadio( ILogger<SyncDropBoxToDanceRadio> log)
        //{
        //  //  _program =  iprogram;
        //    _log = log;
        //    //_instantSMS = instantSMS;
        //}
        // Program


        ///  CRON expression
        /// {second} {minute} {hour} {day} {month} {day-of-week}
        [FunctionName("SyncDropBoxToDanceRadio")]
        public  void Run([TimerTrigger("0 */1 * * * *")]TimerInfo myTimer, ILogger log)
        {
             _program = new Program(log);
           // Console.WriteLine("faunction started!");
            log.LogInformation($"C# Timer trigger function executed at: {DateTime.Now}");
             _program.Run();
        }


         
    }


  
}

