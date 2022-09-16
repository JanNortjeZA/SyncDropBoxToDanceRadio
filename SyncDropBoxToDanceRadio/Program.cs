using System;
using Dropbox.Api;
using System.Threading.Tasks;
using WinSCP;
using Azure.Storage.Blobs;
using static System.Net.WebRequestMethods;
using System.IO;
using System.Text;
using static Dropbox.Api.Files.WriteConflictError;
using System.Reflection.Metadata;
using Newtonsoft.Json;
using Azure;

using System.Collections.Generic;
using static System.Reflection.Metadata.BlobBuilder;
using Dropbox.Api.Files;
using static Dropbox.Api.Files.FileCategory;
using static Dropbox.Api.Files.SearchMatchType;
using static Dropbox.Api.Files.SearchMatchTypeV2;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Azure.Core;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json.Linq;
//using DropNet;
//using Microsoft.Azure.KeyVault.Core;
using System.Runtime.InteropServices;
using System.Net;
//using File = System.Net.WebRequestMethods.File;
using SyncDropBoxToDanceRadio.Models;
using System.Threading;
using File = System.IO.File;

namespace SyncDropBoxToDanceRadio
{
    public class ListFolderContinue
    {
        public List<entries> entries { get; set; } = new List<entries>();
        public string cursor { get; set; }
        public bool has_more { get; set; }
    }
    public class entries
    {
        public string path_lower { get; set; }
        public string name { get; set; }
        public string  id { get; set; }
    }
    public interface IProgram
    {
        //void Process(bool fromQueue = false);
        void Run();
        void testTimer();
    }

    public class Program : IProgram
    {

        private  static ILogger _logger;
        // private readonly IWebServiceWorker _webWorker;
        //private readonly IProgram program;

        public Program(ILogger logger)
        {
            _logger = logger;
           // program = 
            
        }

        public static string _lastCursor { get; set; } = "AAEOQdkibG266z2W-Pgi8NuRlMVEMsjxwt3pR6kmY2sYvLeAuvkJZ0waBPi9wF1Y8EoMn1LirfUDgzJCupK4y6gDGygxL1HtGErFCfbeaDl-1k2rtH7-gjHi1Zkd_mls0104ARZcsdDb_fDyjuOlgFU3xe6l4lJ1gWRmCOmd0rDUMvcxJbyvAHLDVSEjAtdTkAs";
        static string blobConnectionstring = "DefaultEndpointsProtocol=https;AccountName=danceradiozabd6f;AccountKey=ZbSrYcl8wXP+cyojfr/7ZJN3DYxhFxl0fw6kZydmJ86WqUb6EqQUuFzdMjZcZWchTxU+fC5aHVcj+ASteJPpzw==;EndpointSuffix=core.windows.net;";
        static  string[] scopeList = new string[3] { "files.metadata.read", "files.metadata.read", "files.content.read"};
        //  private static Session session;
        // private const string redirectURL = "https://danceradio-dropbox.azurewebsites.net";
        private const string appKey = "szkc2herqfkufr9";
        private const string appSec = "17obxojfkr2neja";
        private const string LoopbackHost = "https://danceradio-dropbox.azurewebsites.net/";

        // URL to receive OAuth 2 redirect from Dropbox server.
        // You also need to register this redirect URL on https://www.dropbox.com/developers/apps.
        private readonly Uri RedirectUri = new Uri(LoopbackHost + "authorize");

        // URL to receive access token from JS.
        private readonly Uri JSRedirectUri = new Uri(LoopbackHost + "token");

        public void testTimer()
        {
            _logger.LogInformation("timer test :)");

        }


      public  void Run()
        {
            
            dynamic jsonObject = new JObject();
            jsonObject.oauth1_token = "qievr8hamyg6ndck";
            jsonObject.oauth1_token_secret = "qomoftv0472git7";
            string json = JsonConvert.SerializeObject(jsonObject);



              _logger.LogInformation($"authenticating to: DropBox");
            //HttpClient client = NewBasicHttpClient("https://api.dropboxapi.com",appKey,appSec);
            //var autResult = (Task.Run(async () => await PostJsonToURLAsync(client, "/2/auth/token/from_oauth1", json))).Result;
            //_logger.LogInformation(autResult);
            //string oAuthToken = "";
            //if (autResult != null)
            //{
            //    JObject _current = JObject.Parse(json);
            //    oAuthToken = _current["oauth2_token"].ToString();
            //}
           // IDropNetClient _client = new DropNetClient(appKey,appSec);
          //  var uri = _client.BuildAuthorizeUrl("https://danceradio-dropbox.azurewebsites.net");
          //  _logger.LogInformation($"token: {JsonConvert.SerializeObject(uri)}");

          //  DropNet.Models.UserLogin token =  _client.GetAccessToken();
           // _logger.LogInformation($"token: {JsonConvert.SerializeObject(token)}");
            // var authTicket = DropboxOAuth2Helper.ProcessCodeFlowAsync( );
            // using (var dbx = new DropboxClient("sl.BPTByEdLn9ehLFY0zRKnXi3kxPwWC8l3IG6Wl8fUeGDGd7ysdCUlykdndzf4dh2bkSueca54aGuzNNqf-4liDl2avL-O25aqyGbVoICTGC1baBTtfDUXpEGwfJWJdSpLKwT09fsv"))
            if ( RunAuth() == 1)
            {
                _logger.LogInformation($"AccessToken: {Global.AccessToken}");
            }

            Task.Run(async () => await this.AcquireAccessToken(scopeList, IncludeGrantedScopes.User));
            var clientNew = new DropboxClient(Global.AccessToken);
            using (clientNew)
            {
                // var full = await dbx.Users.GetCurrentAccountAsync();
                // _logger.LogInformation("{0} - {1}", full.Name.DisplayName, full.Email);
                string lastCur = (Task.Run(async () => await GetLastCursor())).Result;
                if (lastCur == null || lastCur == "")
                {
                    lastCur = _lastCursor;
                }
                var dif = (Task.Run(async () => await clientNew.Files.ListFolderGetLatestCursorAsync(lastCur, true))).Result;
                  //  var dif = await dbx.Files.ListFolderGetLatestCursorAsync(lastCur, true).Result;
              
               
                var retObj = JsonConvert.DeserializeObject<ListFolderContinue>(dif.Cursor);
                _logger.LogInformation($"Has files to process: {retObj.has_more} ");
                if (retObj.has_more)
                {
                    _logger.LogInformation($"{retObj.entries.Count} file/s to be copied");
                    foreach (var file in retObj.entries)
                    {
                        string remFilePath = string.Concat("/DrpBox/", file.path_lower);
                        var filestr = (Task.Run(async () => await clientNew.Files.DownloadAsync(file.id))).Result;
                        //using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(filestr.)))
                        var str = Task.Run(async () => await filestr.GetContentAsStreamAsync()).Result;
                        str.Position = 0;
                        int result = UploadToSftp(str, remFilePath, file.name);
                        if (result == 0)
                            _logger.LogInformation(file.name + " added to danceradio");
                       


                    }
                }
               

            }
            //return str;
        }


        static async Task<string> GetLastCursor()
        {

            string blobStorageConnectionString = blobConnectionstring;
            var blobStorageContainerName = "danceradio-cursor";
            var container = new BlobContainerClient(blobStorageConnectionString, blobStorageContainerName);
            var blob = container.GetBlobClient("/" + "cursor.json");
            var response = await blob.OpenReadAsync();
            response.Position = 0;
            StreamReader reader = new StreamReader(response);
            var final1 = reader.ReadToEnd();

            return final1;

            
        }


        static void SetLastCursor(string newCursor)
        {
            string blobStorageConnectionString = blobConnectionstring;
            var blobStorageContainerName = "danceradio-cursor";
            var container = new BlobContainerClient(blobStorageConnectionString, blobStorageContainerName);
            var blob = container.GetBlobClient("/" + "cursor.json");
            //MemoryStream mStream = new MemoryStream();
            //newCursor.Value.CopyTo(mStream);
            //mStream.Position = 0;
            using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(newCursor)))
            {
                 blob.Upload(ms);
            }
           
        }


        static int UploadToSftp(Stream stream, string remPath, string fileName)
        {
            try
            {
                // Setup session options
                SessionOptions sessionOptions = new SessionOptions
                {
                    Protocol = Protocol.Sftp,
                    HostName = "41.76.109.47",
                    PortNumber = 22,
                    UserName = "danceradio",
                    Password = "djTubel3ss@2022",
                   // SshHostKeyFingerprint = "ssh-rsa 2048 xxxxxxxxxxx..."
                };

                using (Session session = new Session())
                {
                    // Connect
                    session.Open(sessionOptions);

                    // Upload files
                    TransferOptions transferOptions = new TransferOptions();
                    transferOptions.OverwriteMode = OverwriteMode.Overwrite;
                    transferOptions.TransferMode = TransferMode.Binary;
                    string remFilePath = string.Concat("/DrpBox/", remPath);
                    string ext = Path.GetExtension(fileName);
                    // TransferOperationResult transferResult;
                    //Session session1 = session;
                    using (stream)
                    {
                        session.PutFile(stream, remFilePath, transferOptions);
                      _logger.LogDebug($"Saved {remFilePath}/{fileName} ");
                    }




                    }

                    // Throw on any error
                    //  transferResult.Check();

                    // Print results
                    //foreach (TransferEventArgs transfer in transferResult.Transfers)
                    //{
                    //    _logger.LogInformation("Upload of {0} succeeded", transfer.FileName);
                    //}
               
                
                return 0;
            }
            catch (Exception e)
            {
                _logger.LogError("Error: ", e);
                return 1;
            }
        }


        private int RunAuth()
        {
           // DropboxCertHelper.InitializeCertPinning();

         
           // var uid = await this.AcquireAccessToken(scopeList, IncludeGrantedScopes.None);
            var uid = Task.Run(async () => await this.AcquireAccessToken(scopeList, IncludeGrantedScopes.User)).Result;
            if (string.IsNullOrEmpty(uid))
            {
                _logger.LogInformation("uid is NULL");
                return 1;
            }

            // Specify socket level timeout which decides maximum waiting time when no bytes are
            // received by the socket.
            //var httpClient = new HttpClient({ ReadWriteTimeout = 10 * 1000 })
            //{
            //    // Specify request level timeout which decides maximum time that can be spent on
            //    // download/upload files.
            //    Timeout = TimeSpan.FromMinutes(20)
            //};


            HttpClient httpClient = new HttpClient();
            httpClient.Timeout = TimeSpan.FromMinutes(10);
            try
            {
                var config = new DropboxClientConfig("SyncDropBoxToDanceRadio")
                {
                    HttpClient = httpClient
                };

                var client = new DropboxClient(Global.AccessToken, Global.RefreshToken, appKey, appSec, config);

                // This call should succeed since the correct scope has been acquired
              //  await GetCurrentAccount(client);

                _logger.LogWarning($"Successfully created client :) ");
               // var newScopes = new string[] { "files.metadata.read", "files.content.read" };
               // await client.RefreshAccessToken(scopeList).Result;
               // Task.Run(async () => await client.RefreshAccessToken(scopeList));
                //try
                //{
                //    // This should fail since token does not have "account_info.read" scope  
                //    await GetCurrentAccount(client);
                //}
                //catch (Exception)
                //{
                //    _logger.LogInformation("Correctly failed with invalid scope");
                //}
              //  _logger.LogInformation("Attempting to try again with include_granted_scopes");
                // await this.AcquireAccessToken(scopeList, IncludeGrantedScopes.User);
              
               // await GetCurrentAccount(clientNew);

                //_logger.LogInformation("Oauth Test Complete!");
                //_logger.LogInformation("Exit with any key");
                //Console.ReadKey();
            }
            catch (HttpException e)
            {
                _logger.LogError("Exception reported from RPC layer");
                _logger.LogError("    Status code: ", e.StatusCode);
                _logger.LogError("    Message    : ", e.Message);
                if (e.RequestUri != null)
                {
                    _logger.LogError("    Request uri: ", e.RequestUri);
                }
                return 1;
            }

            return 0;
        }

        private async Task HandleOAuth2Redirect(HttpListener http)
        {
            var context = await http.GetContextAsync();
            _logger.LogInformation($"    Request.Url    : {context.Request.Url.AbsolutePath}");
            // We only care about request to RedirectUri endpoint.
            while (context.Request.Url.AbsolutePath != RedirectUri.AbsolutePath)
            {
                context = await http.GetContextAsync();
            }

            context.Response.ContentType = "text/html";

            // Respond with a page which runs JS and sends URL fragment as query string
            // to TokenRedirectUri.
            using (var file = File.OpenRead("index.html"))
            {
                file.CopyTo(context.Response.OutputStream);
            }

            context.Response.OutputStream.Close();
        }

        /// <summary>
        /// Handle the redirect from JS and process raw redirect URI with fragment to
        /// complete the authorization flow.
        /// </summary>
        /// <param name="http">The http listener.</param>
        /// <returns>The <see cref="OAuth2Response"/></returns>
        private async Task<Uri> HandleJSRedirect(HttpListener http)
        {
            var context = await http.GetContextAsync();
            _logger.LogInformation($"    Request uri: {context.Request.Url.AbsolutePath}");
            // We only care about request to TokenRedirectUri endpoint.
            while (context.Request.Url.AbsolutePath != JSRedirectUri.AbsolutePath)
            {
                context = await http.GetContextAsync();
            }

            var redirectUri = new Uri(context.Request.QueryString["url_with_fragment"]);

            return redirectUri;
        }

        /// <summary>
        /// Acquires a dropbox access token and saves it to the default settings for the app.
        /// <para>
        /// This fetches the access token from the applications settings, if it is not found there
        /// (or if the user chooses to reset the settings) then the UI in <see cref="LoginForm"/> is
        /// displayed to authorize the user.
        /// </para>
        /// </summary>
        /// <returns>A valid uid if a token was acquired or null.</returns>
        private async Task<string> AcquireAccessToken(string[] scopeList, IncludeGrantedScopes includeGrantedScopes)
        {
           ;

            var accessToken = Global.AccessToken;
            var refreshToken = Global.RefreshToken;

            if (string.IsNullOrEmpty(accessToken))
            {
                try
                {
                    _logger.LogInformation("Waiting for credentials.");
                    var state = "671B1890-2D78-4B3A-A3F1-F5BF3255817B";
                    _logger.LogInformation($"My Guid {state}");
                    var authorizeUri = DropboxOAuth2Helper.GetAuthorizeUri(OAuthResponseType.Code, appKey, RedirectUri, state: state, tokenAccessType: TokenAccessType.Offline, scopeList: scopeList, includeGrantedScopes: includeGrantedScopes);
                    var http = new HttpListener();
                    
                    http.Prefixes.Add(LoopbackHost);

                    http.Start();

                    System.Diagnostics.Process.Start(authorizeUri.ToString());

                    // Handle OAuth redirect and send URL fragment to local server using JS.
                    await HandleOAuth2Redirect(http);

                    // Handle redirect from JS and process OAuth response.
                    var redirectUri = await HandleJSRedirect(http);

                    _logger.LogInformation("Exchanging code for token");
                    var tokenResult = await DropboxOAuth2Helper.ProcessCodeFlowAsync(redirectUri, appKey, appSec, RedirectUri.ToString(), state);
                    _logger.LogInformation("Finished Exchanging Code for Token");
                    // Bring console window to the front.
                   // SetForegroundWindow(GetConsoleWindow());
                    accessToken = tokenResult.AccessToken;
                    refreshToken = tokenResult.RefreshToken;
                    var uid = tokenResult.Uid;
                    _logger.LogDebug($"Uid: {uid}");
                    _logger.LogDebug($"AccessToken: {accessToken}");
                    if (tokenResult.RefreshToken != null)
                    {
                        _logger.LogInformation($"RefreshToken: {refreshToken}");
                        Global.RefreshToken = refreshToken;
                    }
                    if (tokenResult.ExpiresAt != null)
                    {
                        _logger.LogInformation($"ExpiresAt: {tokenResult.ExpiresAt}" );
                    }
                    if (tokenResult.ScopeList != null)
                    {
                        _logger.LogInformation($"Scopes: {String.Join(" ", tokenResult.ScopeList)}");
                    }
                    //Settings.Default.AccessToken = accessToken;
                    //Settings.Default.Uid = uid;
                    //Settings.Default.Save();
                    http.Stop();
                    return uid;
                }
                catch (Exception e)
                {
                    _logger.LogError("Error: ", e.Message);
                    return null;
                }
            }

            return null;
        }


        public string GetBasicHeader( string appKey, string appSecret)
        {
           return Convert.ToBase64String(Encoding.GetEncoding("ISO-8859-1").GetBytes($"{appKey}:{appSecret}"));
        }

        public async Task<string> PostJsonToURLAsync(HttpClient client, string url,  string json)
        {
            var response = client.PostAsync(url, new StringContent(json, Encoding.UTF8, "application/json")).Result;
            return await response.Content.ReadAsStringAsync();

        }

        public HttpClient NewBasicHttpClient(string host, string username, string password)
        {
            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri(host);
            string encoded = Convert.ToBase64String(Encoding.GetEncoding("ISO-8859-1").GetBytes($"{username}:{password}"));
            client.DefaultRequestHeaders.Add("Authorization", string.Concat("Basic ", encoded));
            return client;
        }



    }
}


