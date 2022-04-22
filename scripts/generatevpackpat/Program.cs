using Microsoft.VisualStudio.Services.WebApi;
using Microsoft.VisualStudio.Services.DelegatedAuthorization.WebApi;
using Microsoft.VisualStudio.Services.Client;
using Newtonsoft.Json;
using Microsoft.VisualStudio.Services.Common;
using System.Threading.Tasks;
using System;
using System.Net.Http;
using System.Linq;
using Microsoft.VisualStudio.Services.DelegatedAuthorization;

namespace GenerateVpackPat
{
    public class Accounts
    {
        public string AccountName { get; set; }
        public Guid AccountId { get; set; }
    }
    public class Program
    {
        public static async Task Main()
        {
            var credentials = new VssClientCredentials();

            var scopes = "vso.build vso.code_write vso.drop_manage vso.identity vso.packaging";
            var tokenAccounts = new[] { "mscodehub", "microsoft" };

            var accountsUrl = "https://app.vssps.visualstudio.com";
            var connection = new VssConnection(new Uri(accountsUrl), credentials);
            var client = new HttpClient(connection.InnerHandler);
            string result = await client.GetStringAsync($"{accountsUrl}/_apis/accounts");
            var accounts = JsonConvert.DeserializeObject<Accounts[]>(result);
            var accountIds = accounts.Where(x => tokenAccounts.Contains(x.AccountName)).Select(x => x.AccountId).ToList();
            if (accountIds.Count != tokenAccounts.Length)
            {
                Console.WriteLine("Did not find all necessary accounts");
                return;
            }

            var tokenClient = await connection.GetClientAsync<TokenHttpClient>();

            var now = DateTime.UtcNow;

            var session = new SessionToken()
            {
                DisplayName = $"MsQuic Vpack Ingest Token {now.ToShortDateString()}",
                Scope = scopes,
                TargetAccounts = accountIds,
                ValidFrom = now,
                ValidTo = now + TimeSpan.FromDays(180)
            };

            var Pat = await tokenClient.CreateSessionTokenAsync(session, SessionTokenType.Compact, isPublic: false);

            Console.WriteLine($"Your PAT is: {Pat.Token}");
        }
    }
}
