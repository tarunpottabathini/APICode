using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text;

namespace APIapplication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Home : ControllerBase
    {
        [HttpGet]
        public async Task TestOktaAsync()
        {
            HttpClient client = new HttpClient();
            //var request = new HttpRequestMessage(HttpMethod.Post, new Uri("https://altruistahealth.okta.com/oauth2/default/v1/token"));
            ////request.Headers.Add("Accept", "application/json");          
            ////if (!string.IsNullOrEmpty(authorization))
            ////    request.Headers.Add("Authorization", authorization);
            //var byteArray = Encoding.ASCII.GetBytes("0oa7sqx2a1WTckpLH4h7" + ":" + "rqVugE_1y1Y5Mg-PgTAG8xzr7oXeQ-4DPNQKzJ5Iut3af6uCkTGpdyddwWoYBDtE");

            //client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

            var content1 = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("redirect_uri", "https://emr.auth.uniteustraining.com/auth/smartonfhir/callback"),
                new KeyValuePair<string, string>("code", "ZNT1WGhrC4rfMBACScVhwPUsnNWZMrOeBedc1M3AdB0")
            });
            //request.Content = content;
            //request.Content.Headers.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded");
            //var response = await client.SendAsync(request);

            //var sf = "";
            var byteArray = Encoding.ASCII.GetBytes("0oa7sqx2a1WTckpLH4h7" + ":" + "rqVugE_1y1Y5Mg-PgTAG8xzr7oXeQ-4DPNQKzJ5Iut3af6uCkTGpdyddwWoYBDtE");

            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

            var postMessage = new Dictionary<string, string>
        {
            {"grant_type", "authorization_code"},
            {"redirect_uri", "https://emr.auth.uniteustraining.com/auth/smartonfhir/callback"},
             {"code", "ZNT1WGhrC4rfMBACScVhwPUsnNWZMrOeBedc1M3AdB0"},
        };

            var request = new HttpRequestMessage(HttpMethod.Post, "https://altruistahealth.okta.com/oauth2/default/v1/token")
            {
                Content = new FormUrlEncodedContent(postMessage)
            };

            //var response = await client.SendAsync(request);
            var response = await client.PostAsync("https://altruistahealth.okta.com/oauth2/default/v1/token", content1);
            //if (response.IsSuccessStatusCode)
            //{
            //    var json = await response.Content.ReadAsStringAsync();
            //    var newToken = JsonConvert.DeserializeObject<OktaToken>(json);
            //    newToken.ExpiresAt = DateTime.UtcNow.AddSeconds(_token.ExpiresIn);

            //    return newToken;
            //}
            var sdd = "";

        }
        public class OktaToken
        {
            public string Token_type { get; set; }
            public int Expires_In { get; set; }
            public string Access_Token { get; set; }
            public string Scope { get; set; }
            public string Id_Token { get; set; }
            public string Patient { get; set; }
        }
        [HttpGet,Route("OktaCopilot")]
        public async Task<ActionResult> oktaCopilot()
        {
            var username = "0oa7sqx2a1WTckpLH4h7";
            var password = "rqVugE_1y1Y5Mg-PgTAG8xzr7oXeQ-4DPNQKzJ5Iut3af6uCkTGpdyddwWoYBDtE";
            var url = "https://altruistahealth.okta.com/oauth2/default/v1/token";

            var client = new HttpClient();

            // Set the authorization header
            var byteArray = Encoding.ASCII.GetBytes($"{username}:{password}");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

            // Prepare the content
            var content = new FormUrlEncodedContent(new[]
            {
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("redirect_uri", "https://emr.auth.uniteustraining.com/auth/smartonfhir/callback"),
            new KeyValuePair<string, string>("code", "2kDNWxnS1u6rxmkM_beirQecuut5JuewgrAz_0fm5zU")
        });

            var response = await client.PostAsync(url, content);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var oktaToken = JsonConvert.DeserializeObject<OktaToken>(responseContent);

                Console.WriteLine("Response: " + responseContent);
                var handler = new JwtSecurityTokenHandler();
                var jwtSecurityToken = handler.ReadJwtToken(oktaToken.Access_Token);
                oktaToken.Patient= jwtSecurityToken.Claims.First(claim => claim.Type == "patient").Value;
                string json = JsonConvert.SerializeObject(oktaToken, Formatting.Indented);
                return Content(json);

            }
            else
            {
                Console.WriteLine("Error: " + response.StatusCode);
            }
            return Content("");
        }
    }
}
