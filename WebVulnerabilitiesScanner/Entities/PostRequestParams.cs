using System.Text.Json.Serialization;

namespace WebVulnerabilitiesScanner.Entities
{
    /// <summary>
    /// Параметры для POST запроса
    /// </summary>
    public class PostRequestParams
    {
        /// <summary>
        /// Эндпоинт
        /// </summary>
        [JsonPropertyName("endpoint")]
        public string Endpoint { get; set; } = string.Empty;

        /// <summary>
        /// Параметры для тела запроса
        /// </summary>
        [JsonPropertyName("body")]
        public Dictionary<string, object> BodyParams { get; set; } = new();

        public PostRequestParams(string endpoint, Dictionary<string, object> bodyParams)
        {
            Endpoint = endpoint;
            BodyParams = bodyParams;
        }
    }
}
