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
        public string Endpoint { get; private set; }

        /// <summary>
        /// Параметры для тела запроса
        /// </summary>
        public Dictionary<string, object> BodyParams { get; private set; }

        public PostRequestParams(string endpoint, Dictionary<string, object> bodyParams) 
        {
            Endpoint = endpoint;
            BodyParams = bodyParams;
        }
    }
}
