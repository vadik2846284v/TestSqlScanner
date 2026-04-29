using System.Text.Json.Serialization;

namespace WebVulnerabilitiesScanner.Entities
{
    /// <summary>
    /// Конфигурация сканирования, загружаемая из JSON-файла.
    /// </summary>
    public class ScanInputConfiguration
    {
        /// <summary>
        /// Произвольное имя конфигурации.
        /// </summary>
        [JsonPropertyName("name")]
        public string Name { get; set; } = "Custom JSON configuration";

        /// <summary>
        /// Базовый URL приложения.
        /// </summary>
        [JsonPropertyName("baseUrl")]
        public string BaseUrl { get; set; } = string.Empty;

        /// <summary>
        /// GET-эндпоинты, в которые payload будет добавляться в конец строки.
        /// </summary>
        [JsonPropertyName("getEndpoints")]
        public List<string> GetRequestEndpoints { get; set; } = new();

        /// <summary>
        /// POST-запросы для проверки.
        /// </summary>
        [JsonPropertyName("postRequests")]
        public List<PostRequestParams> PostRequestsInfo { get; set; } = new();
    }
}
