using System.Text.Json.Serialization;

namespace WebVulnerabilitiesScanner.Entities
{
    /// <summary>
    /// Настройки ИИ-анализа через GigaChat, задаваемые в отдельном JSON-файле.
    /// </summary>
    public class GigaChatConfiguration
    {
        /// <summary>
        /// Значение для Basic-авторизации при получении OAuth-токена GigaChat.
        /// </summary>
        [JsonPropertyName("authorizationKey")]
        public string AuthorizationKey { get; set; } = string.Empty;

        /// <summary>
        /// Название модели GigaChat для генерации анализа.
        /// </summary>
        [JsonPropertyName("model")]
        public string Model { get; set; } = "GigaChat-2-Pro";

        /// <summary>
        /// Значение scope для OAuth-запроса к GigaChat.
        /// </summary>
        [JsonPropertyName("scope")]
        public string Scope { get; set; } = "GIGACHAT_API_PERS";

        /// <summary>
        /// Разрешить ли пропуск строгой проверки TLS-сертификата.
        /// </summary>
        [JsonPropertyName("allowInsecureSsl")]
        public bool AllowInsecureSsl { get; set; }

        /// <summary>
        /// Путь к пользовательскому сертификату или PEM-bundle для проверки TLS-цепочки.
        /// </summary>
        [JsonPropertyName("caCertificatePath")]
        public string? CaCertificatePath { get; set; }
    }
}
