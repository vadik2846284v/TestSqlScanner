using WebVulnerabilitiesScanner.Entities;

namespace WebVulnerabilitiesScanner.Helpers.JsonConfiguration
{
    /// <summary>
    /// Загрузка входной конфигурации сканирования из JSON-файлов.
    /// </summary>
    public class JsonScanInputConfigurationLoader : JsonConfigurationLoader<ScanInputConfiguration>
    {
        /// <summary>
        /// Инициализирует загрузчик JSON-конфигурации.
        /// </summary>
        /// <param name="filePath">Путь к JSON-файлу конфигурации.</param>
        public JsonScanInputConfigurationLoader(string? filePath) : base(filePath)
        {
        }

        /// <summary>
        /// Проверяет, что конфигурация содержит минимально необходимые данные для запуска сканирования.
        /// </summary>
        /// <param name="configuration">Проверяемая конфигурация.</param>
        protected override void ValidateConfiguration(ScanInputConfiguration configuration)
        {
            if (configuration.GetRequestEndpoints.Count == 0 && configuration.PostRequestsInfo.Count == 0)
                throw new InvalidOperationException("JSON-конфигурация не содержит ни GET-, ни POST-эндпоинтов для сканирования.");

            foreach (var postRequest in configuration.PostRequestsInfo)
            {
                if (string.IsNullOrWhiteSpace(postRequest.Endpoint))
                    throw new InvalidOperationException("В JSON-конфигурации найден POST-запрос без endpoint.");

                if (postRequest.BodyParams is null)
                    throw new InvalidOperationException($"В JSON-конфигурации для POST endpoint '{postRequest.Endpoint}' отсутствует body.");
            }
        }
    }
}
