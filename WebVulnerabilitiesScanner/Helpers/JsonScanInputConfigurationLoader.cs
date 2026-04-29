using System.Text.Json;
using WebVulnerabilitiesScanner.Entities;

namespace WebVulnerabilitiesScanner.Helpers
{
    /// <summary>
    /// Загрузка входной конфигурации сканирования из JSON-файлов.
    /// </summary>
    public static class JsonScanInputConfigurationLoader
    {
        private static readonly JsonSerializerOptions JsonSerializerOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        /// <summary>
        /// Загрузка конфигурации из JSON-файла.
        /// </summary>
        /// <param name="filePath">Путь к JSON-файлу</param>
        /// <returns>Готовая конфигурация сканирования</returns>
        public static ScanInputConfiguration Load(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentException("Не передан путь к JSON-файлу с конфигурацией сканирования.");

            if (!File.Exists(filePath))
                throw new FileNotFoundException($"Не найден JSON-файл конфигурации: {filePath}");

            string fileContent = File.ReadAllText(filePath);
            var configuration = JsonSerializer.Deserialize<ScanInputConfiguration>(fileContent, JsonSerializerOptions)
                ?? throw new InvalidOperationException($"Не удалось прочитать JSON-конфигурацию: {filePath}");

            ValidateConfiguration(configuration);
            return configuration;
        }

        /// <summary>
        /// Проверка, что конфигурация содержит минимально необходимые данные для запуска сканирования.
        /// </summary>
        /// <param name="configuration">Проверяемая конфигурация</param>
        private static void ValidateConfiguration(ScanInputConfiguration configuration)
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
