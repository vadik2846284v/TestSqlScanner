using System.Text.Json;
using WebVulnerabilitiesScanner.Entities;

namespace WebVulnerabilitiesScanner.Helpers
{
    /// <summary>
    /// Загрузка входной конфигурации сканирования из JSON-файлов.
    /// </summary>
    public class JsonScanInputConfigurationLoader
    {
        private string _filePath;

        public bool IsFileExists => File.Exists(_filePath);

        private static readonly JsonSerializerOptions JsonSerializerOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        public JsonScanInputConfigurationLoader(string filePath)
        {
            _filePath = filePath;
        }

        /// <summary>
        /// Загрузка конфигурации из JSON-файла.
        /// </summary>
        /// <returns>Готовая конфигурация сканирования</returns>
        public ScanInputConfiguration Load()
        {
            if (!IsFileExists)
                throw new FileNotFoundException($"Не найден JSON-файл конфигурации: {_filePath}");

            string fileContent = File.ReadAllText(_filePath);
            var configuration = JsonSerializer.Deserialize<ScanInputConfiguration>(fileContent, JsonSerializerOptions)
                ?? throw new InvalidOperationException($"Не удалось прочитать JSON-конфигурацию: {_filePath}");

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
