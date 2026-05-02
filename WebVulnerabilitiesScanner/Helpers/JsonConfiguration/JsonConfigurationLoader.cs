using System.Text.Json;

namespace WebVulnerabilitiesScanner.Helpers.JsonConfiguration
{
    /// <summary>
    /// Базовый загрузчик JSON-конфигурации с общей логикой чтения и десериализации файла.
    /// </summary>
    /// <typeparam name="TConfiguration">Тип загружаемой конфигурации.</typeparam>
    public abstract class JsonConfigurationLoader<TConfiguration>
        where TConfiguration : class
    {
        private readonly string? _filePath;

        /// <summary>
        /// Существует ли JSON-файл по заданному пути.
        /// </summary>
        public bool IsFileExists => !string.IsNullOrWhiteSpace(_filePath) && File.Exists(_filePath);

        /// <summary>
        /// Параметры десериализации JSON-конфигурации.
        /// </summary>
        private static readonly JsonSerializerOptions JsonSerializerOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        /// <summary>
        /// Суффикс для текстов ошибок, если требуется уточнить тип конфигурации.
        /// </summary>
        protected virtual string ConfigurationSuffix => string.Empty;

        /// <summary>
        /// Инициализирует загрузчик JSON-конфигурации.
        /// </summary>
        /// <param name="filePath">Путь к JSON-файлу конфигурации.</param>
        protected JsonConfigurationLoader(string? filePath)
        {
            _filePath = filePath;
        }

        /// <summary>
        /// Загружает конфигурацию из JSON-файла.
        /// </summary>
        /// <returns>Готовая конфигурация.</returns>
        public TConfiguration Load()
        {
            string filePath = _filePath ?? throw new InvalidOperationException(
                $"Не задан путь к JSON-файлу конфигурации{ConfigurationSuffix}.");

            if (!IsFileExists)
                throw new FileNotFoundException($"Не найден JSON-файл конфигурации{ConfigurationSuffix}: {filePath}");

            string fileContent = File.ReadAllText(filePath);
            var configuration = JsonSerializer.Deserialize<TConfiguration>(fileContent, JsonSerializerOptions)
                ?? throw new InvalidOperationException(
                    $"Не удалось прочитать JSON-конфигурацию{ConfigurationSuffix}: {filePath}");

            ValidateConfiguration(configuration);
            return configuration;
        }

        /// <summary>
        /// Проверяет корректность десериализованной конфигурации.
        /// </summary>
        /// <param name="configuration">Проверяемая конфигурация.</param>
        protected abstract void ValidateConfiguration(TConfiguration configuration);
    }
}
