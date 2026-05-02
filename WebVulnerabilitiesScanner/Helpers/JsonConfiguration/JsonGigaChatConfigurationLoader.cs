using WebVulnerabilitiesScanner.Entities;

namespace WebVulnerabilitiesScanner.Helpers.JsonConfiguration
{
    /// <summary>
    /// Загрузка отдельной конфигурации GigaChat из JSON-файла.
    /// </summary>
    public class JsonGigaChatConfigurationLoader : JsonConfigurationLoader<GigaChatConfiguration>
    {
        /// <summary>
        /// Уточнение для текстов ошибок при загрузке конфигурации GigaChat.
        /// </summary>
        protected override string ConfigurationSuffix => " GigaChat";

        /// <summary>
        /// Инициализирует загрузчик JSON-конфигурации GigaChat.
        /// </summary>
        /// <param name="filePath">Путь к JSON-файлу конфигурации GigaChat.</param>
        public JsonGigaChatConfigurationLoader(string? filePath) : base(filePath)
        {
        }

        /// <summary>
        /// Проверяет обязательные параметры GigaChat в отдельной JSON-конфигурации.
        /// </summary>
        /// <param name="configuration">Проверяемая конфигурация GigaChat.</param>
        protected override void ValidateConfiguration(GigaChatConfiguration configuration)
        {
            if (string.IsNullOrWhiteSpace(configuration.AuthorizationKey))
                throw new InvalidOperationException("В JSON-конфигурации GigaChat нужно указать authorizationKey.");
        }
    }
}
