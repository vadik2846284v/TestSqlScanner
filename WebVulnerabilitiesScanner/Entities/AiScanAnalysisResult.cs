namespace WebVulnerabilitiesScanner.Entities
{
    /// <summary>
    /// Результат ИИ-анализа итогов сканирования.
    /// </summary>
    public class AiScanAnalysisResult
    {
        /// <summary>
        /// Удалось ли получить содержательный ИИ-анализ.
        /// </summary>
        public bool IsGenerated { get; set; }

        /// <summary>
        /// Завершился ли запрос к ИИ ошибкой после попытки выполнения.
        /// </summary>
        public bool IsFailed { get; set; }

        /// <summary>
        /// Нужно ли включать информацию об ИИ-анализе в HTML-отчёт.
        /// </summary>
        public bool ShouldIncludeInReport => IsGenerated || IsFailed;

        /// <summary>
        /// Текст сгенерированного ИИ-анализа.
        /// </summary>
        public string Summary { get; set; } = string.Empty;

        /// <summary>
        /// Статус выполнения ИИ-анализа для консоли и отчёта.
        /// </summary>
        public string StatusMessage { get; set; } = string.Empty;
    }
}
