namespace WebVulnerabilitiesScanner.Helpers
{
    /// <summary>
    /// Вспомогательные методы для консольного вывода статуса сканирования.
    /// </summary>
    public static class ConsoleHelper
    {
        private const int MaxConsoleLineLength = 120;

        /// <summary>
        /// Выводит сообщение о том, что для запуска сканирования не найдено ни одной проверки.
        /// </summary>
        public static void WriteNoChecksMessage()
        {
            Console.WriteLine("[Scanner] Нет проверок для выполнения.");
        }

        /// <summary>
        /// Выводит в консоль стартовое сообщение с общим количеством проверок.
        /// </summary>
        /// <param name="totalChecks">Общее количество запланированных проверок.</param>
        public static void WriteScanStart(int totalChecks)
        {
            Console.WriteLine($"[Scanner] Запускаю сканирование: {totalChecks} проверок.");
        }

        /// <summary>
        /// Выводит прогресс текущей проверки в формате счётчика и краткого описания запроса.
        /// </summary>
        /// <param name="currentCheck">Номер выполняемой проверки.</param>
        /// <param name="totalChecks">Общее количество проверок.</param>
        /// <param name="requestType">Тип HTTP-запроса.</param>
        /// <param name="endpoint">Проверяемый endpoint.</param>
        /// <param name="payload">Payload, используемый в текущей проверке.</param>
        public static void WriteScanProgress(int currentCheck, int totalChecks, string requestType, string endpoint, string payload)
        {
            string requestPreview = requestType == "GET"
                ? $"{endpoint}{payload}"
                : $"{endpoint} | payload: {payload}";

            Console.WriteLine($"[{currentCheck}/{totalChecks}] {requestType} {ShortenForConsole(requestPreview)}");
        }

        /// <summary>
        /// Сокращает длинную строку до допустимой длины консольной строки и убирает переводы строк.
        /// </summary>
        /// <param name="text">Исходный текст для отображения.</param>
        /// <returns>Подготовленная строка для вывода в консоль.</returns>
        private static string ShortenForConsole(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return string.Empty;

            string singleLineText = text.Replace(Environment.NewLine, " ").Trim();

            if (singleLineText.Length <= MaxConsoleLineLength)
                return singleLineText;

            return singleLineText[..(MaxConsoleLineLength - 3)] + "...";
        }
    }
}
