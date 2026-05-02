using System.Diagnostics;
using WebVulnerabilitiesScanner.Entities;
using WebVulnerabilitiesScanner.Helpers;
using WebVulnerabilitiesScanner.Helpers.JsonConfiguration;

namespace WebVulnerabilitiesScanner
{
    class Programm
    {
        static void Main(params string[] args)
        {
            try
            {
                Console.Write("Введите путь к JSON-файлу с эндпоинтами портала для их проверки: ");
                string? scanConfigurationPath = Console.ReadLine();
                Console.WriteLine();

                ScanInputConfiguration scanConfiguration = LoadScanConfiguration(scanConfigurationPath);
                GigaChatConfiguration? gigaChatConfiguration = TryLoadGigaChatConfiguration();
                RunScanFromJsonConfiguration(scanConfiguration, gigaChatConfiguration);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка запуска сканирования: {ex.Message}");
            }
        }

        /// <summary>
        /// Загружает конфигурацию сканирования из JSON-файла.
        /// </summary>
        /// <param name="scanConfigurationPath">Путь к JSON-файлу конфигурации сканирования.</param>
        /// <returns>Загруженная конфигурация сканирования.</returns>
        private static ScanInputConfiguration LoadScanConfiguration(string? scanConfigurationPath)
        {
            var jsonFileLoader = new JsonScanInputConfigurationLoader(scanConfigurationPath);
            while (!jsonFileLoader.IsFileExists)
            {
                Console.WriteLine("Указанный файл не найден. Пожалуйста, введите корректный путь к JSON-файлу:");
                scanConfigurationPath = Console.ReadLine();
                jsonFileLoader = new JsonScanInputConfigurationLoader(scanConfigurationPath);
            }

            return jsonFileLoader.Load();
        }

        /// <summary>
        /// Загружает отдельную конфигурацию GigaChat либо пропускает AI-анализ.
        /// </summary>
        /// <returns>Конфигурация GigaChat или null, если AI-анализ отключён.</returns>
        private static GigaChatConfiguration? TryLoadGigaChatConfiguration()
        {
            Console.Write("Введите путь к JSON-файлу с настройками GigaChat (Enter чтобы пропустить AI-анализ): ");
            string? gigaChatConfigurationPath = Console.ReadLine();
            Console.WriteLine();

            if (string.IsNullOrWhiteSpace(gigaChatConfigurationPath))
                return null;

            var jsonFileLoader = new JsonGigaChatConfigurationLoader(gigaChatConfigurationPath);
            while (!jsonFileLoader.IsFileExists)
            {
                Console.WriteLine("Файл конфигурации GigaChat не найден. Введите корректный путь или нажмите Enter для пропуска:");
                gigaChatConfigurationPath = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(gigaChatConfigurationPath))
                    return null;

                jsonFileLoader = new JsonGigaChatConfigurationLoader(gigaChatConfigurationPath);
            }

            return jsonFileLoader.Load();
        }

        /// <summary>
        /// Запускает сканирование по конфигурации, загруженной из JSON-файла.
        /// </summary>
        /// <param name="scanConfiguration">Конфигурация сканирования.</param>
        /// <param name="gigaChatConfiguration">Отдельная конфигурация GigaChat.</param>
        private static void RunScanFromJsonConfiguration(
            ScanInputConfiguration scanConfiguration,
            GigaChatConfiguration? gigaChatConfiguration)
        {
            string baseUrl = ResolveBaseUrl(scanConfiguration.BaseUrl);
            string configurationName = string.IsNullOrWhiteSpace(scanConfiguration.Name)
                ? "JSON configuration"
                : scanConfiguration.Name;

            var scanner = new SqlInjectionScanner(baseUrl);
            var results = scanner.ScanForSqlInjection(scanConfiguration.GetRequestEndpoints, scanConfiguration.PostRequestsInfo);
            AiScanAnalysisResult aiAnalysisResult = AnalyzeScanResultsWithAi(
                baseUrl,
                configurationName,
                results,
                gigaChatConfiguration);
            string reportFilePath = ReportFileHelper.SaveScanReport(baseUrl, configurationName, results, aiAnalysisResult);

            Console.WriteLine($"Результаты сканирования сохранены в файл: {reportFilePath}");
            OpenReportInBrowser(reportFilePath);
            Console.WriteLine("Конец сканирования!");
        }

        /// <summary>
        /// Получает базовый URL либо из конфигурации, либо через консольный ввод.
        /// </summary>
        /// <param name="configuredBaseUrl">URL из JSON-конфигурации.</param>
        /// <returns>Нормализованный базовый URL.</returns>
        private static string ResolveBaseUrl(string? configuredBaseUrl)
        {
            if (!string.IsNullOrWhiteSpace(configuredBaseUrl))
                return configuredBaseUrl.Trim().TrimEnd('/');

            Console.Write("Введите url портала, на котором будет происходить сканирование (например: http://example.com): ");
            string? baseUrl = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(baseUrl))
                throw new InvalidOperationException("URL портала не должен быть пустым.");

            return baseUrl.Trim().TrimEnd('/');
        }

        /// <summary>
        /// Выполняет дополнительный AI-анализ результатов сканирования через GigaChat.
        /// </summary>
        /// <param name="baseUrl">Базовый адрес сканируемого портала.</param>
        /// <param name="configurationName">Название конфигурации сканирования.</param>
        /// <param name="results">Результаты сканирования.</param>
        /// <param name="gigaChatConfiguration">Отдельная конфигурация GigaChat.</param>
        /// <returns>Результат выполнения AI-анализа.</returns>
        private static AiScanAnalysisResult AnalyzeScanResultsWithAi(
            string baseUrl,
            string configurationName,
            List<HttpResponseEntity> results,
            GigaChatConfiguration? gigaChatConfiguration)
        {
            var aiAnalysisService = new GigaChatScanAnalysisService(gigaChatConfiguration);
            AiScanAnalysisResult analysisResult = aiAnalysisService
                .AnalyzeResultsAsync(baseUrl, configurationName, results)
                .GetAwaiter()
                .GetResult();

            Console.WriteLine(analysisResult.StatusMessage);
            return analysisResult;
        }

        /// <summary>
        /// Открывает сохранённый HTML-отчёт в браузере по умолчанию.
        /// </summary>
        /// <param name="reportFilePath">Полный путь к файлу отчёта.</param>
        static void OpenReportInBrowser(string reportFilePath)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = reportFilePath,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Не удалось автоматически открыть отчёт: {ex.Message}");
            }
        }
    }
}
