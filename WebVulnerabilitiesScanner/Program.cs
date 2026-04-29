using System.Diagnostics;
using WebVulnerabilitiesScanner.Entities;
using WebVulnerabilitiesScanner.Helpers;

namespace WebVulnerabilitiesScanner
{
    class Programm
    {
        static void Main(params string[] args)
        {
            try
            {
                Console.Write("Введите путь к JSON-файлу с эндпоинтами: ");
                string? jsonFilePath = Console.ReadLine();
                Console.WriteLine();

                var jsonFileLoader = new JsonScanInputConfigurationLoader(jsonFilePath);
                while (!jsonFileLoader.IsFileExists)
                {
                    Console.WriteLine("Указанный файл не найден. Пожалуйста, введите корректный путь к JSON-файлу:");
                    jsonFilePath = Console.ReadLine();
                    jsonFileLoader = new JsonScanInputConfigurationLoader(jsonFilePath);
                }
                var loadedJsonConfiguration = jsonFileLoader.Load();
                RunScanFromJsonConfiguration(loadedJsonConfiguration);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка запуска сканирования: {ex.Message}");
            }
        }

        /// <summary>
        /// Запуск сканирования по конфигурации, загруженной из JSON-файла.
        /// </summary>
        /// <param name="jsonConfiguration">Конфигурация сканирования</param>
        private static void RunScanFromJsonConfiguration(ScanInputConfiguration jsonConfiguration)
        {
            string baseUrl = ResolveBaseUrl(jsonConfiguration.BaseUrl);
            string configurationName = string.IsNullOrWhiteSpace(jsonConfiguration.Name)
                ? "JSON configuration"
                : jsonConfiguration.Name;

            var scanner = new SqlInjectionScanner(baseUrl);
            var results = scanner.ScanForSqlInjection(jsonConfiguration.GetRequestEndpoints, jsonConfiguration.PostRequestsInfo);
            string reportFilePath = ReportFileHelper.SaveScanReport(baseUrl, configurationName, results);

            Console.WriteLine($"Результаты сканирования сохранены в файл: {reportFilePath}");
            OpenReportInBrowser(reportFilePath);
            Console.WriteLine("Конец сканирования!");
        }

        /// <summary>
        /// Получение базового URL либо из конфигурации, либо через консольный ввод.
        /// </summary>
        /// <param name="configuredBaseUrl">URL из JSON-конфигурации</param>
        /// <returns>Нормализованный базовый URL</returns>
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
        /// Открытие сохранённого HTML-отчёта в браузере по умолчанию.
        /// </summary>
        /// <param name="reportFilePath">Полный путь к файлу отчёта</param>
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
