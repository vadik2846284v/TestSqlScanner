using System.Diagnostics;
using WebVulnerabilitiesScanner.Extentions;
using WebVulnerabilitiesScanner.Helpers;
using static WebVulnerabilitiesScanner.TestData.SqlInjectionTestData;

namespace WebVulnerabilitiesScanner
{
    class Programm()
    {
        static void Main(params string[] args)
        {
            // Запрашиваем, на каком типе портала запускаем сканер
            Console.WriteLine("Введите номер типа портала, который будем сканировать");
            foreach (PortalType pt in Enum.GetValues(typeof(PortalType)))
            {
                Console.WriteLine($"{(int)pt} = {pt.GetDescription()}");
            }
            Console.Write("Тип портала: ");
            string stringPortalType = Console.ReadLine();
            Console.WriteLine();

            // Запрос ввода урла портала
            Enum.TryParse(stringPortalType, out PortalType portalType);
            Console.Write("Введите url портала, на котором будет происходить сканирование (например: http://example.com): ");
            string baseUrl = Console.ReadLine();

            // Сканируем на наличие SQL-инъекций и сохраняем HTML-отчёт.
            var scanner = new SqlInjectionScanner(baseUrl, portalType);
            var results = scanner.ScanForSqlInjection();
            string reportFilePath = ReportFileHelper.SaveScanReport(baseUrl, portalType.GetDescription(), results);
            Console.WriteLine($"Результаты сканирования сохранены в файл: {reportFilePath}");
            OpenReportInBrowser(reportFilePath);
            Console.WriteLine("Конец сканирования!");

            //TODO: развернуть среду из CVE или БДУ ФСТЭК
        }

        /// <summary>
        /// Открытие сохранённого HTML-отчёта в браузере по умолчанию.
        /// </summary>
        /// <param name="reportFilePath">Полный путь к файлу отчёта</param>
        static void OpenReportInBrowser(string reportFilePath)
        {
            try
            {
                // Используем оболочку ОС, чтобы открыть HTML в браузере по умолчанию.
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
