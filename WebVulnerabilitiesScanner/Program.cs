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
            Console.Write("Введите url портала, на котором будет происходить сканирование: ");
            string baseUrl = Console.ReadLine();

            // Сканируем на наличие SQL-инъекций и выводим результаты
            var scanner = new SqlInjectionScanner(baseUrl, portalType);
            var results = scanner.ScanForSqlInjection();
            var resultsWithVulnerable = results.FindAll(result => result.IsSqlVulnerable);
            if (resultsWithVulnerable.Count > 0)
            {
                Console.WriteLine("Выводим найденные SQL-инъекции:\n");
                foreach (var result in resultsWithVulnerable)
                {
                    if (result.IsSqlVulnerable)
                    {
                        ConsoleHelper.WriteHttpRequestResult(result);
                        Console.WriteLine();
                    }
                }
            }
            else
                Console.WriteLine("SQL-инъекции не найдены!");
            Console.WriteLine("Конец сканирования!");

            //TODO: развернуть среду из CVE или БДУ ФСТЭК
        }
    }
}
