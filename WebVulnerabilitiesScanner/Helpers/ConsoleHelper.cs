using WebVulnerabilitiesScanner.Entities;

namespace WebVulnerabilitiesScanner.Helpers
{
    public class ConsoleHelper
    {
        /// <summary>
        /// Вывод в консоль результата http-запроса
        /// </summary>
        /// <param name="httpResponseEntity">Сущность ответа http-запроса</param>
        public static void WriteHttpRequestResult(HttpResponseEntity httpResponseEntity) 
        {
            Console.WriteLine($"Полный адрес портала (с эндпоинтом): {httpResponseEntity.UrlWithEndpoint}");
            Console.WriteLine($"Endpoint: {httpResponseEntity.Endpoint}");
            Console.WriteLine($"Payload: {httpResponseEntity.Payload}");
            Console.WriteLine($"Статус: {httpResponseEntity.StatusCode}");
            if (httpResponseEntity.RequestType == "POST")
                Console.WriteLine($"Тело запроса: {httpResponseEntity.JsonBodyParams}");
            Console.WriteLine($"Тип запроса: {httpResponseEntity.RequestType}");
            Console.WriteLine($"Тип SQL-инъекции: {httpResponseEntity.SqlInjectionType}");
            Console.WriteLine($"Признак, по которому определили, что словили Sql-инъекцию: {httpResponseEntity.SqlInjectionSign}");
            Console.WriteLine($"Рекомендация к исправлению:{Environment.NewLine}" + httpResponseEntity.FixRecommendation);
        }
    }
}
