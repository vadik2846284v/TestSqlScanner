using System.Text;
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
            Console.WriteLine(FormatHttpRequestResult(httpResponseEntity));
        }

        /// <summary>
        /// Форматирование результата запроса в читаемый текст.
        /// </summary>
        /// <param name="httpResponseEntity">Сущность ответа http-запроса</param>
        /// <returns>Строковое представление результата запроса</returns>
        public static string FormatHttpRequestResult(HttpResponseEntity httpResponseEntity)
        {
            var builder = new StringBuilder();
            builder.AppendLine($"Полный адрес портала (с эндпоинтом): {httpResponseEntity.UrlWithEndpoint}");
            builder.AppendLine($"Endpoint: {httpResponseEntity.Endpoint}");
            builder.AppendLine($"Payload: {httpResponseEntity.Payload}");
            builder.AppendLine($"Статус: {httpResponseEntity.StatusCode}");
            if (httpResponseEntity.RequestType == "POST")
                builder.AppendLine($"Тело запроса: {httpResponseEntity.JsonBodyParams}");
            builder.AppendLine($"Тип запроса: {httpResponseEntity.RequestType}");
            builder.AppendLine($"Тип SQL-инъекции: {httpResponseEntity.SqlInjectionType}");
            builder.AppendLine($"Признак, по которому определили, что словили Sql-инъекцию: {httpResponseEntity.SqlInjectionSign}");
            builder.Append($"Рекомендация к исправлению:{Environment.NewLine}{httpResponseEntity.FixRecommendation}");
            return builder.ToString();
        }
    }
}
