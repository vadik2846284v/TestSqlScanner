using WebVulnerabilitiesScanner.Entities;

namespace WebVulnerabilitiesScanner.TestData
{
    /// <summary>
    /// Тестовые данные для OWASP JuiceShop
    /// </summary>
    public class JuiceShopTestData : SqlInjectionTestData
    {
        /// <summary>
        /// Эндпоинты для GET-запросов
        /// </summary>
        public override List<string> GetRequestEndpoints => new List<string>
        {
            "/rest/products/search?q="
            //Добавить эндпоинты
        };

        /// <summary>
        /// Данные для POST-запросов
        /// </summary>
        public override List<PostRequestParams> PostRequestsInfo => new List<PostRequestParams>
        {
            new PostRequestParams("/rest/user/login", new Dictionary<string, object> { { "email", "test@test.ru" }, { "password", 123456 } }),
            new PostRequestParams("/api/SecurityAnswers/", new Dictionary<string, object>{ { "UserId", 1 }, { "answer", "test" }, { "SecurityQuestionId", 1 } })
        };
    }
}
