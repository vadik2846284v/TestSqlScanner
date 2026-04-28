using System.ComponentModel;

namespace WebVulnerabilitiesScanner.Extentions
{
    public static class EnumExtentions
    {
        /// <summary>
        /// Получение значения Description из атрибута у Enum
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string GetDescription(this Enum value)
        {
            var field = value.GetType().GetField(value.ToString());
            var attribute = (DescriptionAttribute)Attribute.GetCustomAttribute(field, typeof(DescriptionAttribute));
            return attribute == null ? value.ToString() : attribute.Description;
        }
    }
}
