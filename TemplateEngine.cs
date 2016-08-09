using System;
using System.Collections.Generic;

  public class TemplateEngine
    {
        private readonly Dictionary<string, object> _templateModel;
        private readonly string _templateText;

        public TemplateEngine(Dictionary<string, object> templateModel, string templateText)
        {
            _templateModel = templateModel;
            _templateText = templateText;
        }

        /// <summary>
        /// Renders the template.
        /// </summary>
        /// <returns></returns>
        public string Render()
        {
            Dictionary<string, object> modelProperties = _templateModel;
            var output = LoadTemplate();

            foreach (var modelProperty in modelProperties)
            {
                output = output.Replace("##" + modelProperty.Key + "##", ObjectToString(modelProperty.Value));
            }

            return output;
        }

        /// <summary>
        /// Loads the template.
        /// </summary>
        /// <returns></returns>
        private string LoadTemplate()
        {
            return _templateText;
        }

        /// <summary>
        /// Converts the objects to a string.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        private static string ObjectToString(object value)
        {
            if (value == null)
                return string.Empty;

            if (value.GetType() == typeof(string))
                return (string)value;

            if (value.GetType() == typeof(DateTime))
            {
                // Add formatting here at some point
                DateTime dateTime = (DateTime)value;
                return dateTime.ToString();
            }

            return value.ToString();
        }
    }