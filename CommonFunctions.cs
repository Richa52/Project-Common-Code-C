using NPOI.HSSF.UserModel;
using NPOI.HSSF.Util;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.IO;
using System.Linq;
using System.Net.Configuration;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Configuration;
using System.Xml.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Net;


    public static class CommonFunctions
    {
        #region XML Related

        public static XElement ToXML<T>(this IList<T> lstToConvert, string rootName, string subLevelName)
        {
            Func<T, bool> filter = null;
            var lstConvert = (filter == null) ? lstToConvert : lstToConvert.Where(filter);
            return new XElement(rootName,
               (from node in lstConvert
                select new XElement(subLevelName,
                   from subnode in node.GetType().GetProperties()
                   select new XElement(subnode.Name, subnode.GetValue(node, null)))));
        }

        //public static XElement ToXML(this DataSet lstToConvert, string rootName, string subLevelName)
        //{
        //    DataTable _dt = lstToConvert.Tables[0];
        //    var lstConvert = _dt.AsEnumerable();
        //    return new XElement(rootName,
        //       (from node in lstConvert
        //        select new XElement(subLevelName,
        //           from subnode in node.GetType().GetProperties()
        //           select new XElement(subnode.Name, subnode.GetValue(node, null)))));
        //}

        //DataTable Convert To List Method
        public static IList<T> GetList<T>(DataTable table)
        {
            List<T> list = new List<T>();
            T t = default(T);
            PropertyInfo[] propertypes = null;
            string tempName = string.Empty;
            foreach (DataRow row in table.Rows)
            {
                t = Activator.CreateInstance<T>();
                propertypes = t.GetType().GetProperties();
                foreach (PropertyInfo pro in propertypes)
                {
                    tempName = pro.Name;
                    if (table.Columns.Contains(tempName))
                    {
                        object value = row[tempName];
                        if (value.GetType() == typeof(System.DBNull))
                        {
                            value = null;
                        }
                        pro.SetValue(t, value, null);
                    }
                }
                list.Add(t);
            }
            return list;
        }

        #endregion

        #region Enum Related Methods

        public static List<EnumListItem> GetEnumValues(Type type, bool isSelectRequired)
        {
            List<EnumListItem> el = new List<EnumListItem>();
            EnumListItem ei;
            foreach (int item in Enum.GetValues(type))
            {
                ei = GetEnumItem(type, item);
                el.Add(ei);
            }
            return el;
        }

        private static EnumListItem GetEnumItem(Type type, int item)
        {
            string name = Enum.GetName(type, item);
            string displayName = string.Empty;
            object[] displayAttributes = type.GetField(Enum.GetName(type, item)).GetCustomAttributes(typeof(DisplayValueAttribute), false);
            if (displayAttributes.Length > 0)
                displayName = ((DisplayValueAttribute)displayAttributes[0]).Value;
            else
                displayName = name;
            return new EnumListItem(item, name, displayName);
        }

        public static List<EnumListItem> GetEnumValues(Type type, bool isSelectRequired, IList objList, string itemProperty)
        {
            List<EnumListItem> el = new List<EnumListItem>();
            EnumListItem ei;
            foreach (object obj in objList)
            {
                int item = (int)obj.GetType().GetProperty(itemProperty).GetValue(obj, null);
                ei = GetEnumItem(type, item);
                el.Add(ei);
            }
            return el;
        }

        #endregion

        #region CurrentUserInfo

        public static CurrentUserInfo CurrentUserInformation
        {
            get
            {
                if (HttpContext.Current.Session["CurrentUserInformation"] != null)
                {
                    return (CurrentUserInfo)HttpContext.Current.Session["CurrentUserInformation"];
                }
                else
                {
                    return new CurrentUserInfo();
                }
            }
            set
            {
                HttpContext.Current.Session["CurrentUserInformation"] = value;
            }
        }

        #endregion

        #region common Properties


        public static string AdminEmail
        {
            get
            {
                Configuration config = WebConfigurationManager.OpenWebConfiguration("~/Web.config");
                MailSettingsSectionGroup mailSettings = (MailSettingsSectionGroup)config.GetSectionGroup("system.net/mailSettings");
                return mailSettings.Smtp.Network.UserName.ToString();
            }
        }

        #endregion

        #region File & Folder Related Properties & Methods

        /// <summary>
        /// To Get File Bytes on base of passed file path
        /// </summary>
        /// <param name="fileNamewithPath"></param>
        /// <returns></returns>
        public static byte[] GetFileBytes(string fileNamewithPath)
        {
            byte[] fileByte = null;
            if (File.Exists(HttpContext.Current.Server.MapPath(fileNamewithPath)))
            {
                FileStream fstrm = new FileStream(HttpContext.Current.Server.MapPath(fileNamewithPath), System.IO.FileMode.Open, System.IO.FileAccess.Read);

                fileByte = new byte[fstrm.Length];
                fstrm.Read(fileByte, 0, fileByte.Length);
                fstrm.Close();
            }
            return fileByte;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="Path"></param>
        public static bool CreateDirectory(string Path)
        {
            if (!Directory.Exists(Path))
            {
                try
                {
                    Directory.CreateDirectory(Path);
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }
            else
            {
                return true;
            }
        }

        //Save the file with File byte array
        public static bool SaveFile(string path, string fileName, byte[] fileByte)
        {
            if (CreateDirectory(path))
            {
                if (fileByte != null)
                {
                    FileStream fs = null;
                    try
                    {
                        string fileActualName = fileName;
                        fs = new FileStream(path + fileActualName, FileMode.Create, FileAccess.Write);
                        fs.Write(fileByte, 0, fileByte.Length);
                        fs.Flush();
                        fs.Dispose();
                        fs.Close();
                        return true;
                    }
                    catch (Exception)
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        //Save the file normally
        public static bool SaveFile(string path, string fileName)
        {
            if (CreateDirectory(path))
            {
                FileStream fs = null;
                try
                {
                    string fileActualName = fileName;
                    fs = new FileStream(path + fileActualName, FileMode.Create, FileAccess.Write);
                    fs.Flush();
                    fs.Dispose();
                    fs.Close();
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="virtualPath"></param>
        /// <param name="fileName"></param>
        /// <returns></returns>
        public static bool DeleteFile(string filenameWithPath)
        {
            try
            {
                if (File.Exists(filenameWithPath))
                {
                    File.Delete(filenameWithPath);
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static string GetFileExtension(string fileName)
        {
            if (fileName != null)
                return fileName.Substring(fileName.LastIndexOf('.') + 1, fileName.Length - (fileName.LastIndexOf('.') + 1));
            else
                return null;
        }

        #endregion

        #region Common

        public static bool ValidateDataset(DataSet ds)
        {
            bool isValid = false;

            if (ds != null && ds.Tables.Count > 0 && ds.Tables[0].Rows.Count > 0)
            {
                isValid = true;
            }

            return isValid;
        }

        public static bool ValidateDataTable(DataTable dt)
        {
            bool isValid = false;

            if (dt != null && dt.Rows.Count > 0)
            {
                isValid = true;
            }

            return isValid;

        }

        public static string GetCommanSeparatedValues(List<object> lstIn)
        {
            string strCSVIds = string.Empty;

            for (int i = 0; i < lstIn.Count; i++)
            {
                if (!String.IsNullOrEmpty(lstIn[i].ToString()))
                    strCSVIds += lstIn[i].ToString() + ",";
            }

            strCSVIds = strCSVIds.Substring(0, strCSVIds.LastIndexOf(","));

            return strCSVIds;
        }



        #endregion

        #region Password

        /// <summary>
        /// get encrypted password
        /// </summary>
        /// <param name="cleanString"></param>
        /// <returns></returns>
        public static String getEncrypt(String cleanString)  //getting encrypted string
        {
            Byte[] clearBytes = new UnicodeEncoding().GetBytes(cleanString);
            Byte[] hashedBytes = ((HashAlgorithm)CryptoConfig.CreateFromName("MD5")).ComputeHash(clearBytes);

            return BitConverter.ToString(hashedBytes);
        }

        //For SALT + SHA1
        private const int PBKDF2IterCount = 1000; // default for Rfc2898DeriveBytes
        private const int PBKDF2SubkeyLength = 256 / 8; // 256 bits
        private const int SaltSize = 128 / 8; // 128 bits

        /// <summary>
        /// To get salt value of passwword
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string HashPassword(string password)
        {
            byte[] salt;
            byte[] subkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, SaltSize, PBKDF2IterCount))
            {
                salt = deriveBytes.Salt;
                subkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }

            byte[] outputBytes = new byte[1 + SaltSize + PBKDF2SubkeyLength];
            System.Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
            System.Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, PBKDF2SubkeyLength);
            return Convert.ToBase64String(outputBytes);
        }

        /// <summary>
        /// Verify the hashed passwrd
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static bool VerifyHashedPassword(string hashedPassword, string password)
        {
            byte[] hashedPasswordBytes = Convert.FromBase64String(hashedPassword);

            // Wrong length or version header.
            if (hashedPasswordBytes.Length != (1 + SaltSize + PBKDF2SubkeyLength) || hashedPasswordBytes[0] != 0x00)
                return false;

            byte[] salt = new byte[SaltSize];
            System.Buffer.BlockCopy(hashedPasswordBytes, 1, salt, 0, SaltSize);
            byte[] storedSubkey = new byte[PBKDF2SubkeyLength];
            System.Buffer.BlockCopy(hashedPasswordBytes, 1 + SaltSize, storedSubkey, 0, PBKDF2SubkeyLength);

            byte[] generatedSubkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, PBKDF2IterCount))
            {
                generatedSubkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }
            return storedSubkey.SequenceEqual(generatedSubkey);
        }

        /// <summary>
        /// Random String
        /// </summary>
        /// <returns></returns>
        public static string GetRandomString(int iLength)
        {
            string strRandomString = string.Empty;
            RandomStringGenerator objRSG = new RandomStringGenerator();
            objRSG.MinSpecialCharacters = 1;
            objRSG.MinUpperCaseCharacters = 1;
            objRSG.MinNumericCharacters = 1;
            objRSG.UseUpperCaseCharacters = true;
            objRSG.UseLowerCaseCharacters = true;
            objRSG.UseSpecialCharacters = true;
            objRSG.UseNumericCharacters = true;
            strRandomString = objRSG.Generate(iLength);
            return strRandomString;
        }

        #endregion

        #region Month

        public static string GetMonth(string strMonth)
        {
            switch (strMonth)
            {
                case "Jan":
                    return "1";
                case "Feb":
                    return "2";
                case "Mar":
                    return "3";
                case "Apr":
                    return "4";
                case "May":
                    return "5";
                case "Jun":
                    return "6";
                case "July":
                    return "7";
                case "Aug":
                    return "8";
                case "Sep":
                    return "9";
                case "Oct":
                    return "10";
                case "Nov":
                    return "11";
                case "Dec":
                    return "12";
                default:
                    return "0";
            }

        }

        #endregion

        #region NPOI Color

        public static HSSFColor setColorNPOI(HSSFWorkbook workbook, short index, byte r, byte g, byte b)
        {
            HSSFPalette palette = workbook.GetCustomPalette();
            HSSFColor hssfColor = null;
            hssfColor = palette.FindColor(r, g, b);
            if (hssfColor == null)
            {
                palette.SetColorAtIndex(index, r, g, b);
                hssfColor = palette.GetColor(index);
            }
            return hssfColor;
        }

        #endregion

        
        #region Common Encrypt Decrypt Methods
        public static string Encrypt(string toEncrypt, bool useHashing, string strSaltKey)
        {
            byte[] keyArray;
            byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(toEncrypt);

            string key = strSaltKey;
            //System.Windows.Forms.MessageBox.Show(key);
            //If hashing use get hashcode regards to your key
            if (useHashing)
            {
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                //Always release the resources and flush data
                // of the Cryptographic service provide. Best Practice

                hashmd5.Clear();
            }
            else
                keyArray = UTF8Encoding.UTF8.GetBytes(key);

            AesCryptoServiceProvider tdes = new AesCryptoServiceProvider();
            //set the secret key for the tripleDES algorithm
            tdes.Key = keyArray;
            //mode of operation. there are other 4 modes.
            //We choose ECB(Electronic code Book)
            tdes.Mode = CipherMode.ECB;
            //padding mode(if any extra byte added)

            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tdes.CreateEncryptor();
            //transform the specified region of bytes array to resultArray
            byte[] resultArray =
              cTransform.TransformFinalBlock(toEncryptArray, 0,
              toEncryptArray.Length);
            //Release resources held by TripleDes Encryptor
            tdes.Clear();
            //Return the encrypted data into unreadable string format
            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }

        public static string Decrypt(string cipherString, bool useHashing, string strSaltKey = "")
        {
            byte[] keyArray;
            //get the byte code of the string

            byte[] toEncryptArray = Convert.FromBase64String(cipherString);


            //Get your key from config file to open the lock!
            string key = strSaltKey;

            if (useHashing)
            {
                //if hashing was used get the hash code with regards to your key
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                //release any resource held by the MD5CryptoServiceProvider

                hashmd5.Clear();
            }
            else
            {
                //if hashing was not implemented get the byte code of the key
                keyArray = UTF8Encoding.UTF8.GetBytes(key);
            }

            AesCryptoServiceProvider tdes = new AesCryptoServiceProvider();
            //set the secret key for the tripleDES algorithm
            tdes.Key = keyArray;
            //mode of operation. there are other 4 modes. 
            //We choose ECB(Electronic code Book)

            tdes.Mode = CipherMode.ECB;
            //padding mode(if any extra byte added)
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tdes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(
                                 toEncryptArray, 0, toEncryptArray.Length);
            //Release resources held by TripleDes Encryptor                
            tdes.Clear();
            //return the Clear decrypted TEXT
            return UTF8Encoding.UTF8.GetString(resultArray);
        }

        #endregion
        // -- Code ends --

        #region In Condition

        public static bool In<T>(this T source, params T[] list)
        {
            return list.Contains(source);
        }

        #endregion

       
        #region Random Code Generator
        public static string GetNewRandomCode(int iLength)
        {
            string strRandomString = string.Empty;
            RandomStringGenerator objRSG = new RandomStringGenerator();
            objRSG.MinSpecialCharacters = 0;
            objRSG.MinUpperCaseCharacters = 7;
            objRSG.MinNumericCharacters = 3;
            objRSG.UseUpperCaseCharacters = true;
            objRSG.UseLowerCaseCharacters = true;
            objRSG.UseSpecialCharacters = true;
            objRSG.UseNumericCharacters = true;
            strRandomString = objRSG.Generate(iLength);
            return strRandomString;
        }

        public static string GetNewRandomGrpCode(int iLength)
        {
            string strRandomString = string.Empty;
            RandomStringGenerator objRSG = new RandomStringGenerator();
            objRSG.MinSpecialCharacters = 0;
            objRSG.MinUpperCaseCharacters = 6;
            objRSG.MinNumericCharacters = 2;
            objRSG.UseUpperCaseCharacters = true;
            objRSG.UseLowerCaseCharacters = true;
            objRSG.UseSpecialCharacters = true;
            objRSG.UseNumericCharacters = true;
            strRandomString = objRSG.Generate(iLength);

            strRandomString = "GRP" + strRandomString;

            return strRandomString;
        }
        #endregion
        //Code ends--

        #region Get Timestamp

        public static Int64? GetTimeStamp()
        {
            return (Int64?)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
        }

        public static Int64? GetTimeStamp(DateTime dtDate)
        {
            return (Int64?)(dtDate - new DateTime(1970, 1, 1)).TotalSeconds;
        }

        public static DateTime epoch2string(Int64 epoch)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(epoch);
        }

        #endregion

        #region GetGUID

        public static string GetGUID()
        {
            return Guid.NewGuid().ToString();
        }

        #endregion

        #region Get Json

        public static string EscapeQuotes(string str)
        {
            string retVal = System.String.Empty;
            if (!System.String.IsNullOrEmpty(str))
            {
                // replace special quotes
                retVal = str.Replace((char)8216, '\'');
                retVal = retVal.Replace((char)8217, '\'');

                // escapes for SQL
                retVal = retVal.Replace(@"\", @"\\");
                retVal = retVal.Replace(@"'", @"\'");
            }
            return retVal;
        }

        #endregion

        #region Get IP

        public static string GetIP()
        {
            OperationContext context = OperationContext.Current;
            string strIPAdress = string.Empty;
            if (context != null)
            {
                if (context.IncomingMessageProperties != null)
                {
                    MessageProperties prop = context.IncomingMessageProperties;
                    if (prop != null)
                    {
                        RemoteEndpointMessageProperty endpoint = prop[RemoteEndpointMessageProperty.Name] as RemoteEndpointMessageProperty;
                        strIPAdress = endpoint.Address;
                    }
                }
            }
            return strIPAdress;
        }

        #endregion


        
        #region ExtensionMetod
        public static Int64? CheckNull(this Int64? value)
        {
            return value == null ? 0 : value;
        }
        #endregion


       
        #region Units Conversions

        public static decimal DegreetoFahrenheit(Double degree)
        {
            Double fahrenheit = 0;
            fahrenheit = (degree * 1.8) + 32;

            return Convert.ToDecimal(fahrenheit);
        }


        public static decimal FahrenheittoDegree(Double degree)
        {
            Double fahrenheit = 0;
            fahrenheit = (degree / 1.8) - 32;

            return Convert.ToDecimal(fahrenheit);
        }

        public static decimal KWHtoHP(Double value)
        {
            Double hp = 0;
            hp = value / 0.745699872;

            return Convert.ToDecimal(hp);
        }

        public static decimal HPtoKWH(Double value)
        {
            Double hp = 0;
            hp = value * 0.745699872;

            return Convert.ToDecimal(hp);
        }

        public static decimal MM_To_inches(Double value)
        {
            Double inches = 0;
            inches = (value / 25.4);

            return Convert.ToDecimal(inches);
        }

        public static decimal inches_To_MM(Double value)
        {
            Double inches = 0;
            inches = (value * 25.4);

            return Convert.ToDecimal(inches);
        }


        public static decimal MMper_sec_To_inchesper_sec(Double value)
        {
            Double inches = 0;
            inches = (value / 25.4);

            return Convert.ToDecimal(inches);
        }


        public static decimal inchesper_sec_To_MM(Double value)
        {
            Double inches = 0;
            inches = (value * 25.4);

            return Convert.ToDecimal(inches);
        }

        #endregion

        #region Get Location

        /// <summary>
        /// 
        /// </summary>
        /// <param name="strLattitude"></param>
        /// <param name="strLongitude"></param>
        /// <returns></returns>((System.Data.DataRelation)new System.Collections.ArrayList.ArrayListDebugView(((System.Data.DataRelationCollection.DataSetRelationCollection)dsResult.relationCollection).List).Items[0]).ChildKeyConstraint.parentKey.Table.NestedParentRelations
        public static string GetLocation(string strLattitude, string strLongitude)
        {
            string strLocation = string.Empty;
            try
            {
                string url = "http://maps.google.com/maps/api/geocode/xml?latlng={0},{1}&sensor=false";
                url = string.Format(url, strLattitude, strLongitude);
                WebRequest request = WebRequest.Create(url);
                using (WebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                    {
                        DataSet dsResult = new DataSet();
                        dsResult.ReadXml(reader);
                        if (dsResult != null && dsResult.Tables.Count > 0 && dsResult.Tables["result"] != null && dsResult.Tables["result"].Rows.Count > 0)
                        {
                            //strLocation = dsResult.Tables["result"].Rows[0]["formatted_address"].ToString();
                            string strCountryID = dsResult.Tables["type"].Select("type_text = 'country'")[0]["address_component_id"].ToString();
                            strLocation = dsResult.Tables["address_component"].Select("address_component_id = '" + strCountryID + "'")[0]["long_name"].ToString();
                        }
                    }
                }
            }
            catch (Exception)
            {
                strLocation = string.Empty;
            }
            return strLocation;
        }

        #endregion

        #region GetKey
        public static string EncryptGenerateKey(string strEmail)
        {
            string strEmailDate = strEmail + "###" + GetTimeStamp();
            string strEncEmail = Encrypt(strEmailDate, true, GetGUID());
            return strEncEmail.Replace("/", "").Replace("+", "").Replace("=", "");
        }
        #endregion
    }
}
