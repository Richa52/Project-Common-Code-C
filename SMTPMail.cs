using System;
using System.Configuration;
using System.Net.Mail;
using System.Text.RegularExpressions;



    public static class SMTPMail
    {
        static string _SMTPAddress = ConfigurationManager.AppSettings["SMTPAddress"];
        public static bool sendSMTPMail(string mailFrom, string mailTo, string mailSubject, string mailBody, string mailCC, string mailBcc)
        {
            bool _IsMailSent = false;
            MailMessage message = new MailMessage(mailFrom, mailTo, mailSubject, mailBody);
            message.IsBodyHtml = true;
            try
            {
                if (!(mailCC == string.Empty || mailCC == null))
                {
                    string[] strCC = mailCC.Split(';');

                    foreach (string strThisCC in strCC)
                    {
                        if (!strThisCC.Equals(""))
                        {
                            message.CC.Add(strThisCC.Trim());
                        }
                    }
                }
                if (!(mailBcc == string.Empty || mailBcc == null))
                {
                    string[] strBCC = mailBcc.Split(';');

                    foreach (string strThisBCC in strBCC)
                    {
                        if (!strThisBCC.Equals(""))
                        {
                            message.Bcc.Add(strThisBCC.Trim());
                        }
                    }
                }
                SmtpClient mySmtpClient = new SmtpClient();
                mySmtpClient.EnableSsl = true;                

                mySmtpClient.Send(message);

                _IsMailSent = true;
            }
            catch (SmtpException)
            {

            }
            catch (Exception)
            {

                return false;
            }
            return _IsMailSent;
        }
        public static bool sendSMTPMail(string mailFrom, string mailTo, string mailSubject, string mailBody, string mailCC, string mailBcc, string FilePath)
        {
            bool _IsMailSent = false;
            MailMessage message = new MailMessage(mailFrom, mailTo, mailSubject, mailBody);
            message.IsBodyHtml = true;

            try
            {
                if (!(mailCC == string.Empty || mailCC == null))
                {
                    string[] strCC = mailCC.Split(';');

                    foreach (string strThisCC in strCC)
                    {
                        if (!strThisCC.Equals(""))
                        {
                            message.CC.Add(strThisCC.Trim());
                        }
                    }
                }
                if (!(mailBcc == string.Empty || mailBcc == null))
                {
                    string[] strBCC = mailBcc.Split(';');

                    foreach (string strThisBCC in strBCC)
                    {
                        if (!strThisBCC.Equals(""))
                        {
                            message.Bcc.Add(strThisBCC.Trim());
                        }
                    }
                }

                //Attachments
                message.Attachments.Add(new System.Net.Mail.Attachment(FilePath));
                SmtpClient mySmtpClient = new SmtpClient();
                mySmtpClient.EnableSsl = false;
                mySmtpClient.Send(message);
                _IsMailSent = true;

            }
            catch (SmtpException)
            {

            }
            catch (Exception)
            {

                return false;
            }
            return _IsMailSent;
        }



        public static bool sendSMTPMail(string ToUsers, string Subject, string BodyMessage, string CcUsers, string BccUsers)
        {

            //Declarations
            bool _IsMailSent = false;
            MailMessage message = new MailMessage();
            SmtpClient client = new SmtpClient(_SMTPAddress);            
            try
            {
                //ValidateEmail used to check the Email address whether valid or not? 
                //proceedEmails used to avoid duplicate emails added in the list
                if (ValidateEmail(ToUsers))
                {
                    message.To.Add(new MailAddress(ToUsers));
                }

                //ValidateEmail used to check the Email address whether valid or not? 
                //proceedCCEmails used to avoid duplicate emails added in the list
                if (ValidateEmail(CcUsers))
                {

                    message.CC.Add(new MailAddress(CcUsers));
                }



                //ValidateEmail used to check the Email address whether valid or not? 
                //proceedBCCEmails used to avoid duplicate emails added in the list
                if (ValidateEmail(BccUsers))
                {
                    message.Bcc.Add(new MailAddress(BccUsers));
                }


                if (message.To != null && message.To.Count > 0)
                {
                    message.From = new MailAddress("motormate@in.abb.com");                    
                    message.Subject = Subject;
                    message.Body = BodyMessage;
                    message.IsBodyHtml = true;
                    client.Send(message);
                    _IsMailSent = true;
                }

            }
            catch (SmtpException ex)
            {
                _IsMailSent = false;
                throw ex;                
            }
            catch (Exception ex)
            {
                _IsMailSent = false;
                throw ex;
            }
            return _IsMailSent;


        }

        private static bool ValidateEmail(string emailAddress)
        {
            Regex regex = new Regex(@"^([\w\.\-]+)@([\w\-]+)((\.(\w){2,3})+)$");
            Match match = regex.Match(emailAddress);
            if (match.Success)
                return true;
            else
                return false;
        }
    }