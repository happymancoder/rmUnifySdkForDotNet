//-------------------------------------------------
// <copyright file="PlatformHelper.cs" company="RM Education">                    
//     Copyright © 2013 RM Education Ltd
//     See LICENCE.txt file for more details
// </copyright>
//-------------------------------------------------
using System;
using System.Web;

namespace RM.Unify.Sdk.Client.Platform
{
    internal class PlatformHelper
    {
        private static byte[] _tickImage = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAABEAAAANCAYAAABPeYUaAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAadEVYdFNvZnR3YXJlAFBhaW50Lk5FVCB2My41LjEwMPRyoQAAAH9JREFUOE+dkMkNwCAMBKmGguiHgugozzzzTAeEtWxkrCAMIyHkazjCCVXBKT88V8tbarwi7YDLa/TwtoA6G+lONIxd4JYRW0CME62AyyNUUUguP7lffymQRix5q1sA/gZ0jOX6RCvaFoCZBDmXQLCi5T/MENGxQKDpBocOQvgAl6sV4Md89G8AAAAASUVORK5CYII=");

        internal static string UrlEncode(string s)
        {
            return HttpUtility.UrlEncode(s);
        }

        internal static void RedirectBrowser(string url, bool endResponse)
        {
            var response = HttpContext.Current.Response;
            response.Redirect(url, endResponse);
        }

        internal static void AddSessionCookie(string cookieName, string cookieValue)
        {
            HttpContext.Current.Response.Cookies.Add(new HttpCookie(cookieName, cookieValue));
        }

        /// Returns null if cookie does not exist
        internal static string GetCookie(string cookieName)
        {
            var cookie = HttpContext.Current.Request.Cookies["_rmunify_user"];
            return cookie == null ? null : cookie.Value;
        }

        internal static void DeleteCookie(string cookieName)
        {
            HttpCookie cookie = new HttpCookie(cookieName);
            cookie.Expires = DateTime.Now.AddDays(-1d);
            HttpContext.Current.Response.Cookies.Add(cookie);
        }

        // Returns null if parameter doesn't exist (as get or post)
        internal static string GetParam(string paramName)
        {
            return HttpContext.Current.Request.Params[paramName];
        }

        internal static void SendTickResponse(bool endResponse)
        {
            var response = HttpContext.Current.Response;
            response.ClearContent();
            response.StatusCode = 200;
            response.Cache.SetCacheability(HttpCacheability.NoCache);
            response.ContentType = "image/png";
            response.BinaryWrite(_tickImage);
            if (endResponse)
            {
                response.End();
            }
        }
    }
}
