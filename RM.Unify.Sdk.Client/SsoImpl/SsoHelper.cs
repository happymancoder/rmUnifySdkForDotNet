//-------------------------------------------------
// <copyright file="SsoHelper.cs" company="RM Education">                    
//     Copyright © 2013 RM Education Ltd
//     See LICENCE.txt file for more details
// </copyright>
//-------------------------------------------------
using System;
using RM.Unify.Sdk.Client.Platform;
using System.Reflection;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Globalization;

namespace RM.Unify.Sdk.Client.SsoImpl
{
    internal class SsoHelper
    {
        private RmUnifyCallbackApi _callbackApi;
        private static string _libVersionParam;

        private static string _LibVersionParam
        {
            get
            {
                if (_libVersionParam == null)
                {
                    var assembly = Assembly.GetExecutingAssembly();
                    FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
                    _libVersionParam = "rmunifylib=" + PlatformHelper.UrlEncode(".NET" + fvi.FileVersion);
                }
                return _libVersionParam;
            }
        }

        internal SsoHelper(RmUnifyCallbackApi callbackApi)
        {
            _callbackApi = callbackApi;
        }

        internal void Login(string returnUrl, bool refreshOnly, bool endResponse)
        {
            if (!refreshOnly || IsRmUnifyUser())
            {
                InitiateSignIn(returnUrl, endResponse);
            }
        }

        internal bool Logout(bool endResponse)
        {
            if (IsRmUnifyUser())
            {
                PlatformHelper.DeleteCookie("_rmunify_user");
                PlatformHelper.RedirectBrowser(SsoConfig.IssueUrl + "?wa=wsignout1.0&wreply=" + PlatformHelper.UrlEncode(_callbackApi.Realm) + "&" + _LibVersionParam, endResponse);
                return true;
            }
            return false;
        }

        internal void ProcessSso(bool endResponse)
        {
            try
            {
                if (!ProcessSignIn())
                {
                    if (!ProcessSignOut(endResponse))
                    {
                        string returnUrl = PlatformHelper.GetParam("returnUrl");
                        InitiateSignIn(returnUrl, endResponse);
                    }
                }
            }
            catch (Exception ex)
            {
                if (_callbackApi.RmUnifyErrorPages)
                {
                    var errorUrl = SsoConfig.GetErrorUrl(_callbackApi.Realm, ex, _LibVersionParam);
                    if (!string.IsNullOrEmpty(errorUrl))
                    {
                        PlatformHelper.RedirectBrowser(errorUrl, true);
                        return;
                    }
                }
                throw;
            }
        }

        internal static bool IsRmUnifyUser()
        {
            return PlatformHelper.GetCookie("_rmunify_user") == "true";
        }

        internal bool ProcessSignIn()
        {
            if (PlatformHelper.GetParam("wa") == "wsignin1.0")
            {
                string messageStr = PlatformHelper.GetParam("wresult");
                SignInMessage message = new SignInMessage(messageStr);
                DateTime notOnOrAfter = message.Verify(_callbackApi.Realm, _callbackApi.MaxClockSkewSeconds, _callbackApi.Cache);

                SsoUser user = new SsoUser(message);
                PlatformHelper.AddSessionCookie("_rmunify_user", "true");

                if (!string.IsNullOrEmpty(user.Organization.Id))
                {
                    if (!string.IsNullOrEmpty(user.Organization.AppEstablishmentKey))
                    {
                        if (user.Organization.IsSsoConnector)
                        {
                            if (!_callbackApi.IsOrganizationLicensed(user.Organization.AppEstablishmentKey, user.Organization, RmUnifyCallbackApi.Source.SingleSignOn))
                            {
                                throw new RmUnifySsoException(RmUnifySsoException.ERRORCODES_NOLICENCE, "No licence found for school with establishment key: " + user.Organization.AppEstablishmentKey);
                            }
                        }
                        _callbackApi.UpdateLinkedOrganization(user.Organization.AppEstablishmentKey, user.Organization, RmUnifyCallbackApi.Source.SingleSignOn);
                    }
                    else
                    {
                        if (user.Organization.IsSsoConnector)
                        {
                            throw new RmUnifySsoException(RmUnifySsoException.ERRORCODES_INVALIDAPPESTABLISHMENTKEY, "Invalid AppEstablishmentKey in SSO Connector");
                        }
                        _callbackApi.CreateOrUpdateOrganization(user.Organization, RmUnifyCallbackApi.Source.SingleSignOn);
                    }
                }

                if (!string.IsNullOrEmpty(user.AppUserId))
                {
                    if (string.IsNullOrEmpty(user.Organization.AppEstablishmentKey))
                    {
                        throw new RmUnifySsoException(RmUnifySsoException.ERRORCODES_INVALIDAPPESTABLISHMENTKEY, "Invalid AppEstablishmentKey for linked user");
                    }
                    _callbackApi.UpdateLinkedUser(user.AppUserId, user.Organization.AppEstablishmentKey, user, RmUnifyCallbackApi.Source.SingleSignOn);
                }
                else
                {
                    if (string.IsNullOrEmpty(user.Id))
                    {
                        throw new RmUnifySsoException(RmUnifySsoException.ERRORCODES_MISSINGATTRIBUTES, "No user ID (IdentityGuid or PersistentId) provided by RM Unify");
                    }
                    _callbackApi.CreateOrUpdateUser(user, RmUnifyCallbackApi.Source.SingleSignOn);
                }


                PlatformHelper.AddSessionCookie("_rmunify_user", "true");

                string returnUrl = PlatformHelper.GetParam("wctx");
                try
                {
                    if (!string.IsNullOrEmpty(user.AppUserId))
                    {
                        _callbackApi.DoLoginForLinkedUser(user.AppUserId, user.Organization.AppEstablishmentKey, user, notOnOrAfter, returnUrl);
                    }
                    else
                    {
                        _callbackApi.DoLogin(user, notOnOrAfter, returnUrl);
                    }
                }
                catch
                {
                    try
                    {
                        PlatformHelper.DeleteCookie("_rmunify_user");
                    }
                    catch { }
                    throw;
                }

                return true;
            }

            return false;
        }

        internal bool ProcessSignOut(bool endResponse)
        {
            if (PlatformHelper.GetParam("wa") == "wsignoutcleanup1.0")
            {
                var userId = PlatformHelper.GetParam("userId");
                var issueInstant = PlatformHelper.GetParam("issueInstant");
                var signature = PlatformHelper.GetParam("signature");

                VerifyLogoutRequestSignature(userId, issueInstant, signature);
                VerifyIssueInstant(issueInstant);

                PlatformHelper.DeleteCookie("_rmunify_user");
                _callbackApi.DoLogout(userId, issueInstant, signature);

                return true;
            }
            return false;
        }

        internal void InitiateSignIn(string returnUrl, bool endResponse)
        {
            string url = SsoConfig.IssueUrl + "?wa=wsignin1.0&wtrealm=" + PlatformHelper.UrlEncode(_callbackApi.Realm);
            if (returnUrl != null)
            {
                url += "&wctx=" + PlatformHelper.UrlEncode(returnUrl);
            }
            url +=  "&" + _LibVersionParam;
            PlatformHelper.RedirectBrowser(url, endResponse);
        }

        internal void VerifyLogoutRequestSignature(string userId, string issueInstant, string signature)
        {
            // Decode the Base64 signature
            var signatureBytes = Convert.FromBase64String(signature);

            // Convert the original data to bytes
            var dataBytes = Encoding.UTF8.GetBytes($"userId={userId}&issueInstant={issueInstant}");

            // Extract the public key (RSA)
            using (var publicKey = SsoConfig.SsoCertificate.GetRSAPublicKey())
            {
                var isValid = publicKey.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA1,
                    RSASignaturePadding.Pkcs1);

                if(!isValid)
                    throw new RmUnifySsoException(RmUnifySsoException.ERRORCODES_VERIFICATIONFAILED, "Logout failed: signature could not be verified");
            }
        }

        internal void VerifyIssueInstant(string issueInstant)
        {
            if(!DateTime.TryParseExact(issueInstant, "yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var issueDateTime))
                throw new RmUnifySsoException(RmUnifySsoException.ERRORCODES_VERIFICATIONFAILED, "Logout failed: unable to parse the logout request issue time");

            var notBefore = DateTime.UtcNow.AddMinutes(5);

            if (issueDateTime < notBefore)
                throw new RmUnifySsoException(RmUnifySsoException.ERRORCODES_FUTUREOREXPIREDTOKEN, "Logout failed: request is stale");
        }
    }
}
