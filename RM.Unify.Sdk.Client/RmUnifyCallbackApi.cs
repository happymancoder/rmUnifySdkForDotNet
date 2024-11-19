//-------------------------------------------------
// <copyright file="RmUnifyCallbackApi.cs" company="RM Education">                    
//     Copyright © 2013 RM Education Ltd
//     See LICENCE.txt file for more details
// </copyright>
//-------------------------------------------------
using System;

namespace RM.Unify.Sdk.Client
{
    /// <summary>
    /// RM Unify callback API
    /// Subclass this class, and implement the abstract methods and properties, in order to support sign in with RM Unify
    /// v1.0 supports single sign on
    /// Future versions will allow your app to implement account linking (brownfield) and in-advance provisioning simply
    /// by implementing further functions.
    /// </summary>
    public abstract class RmUnifyCallbackApi
    {
        public enum Source
        {
            SingleSignOn,
            InAdvanceProvisioning
        }

        /// <summary>
        /// RM Unify cache (used for token replay)
        /// </summary>
        protected static IRmUnifyCache _cache;

        /// <summary>
        /// The WS-Federation realm of your app, as configured in RM Unify
        /// This must be a URL in a domain that you own, but need not actually exist.
        /// For example, if you are working on a development copy of your app, and your live app is hosted at
        /// https://myapp.mycompany.com/, you might choose the URL https://dev.myapp.mycompany.com/realm.
        /// </summary>
        public abstract string Realm { get; }

        /// <summary>
        /// The maximum difference between the clock on your servers and the RM Unify sign in server
        /// Default value is 300 seconds if this property is not overridden.
        /// If the difference between clocks is larger than this value, single sign on requests may be rejected.
        /// The RM Unify sign in server clock is regularly synchronised, but under very heavy load the clock may be
        /// up to 60 seconds out.
        /// </summary>
        public virtual int MaxClockSkewSeconds { get { return 300; } }

        /// <summary>
        /// Cache used by client library to prevent token replay
        /// If your app only has one front-end server, you can just use the default implementation.
        /// If your app has multiple front-end servers, we recommend increasing security by implementing a shared cache.
        /// </summary>
        public virtual IRmUnifyCache Cache {
            get
            {
                if (_cache == null)
                {
                    _cache = new RM.Unify.Sdk.Client.Platform.RmUnifyDefaultCache();
                }
                return _cache;
            }
        }

        /// <summary>
        /// Whether to show the RM Unify error pages if there is an error during single sign on.
        /// If true, the browser will be redirected to an error page in RM Unify; if false, the error will be thrown
        /// to your application to handle.
        /// </summary>
        public virtual bool RmUnifyErrorPages { get { return true; } }

        /// <summary>
        /// Create a new organization or update an existing one.
        /// This method will never be called if the organization.Id is null (for example, if the attribute
        /// has not been requested from RM Unify).
        /// If your app stores information about an organization, it should use organization.Id as a key to create a
        /// new organization record or update an existing one.
        /// </summary>
        /// <param name="organization">Organization profile</param>
        /// <param name="source">Source of update (sign on or provisioning)</param>
        public abstract void CreateOrUpdateOrganization(RmUnifyOrganization organization, Source source);

        /// <summary>
        /// Create a new user or update an existing one.
        /// This method will never be called if the user.Id is null (for example, if neither IdentityGuid nor
        /// PersistentId has been requested from RM Unify).
        /// If your app stores information about a user, it should use user.Id as a key to create a new user record or
        /// update an existing one.
        /// Be aware that it is possible for a user to move organization (i.e. the same user.Id may appear in a different
        /// organization.Id).  In this case, it is safe to delete the old user profile.
        /// </summary>
        /// <param name="user">User profile</param>
        /// <param name="source">Source of update (sign on or provisioning)</param>
        public abstract void CreateOrUpdateUser(RmUnifyUser user, Source source);

        /// <summary>
        /// Log the current user into your app.
        /// This method is called when single sign on from RM Unify successfully completes.  CreateOrUpdateOrganization()
        /// and CreateOrUpdateUser() will always be called first (in that order) provided the appropriate Ids are available.
        /// Your app should set any session cookies required to log the user in.
        /// Your app should then redirect the user to returnUrl (if set) or to the default URL for this user in your app.
        /// </summary>
        /// <param name="user">User profile</param>
        /// <param name="maxSessionEnd">Maximum time after which reauthentication should be prompted</param>
        /// <param name="returnUrl">Return URL specified in login request (null if none)</param>
        public abstract void DoLogin(RmUnifyUser user, DateTime maxSessionEnd, string returnUrl);

        /// <summary>
        /// Log the current user out of your app.
        /// This method is called when single logout is initiated from RM Unify.  If should delete any session cookies
        /// associated with your app.  The method should *not* error if there is no session.
        /// You may also wish any open app tabs to redirect to a logged out page.  This can be achieved by regularly checking
        /// for the existence of a session cookie using JavaScript, and disabling the app if none is found.
        /// As well as implementing this method, you will also need to call Logout() on the RmUnifyClientApi if someone
        /// clicks the logout button in your app (after deleting your session cookie).
        /// </summary>
        /// <param name="userId">the user’s IdentityGuid or PersistentId, URL-encoded</param>
        /// <param name="issueInstant">the UTC time of the logout request, URL-encoded</param>
        /// <param name="signature">the signature is generated from the userId and the issueInstant, prior to URL-encoding</param>
        public abstract void DoLogout(string userId, string issueInstant, string signature);

        /// <summary>
        /// Check that a pre-existing organization that has been linked to RM Unify is licenced in your app.
        /// Only necessary if your app supports SSO Connectors (http://dev.rmunify.com/reference/supporting-sso-connector-licensing.aspx).
        /// In this case, the organization has purchased your app outside RM Unify and wishes to connect RM Unify to this
        /// licence. They get an "app establishment key" from you and enter it into RM Unify. This key is passed in to this
        /// method for you to verify the licence.
        /// Called before UpdateLinkedOrganization() if the organization has an SSO Connector to your app.
        /// </summary>
        /// <param name="appEstablishmentKey">App establishment key (as provided by you to the organization)</param>
        /// <param name="organization">Organization profile</param>
        /// <param name="source">Source of update (sign on or provisioning)</param>
        /// <returns>True if organization licensed, false otherwise</returns>
        public virtual bool IsOrganizationLicensed(string appEstablishmentKey, RmUnifyOrganization organization, Source source)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Update properties of a pre-existing organization that has been linked to RM Unify.
        /// Only necessary if your app supports SSO Connectors (http://dev.rmunify.com/reference/supporting-sso-connector-licensing.aspx)
        /// or the RM Unify user account matching process (http://dev.rmunify.com/reference/supporting-user-account-matching/the-rm-unify-process.aspx).
        /// In this case, the organization has obtained your app outside RM Unify and wishes to connect RM Unify to their
        /// existing establishment in your app. They get an "app establishment key" from you and enter it into RM Unify.
        /// This key is passed in to this method for you to identify the establishment and update it.
        /// Called instead of CreateOrUpdateOrganization() if the organization has an SSO Connector to your app
        /// or has linked the organization as part of the RM Unify user account matching process.
        /// </summary>
        /// <param name="appEstablishmentKey">App establishment key (as provided by you to the organization)</param>
        /// <param name="organization">Organization profile</param>
        /// <param name="source">Source of update (sign on or provisioning)</param>
        public virtual void UpdateLinkedOrganization(string appEstablishmentKey, RmUnifyOrganization organization, Source source)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Update properties of a pre-existing user that has been linked to RM Unify.
        /// Only necessary if your app supports the RM Unify user account matching process
        /// (http://dev.rmunify.com/reference/supporting-user-account-matching/the-rm-unify-process.aspx).
        /// In this case, the organization has provisioned users into your app outside RM Unify and wishes to connect RM Unify
        /// to their existing users. Their "app establishment key" and the existing user id in your app (typically login name)
        /// is passed in to this method so that you can verify that the user is in the establishment and update them.
        /// Called instead of CreateOrUpdateUser() if the current user has been linked to a user in your app as part of the
        /// RM Unify user account matching process.
        /// </summary>
        /// <param name="appUserId">User ID in your app (typically login name)</param>
        /// <param name="appEstablishmentKey">App establishment key (as provided by you to the organization)</param>
        /// <param name="user">User profile</param>
        /// <param name="source">Source of update (sign on or provisioning)</param>
        public virtual void UpdateLinkedUser(string appUserId, string appEstablishmentKey, RmUnifyUser user, Source source)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Log in as a pre-existing user who has been linked to an RM Unify user.
        /// This method is called when single sign on from RM Unify successfully completes.  CreateOrUpdateOrganization()
        /// and CreateOrUpdateUser() will always be called first (in that order) provided the appropriate Ids are available.
        /// Your app should set any session cookies required to log the user in.
        /// Your app should then redirect the user to returnUrl (if set) or to the default URL for this user in your app.
        /// </summary>
        /// <param name="appUserId">User ID in your app (typically login name)</param>
        /// <param name="appEstablishmentKey">App establishment key (as provided by you to the organization)</param>
        /// <param name="user">User profile</param>
        /// <param name="maxSessionEnd">Maxiumum time after which reauthentication should be prompted</param>
        /// <param name="returnUrl">Return URL specified in login request (null if none)</param>
        public virtual void DoLoginForLinkedUser(string appUserId, string appEstablishmentKey, RmUnifyUser user, DateTime maxSessionEnd, string returnUrl)
        {
            throw new NotImplementedException();
        }
    }
}
