import frappe
import requests
from frappe import _
from datetime import datetime, timedelta

@frappe.whitelist(allow_guest=True)
def authorize():
    """Redirect user to Zoho OAuth consent screen"""
    settings = frappe.get_single("Zoho Campaigns Settings")
    
    if not settings.client_id or not settings.redirect_uri:
        frappe.throw(_("Please configure Client ID and Redirect URI in Zoho Campaigns Settings"))
    
    auth_url = (
        f"https://accounts.zoho.in/oauth/v2/auth?"
        f"response_type=code&"
        f"client_id={settings.client_id}&"
        f"scope=ZohoCampaigns.campaign.READ%20ZohoCampaigns.contact.CREATE%20ZohoCampaigns.contact.READ%20ZohoCampaigns.contact.UPDATE&"
        f"redirect_uri={settings.redirect_uri}&"
        f"access_type=offline&"
        f"prompt=consent"
    )
    
    frappe.local.response["type"] = "redirect"
    frappe.local.response["location"] = auth_url


@frappe.whitelist(allow_guest=True)
def callback():
    """Handle OAuth callback and exchange code for tokens"""
    # Zoho returns {"message": "auth_code"} instead of ?code=auth_code
    code = frappe.form_dict.get("code")
    
    # If not in URL params, check if it's in the response body
    if not code:
        try:
            message = frappe.form_dict.get("message")
            if message:
                code = message
        except:
            pass
    
    if not code:
        frappe.throw(_("Authorization code not received"))
    
    settings = frappe.get_single("Zoho Campaigns Settings")
    
    token_url = "https://accounts.zoho.in/oauth/v2/token"
    payload = {
        "client_id": settings.client_id,
        "client_secret": settings.get_password("client_secret"),
        "grant_type": "authorization_code",
        "redirect_uri": settings.redirect_uri,
        "code": code
    }
    
    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        data = response.json()
        
        # Check if response contains error
        if "error" in data:
            frappe.throw(_(f"OAuth Error: {data.get('error')}"))
        
        # Save tokens and API domain
        settings.access_token = data.get("access_token")
        settings.refresh_token = data.get("refresh_token")
        settings.api_domain = data.get("api_domain", "https://www.zohoapis.in")
        settings.token_expiry = datetime.now() + timedelta(seconds=data.get("expires_in", 3600))
        settings.is_active = 1
        settings.save(ignore_permissions=True)
        frappe.db.commit()
        
        # Show success message and redirect
        frappe.msgprint(_("Successfully connected to Zoho Campaigns!"), indicator="green")
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = "/app/zoho-campaigns-settings"
        
    except requests.exceptions.RequestException as e:
        frappe.log_error(frappe.get_traceback(), _("Zoho OAuth Callback Error"))
        frappe.throw(_("Failed to obtain access token: {0}").format(str(e)))


def refresh_access_token():
    """Refresh access token using refresh token"""
    settings = frappe.get_single("Zoho Campaigns Settings")
    
    if not settings.refresh_token:
        frappe.throw(_("No refresh token available. Please re-authorize."))
    
    token_url = "https://accounts.zoho.in/oauth/v2/token"
    payload = {
        "client_id": settings.client_id,
        "client_secret": settings.get_password("client_secret"),
        "grant_type": "refresh_token",
        "refresh_token": settings.get_password("refresh_token")
    }
    
    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        data = response.json()
        
        if "error" in data:
            frappe.throw(_(f"Token Refresh Error: {data.get('error')}"))
        
        # Update access token (refresh token stays the same)
        settings.access_token = data.get("access_token")
        settings.api_domain = data.get("api_domain", settings.api_domain)
        settings.token_expiry = datetime.now() + timedelta(seconds=data.get("expires_in", 3600))
        settings.save(ignore_permissions=True)
        frappe.db.commit()
        
        return data.get("access_token")
        
    except requests.exceptions.RequestException as e:
        frappe.log_error(frappe.get_traceback(), _("Zoho Token Refresh Error"))
        frappe.throw(_("Failed to refresh access token: {0}").format(str(e)))