# =============================================================================
# drp/urls.py - Complete URL Configuration for Walmart DRP System
# =============================================================================

from django.urls import path, include
from django.views.generic import TemplateView
from . import views

# App name for namespacing
app_name = 'drp'

urlpatterns = [
    # =============================================================================
    # API ENDPOINTS
    # =============================================================================
    
    # DRP Management APIs
    path('api/drp/issue/', views.issue_drp, name='api_issue_drp'),
    path('api/drp/verify/', views.verify_drp, name='api_verify_drp'),
    path('api/drp/revoke/', views.revoke_drp, name='api_revoke_drp'),
    path('api/drp/seller/<uuid:seller_id>/', views.get_seller_drp, name='api_get_seller_drp'),
    path('api/drp/report/', views.report_seller, name='api_report_seller'),
    
    # Seller Management APIs
    path('api/sellers/', views.SellerListCreateView.as_view(), name='api_seller_list_create'),
    path('api/sellers/<uuid:pk>/', views.SellerDetailView.as_view(), name='api_seller_detail'),
    path('api/sellers/<uuid:seller_id>/drps/', views.get_seller_drps, name='api_seller_drps'),
    path('api/sellers/<uuid:seller_id>/approve/', views.approve_seller, name='api_approve_seller'),
    path('api/sellers/<uuid:seller_id>/flag/', views.flag_seller, name='api_flag_seller'),
    path('api/sellers/<uuid:seller_id>/blacklist/', views.blacklist_seller, name='api_blacklist_seller'),
    path('api/sellers/<uuid:seller_id>/reports/', views.get_seller_reports, name='api_seller_reports'),
    
    # DRP Management APIs
    path('api/drps/', views.DRPListView.as_view(), name='api_drp_list'),
    path('api/drps/<uuid:pk>/', views.DRPDetailView.as_view(), name='api_drp_detail'),
    path('api/drps/<uuid:drp_id>/logs/', views.get_drp_logs, name='api_drp_logs'),
    path('api/drps/bulk-revoke/', views.bulk_revoke_drps, name='api_bulk_revoke_drps'),
    
    # Reports Management APIs
    path('api/reports/', views.ReportListView.as_view(), name='api_report_list'),
    path('api/reports/<uuid:pk>/', views.ReportDetailView.as_view(), name='api_report_detail'),
    path('api/reports/<uuid:report_id>/resolve/', views.resolve_report, name='api_resolve_report'),
    
    # Analytics APIs
    path('api/analytics/dashboard/', views.dashboard_analytics, name='api_dashboard_analytics'),
    path('api/analytics/seller-stats/', views.seller_statistics, name='api_seller_stats'),
    path('api/analytics/drp-stats/', views.drp_statistics, name='api_drp_stats'),
    path('api/analytics/verification-trends/', views.verification_trends, name='api_verification_trends'),
    
    # Bulk Operations APIs
    path('api/bulk/import-sellers/', views.bulk_import_sellers, name='api_bulk_import_sellers'),
    path('api/bulk/export-sellers/', views.bulk_export_sellers, name='api_bulk_export_sellers'),
    path('api/bulk/update-trust-scores/', views.bulk_update_trust_scores, name='api_bulk_update_trust_scores'),
    
    # =============================================================================
    # FRONTEND VIEWS
    # =============================================================================
    
    # Main Pages
    path('', views.home_page, name='home'),
    path('verify/', views.verify_page, name='verify_page'),
    path('seller/', views.seller_portal, name='seller_portal'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    
    # Seller Portal Pages
    path('seller/dashboard/', views.seller_dashboard, name='seller_dashboard'),
    path('seller/profile/', views.seller_profile, name='seller_profile'),
    path('seller/drp-status/', views.seller_drp_status, name='seller_drp_status'),
    path('seller/verification-history/', views.seller_verification_history, name='seller_verification_history'),
    
    # Admin Pages
    path('admin/sellers/', views.admin_sellers, name='admin_sellers'),
    path('admin/sellers/<uuid:seller_id>/', views.admin_seller_detail, name='admin_seller_detail'),
    path('admin/drps/', views.admin_drps, name='admin_drps'),
    path('admin/drps/<uuid:drp_id>/', views.admin_drp_detail, name='admin_drp_detail'),
    path('admin/reports/', views.admin_reports, name='admin_reports'),
    path('admin/reports/<uuid:report_id>/', views.admin_report_detail, name='admin_report_detail'),
    path('admin/analytics/', views.admin_analytics, name='admin_analytics'),
    path('admin/settings/', views.admin_settings, name='admin_settings'),
    
    # QR Code and Token Pages
    path('qr/<uuid:drp_id>/', views.qr_code_page, name='qr_code_page'),
    path('token/<str:token>/', views.token_verify_page, name='token_verify_page'),
    path('download-qr/<uuid:drp_id>/', views.download_qr_code, name='download_qr_code'),
    
    # Public Verification Pages
    path('public/verify-seller/<uuid:seller_id>/', views.public_verify_seller, name='public_verify_seller'),
    path('public/seller-info/<uuid:seller_id>/', views.public_seller_info, name='public_seller_info'),
    
    # =============================================================================
    # WEBHOOK ENDPOINTS (for external integrations)
    # =============================================================================
    
    path('webhook/seller-update/', views.webhook_seller_update, name='webhook_seller_update'),
    path('webhook/fraud-alert/', views.webhook_fraud_alert, name='webhook_fraud_alert'),
    path('webhook/trust-score-update/', views.webhook_trust_score_update, name='webhook_trust_score_update'),
    
    # =============================================================================
    # MOBILE API ENDPOINTS
    # =============================================================================
    
    path('mobile/api/v1/verify/', views.mobile_verify_drp, name='mobile_verify_drp'),
    path('mobile/api/v1/seller-info/', views.mobile_seller_info, name='mobile_seller_info'),
    path('mobile/api/v1/quick-verify/', views.mobile_quick_verify, name='mobile_quick_verify'),
    
    # =============================================================================
    # TESTING ENDPOINTS (for development/demo)
    # =============================================================================
    
    path('test/create-sample-data/', views.create_sample_data, name='create_sample_data'),
    path('test/reset-database/', views.reset_database, name='reset_database'),
    path('test/generate-test-drps/', views.generate_test_drps, name='generate_test_drps'),
    
    # =============================================================================
    # UTILITY ENDPOINTS
    # =============================================================================
    
    path('utils/health-check/', views.health_check, name='health_check'),
    path('utils/system-status/', views.system_status, name='system_status'),
    path('utils/clear-expired-drps/', views.clear_expired_drps, name='clear_expired_drps'),
    
    # =============================================================================
    # AJAX ENDPOINTS (for dynamic frontend updates)
    # =============================================================================
    
    path('ajax/get-seller-status/', views.ajax_get_seller_status, name='ajax_get_seller_status'),
    path('ajax/update-seller-status/', views.ajax_update_seller_status, name='ajax_update_seller_status'),
    path('ajax/get-drp-status/', views.ajax_get_drp_status, name='ajax_get_drp_status'),
    path('ajax/get-verification-logs/', views.ajax_get_verification_logs, name='ajax_get_verification_logs'),
    path('ajax/search-sellers/', views.ajax_search_sellers, name='ajax_search_sellers'),
    
    # =============================================================================
    # REDIRECT ENDPOINTS (for backward compatibility)
    # =============================================================================
    
    path('v/<str:token>/', views.legacy_verify_redirect, name='legacy_verify_redirect'),
    path('drp/<uuid:drp_id>/', views.legacy_drp_redirect, name='legacy_drp_redirect'),
    
    # =============================================================================
    # ERROR HANDLING PAGES
    # =============================================================================
    
    path('error/token-expired/', TemplateView.as_view(template_name='errors/token_expired.html'), 
         name='token_expired_page'),
    path('error/token-invalid/', TemplateView.as_view(template_name='errors/token_invalid.html'), 
         name='token_invalid_page'),
    path('error/seller-flagged/', TemplateView.as_view(template_name='errors/seller_flagged.html'), 
         name='seller_flagged_page'),
    path('error/access-denied/', TemplateView.as_view(template_name='errors/access_denied.html'), 
         name='access_denied_page'),
    
    # =============================================================================
    # DOCUMENTATION ENDPOINTS
    # =============================================================================
    
    path('docs/', TemplateView.as_view(template_name='docs/index.html'), name='docs_index'),
    path('docs/api/', TemplateView.as_view(template_name='docs/api.html'), name='docs_api'),
    path('docs/integration/', TemplateView.as_view(template_name='docs/integration.html'), name='docs_integration'),
    path('docs/faq/', TemplateView.as_view(template_name='docs/faq.html'), name='docs_faq'),
]

# =============================================================================
# EXAMPLE CURL COMMANDS FOR TESTING
# =============================================================================

"""
# 1. Create a seller
curl -X POST http://localhost:8000/api/sellers/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token-here" \
  -d '{
    "name": "Best Electronics Store",
    "email": "contact@bestelectronics.com",
    "phone": "+1-555-0123",
    "trust_score": 85
  }'

# 2. Issue DRP for seller
curl -X POST http://localhost:8000/api/drp/issue/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token-here" \
  -d '{
    "seller_id": "uuid-of-seller"
  }'

# 3. Verify DRP token
curl -X POST http://localhost:8000/api/drp/verify/ \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'

# 4. Get seller DRP
curl -X GET http://localhost:8000/api/drp/seller/uuid-of-seller/ \
  -H "Content-Type: application/json"

# 5. Revoke DRP
curl -X POST http://localhost:8000/api/drp/revoke/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token-here" \
  -d '{
    "drp_id": "uuid-of-drp",
    "reason": "Fraud detected"
  }'

# 6. Report seller
curl -X POST http://localhost:8000/api/drp/report/ \
  -H "Content-Type: application/json" \
  -d '{
    "seller_id": "uuid-of-seller",
    "report_type": "fraud",
    "description": "Seller is impersonating Walmart"
  }'

# 7. Approve seller
curl -X POST http://localhost:8000/api/sellers/uuid-of-seller/approve/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token-here" \
  -d '{
    "trust_score": 90
  }'

# 8. Flag seller
curl -X POST http://localhost:8000/api/sellers/uuid-of-seller/flag/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token-here" \
  -d '{
    "reason": "Multiple customer complaints"
  }'

# 9. Get dashboard analytics
curl -X GET http://localhost:8000/api/analytics/dashboard/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token-here"

# 10. Health check
curl -X GET http://localhost:8000/utils/health-check/ \
  -H "Content-Type: application/json"
"""

# =============================================================================
# URL PATTERNS SUMMARY
# =============================================================================

"""
Total URL patterns: 60+

Categories:
- API Endpoints: 25+ (DRP, Seller, Reports, Analytics, Bulk Operations)
- Frontend Views: 15+ (Customer, Seller, Admin pages)
- Webhook Endpoints: 3 (External integrations)
- Mobile API: 3 (Mobile app support)
- Testing Endpoints: 3 (Development/demo)
- Utility Endpoints: 3 (Health, status, cleanup)
- AJAX Endpoints: 5 (Dynamic frontend)
- Redirect Endpoints: 2 (Backward compatibility)
- Error Pages: 4 (User-friendly error handling)
- Documentation: 4 (API docs, integration guides)

Key Features:
✅ RESTful API design
✅ UUID-based resource identification
✅ Namespaced URLs for organization
✅ Mobile API support
✅ Webhook support for integrations
✅ Comprehensive error handling
✅ Testing and utility endpoints
✅ Documentation endpoints
✅ AJAX endpoints for dynamic UI
✅ Backward compatibility redirects
"""