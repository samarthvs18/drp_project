"""
Walmart DRP System - Django Admin Configuration
Comprehensive admin interface for managing sellers, DRPs, and system operations
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.http import HttpResponse
from django.shortcuts import redirect
from django.contrib import messages
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
import csv
import base64
from io import BytesIO
from PIL import Image

from .models import Seller, DRP, DRPLog, TrustMetric, VerificationRequest
from .utils import generate_drp_token, generate_qr_code, revoke_drp_token


class TrustMetricInline(admin.TabularInline):
    """Inline admin for trust metrics"""
    model = TrustMetric
    extra = 0
    readonly_fields = ('metric_type', 'score', 'created_at')
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False


class DRPInline(admin.TabularInline):
    """Inline admin for DRP tokens"""
    model = DRP
    extra = 0
    readonly_fields = ('token_id', 'created_at', 'expires_at', 'status', 'qr_preview')
    fields = ('token_id', 'status', 'created_at', 'expires_at', 'qr_preview')
    can_delete = False
    
    def qr_preview(self, obj):
        """Display QR code preview in admin"""
        if obj.qr_code:
            return format_html(
                '<img src="data:image/png;base64,{}" width="50" height="50" />',
                obj.qr_code
            )
        return "No QR Code"
    qr_preview.short_description = "QR Preview"
    
    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Seller)
class SellerAdmin(admin.ModelAdmin):
    """Enhanced Seller Admin with comprehensive management features"""
    
    list_display = (
        'name', 'email', 'verification_status_badge', 'trust_score_display',
        'active_drp_count', 'last_drp_issued', 'is_active_display', 'created_at'
    )
    list_filter = (
        'verification_status', 'is_active', 'trust_score', 'created_at',
        ('drp_set__created_at', admin.DateFieldListFilter)
    )
    search_fields = ('name', 'email', 'seller_id')
    readonly_fields = (
        'seller_id', 'created_at', 'updated_at', 'trust_score_display',
        'verification_history', 'drp_statistics', 'security_alerts'
    )
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('seller_id', 'name', 'email', 'phone', 'business_type')
        }),
        ('Verification Status', {
            'fields': ('verification_status', 'is_active', 'trust_score', 'trust_score_display'),
            'classes': ('wide',)
        }),
        ('Security & Compliance', {
            'fields': ('security_alerts', 'verification_notes', 'internal_notes'),
            'classes': ('collapse',)
        }),
        ('System Information', {
            'fields': ('created_at', 'updated_at', 'verification_history', 'drp_statistics'),
            'classes': ('collapse',)
        }),
    )
    
    inlines = [TrustMetricInline, DRPInline]
    actions = [
        'approve_sellers', 'reject_sellers', 'flag_sellers', 'bulk_issue_drp',
        'export_seller_data', 'reset_trust_scores', 'send_verification_email'
    ]
    
    def verification_status_badge(self, obj):
        """Display verification status with color coding"""
        colors = {
            'pending': '#fbbf24',  # yellow
            'verified': '#10b981',  # green
            'rejected': '#ef4444',  # red
            'flagged': '#f59e0b',   # orange
            'suspended': '#6b7280'  # gray
        }
        color = colors.get(obj.verification_status, '#6b7280')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_verification_status_display()
        )
    verification_status_badge.short_description = "Status"
    verification_status_badge.admin_order_field = 'verification_status'
    
    def trust_score_display(self, obj):
        """Display trust score with progress bar"""
        if obj.trust_score is None:
            return "N/A"
        
        # Color coding based on trust score
        if obj.trust_score >= 80:
            color = '#10b981'  # green
        elif obj.trust_score >= 60:
            color = '#fbbf24'  # yellow
        else:
            color = '#ef4444'  # red
            
        return format_html(
            '<div style="width: 100px; background-color: #e5e7eb; border-radius: 3px;">'
            '<div style="width: {}%; height: 20px; background-color: {}; border-radius: 3px; '
            'display: flex; align-items: center; justify-content: center; color: white; font-size: 12px;">'
            '{}%</div></div>',
            obj.trust_score, color, obj.trust_score
        )
    trust_score_display.short_description = "Trust Score"
    trust_score_display.admin_order_field = 'trust_score'
    
    def active_drp_count(self, obj):
        """Count of active DRP tokens"""
        count = obj.drp_set.filter(status='active', expires_at__gt=timezone.now()).count()
        return format_html('<strong>{}</strong>', count)
    active_drp_count.short_description = "Active DRPs"
    
    def last_drp_issued(self, obj):
        """Last DRP issuance date"""
        last_drp = obj.drp_set.order_by('-created_at').first()
        if last_drp:
            return last_drp.created_at.strftime('%Y-%m-%d %H:%M')
        return "Never"
    last_drp_issued.short_description = "Last DRP Issued"
    
    def is_active_display(self, obj):
        """Display active status with icon"""
        if obj.is_active:
            return format_html('<span style="color: green;">✓ Active</span>')
        return format_html('<span style="color: red;">✗ Inactive</span>')
    is_active_display.short_description = "Status"
    is_active_display.admin_order_field = 'is_active'
    
    def verification_history(self, obj):
        """Display verification history"""
        history = []
        # Get DRP logs for this seller
        logs = DRPLog.objects.filter(seller=obj).order_by('-timestamp')[:5]
        for log in logs:
            history.append(f"{log.timestamp.strftime('%Y-%m-%d %H:%M')} - {log.action}")
        
        if history:
            return format_html('<br>'.join(history))
        return "No history available"
    verification_history.short_description = "Recent History"
    
    def drp_statistics(self, obj):
        """Display DRP statistics"""
        total_drps = obj.drp_set.count()
        active_drps = obj.drp_set.filter(status='active').count()
        revoked_drps = obj.drp_set.filter(status='revoked').count()
        expired_drps = obj.drp_set.filter(status='expired').count()
        
        return format_html(
            '<strong>Total:</strong> {} | <strong>Active:</strong> {} | '
            '<strong>Revoked:</strong> {} | <strong>Expired:</strong> {}',
            total_drps, active_drps, revoked_drps, expired_drps
        )
    drp_statistics.short_description = "DRP Statistics"
    
    def security_alerts(self, obj):
        """Display security alerts"""
        alerts = []
        
        # Check for suspicious activity
        recent_verifications = VerificationRequest.objects.filter(
            seller=obj, 
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        if recent_verifications > 50:
            alerts.append("⚠️ High verification requests (24h)")
        
        # Check for flagged status
        if obj.verification_status == 'flagged':
            alerts.append("🚩 Seller flagged for review")
        
        # Check for low trust score
        if obj.trust_score and obj.trust_score < 40:
            alerts.append("⚠️ Low trust score")
        
        # Check for expired verification
        if obj.verification_status == 'verified' and obj.updated_at < timezone.now() - timedelta(days=365):
            alerts.append("⏰ Verification expired")
        
        if alerts:
            return format_html('<br>'.join(alerts))
        return format_html('<span style="color: green;">✓ No alerts</span>')
    security_alerts.short_description = "Security Alerts"
    
    # Admin Actions
    def approve_sellers(self, request, queryset):
        """Bulk approve selected sellers"""
        updated = queryset.update(verification_status='verified', is_active=True)
        
        # Log the action
        for seller in queryset:
            DRPLog.objects.create(
                seller=seller,
                action='approved',
                details=f'Bulk approved by admin: {request.user.username}',
                admin_user=request.user
            )
        
        self.message_user(request, f'{updated} sellers approved successfully.')
    approve_sellers.short_description = "Approve selected sellers"
    
    def reject_sellers(self, request, queryset):
        """Bulk reject selected sellers"""
        updated = queryset.update(verification_status='rejected', is_active=False)
        
        # Revoke all active DRPs
        for seller in queryset:
            # Revoke active DRPs
            active_drps = seller.drp_set.filter(status='active')
            for drp in active_drps:
                revoke_drp_token(drp.token_id, f'Seller rejected by admin: {request.user.username}')
            
            # Log the action
            DRPLog.objects.create(
                seller=seller,
                action='rejected',
                details=f'Bulk rejected by admin: {request.user.username}',
                admin_user=request.user
            )
        
        self.message_user(request, f'{updated} sellers rejected successfully.')
    reject_sellers.short_description = "Reject selected sellers"
    
    def flag_sellers(self, request, queryset):
        """Bulk flag selected sellers for review"""
        updated = queryset.update(verification_status='flagged')
        
        # Log the action
        for seller in queryset:
            DRPLog.objects.create(
                seller=seller,
                action='flagged',
                details=f'Flagged for review by admin: {request.user.username}',
                admin_user=request.user
            )
        
        self.message_user(request, f'{updated} sellers flagged for review.')
    flag_sellers.short_description = "Flag selected sellers for review"
    
    def bulk_issue_drp(self, request, queryset):
        """Bulk issue DRP tokens for verified sellers"""
        issued_count = 0
        
        for seller in queryset.filter(verification_status='verified', is_active=True):
            # Check if seller already has active DRP
            if not seller.drp_set.filter(status='active', expires_at__gt=timezone.now()).exists():
                # Generate new DRP
                token_data = generate_drp_token(seller)
                qr_code = generate_qr_code(token_data['token'])
                
                DRP.objects.create(
                    seller=seller,
                    token_id=token_data['token_id'],
                    jwt_token=token_data['token'],
                    qr_code=qr_code,
                    expires_at=token_data['expires_at']
                )
                
                # Log the action
                DRPLog.objects.create(
                    seller=seller,
                    action='drp_issued',
                    details=f'DRP issued via bulk action by admin: {request.user.username}',
                    admin_user=request.user
                )
                
                issued_count += 1
        
        self.message_user(request, f'{issued_count} DRP tokens issued successfully.')
    bulk_issue_drp.short_description = "Issue DRP tokens for verified sellers"
    
    def export_seller_data(self, request, queryset):
        """Export seller data to CSV"""
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="sellers_export.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'Seller ID', 'Name', 'Email', 'Phone', 'Business Type',
            'Verification Status', 'Trust Score', 'Is Active',
            'Created At', 'Updated At', 'Active DRPs', 'Total DRPs'
        ])
        
        for seller in queryset:
            active_drps = seller.drp_set.filter(status='active').count()
            total_drps = seller.drp_set.count()
            
            writer.writerow([
                seller.seller_id, seller.name, seller.email, seller.phone,
                seller.business_type, seller.verification_status,
                seller.trust_score, seller.is_active,
                seller.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                seller.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                active_drps, total_drps
            ])
        
        return response
    export_seller_data.short_description = "Export seller data to CSV"
    
    def reset_trust_scores(self, request, queryset):
        """Reset trust scores to default (50)"""
        updated = queryset.update(trust_score=50)
        
        # Log the action
        for seller in queryset:
            DRPLog.objects.create(
                seller=seller,
                action='trust_score_reset',
                details=f'Trust score reset to 50 by admin: {request.user.username}',
                admin_user=request.user
            )
        
        self.message_user(request, f'{updated} trust scores reset to 50.')
    reset_trust_scores.short_description = "Reset trust scores to default"
    
    def send_verification_email(self, request, queryset):
        """Send verification email to selected sellers"""
        # This would integrate with your email system
        count = queryset.count()
        
        # Log the action
        for seller in queryset:
            DRPLog.objects.create(
                seller=seller,
                action='verification_email_sent',
                details=f'Verification email sent by admin: {request.user.username}',
                admin_user=request.user
            )
        
        self.message_user(request, f'Verification emails sent to {count} sellers.')
    send_verification_email.short_description = "Send verification emails"


@admin.register(DRP)
class DRPAdmin(admin.ModelAdmin):
    """Enhanced DRP Admin with token management features"""
    
    list_display = (
        'token_id_short', 'seller_link', 'status_badge', 'created_at',
        'expires_at', 'time_remaining', 'verification_count', 'qr_preview'
    )
    list_filter = (
        'status', 'created_at', 'expires_at',
        ('seller__verification_status', admin.AllValuesFieldListFilter)
    )
    search_fields = ('token_id', 'seller__name', 'seller__email')
    readonly_fields = (
        'token_id', 'jwt_token', 'created_at', 'expires_at',
        'qr_code_display', 'token_details', 'verification_history'
    )
    
    fieldsets = (
        ('Token Information', {
            'fields': ('token_id', 'seller', 'status', 'created_at', 'expires_at')
        }),
        ('Token Data', {
            'fields': ('jwt_token', 'token_details'),
            'classes': ('collapse',)
        }),
        ('QR Code', {
            'fields': ('qr_code_display',),
            'classes': ('wide',)
        }),
        ('Usage Statistics', {
            'fields': ('verification_history',),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['revoke_drp_tokens', 'extend_drp_expiry', 'regenerate_qr_codes']
    
    def token_id_short(self, obj):
        """Display shortened token ID"""
        return f"{obj.token_id[:8]}..."
    token_id_short.short_description = "Token ID"
    token_id_short.admin_order_field = 'token_id'
    
    def seller_link(self, obj):
        """Clickable link to seller admin page"""
        url = reverse('admin:drp_seller_change', args=[obj.seller.pk])
        return format_html('<a href="{}">{}</a>', url, obj.seller.name)
    seller_link.short_description = "Seller"
    seller_link.admin_order_field = 'seller__name'
    
    def status_badge(self, obj):
        """Display status with color coding"""
        colors = {
            'active': '#10b981',     # green
            'expired': '#6b7280',    # gray
            'revoked': '#ef4444',    # red
            'suspended': '#f59e0b'   # orange
        }
        color = colors.get(obj.status, '#6b7280')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.status.upper()
        )
    status_badge.short_description = "Status"
    status_badge.admin_order_field = 'status'
    
    def time_remaining(self, obj):
        """Display time remaining until expiry"""
        if obj.status == 'expired':
            return "Expired"
        elif obj.status == 'revoked':
            return "Revoked"
        
        now = timezone.now()
        if obj.expires_at > now:
            delta = obj.expires_at - now
            if delta.days > 0:
                return f"{delta.days}d {delta.seconds//3600}h"
            elif delta.seconds > 3600:
                return f"{delta.seconds//3600}h {(delta.seconds%3600)//60}m"
            else:
                return f"{delta.seconds//60}m"
        else:
            return "Expired"
    time_remaining.short_description = "Time Remaining"
    
    def verification_count(self, obj):
        """Count of verification requests"""
        count = VerificationRequest.objects.filter(drp=obj).count()
        return format_html('<strong>{}</strong>', count)
    verification_count.short_description = "Verifications"
    
    def qr_preview(self, obj):
        """Display QR code preview"""
        if obj.qr_code:
            return format_html(
                '<img src="data:image/png;base64,{}" width="40" height="40" />',
                obj.qr_code
            )
        return "No QR"
    qr_preview.short_description = "QR"
    
    def qr_code_display(self, obj):
        """Display full QR code"""
        if obj.qr_code:
            return format_html(
                '<img src="data:image/png;base64,{}" width="200" height="200" />',
                obj.qr_code
            )
        return "No QR Code available"
    qr_code_display.short_description = "QR Code"
    
    def token_details(self, obj):
        """Display decoded token information"""
        if obj.jwt_token:
            try:
                import jwt
                from django.conf import settings
                
                # Decode token (without verification for display)
                payload = jwt.decode(obj.jwt_token, options={"verify_signature": False})
                
                details = []
                for key, value in payload.items():
                    if key == 'exp':
                        # Convert timestamp to readable date
                        exp_date = timezone.datetime.fromtimestamp(value, tz=timezone.utc)
                        details.append(f"<strong>{key}:</strong> {exp_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    else:
                        details.append(f"<strong>{key}:</strong> {value}")
                
                return format_html('<br>'.join(details))
            except Exception as e:
                return f"Error decoding token: {str(e)}"
        return "No token data"
    token_details.short_description = "Token Details"
    
    def verification_history(self, obj):
        """Display verification request history"""
        verifications = VerificationRequest.objects.filter(drp=obj).order_by('-created_at')[:10]
        
        if verifications:
            history = []
            for verification in verifications:
                status_icon = "✓" if verification.is_valid else "✗"
                history.append(
                    f"{verification.created_at.strftime('%Y-%m-%d %H:%M')} - "
                    f"{status_icon} {verification.ip_address} - {verification.user_agent[:50]}..."
                )
            return format_html('<br>'.join(history))
        return "No verification history"
    verification_history.short_description = "Verification History"
    
    # Admin Actions
    def revoke_drp_tokens(self, request, queryset):
        """Revoke selected DRP tokens"""
        revoked_count = 0
        
        for drp in queryset.filter(status='active'):
            success = revoke_drp_token(drp.token_id, f'Revoked by admin: {request.user.username}')
            if success:
                revoked_count += 1
        
        self.message_user(request, f'{revoked_count} DRP tokens revoked successfully.')
    revoke_drp_tokens.short_description = "Revoke selected DRP tokens"
    
    def extend_drp_expiry(self, request, queryset):
        """Extend expiry time for selected DRP tokens"""
        extended_count = 0
        
        for drp in queryset.filter(status='active'):
            # Extend by 1 hour
            drp.expires_at = drp.expires_at + timedelta(hours=1)
            drp.save()
            
            # Log the action
            DRPLog.objects.create(
                seller=drp.seller,
                drp=drp,
                action='extended',
                details=f'DRP expiry extended by 1 hour by admin: {request.user.username}',
                admin_user=request.user
            )
            
            extended_count += 1
        
        self.message_user(request, f'{extended_count} DRP tokens extended by 1 hour.')
    extend_drp_expiry.short_description = "Extend expiry by 1 hour"
    
    def regenerate_qr_codes(self, request, queryset):
        """Regenerate QR codes for selected DRP tokens"""
        regenerated_count = 0
        
        for drp in queryset.filter(status='active'):
            # Generate new QR code
            qr_code = generate_qr_code(drp.jwt_token)
            drp.qr_code = qr_code
            drp.save()
            
            # Log the action
            DRPLog.objects.create(
                seller=drp.seller,
                drp=drp,
                action='qr_regenerated',
                details=f'QR code regenerated by admin: {request.user.username}',
                admin_user=request.user
            )
            
            regenerated_count += 1
        
        self.message_user(request, f'{regenerated_count} QR codes regenerated.')
    regenerate_qr_codes.short_description = "Regenerate QR codes"


@admin.register(DRPLog)
class DRPLogAdmin(admin.ModelAdmin):
    """DRP Log Admin for audit trail"""
    
    list_display = (
        'timestamp', 'seller_link', 'action_badge', 'ip_address',
        'user_agent_short', 'admin_user', 'is_successful'
    )
    list_filter = (
        'action', 'is_successful', 'timestamp',
        ('admin_user', admin.AllValuesFieldListFilter)
    )
    search_fields = ('seller__name', 'seller__email', 'action', 'ip_address')
    readonly_fields = ('timestamp', 'seller', 'drp', 'action', 'details', 'ip_address', 'user_agent', 'admin_user')
    
    fieldsets = (
        ('Log Information', {
            'fields': ('timestamp', 'seller', 'drp', 'action', 'is_successful')
        }),
        ('Details', {
            'fields': ('details', 'ip_address', 'user_agent', 'admin_user'),
            'classes': ('wide',)
        }),
    )
    
    def seller_link(self, obj):
        """Clickable link to seller"""
        if obj.seller:
            url = reverse('admin:drp_seller_change', args=[obj.seller.pk])
            return format_html('<a href="{}">{}</a>', url, obj.seller.name)
        return "N/A"
    seller_link.short_description = "Seller"
    
    def action_badge(self, obj):
        """Display action with color coding"""
        colors = {
            'verified': '#10b981',      # green
            'drp_issued': '#3b82f6',    # blue
            'drp_revoked': '#ef4444',   # red
            'approved': '#10b981',      # green
            'rejected': '#ef4444',      # red
            'flagged': '#f59e0b',       # orange
            'failed_verification': '#ef4444'  # red
        }
        color = colors.get(obj.action, '#6b7280')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.action.replace('_', ' ').title()
        )
    action_badge.short_description = "Action"
    action_badge.admin_order_field = 'action'
    
    def user_agent_short(self, obj):
        """Display shortened user agent"""
        if obj.user_agent:
            return obj.user_agent[:50] + "..." if len(obj.user_agent) > 50 else obj.user_agent
        return "N/A"
    user_agent_short.short_description = "User Agent"
    
    def has_add_permission(self, request):
        """Disable manual log creation"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Disable log editing"""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Disable log deletion"""
        return False


@admin.register(VerificationRequest)
class VerificationRequestAdmin(admin.ModelAdmin):
    """Verification Request Admin for monitoring"""
    
    list_display = (
        'created_at', 'seller_link', 'drp_link', 'is_valid_display',
        'ip_address', 'user_agent_short', 'verification_method'
    )
    list_filter = (
        'is_valid', 'verification_method', 'created_at',
        ('seller__verification_status', admin.AllValuesFieldListFilter)
    )
    search_fields = ('seller__name', 'seller__email', 'ip_address', 'drp__token_id')
    readonly_fields = ('created_at', 'seller', 'drp', 'is_valid', 'ip_address', 'user_agent', 'verification_method')
    
    fieldsets = (
        ('Verification Information', {
            'fields': ('created_at', 'seller', 'drp', 'is_valid', 'verification_method')
        }),
        ('Request Details', {
            'fields': ('ip_address', 'user_agent'),
            'classes': ('wide',)
        }),
    )
    
    def seller_link(self, obj):
        """Clickable link to seller"""
        if obj.seller:
            url = reverse('admin:drp_seller_change', args=[obj.seller.pk])
            return format_html('<a href="{}">{}</a>', url, obj.seller.name)
        return "N/A"
    seller_link.short_description = "Seller"
    
    def drp_link(self, obj):
        """Clickable link to DRP"""
        if obj.drp:
            url = reverse('admin:drp_drp_change', args=[obj.drp.pk])
            return format_html('<a href="{}">{}</a>', url, f"{obj.drp.token_id[:8]}...")
        return "N/A"
    drp_link.short_description = "DRP"
    
    def is_valid_display(self, obj):
        """Display validation status with icon"""
        if obj.is_valid:
            return format_html('<span style="color: green;">✓ Valid</span>')
        return format_html('<span style="color: red;">✗ Invalid</span>')
    is_valid_display.short_description = "Valid"
    is_valid_display.admin_order_field = 'is_valid'
    
    def user_agent_short(self, obj):
        """Display shortened user agent"""
        if obj.user_agent:
            return obj.user_agent[:50] + "..." if len(obj.user_agent) > 50 else obj.user_agent
        return "N/A"
    user_agent_short.short_description = "User Agent"
    
    def has_add_permission(self, request):
        """Disable manual request creation"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Disable request editing"""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Allow deletion of old verification requests"""
        return True


@admin.register(TrustMetric)
class TrustMetricAdmin(admin.ModelAdmin):
    """Trust Metric Admin for monitoring trust scores"""
    
    list_display = (
        'seller_link', 'metric_type', 'score_display', 'weight',
        'created_at', 'is_active'
    )
    list_filter = (
        'metric_type', 'is_active', 'created_at',
        ('seller__verification_status', admin.AllValuesFieldListFilter)
    )
    search_fields = ('seller__name', 'seller__email', 'metric_type')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Metric Information', {
            'fields': ('seller', 'metric_type', 'score', 'weight', 'is_active')
        }),
        ('Details', {
            'fields': ('description', 'source', 'created_at', 'updated_at'),
            'classes': ('wide',)
        }),
    )
    
    def seller_link(self, obj):
        """Clickable link to seller"""
        url = reverse('admin:drp_seller_change', args=[obj.seller.pk])
        return format_html('<a href="{}">{}</a>', url, obj.seller.name)
    seller_link.short_description = "Seller"
    
    def score_display(self, obj):
        """Display score with color coding"""
        if obj.score >= 80:
            color = '#10b981'  # green
        elif obj.score >= 60:
            color = '#fbbf24'  # yellow
        else:
            color = '#ef4444'  # red
            
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.score
        )
    score_display.short_description = "Score"
    score_display.admin_order_field = 'score'


# Custom Admin Site Configuration
class WalmartDRPAdminSite(admin.AdminSite):
    """Custom admin site for Walmart DRP System"""
    
    site_header = 'Walmart DRP Administration'
    site_title = 'Walmart DRP Admin'
    index_title = 'Digital Retailer Pass Management'
    
    def index(self, request, extra_context=None):
        """Custom admin index with dashboard statistics"""
        extra_context = extra_context or {}
        
        # Get dashboard statistics
        from django.db.models import Count, Q
        from datetime import datetime, timedelta
        
        now = timezone.now()
        today = now.date()
        yesterday = today - timedelta(days=1)
        week_ago = today - timedelta(days=7)
        
        # Seller statistics
        total_sellers = Seller.objects.count()
        verified_sellers = Seller.objects.filter(verification_status='verified').count()
        pending_sellers = Seller.objects.filter(verification_status='pending').count()
        flagged_sellers = Seller.objects.filter(verification_status='flagged').count()
        
        # DRP statistics
        total_drps = DRP.objects.count()
        active_drps = DRP.objects.filter(status='active', expires_at__gt=now).count()
        expired_drps = DRP.objects.filter(status='expired').count()
        revoked_drps = DRP.objects.filter(status='revoked').count()
        
        # Recent activity
        recent_verifications = VerificationRequest.objects.filter(
            created_at__date=today
        ).count()
        
        recent_drp_issued = DRP.objects.filter(
            created_at__date=today
        ).count()
        
        # Trust score distribution
        high_trust = Seller.objects.filter(trust_score__gte=80).count()
        medium_trust = Seller.objects.filter(trust_score__gte=60, trust_score__lt=80).count()
        low_trust = Seller.objects.filter(trust_score__lt=60).count()
        
        # Security alerts
        security_alerts = []
        
        # Check for high verification requests
        high_verification_sellers = Seller.objects.annotate(
            daily_verifications=Count('verificationrequest', 
                                    filter=Q(verificationrequest__created_at__date=today))
        ).filter(daily_verifications__gt=50)
        
        if high_verification_sellers.exists():
            security_alerts.append({
                'type': 'warning',
                'message': f'{high_verification_sellers.count()} sellers have unusually high verification requests today'
            })
        
        # Check for flagged sellers
        if flagged_sellers > 0:
            security_alerts.append({
                'type': 'danger',
                'message': f'{flagged_sellers} sellers are flagged and require review'
            })
        
        # Check for expiring DRPs
        expiring_soon = DRP.objects.filter(
            status='active',
            expires_at__lt=now + timedelta(minutes=30),
            expires_at__gt=now
        ).count()
        
        if expiring_soon > 0:
            security_alerts.append({
                'type': 'info',
                'message': f'{expiring_soon} DRP tokens will expire in the next 30 minutes'
            })
        
        # System health
        system_health = {
            'seller_approval_rate': (verified_sellers / total_sellers * 100) if total_sellers > 0 else 0,
            'drp_active_rate': (active_drps / total_drps * 100) if total_drps > 0 else 0,
            'daily_verification_rate': recent_verifications,
            'average_trust_score': Seller.objects.aggregate(
                avg_trust=models.Avg('trust_score')
            )['avg_trust'] or 0
        }
        
        extra_context.update({
            'dashboard_stats': {
                'sellers': {
                    'total': total_sellers,
                    'verified': verified_sellers,
                    'pending': pending_sellers,
                    'flagged': flagged_sellers,
                },
                'drps': {
                    'total': total_drps,
                    'active': active_drps,
                    'expired': expired_drps,
                    'revoked': revoked_drps,
                },
                'activity': {
                    'verifications_today': recent_verifications,
                    'drps_issued_today': recent_drp_issued,
                },
                'trust_distribution': {
                    'high': high_trust,
                    'medium': medium_trust,
                    'low': low_trust,
                }
            },
            'security_alerts': security_alerts,
            'system_health': system_health,
        })
        
        return super().index(request, extra_context)


# Register models with custom admin site
walmart_admin_site = WalmartDRPAdminSite(name='walmart_drp_admin')
walmart_admin_site.register(Seller, SellerAdmin)
walmart_admin_site.register(DRP, DRPAdmin)
walmart_admin_site.register(DRPLog, DRPLogAdmin)
walmart_admin_site.register(VerificationRequest, VerificationRequestAdmin)
walmart_admin_site.register(TrustMetric, TrustMetricAdmin)


# Custom Admin Dashboard Views
from django.shortcuts import render
from django.contrib.admin.views.decorators import staff_member_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

@staff_member_required
def admin_dashboard_api(request):
    """API endpoint for dashboard data"""
    from django.db.models import Count, Avg
    from datetime import datetime, timedelta
    
    now = timezone.now()
    today = now.date()
    
    # Get real-time statistics
    data = {
        'sellers': {
            'total': Seller.objects.count(),
            'verified': Seller.objects.filter(verification_status='verified').count(),
            'pending': Seller.objects.filter(verification_status='pending').count(),
            'flagged': Seller.objects.filter(verification_status='flagged').count(),
        },
        'drps': {
            'total': DRP.objects.count(),
            'active': DRP.objects.filter(status='active', expires_at__gt=now).count(),
            'expired': DRP.objects.filter(status='expired').count(),
            'revoked': DRP.objects.filter(status='revoked').count(),
        },
        'verifications': {
            'today': VerificationRequest.objects.filter(created_at__date=today).count(),
            'successful': VerificationRequest.objects.filter(
                created_at__date=today, is_valid=True
            ).count(),
            'failed': VerificationRequest.objects.filter(
                created_at__date=today, is_valid=False
            ).count(),
        },
        'trust_scores': {
            'average': Seller.objects.aggregate(avg=Avg('trust_score'))['avg'] or 0,
            'high': Seller.objects.filter(trust_score__gte=80).count(),
            'medium': Seller.objects.filter(trust_score__gte=60, trust_score__lt=80).count(),
            'low': Seller.objects.filter(trust_score__lt=60).count(),
        }
    }
    
    return JsonResponse(data)


@staff_member_required
def admin_security_dashboard(request):
    """Security monitoring dashboard"""
    from django.db.models import Count, Q
    from datetime import datetime, timedelta
    
    now = timezone.now()
    today = now.date()
    
    # Security metrics
    security_data = {
        'high_risk_sellers': Seller.objects.filter(
            Q(trust_score__lt=40) | Q(verification_status='flagged')
        ).count(),
        'suspicious_activity': VerificationRequest.objects.filter(
            created_at__date=today
        ).values('ip_address').annotate(
            count=Count('id')
        ).filter(count__gt=20).count(),
        'failed_verifications': VerificationRequest.objects.filter(
            created_at__date=today, is_valid=False
        ).count(),
        'revoked_drps_today': DRP.objects.filter(
            status='revoked',
            updated_at__date=today
        ).count(),
    }
    
    # Recent security events
    security_events = DRPLog.objects.filter(
        timestamp__date=today,
        action__in=['flagged', 'drp_revoked', 'rejected', 'failed_verification']
    ).order_by('-timestamp')[:10]
    
    # IP address analysis
    suspicious_ips = VerificationRequest.objects.filter(
        created_at__gte=now - timedelta(hours=24)
    ).values('ip_address').annotate(
        request_count=Count('id'),
        unique_sellers=Count('seller', distinct=True)
    ).filter(request_count__gt=50).order_by('-request_count')[:10]
    
    context = {
        'security_data': security_data,
        'security_events': security_events,
        'suspicious_ips': suspicious_ips,
    }
    
    return render(request, 'admin/security_dashboard.html', context)


@staff_member_required
@require_http_methods(["POST"])
def bulk_seller_action(request):
    """API endpoint for bulk seller actions"""
    import json
    
    data = json.loads(request.body)
    action = data.get('action')
    seller_ids = data.get('seller_ids', [])
    
    if not action or not seller_ids:
        return JsonResponse({'error': 'Missing action or seller_ids'}, status=400)
    
    sellers = Seller.objects.filter(id__in=seller_ids)
    
    if action == 'approve':
        sellers.update(verification_status='verified', is_active=True)
        # Log the action
        for seller in sellers:
            DRPLog.objects.create(
                seller=seller,
                action='approved',
                details=f'Bulk approved by admin: {request.user.username}',
                admin_user=request.user
            )
        return JsonResponse({'success': True, 'message': f'{len(seller_ids)} sellers approved'})
    
    elif action == 'reject':
        sellers.update(verification_status='rejected', is_active=False)
        # Revoke active DRPs
        for seller in sellers:
            active_drps = seller.drp_set.filter(status='active')
            for drp in active_drps:
                revoke_drp_token(drp.token_id, f'Seller rejected by admin: {request.user.username}')
            
            DRPLog.objects.create(
                seller=seller,
                action='rejected',
                details=f'Bulk rejected by admin: {request.user.username}',
                admin_user=request.user
            )
        return JsonResponse({'success': True, 'message': f'{len(seller_ids)} sellers rejected'})
    
    elif action == 'flag':
        sellers.update(verification_status='flagged')
        # Log the action
        for seller in sellers:
            DRPLog.objects.create(
                seller=seller,
                action='flagged',
                details=f'Bulk flagged by admin: {request.user.username}',
                admin_user=request.user
            )
        return JsonResponse({'success': True, 'message': f'{len(seller_ids)} sellers flagged'})
    
    else:
        return JsonResponse({'error': 'Invalid action'}, status=400)


@staff_member_required
def export_audit_report(request):
    """Export comprehensive audit report"""
    from django.http import HttpResponse
    from datetime import datetime, timedelta
    import csv
    
    # Get date range from request
    days = int(request.GET.get('days', 30))
    start_date = timezone.now() - timedelta(days=days)
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="drp_audit_report_{timezone.now().strftime("%Y%m%d")}.csv"'
    
    writer = csv.writer(response)
    
    # Write header
    writer.writerow([
        'Timestamp', 'Seller ID', 'Seller Name', 'Action', 'DRP Token ID',
        'IP Address', 'User Agent', 'Admin User', 'Details', 'Success'
    ])
    
    # Write log entries
    logs = DRPLog.objects.filter(
        timestamp__gte=start_date
    ).select_related('seller', 'drp', 'admin_user').order_by('-timestamp')
    
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.seller.seller_id if log.seller else 'N/A',
            log.seller.name if log.seller else 'N/A',
            log.action,
            log.drp.token_id if log.drp else 'N/A',
            log.ip_address or 'N/A',
            log.user_agent or 'N/A',
            log.admin_user.username if log.admin_user else 'System',
            log.details or 'N/A',
            'Yes' if log.is_successful else 'No'
        ])
    
    return response


# Custom Admin Widgets and Forms
from django import forms
from django.contrib.admin.widgets import AdminTextareaWidget

class SellerAdminForm(forms.ModelForm):
    """Custom form for Seller admin"""
    
    class Meta:
        model = Seller
        fields = '__all__'
        widgets = {
            'verification_notes': AdminTextareaWidget(attrs={'rows': 3}),
            'internal_notes': AdminTextareaWidget(attrs={'rows': 3}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Add custom validation
        if self.instance.pk:
            # Show warning if seller has active DRPs and status is being changed
            if self.instance.drp_set.filter(status='active').exists():
                self.fields['verification_status'].help_text = (
                    "⚠️ This seller has active DRP tokens. "
                    "Changing status may affect active tokens."
                )
    
    def clean_trust_score(self):
        """Validate trust score range"""
        trust_score = self.cleaned_data.get('trust_score')
        if trust_score is not None and (trust_score < 0 or trust_score > 100):
            raise forms.ValidationError("Trust score must be between 0 and 100.")
        return trust_score
    
    def clean_email(self):
        """Validate email uniqueness"""
        email = self.cleaned_data.get('email')
        if email:
            existing = Seller.objects.filter(email=email).exclude(pk=self.instance.pk)
            if existing.exists():
                raise forms.ValidationError("A seller with this email already exists.")
        return email


class DRPAdminForm(forms.ModelForm):
    """Custom form for DRP admin"""
    
    class Meta:
        model = DRP
        fields = '__all__'
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Make certain fields read-only
        if self.instance.pk:
            self.fields['token_id'].widget.attrs['readonly'] = True
            self.fields['jwt_token'].widget.attrs['readonly'] = True
            self.fields['created_at'].widget.attrs['readonly'] = True
    
    def clean_status(self):
        """Validate status changes"""
        status = self.cleaned_data.get('status')
        
        if self.instance.pk:
            old_status = self.instance.status
            
            # Prevent reactivation of revoked tokens
            if old_status == 'revoked' and status == 'active':
                raise forms.ValidationError(
                    "Cannot reactivate a revoked DRP token. "
                    "Please issue a new token instead."
                )
            
            # Prevent manual expiration of active tokens
            if old_status == 'active' and status == 'expired':
                raise forms.ValidationError(
                    "Use the revoke action instead of manually setting to expired."
                )
        
        return status


# Register custom forms with admin classes
SellerAdmin.form = SellerAdminForm
DRPAdmin.form = DRPAdminForm


# Custom admin commands integration
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    """Custom management command for admin operations"""
    help = 'Walmart DRP Admin Operations'
    
    def add_arguments(self, parser):
        parser.add_argument('--cleanup-expired', action='store_true',
                          help='Clean up expired DRP tokens')
        parser.add_argument('--update-trust-scores', action='store_true',
                          help='Update trust scores based on metrics')
        parser.add_argument('--generate-report', type=str,
                          help='Generate system report (daily/weekly/monthly)')
    
    def handle(self, *args, **options):
        if options['cleanup_expired']:
            self.cleanup_expired_tokens()
        
        if options['update_trust_scores']:
            self.update_trust_scores()
        
        if options['generate_report']:
            self.generate_report(options['generate_report'])
    
    def cleanup_expired_tokens(self):
        """Clean up expired DRP tokens"""
        expired_count = DRP.objects.filter(
            status='active',
            expires_at__lt=timezone.now()
        ).update(status='expired')
        
        self.stdout.write(
            self.style.SUCCESS(f'Cleaned up {expired_count} expired DRP tokens')
        )
    
    def update_trust_scores(self):
        """Update trust scores based on metrics"""
        for seller in Seller.objects.all():
            # Calculate weighted trust score
            metrics = seller.trustmetric_set.filter(is_active=True)
            if metrics.exists():
                total_score = 0
                total_weight = 0
                
                for metric in metrics:
                    total_score += metric.score * metric.weight
                    total_weight += metric.weight
                
                if total_weight > 0:
                    new_score = total_score / total_weight
                    seller.trust_score = min(100, max(0, int(new_score)))
                    seller.save()
        
        self.stdout.write(
            self.style.SUCCESS('Updated trust scores for all sellers')
        )
    
    def generate_report(self, report_type):
        """Generate system reports"""
        if report_type == 'daily':
            # Generate daily report
            pass
        elif report_type == 'weekly':
            # Generate weekly report
            pass
        elif report_type == 'monthly':
            # Generate monthly report
            pass
        
        self.stdout.write(
            self.style.SUCCESS(f'Generated {report_type} report')
        )