from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid


class Seller(models.Model):
    """
    Seller model representing Walmart Marketplace sellers
    """
    # Verification Status Choices
    VERIFICATION_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
        ('suspended', 'Suspended'),
        ('flagged', 'Flagged'),
    ]
    
    # Trust Score Tiers
    TRUST_TIER_CHOICES = [
        ('basic', 'Basic'),
        ('verified', 'Verified'),
        ('gold', 'Gold'),
    ]
    
    # Primary Fields
    seller_id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False,
        help_text="Unique identifier for the seller"
    )
    
    name = models.CharField(
        max_length=255,
        help_text="Seller's business name"
    )
    
    email = models.EmailField(
        unique=True,
        help_text="Seller's contact email"
    )
    
    phone = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        help_text="Seller's contact phone number"
    )
    
    # Trust and Verification
    trust_score = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Trust score from 0-100"
    )
    
    trust_tier = models.CharField(
        max_length=20,
        choices=TRUST_TIER_CHOICES,
        default='basic',
        help_text="Trust tier based on score and verification"
    )
    
    verification_status = models.CharField(
        max_length=20,
        choices=VERIFICATION_STATUS_CHOICES,
        default='pending',
        help_text="Current verification status"
    )
    
    is_active = models.BooleanField(
        default=True,
        help_text="Whether seller is active"
    )
    
    # Business Information
    business_address = models.TextField(
        blank=True,
        null=True,
        help_text="Seller's business address"
    )
    
    business_registration_number = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Business registration/license number"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    verified_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When seller was verified"
    )
    
    # Admin tracking
    verified_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='verified_sellers',
        help_text="Admin who verified this seller"
    )
    
    # Fraud tracking
    fraud_reports_count = models.IntegerField(
        default=0,
        help_text="Number of fraud reports against this seller"
    )
    
    last_fraud_report_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time fraud was reported"
    )
    
    notes = models.TextField(
        blank=True,
        null=True,
        help_text="Admin notes about seller"
    )
    
    class Meta:
        db_table = 'sellers'
        verbose_name = 'Seller'
        verbose_name_plural = 'Sellers'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.verification_status})"
    
    def save(self, *args, **kwargs):
        # Auto-set trust tier based on score
        if self.trust_score >= 80:
            self.trust_tier = 'gold'
        elif self.trust_score >= 50:
            self.trust_tier = 'verified'
        else:
            self.trust_tier = 'basic'
        
        # Set verified_at timestamp
        if self.verification_status == 'verified' and not self.verified_at:
            self.verified_at = timezone.now()
        
        super().save(*args, **kwargs)
    
    @property
    def is_verified(self):
        """Check if seller is verified and active"""
        return self.verification_status == 'verified' and self.is_active
    
    @property
    def is_flagged(self):
        """Check if seller is flagged for fraud"""
        return self.verification_status == 'flagged' or self.fraud_reports_count > 0
    
    @property
    def can_issue_drp(self):
        """Check if seller can be issued a DRP"""
        return self.is_verified and not self.is_flagged


class DRP(models.Model):
    """
    Digital Retailer Pass model for JWT tokens and QR codes
    """
    DRP_STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
        ('suspended', 'Suspended'),
    ]
    
    # Primary Fields
    drp_id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique DRP identifier"
    )
    
    seller = models.ForeignKey(
        Seller,
        on_delete=models.CASCADE,
        related_name='drps',
        help_text="Associated seller"
    )
    
    # Token and QR Code
    jwt_token = models.TextField(
        help_text="JWT token containing seller information"
    )
    
    qr_code_base64 = models.TextField(
        help_text="Base64 encoded QR code image"
    )
    
    # Timing
    issued_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When DRP was issued"
    )
    
    expires_at = models.DateTimeField(
        help_text="When DRP expires"
    )
    
    last_verified_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time DRP was verified by customer"
    )
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=DRP_STATUS_CHOICES,
        default='active',
        help_text="Current DRP status"
    )
    
    # Admin tracking
    issued_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='issued_drps',
        help_text="Admin who issued this DRP"
    )
    
    revoked_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='revoked_drps',
        help_text="Admin who revoked this DRP"
    )
    
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When DRP was revoked"
    )
    
    revocation_reason = models.TextField(
        blank=True,
        null=True,
        help_text="Reason for revocation"
    )
    
    # Usage tracking
    verification_count = models.IntegerField(
        default=0,
        help_text="Number of times this DRP was verified"
    )
    
    ip_addresses = models.JSONField(
        default=list,
        help_text="IP addresses that verified this DRP"
    )
    
    class Meta:
        db_table = 'drps'
        verbose_name = 'Digital Retailer Pass'
        verbose_name_plural = 'Digital Retailer Passes'
        ordering = ['-issued_at']
        indexes = [
            models.Index(fields=['seller', 'status']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"DRP-{str(self.drp_id)[:8]} for {self.seller.name}"
    
    @property
    def is_active(self):
        """Check if DRP is currently active"""
        return (
            self.status == 'active' and
            self.expires_at > timezone.now() and
            self.seller.is_verified
        )
    
    @property
    def is_expired(self):
        """Check if DRP has expired"""
        return self.expires_at <= timezone.now()
    
    @property
    def is_revoked(self):
        """Check if DRP has been revoked"""
        return self.status == 'revoked'
    
    def revoke(self, admin_user=None, reason=None):
        """Revoke the DRP"""
        self.status = 'revoked'
        self.revoked_at = timezone.now()
        self.revoked_by = admin_user
        self.revocation_reason = reason
        self.save()
    
    def increment_verification_count(self, ip_address=None):
        """Increment verification count and track IP"""
        self.verification_count += 1
        self.last_verified_at = timezone.now()
        
        if ip_address:
            ip_list = self.ip_addresses or []
            if ip_address not in ip_list:
                ip_list.append(ip_address)
                self.ip_addresses = ip_list
        
        self.save()


class DRPVerificationLog(models.Model):
    """
    Log of DRP verification attempts for audit and security
    """
    VERIFICATION_RESULT_CHOICES = [
        ('valid', 'Valid'),
        ('invalid', 'Invalid'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
        ('seller_flagged', 'Seller Flagged'),
        ('token_malformed', 'Token Malformed'),
    ]
    
    # Primary Fields
    log_id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    drp = models.ForeignKey(
        DRP,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='verification_logs',
        help_text="DRP that was verified (null if invalid token)"
    )
    
    # Verification Details
    token_provided = models.TextField(
        help_text="Token that was provided for verification"
    )
    
    verification_result = models.CharField(
        max_length=20,
        choices=VERIFICATION_RESULT_CHOICES,
        help_text="Result of verification"
    )
    
    # Request Details
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address of verifier"
    )
    
    user_agent = models.TextField(
        blank=True,
        null=True,
        help_text="User agent string"
    )
    
    # Timing
    verified_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When verification was attempted"
    )
    
    # Additional context
    verification_method = models.CharField(
        max_length=20,
        choices=[
            ('api', 'API'),
            ('qr_scan', 'QR Scan'),
            ('manual', 'Manual Entry'),
        ],
        default='api',
        help_text="How verification was performed"
    )
    
    additional_data = models.JSONField(
        default=dict,
        help_text="Additional verification context"
    )
    
    class Meta:
        db_table = 'drp_verification_logs'
        verbose_name = 'DRP Verification Log'
        verbose_name_plural = 'DRP Verification Logs'
        ordering = ['-verified_at']
        indexes = [
            models.Index(fields=['drp', 'verified_at']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['verification_result']),
        ]
    
    def __str__(self):
        return f"Verification {self.verification_result} at {self.verified_at}"


class FraudReport(models.Model):
    """
    Fraud reports against sellers for tracking and admin action
    """
    REPORT_TYPE_CHOICES = [
        ('impersonation', 'Impersonation'),
        ('fake_product', 'Fake Product'),
        ('fake_support', 'Fake Support Call'),
        ('phishing', 'Phishing/Scam'),
        ('gift_card_fraud', 'Gift Card Fraud'),
        ('other', 'Other'),
    ]
    
    REPORT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('dismissed', 'Dismissed'),
    ]
    
    # Primary Fields
    report_id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    seller = models.ForeignKey(
        Seller,
        on_delete=models.CASCADE,
        related_name='fraud_reports',
        help_text="Seller being reported"
    )
    
    # Report Details
    report_type = models.CharField(
        max_length=20,
        choices=REPORT_TYPE_CHOICES,
        help_text="Type of fraud reported"
    )
    
    description = models.TextField(
        help_text="Description of the fraud incident"
    )
    
    # Reporter Information (optional - customers might report anonymously)
    reporter_name = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Name of person reporting"
    )
    
    reporter_email = models.EmailField(
        blank=True,
        null=True,
        help_text="Email of person reporting"
    )
    
    reporter_phone = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        help_text="Phone of person reporting"
    )
    
    # Status and Processing
    status = models.CharField(
        max_length=20,
        choices=REPORT_STATUS_CHOICES,
        default='pending',
        help_text="Current status of report"
    )
    
    # Admin tracking
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_fraud_reports',
        help_text="Admin assigned to investigate"
    )
    
    admin_notes = models.TextField(
        blank=True,
        null=True,
        help_text="Internal admin notes"
    )
    
    # Timing
    reported_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When report was filed"
    )
    
    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When report was resolved"
    )
    
    # Evidence
    evidence_files = models.JSONField(
        default=list,
        help_text="File paths to evidence uploaded"
    )
    
    class Meta:
        db_table = 'fraud_reports'
        verbose_name = 'Fraud Report'
        verbose_name_plural = 'Fraud Reports'
        ordering = ['-reported_at']
        indexes = [
            models.Index(fields=['seller', 'status']),
            models.Index(fields=['report_type']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"Fraud Report #{str(self.report_id)[:8]} - {self.seller.name}"
    
    def resolve(self, admin_user=None, notes=None):
        """Mark report as resolved"""
        self.status = 'resolved'
        self.resolved_at = timezone.now()
        if admin_user:
            self.assigned_to = admin_user
        if notes:
            self.admin_notes = notes
        self.save()
        
        # Update seller's fraud count
        self.seller.fraud_reports_count += 1
        self.seller.last_fraud_report_at = timezone.now()
        self.seller.save()


class DRPSettings(models.Model):
    """
    System settings for DRP configuration
    """
    # Singleton pattern - only one settings record
    id = models.AutoField(primary_key=True)
    
    # Token Settings
    token_expiry_minutes = models.IntegerField(
        default=10,
        help_text="DRP token expiry time in minutes"
    )
    
    # Trust Score Thresholds
    trust_score_basic_threshold = models.IntegerField(
        default=30,
        help_text="Minimum trust score for basic tier"
    )
    
    trust_score_verified_threshold = models.IntegerField(
        default=50,
        help_text="Minimum trust score for verified tier"
    )
    
    trust_score_gold_threshold = models.IntegerField(
        default=80,
        help_text="Minimum trust score for gold tier"
    )
    
    # Security Settings
    max_fraud_reports_before_flag = models.IntegerField(
        default=3,
        help_text="Maximum fraud reports before auto-flagging seller"
    )
    
    auto_revoke_on_flag = models.BooleanField(
        default=True,
        help_text="Automatically revoke DRP when seller is flagged"
    )
    
    # System Maintenance
    cleanup_expired_drps_days = models.IntegerField(
        default=30,
        help_text="Days to keep expired DRPs before cleanup"
    )
    
    # Notification Settings
    notify_admins_on_fraud = models.BooleanField(
        default=True,
        help_text="Send notifications to admins on fraud reports"
    )
    
    # Rate Limiting
    max_verifications_per_ip_per_hour = models.IntegerField(
        default=100,
        help_text="Maximum verifications per IP per hour"
    )
    
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Admin who last updated settings"
    )
    
    class Meta:
        db_table = 'drp_settings'
        verbose_name = 'DRP Settings'
        verbose_name_plural = 'DRP Settings'
    
    def __str__(self):
        return f"DRP Settings (Token expires: {self.token_expiry_minutes}min)"
    
    def save(self, *args, **kwargs):
        # Ensure only one settings record exists
        if DRPSettings.objects.exists() and not self.pk:
            raise ValueError("DRP Settings already exists. Use update instead.")
        super().save(*args, **kwargs)
    
    @classmethod
    def get_settings(cls):
        """Get or create system settings"""
        settings, created = cls.objects.get_or_create(
            id=1,
            defaults={
                'token_expiry_minutes': 10,
                'trust_score_basic_threshold': 30,
                'trust_score_verified_threshold': 50,
                'trust_score_gold_threshold': 80,
                'max_fraud_reports_before_flag': 3,
                'auto_revoke_on_flag': True,
                'cleanup_expired_drps_days': 30,
                'notify_admins_on_fraud': True,
                'max_verifications_per_ip_per_hour': 100,
            }
        )
        return settings