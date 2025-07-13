from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid

class Seller(models.Model):
    VERIFICATION_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
        ('suspended', 'Suspended'),
    ]
    
    TIER_CHOICES = [
        ('basic', 'Basic'),
        ('verified', 'Verified'),
        ('gold', 'Gold'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    business_name = models.CharField(max_length=200, blank=True, null=True)
    business_address = models.TextField(blank=True, null=True)
    
    trust_score = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0), MaxValueValidator(100.0)],
        help_text="Trust score from 0 to 100"
    )
    
    verification_status = models.CharField(
        max_length=20,
        choices=VERIFICATION_STATUS_CHOICES,
        default='pending'
    )
    
    tier = models.CharField(
        max_length=20,
        choices=TIER_CHOICES,
        default='basic'
    )
    
    is_active = models.BooleanField(default=True)
    is_flagged = models.BooleanField(default=False)
    flag_reason = models.TextField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Metrics
    total_transactions = models.IntegerField(default=0)
    successful_transactions = models.IntegerField(default=0)
    customer_complaints = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Seller'
        verbose_name_plural = 'Sellers'
    
    def __str__(self):
        return f"{self.name} ({self.email})"
    
    @property
    def success_rate(self):
        if self.total_transactions == 0:
            return 0
        return (self.successful_transactions / self.total_transactions) * 100
    
    @property
    def can_issue_drp(self):
        return (
            self.is_active and 
            self.verification_status == 'verified' and 
            not self.is_flagged
        )
    
    def update_trust_score(self):
        """Calculate trust score based on various factors"""
        base_score = 50.0
        
        # Success rate factor (0-30 points)
        success_factor = min(self.success_rate * 0.3, 30.0)
        
        # Complaint factor (deduct up to 20 points)
        complaint_factor = min(self.customer_complaints * 2, 20.0)
        
        # Tier bonus
        tier_bonus = {'basic': 0, 'verified': 10, 'gold': 20}[self.tier]
        
        # Flagged penalty
        flag_penalty = 30.0 if self.is_flagged else 0.0
        
        new_score = base_score + success_factor + tier_bonus - complaint_factor - flag_penalty
        self.trust_score = max(0.0, min(100.0, new_score))
        self.save()


class DRP(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
        ('suspended', 'Suspended'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE, related_name='drps')
    
    jwt_token = models.TextField()
    qr_code_base64 = models.TextField()
    
    issued_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    # Tracking fields
    verification_count = models.IntegerField(default=0)
    last_verified_at = models.DateTimeField(null=True, blank=True)
    
    # Revocation fields
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    revocation_reason = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-issued_at']
        verbose_name = 'Digital Retailer Pass'
        verbose_name_plural = 'Digital Retailer Passes'
    
    def __str__(self):
        return f"DRP-{str(self.id)[:8]} ({self.seller.name})"
    
    @property
    def is_valid(self):
        return (
            self.status == 'active' and
            self.expires_at > timezone.now() and
            self.seller.can_issue_drp
        )
    
    @property
    def time_until_expiry(self):
        if self.expires_at:
            delta = self.expires_at - timezone.now()
            return delta.total_seconds()
        return 0
    
    def revoke(self, user=None, reason=None):
        """Revoke this DRP"""
        self.status = 'revoked'
        self.revoked_at = timezone.now()
        self.revoked_by = user
        self.revocation_reason = reason
        self.save()
        
        # Log the revocation
        DRPLog.objects.create(
            drp=self,
            action='revoked',
            user=user,
            details=f"Revoked: {reason}" if reason else "Revoked"
        )


class DRPLog(models.Model):
    ACTION_CHOICES = [
        ('issued', 'Issued'),
        ('verified', 'Verified'),
        ('revoked', 'Revoked'),
        ('expired', 'Expired'),
        ('flagged', 'Flagged'),
        ('renewed', 'Renewed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    drp = models.ForeignKey(DRP, on_delete=models.CASCADE, related_name='logs')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Request details
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    
    details = models.TextField(blank=True, null=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'DRP Log'
        verbose_name_plural = 'DRP Logs'
    
    def __str__(self):
        return f"{self.action.title()} - {self.drp} at {self.timestamp}"


class SellerReport(models.Model):
    REPORT_TYPE_CHOICES = [
        ('fraud', 'Fraud'),
        ('impersonation', 'Impersonation'),
        ('fake_product', 'Fake Product'),
        ('poor_service', 'Poor Service'),
        ('other', 'Other'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('dismissed', 'Dismissed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE, related_name='reports')
    
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES)
    description = models.TextField()
    
    reporter_name = models.CharField(max_length=100, blank=True, null=True)
    reporter_email = models.EmailField(blank=True, null=True)
    reporter_phone = models.CharField(max_length=20, blank=True, null=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    resolution_notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Seller Report'
        verbose_name_plural = 'Seller Reports'
    
    def __str__(self):
        return f"{self.report_type.title()} report for {self.seller.name}"


class DRPSettings(models.Model):
    """System-wide DRP settings"""
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    description = models.TextField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'DRP Setting'
        verbose_name_plural = 'DRP Settings'
    
    def __str__(self):
        return f"{self.key}: {self.value}"
    
    @classmethod
    def get_setting(cls, key, default=None):
        try:
            return cls.objects.get(key=key).value
        except cls.DoesNotExist:
            return default
    
    @classmethod
    def set_setting(cls, key, value, description=None):
        setting, created = cls.objects.get_or_create(
            key=key,
            defaults={'value': value, 'description': description}
        )
        if not created:
            setting.value = value
            if description:
                setting.description = description
            setting.save()
        return setting