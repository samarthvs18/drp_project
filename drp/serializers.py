"""
Django REST Framework Serializers for Digital Retailer Pass (DRP) System
Walmart Marketplace Integration - Complete Implementation

This module contains all serializers for:
- Seller management and verification
- DRP token issuance and validation
- Admin operations and logging
- Customer verification interface
- Trust score calculations
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import datetime, timedelta
import jwt
import qrcode
import base64
from io import BytesIO
from django.conf import settings
from .models import Seller, DRP, DRPLog, TrustMetrics
from .utils import generate_drp_token, verify_drp_token, generate_qr_code


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model - used for seller account management
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        """Create user with encrypted password"""
        password = validated_data.pop('password', None)
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user


class TrustMetricsSerializer(serializers.ModelSerializer):
    """
    Serializer for Trust Metrics tracking
    Used for seller reputation and DRP tier determination
    """
    trust_level = serializers.SerializerMethodField()
    
    class Meta:
        model = TrustMetrics
        fields = [
            'id', 'seller', 'positive_reviews', 'negative_reviews', 
            'successful_transactions', 'flagged_incidents', 'response_time_hours',
            'account_age_days', 'verification_documents_count', 'trust_score',
            'trust_level', 'last_updated'
        ]
        read_only_fields = ['last_updated']

    def get_trust_level(self, obj):
        """Calculate trust level based on trust score"""
        if obj.trust_score >= 90:
            return 'GOLD'
        elif obj.trust_score >= 70:
            return 'VERIFIED'
        elif obj.trust_score >= 50:
            return 'BASIC'
        else:
            return 'PROBATION'


class SellerListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for seller listing views
    """
    trust_level = serializers.SerializerMethodField()
    current_drp_status = serializers.SerializerMethodField()
    
    class Meta:
        model = Seller
        fields = [
            'id', 'seller_id', 'name', 'email', 'trust_score', 
            'verification_status', 'is_active', 'trust_level', 
            'current_drp_status', 'created_at'
        ]

    def get_trust_level(self, obj):
        """Get trust level from trust score"""
        if obj.trust_score >= 90:
            return 'GOLD'
        elif obj.trust_score >= 70:
            return 'VERIFIED'
        elif obj.trust_score >= 50:
            return 'BASIC'
        else:
            return 'PROBATION'

    def get_current_drp_status(self, obj):
        """Get current DRP status"""
        try:
            latest_drp = obj.drps.filter(is_active=True).latest('issued_at')
            if latest_drp.expires_at < timezone.now():
                return 'EXPIRED'
            return latest_drp.status
        except DRP.DoesNotExist:
            return 'NO_DRP'


class SellerDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for seller management
    Includes trust metrics and DRP history
    """
    user = UserSerializer(read_only=True)
    trust_metrics = TrustMetricsSerializer(read_only=True)
    trust_level = serializers.SerializerMethodField()
    drp_count = serializers.SerializerMethodField()
    current_drp = serializers.SerializerMethodField()
    recent_logs = serializers.SerializerMethodField()
    
    class Meta:
        model = Seller
        fields = [
            'id', 'seller_id', 'user', 'name', 'email', 'phone', 
            'business_type', 'trust_score', 'verification_status', 
            'is_active', 'is_flagged', 'flagged_reason', 'notes',
            'trust_metrics', 'trust_level', 'drp_count', 'current_drp',
            'recent_logs', 'created_at', 'updated_at'
        ]
        read_only_fields = ['seller_id', 'created_at', 'updated_at']

    def get_trust_level(self, obj):
        """Calculate trust level"""
        if obj.trust_score >= 90:
            return 'GOLD'
        elif obj.trust_score >= 70:
            return 'VERIFIED'
        elif obj.trust_score >= 50:
            return 'BASIC'
        else:
            return 'PROBATION'

    def get_drp_count(self, obj):
        """Get total DRP count for seller"""
        return obj.drps.count()

    def get_current_drp(self, obj):
        """Get current active DRP"""
        try:
            drp = obj.drps.filter(is_active=True).latest('issued_at')
            return {
                'id': drp.id,
                'drp_id': drp.drp_id,
                'status': drp.status,
                'issued_at': drp.issued_at,
                'expires_at': drp.expires_at,
                'is_expired': drp.expires_at < timezone.now()
            }
        except DRP.DoesNotExist:
            return None

    def get_recent_logs(self, obj):
        """Get recent activity logs"""
        logs = DRPLog.objects.filter(seller=obj).order_by('-timestamp')[:5]
        return DRPLogSerializer(logs, many=True).data

    def validate_email(self, value):
        """Validate email uniqueness"""
        if Seller.objects.filter(email=value).exclude(pk=self.instance.pk if self.instance else None).exists():
            raise serializers.ValidationError("Seller with this email already exists.")
        return value

    def validate_trust_score(self, value):
        """Validate trust score range"""
        if not 0 <= value <= 100:
            raise serializers.ValidationError("Trust score must be between 0 and 100.")
        return value


class DRPSerializer(serializers.ModelSerializer):
    """
    Serializer for DRP (Digital Retailer Pass) management
    Handles token generation and QR code creation
    """
    seller_name = serializers.CharField(source='seller.name', read_only=True)
    seller_email = serializers.CharField(source='seller.email', read_only=True)
    trust_level = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()
    qr_code_base64 = serializers.SerializerMethodField()
    token_payload = serializers.SerializerMethodField()
    
    class Meta:
        model = DRP
        fields = [
            'id', 'drp_id', 'seller', 'seller_name', 'seller_email',
            'jwt_token', 'qr_code_base64', 'status', 'trust_level',
            'issued_at', 'expires_at', 'is_expired', 'is_active',
            'revoked_at', 'revoked_by', 'revoked_reason', 'token_payload'
        ]
        read_only_fields = [
            'drp_id', 'jwt_token', 'issued_at', 'expires_at', 
            'revoked_at', 'revoked_by'
        ]

    def get_trust_level(self, obj):
        """Get trust level from seller trust score"""
        if obj.seller.trust_score >= 90:
            return 'GOLD'
        elif obj.seller.trust_score >= 70:
            return 'VERIFIED'
        elif obj.seller.trust_score >= 50:
            return 'BASIC'
        else:
            return 'PROBATION'

    def get_is_expired(self, obj):
        """Check if DRP is expired"""
        return obj.expires_at < timezone.now()

    def get_qr_code_base64(self, obj):
        """Generate QR code as base64 string"""
        if obj.jwt_token:
            return generate_qr_code(obj.jwt_token)
        return None

    def get_token_payload(self, obj):
        """Decode JWT token payload for display"""
        if obj.jwt_token:
            try:
                payload = jwt.decode(
                    obj.jwt_token, 
                    settings.SECRET_KEY, 
                    algorithms=['HS256']
                )
                return {
                    'seller_id': payload.get('seller_id'),
                    'seller_name': payload.get('seller_name'),
                    'trust_score': payload.get('trust_score'),
                    'exp': payload.get('exp'),
                    'iat': payload.get('iat')
                }
            except jwt.InvalidTokenError:
                return None
        return None


class DRPIssueSerializer(serializers.Serializer):
    """
    Serializer for DRP issuance requests
    Handles validation and token generation
    """
    seller_id = serializers.CharField(max_length=50)
    validity_minutes = serializers.IntegerField(default=10, min_value=1, max_value=60)
    force_refresh = serializers.BooleanField(default=False)
    
    def validate_seller_id(self, value):
        """Validate seller exists and is active"""
        try:
            seller = Seller.objects.get(seller_id=value)
            if not seller.is_active:
                raise serializers.ValidationError("Seller account is inactive.")
            if seller.is_flagged:
                raise serializers.ValidationError("Seller account is flagged.")
            if seller.verification_status != 'VERIFIED':
                raise serializers.ValidationError("Seller is not verified.")
        except Seller.DoesNotExist:
            raise serializers.ValidationError("Seller not found.")
        return value

    def create(self, validated_data):
        """Generate new DRP token"""
        seller = Seller.objects.get(seller_id=validated_data['seller_id'])
        validity_minutes = validated_data.get('validity_minutes', 10)
        force_refresh = validated_data.get('force_refresh', False)
        
        # Check if active DRP exists
        if not force_refresh:
            active_drp = seller.drps.filter(
                is_active=True,
                expires_at__gt=timezone.now()
            ).first()
            
            if active_drp:
                return active_drp
        
        # Deactivate existing DRPs
        seller.drps.filter(is_active=True).update(is_active=False)
        
        # Generate new token
        token = generate_drp_token(seller, validity_minutes)
        
        # Create new DRP
        drp = DRP.objects.create(
            seller=seller,
            jwt_token=token,
            expires_at=timezone.now() + timedelta(minutes=validity_minutes),
            status='ACTIVE'
        )
        
        # Log the issuance
        DRPLog.objects.create(
            seller=seller,
            drp=drp,
            action='ISSUED',
            details=f'DRP issued for {validity_minutes} minutes'
        )
        
        return drp


class DRPVerifySerializer(serializers.Serializer):
    """
    Serializer for DRP verification requests
    Handles token validation and response formatting
    """
    drp_token = serializers.CharField(max_length=1000, required=False)
    drp_id = serializers.CharField(max_length=50, required=False)
    
    def validate(self, data):
        """Validate that either token or ID is provided"""
        if not data.get('drp_token') and not data.get('drp_id'):
            raise serializers.ValidationError("Either drp_token or drp_id must be provided.")
        return data

    def verify_token(self):
        """Verify DRP token and return validation result"""
        drp_token = self.validated_data.get('drp_token')
        drp_id = self.validated_data.get('drp_id')
        
        result = {
            'is_valid': False,
            'seller_info': None,
            'trust_level': None,
            'status': 'INVALID',
            'message': 'Invalid DRP',
            'expires_at': None,
            'verified_at': timezone.now()
        }
        
        try:
            # Find DRP by token or ID
            if drp_token:
                # Verify JWT token
                payload = verify_drp_token(drp_token)
                if not payload:
                    result['message'] = 'Invalid or expired token'
                    return result
                
                drp = DRP.objects.get(jwt_token=drp_token, is_active=True)
            else:
                drp = DRP.objects.get(drp_id=drp_id, is_active=True)
            
            # Check expiration
            if drp.expires_at < timezone.now():
                result['status'] = 'EXPIRED'
                result['message'] = 'DRP has expired'
                return result
            
            # Check seller status
            if not drp.seller.is_active:
                result['status'] = 'INACTIVE'
                result['message'] = 'Seller account is inactive'
                return result
            
            if drp.seller.is_flagged:
                result['status'] = 'FLAGGED'
                result['message'] = f'Seller is flagged: {drp.seller.flagged_reason}'
                return result
            
            # Valid DRP
            result.update({
                'is_valid': True,
                'status': 'VALID',
                'message': 'DRP is valid and verified',
                'expires_at': drp.expires_at,
                'seller_info': {
                    'id': drp.seller.seller_id,
                    'name': drp.seller.name,
                    'email': drp.seller.email,
                    'trust_score': drp.seller.trust_score,
                    'verification_status': drp.seller.verification_status
                },
                'trust_level': self._get_trust_level(drp.seller.trust_score)
            })
            
            # Log verification
            DRPLog.objects.create(
                seller=drp.seller,
                drp=drp,
                action='VERIFIED',
                details='DRP verified by customer'
            )
            
        except DRP.DoesNotExist:
            result['message'] = 'DRP not found'
        except Exception as e:
            result['message'] = f'Verification error: {str(e)}'
        
        return result

    def _get_trust_level(self, trust_score):
        """Calculate trust level from score"""
        if trust_score >= 90:
            return 'GOLD'
        elif trust_score >= 70:
            return 'VERIFIED'
        elif trust_score >= 50:
            return 'BASIC'
        else:
            return 'PROBATION'


class DRPRevokeSerializer(serializers.Serializer):
    """
    Serializer for DRP revocation requests
    Admin-only operation with reason tracking
    """
    drp_id = serializers.CharField(max_length=50)
    reason = serializers.CharField(max_length=500)
    revoked_by = serializers.CharField(max_length=150)
    
    def validate_drp_id(self, value):
        """Validate DRP exists and is active"""
        try:
            drp = DRP.objects.get(drp_id=value, is_active=True)
            if drp.expires_at < timezone.now():
                raise serializers.ValidationError("DRP is already expired.")
        except DRP.DoesNotExist:
            raise serializers.ValidationError("Active DRP not found.")
        return value

    def revoke_drp(self):
        """Revoke the DRP and log the action"""
        drp = DRP.objects.get(drp_id=self.validated_data['drp_id'])
        reason = self.validated_data['reason']
        revoked_by = self.validated_data['revoked_by']
        
        # Update DRP status
        drp.is_active = False
        drp.status = 'REVOKED'
        drp.revoked_at = timezone.now()
        drp.revoked_by = revoked_by
        drp.revoked_reason = reason
        drp.save()
        
        # Log revocation
        DRPLog.objects.create(
            seller=drp.seller,
            drp=drp,
            action='REVOKED',
            details=f'DRP revoked by {revoked_by}: {reason}'
        )
        
        return drp


class DRPLogSerializer(serializers.ModelSerializer):
    """
    Serializer for DRP activity logs
    Used for audit trails and monitoring
    """
    seller_name = serializers.CharField(source='seller.name', read_only=True)
    drp_id = serializers.CharField(source='drp.drp_id', read_only=True)
    
    class Meta:
        model = DRPLog
        fields = [
            'id', 'seller', 'seller_name', 'drp', 'drp_id', 'action',
            'details', 'timestamp', 'ip_address', 'user_agent'
        ]
        read_only_fields = ['timestamp']


class SellerFlagSerializer(serializers.Serializer):
    """
    Serializer for flagging sellers
    Admin operation with reason tracking
    """
    seller_id = serializers.CharField(max_length=50)
    reason = serializers.CharField(max_length=500)
    flagged_by = serializers.CharField(max_length=150)
    deactivate_drps = serializers.BooleanField(default=True)
    
    def validate_seller_id(self, value):
        """Validate seller exists"""
        try:
            Seller.objects.get(seller_id=value)
        except Seller.DoesNotExist:
            raise serializers.ValidationError("Seller not found.")
        return value

    def flag_seller(self):
        """Flag seller and optionally deactivate DRPs"""
        seller = Seller.objects.get(seller_id=self.validated_data['seller_id'])
        reason = self.validated_data['reason']
        flagged_by = self.validated_data['flagged_by']
        deactivate_drps = self.validated_data.get('deactivate_drps', True)
        
        # Flag seller
        seller.is_flagged = True
        seller.flagged_reason = reason
        seller.save()
        
        # Deactivate DRPs if requested
        if deactivate_drps:
            active_drps = seller.drps.filter(is_active=True)
            for drp in active_drps:
                drp.is_active = False
                drp.status = 'REVOKED'
                drp.revoked_at = timezone.now()
                drp.revoked_by = flagged_by
                drp.revoked_reason = f'Seller flagged: {reason}'
                drp.save()
        
        # Log the action
        DRPLog.objects.create(
            seller=seller,
            action='FLAGGED',
            details=f'Seller flagged by {flagged_by}: {reason}'
        )
        
        return seller


class AdminDashboardSerializer(serializers.Serializer):
    """
    Serializer for admin dashboard statistics
    Provides overview metrics for monitoring
    """
    total_sellers = serializers.IntegerField(read_only=True)
    active_sellers = serializers.IntegerField(read_only=True)
    flagged_sellers = serializers.IntegerField(read_only=True)
    pending_verification = serializers.IntegerField(read_only=True)
    
    active_drps = serializers.IntegerField(read_only=True)
    expired_drps = serializers.IntegerField(read_only=True)
    revoked_drps = serializers.IntegerField(read_only=True)
    
    verifications_today = serializers.IntegerField(read_only=True)
    verifications_week = serializers.IntegerField(read_only=True)
    
    trust_distribution = serializers.DictField(read_only=True)
    recent_activity = serializers.ListField(read_only=True)


class BulkSellerUpdateSerializer(serializers.Serializer):
    """
    Serializer for bulk seller operations
    Admin utility for mass updates
    """
    seller_ids = serializers.ListField(
        child=serializers.CharField(max_length=50),
        min_length=1,
        max_length=100
    )
    action = serializers.ChoiceField(choices=[
        'ACTIVATE', 'DEACTIVATE', 'VERIFY', 'UNVERIFY', 'RECALCULATE_TRUST'
    ])
    reason = serializers.CharField(max_length=500, required=False)
    
    def validate_seller_ids(self, value):
        """Validate all seller IDs exist"""
        existing_sellers = Seller.objects.filter(seller_id__in=value).values_list('seller_id', flat=True)
        missing_sellers = set(value) - set(existing_sellers)
        
        if missing_sellers:
            raise serializers.ValidationError(f"Sellers not found: {', '.join(missing_sellers)}")
        
        return value

    def perform_bulk_operation(self):
        """Execute bulk operation on sellers"""
        seller_ids = self.validated_data['seller_ids']
        action = self.validated_data['action']
        reason = self.validated_data.get('reason', '')
        
        sellers = Seller.objects.filter(seller_id__in=seller_ids)
        results = []
        
        for seller in sellers:
            try:
                if action == 'ACTIVATE':
                    seller.is_active = True
                elif action == 'DEACTIVATE':
                    seller.is_active = False
                    # Deactivate DRPs
                    seller.drps.filter(is_active=True).update(is_active=False)
                elif action == 'VERIFY':
                    seller.verification_status = 'VERIFIED'
                elif action == 'UNVERIFY':
                    seller.verification_status = 'PENDING'
                    # Deactivate DRPs
                    seller.drps.filter(is_active=True).update(is_active=False)
                elif action == 'RECALCULATE_TRUST':
                    # Recalculate trust score from metrics
                    if hasattr(seller, 'trust_metrics'):
                        seller.trust_metrics.calculate_trust_score()
                        seller.trust_score = seller.trust_metrics.trust_score
                
                seller.save()
                
                # Log the action
                DRPLog.objects.create(
                    seller=seller,
                    action=f'BULK_{action}',
                    details=f'Bulk {action.lower()}: {reason}'
                )
                
                results.append({
                    'seller_id': seller.seller_id,
                    'success': True,
                    'message': f'{action} completed successfully'
                })
                
            except Exception as e:
                results.append({
                    'seller_id': seller.seller_id,
                    'success': False,
                    'message': str(e)
                })
        
        return results


class APIKeySerializer(serializers.Serializer):
    """
    Serializer for API key management
    For external integrations
    """
    name = serializers.CharField(max_length=100)
    permissions = serializers.ListField(
        child=serializers.ChoiceField(choices=[
            'READ_SELLER', 'WRITE_SELLER', 'ISSUE_DRP', 'VERIFY_DRP', 'REVOKE_DRP'
        ])
    )
    expires_at = serializers.DateTimeField(required=False)
    
    def validate_expires_at(self, value):
        """Validate expiration is in the future"""
        if value and value <= timezone.now():
            raise serializers.ValidationError("Expiration date must be in the future.")
        return value