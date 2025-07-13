# drp/views.py
"""
Digital Retailer Pass (DRP) System Views
Walmart Marketplace Seller Verification System

This module contains all API views for DRP management including:
- DRP issuance and verification
- Seller management
- Admin operations
- AJAX endpoints for frontend integration
"""

import json
import logging
from datetime import datetime, timedelta
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.admin.views.decorators import staff_member_required
from django.utils.decorators import method_decorator
from django.db.models import Q, Count, Avg
from django.core.paginator import Paginator
from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from rest_framework import status, viewsets, permissions
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.pagination import PageNumberPagination

from .models import Seller, DRP, DRPLog, VerificationRequest
from .serializers import (
    SellerSerializer, DRPSerializer, DRPLogSerializer,
    VerificationRequestSerializer, DRPIssueSerializer,
    DRPVerifySerializer, SellerCreateSerializer
)
from .utils import (
    generate_drp_token, verify_drp_token, generate_qr_code,
    calculate_trust_score, get_verification_status_display,
    log_drp_activity, send_notification
)

# Configure logging
logger = logging.getLogger(__name__)

# Custom pagination class
class DRPPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

# =============================================
# CORE DRP API VIEWS
# =============================================

class DRPIssueView(APIView):
    """
    API endpoint for issuing new DRPs to verified sellers
    
    POST /api/drp/issue/
    {
        "seller_id": 123,
        "validity_minutes": 10,
        "drp_type": "BASIC"
    }
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            serializer = DRPIssueSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    'status': 'error',
                    'message': 'Invalid request data',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            seller_id = serializer.validated_data['seller_id']
            validity_minutes = serializer.validated_data.get('validity_minutes', 10)
            drp_type = serializer.validated_data.get('drp_type', 'BASIC')
            
            # Get seller and validate
            try:
                seller = Seller.objects.get(id=seller_id)
            except Seller.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'Seller not found'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Check if seller is eligible for DRP
            if not seller.is_active:
                return Response({
                    'status': 'error',
                    'message': 'Seller account is inactive'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if seller.verification_status != 'VERIFIED':
                return Response({
                    'status': 'error',
                    'message': 'Seller must be verified to receive DRP'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check for existing active DRP
            existing_drp = DRP.objects.filter(
                seller=seller,
                status='ACTIVE',
                expires_at__gt=timezone.now()
            ).first()
            
            if existing_drp:
                # Return existing DRP if still valid
                qr_code = generate_qr_code(existing_drp.token)
                return Response({
                    'status': 'success',
                    'message': 'Active DRP already exists',
                    'drp': {
                        'id': existing_drp.id,
                        'token': existing_drp.token,
                        'qr_code': qr_code,
                        'expires_at': existing_drp.expires_at.isoformat(),
                        'drp_type': existing_drp.drp_type,
                        'seller_name': seller.name,
                        'trust_score': seller.trust_score
                    }
                })
            
            # Generate new DRP token
            token_payload = {
                'seller_id': seller.id,
                'seller_name': seller.name,
                'trust_score': seller.trust_score,
                'drp_type': drp_type,
                'verification_status': seller.verification_status,
                'issued_at': timezone.now().isoformat(),
                'exp': (timezone.now() + timedelta(minutes=validity_minutes)).timestamp()
            }
            
            drp_token = generate_drp_token(token_payload)
            qr_code = generate_qr_code(drp_token)
            
            # Create DRP record
            drp = DRP.objects.create(
                seller=seller,
                token=drp_token,
                qr_code=qr_code,
                expires_at=timezone.now() + timedelta(minutes=validity_minutes),
                drp_type=drp_type,
                status='ACTIVE',
                issued_by=request.user if request.user.is_authenticated else None
            )
            
            # Log activity
            log_drp_activity(
                drp=drp,
                action='ISSUED',
                user=request.user,
                details=f'DRP issued for {validity_minutes} minutes'
            )
            
            # Send notification to seller
            send_notification(
                seller=seller,
                title='DRP Issued',
                message=f'Your Digital Retailer Pass has been issued and is valid for {validity_minutes} minutes.',
                notification_type='DRP_ISSUED'
            )
            
            return Response({
                'status': 'success',
                'message': 'DRP issued successfully',
                'drp': {
                    'id': drp.id,
                    'token': drp.token,
                    'qr_code': qr_code,
                    'expires_at': drp.expires_at.isoformat(),
                    'drp_type': drp.drp_type,
                    'seller_name': seller.name,
                    'trust_score': seller.trust_score,
                    'verification_url': f"{settings.FRONTEND_URL}/verify/{drp.token}"
                }
            })
            
        except Exception as e:
            logger.error(f"Error issuing DRP: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DRPVerifyView(APIView):
    """
    API endpoint for verifying DRP tokens
    
    POST /api/drp/verify/
    {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "customer_ip": "192.168.1.1",
        "verification_context": "ONLINE_PURCHASE"
    }
    """
    permission_classes = []  # Public endpoint
    
    def post(self, request):
        try:
            serializer = DRPVerifySerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    'status': 'error',
                    'message': 'Invalid request data',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            token = serializer.validated_data['token']
            customer_ip = serializer.validated_data.get('customer_ip', request.META.get('REMOTE_ADDR'))
            verification_context = serializer.validated_data.get('verification_context', 'GENERAL')
            
            # Verify token
            verification_result = verify_drp_token(token)
            
            if not verification_result['valid']:
                # Log failed verification
                VerificationRequest.objects.create(
                    token=token,
                    customer_ip=customer_ip,
                    verification_context=verification_context,
                    status='FAILED',
                    failure_reason=verification_result['error']
                )
                
                return Response({
                    'status': 'invalid',
                    'message': verification_result['error'],
                    'verification_details': {
                        'valid': False,
                        'reason': verification_result['error'],
                        'verified_at': timezone.now().isoformat()
                    }
                })
            
            # Get DRP and seller details
            payload = verification_result['payload']
            seller_id = payload.get('seller_id')
            
            try:
                seller = Seller.objects.get(id=seller_id)
                drp = DRP.objects.filter(
                    seller=seller,
                    token=token,
                    status='ACTIVE'
                ).first()
            except Seller.DoesNotExist:
                return Response({
                    'status': 'invalid',
                    'message': 'Seller not found'
                })
            
            # Check if DRP exists and is active
            if not drp:
                return Response({
                    'status': 'invalid',
                    'message': 'DRP not found or inactive'
                })
            
            # Check if seller is still active and verified
            if not seller.is_active:
                return Response({
                    'status': 'flagged',
                    'message': 'Seller account is currently inactive',
                    'verification_details': {
                        'valid': False,
                        'reason': 'SELLER_INACTIVE',
                        'seller_status': 'INACTIVE'
                    }
                })
            
            if seller.verification_status == 'FLAGGED':
                return Response({
                    'status': 'flagged',
                    'message': 'Seller has been flagged for security review',
                    'verification_details': {
                        'valid': False,
                        'reason': 'SELLER_FLAGGED',
                        'seller_status': 'FLAGGED'
                    }
                })
            
            # Log successful verification
            verification_request = VerificationRequest.objects.create(
                drp=drp,
                token=token,
                customer_ip=customer_ip,
                verification_context=verification_context,
                status='SUCCESS'
            )
            
            # Log DRP activity
            log_drp_activity(
                drp=drp,
                action='VERIFIED',
                details=f'DRP verified by customer from IP: {customer_ip}',
                verification_request=verification_request
            )
            
            # Update seller trust score based on successful verification
            seller.update_trust_score('VERIFICATION_SUCCESS')
            
            return Response({
                'status': 'verified',
                'message': 'DRP verified successfully',
                'verification_details': {
                    'valid': True,
                    'seller_id': seller.id,
                    'seller_name': seller.name,
                    'trust_score': seller.trust_score,
                    'verification_status': seller.verification_status,
                    'drp_type': drp.drp_type,
                    'issued_at': drp.issued_at.isoformat(),
                    'expires_at': drp.expires_at.isoformat(),
                    'verified_at': timezone.now().isoformat(),
                    'verification_id': verification_request.id
                },
                'seller_info': {
                    'name': seller.name,
                    'trust_level': seller.get_trust_level(),
                    'verification_badge': seller.get_verification_badge(),
                    'total_verifications': seller.get_verification_count(),
                    'member_since': seller.created_at.strftime('%Y-%m-%d')
                }
            })
            
        except Exception as e:
            logger.error(f"Error verifying DRP: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DRPRevokeView(APIView):
    """
    API endpoint for revoking DRPs (Admin only)
    
    POST /api/drp/revoke/
    {
        "drp_id": 123,
        "reason": "SECURITY_BREACH",
        "notes": "Seller reported for fraudulent activity"
    }
    """
    permission_classes = [IsAdminUser]
    
    def post(self, request):
        try:
            drp_id = request.data.get('drp_id')
            reason = request.data.get('reason', 'MANUAL_REVOCATION')
            notes = request.data.get('notes', '')
            
            if not drp_id:
                return Response({
                    'status': 'error',
                    'message': 'DRP ID is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                drp = DRP.objects.get(id=drp_id)
            except DRP.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'DRP not found'
                }, status=status.HTTP_404_NOT_FOUND)
            
            if drp.status != 'ACTIVE':
                return Response({
                    'status': 'error',
                    'message': 'DRP is not active'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Revoke DRP
            drp.status = 'REVOKED'
            drp.revoked_at = timezone.now()
            drp.revoked_by = request.user
            drp.revocation_reason = reason
            drp.revocation_notes = notes
            drp.save()
            
            # Log activity
            log_drp_activity(
                drp=drp,
                action='REVOKED',
                user=request.user,
                details=f'DRP revoked. Reason: {reason}. Notes: {notes}'
            )
            
            # Send notification to seller
            send_notification(
                seller=drp.seller,
                title='DRP Revoked',
                message=f'Your Digital Retailer Pass has been revoked. Reason: {reason}',
                notification_type='DRP_REVOKED'
            )
            
            return Response({
                'status': 'success',
                'message': 'DRP revoked successfully',
                'drp': {
                    'id': drp.id,
                    'status': drp.status,
                    'revoked_at': drp.revoked_at.isoformat(),
                    'revocation_reason': drp.revocation_reason
                }
            })
            
        except Exception as e:
            logger.error(f"Error revoking DRP: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# =============================================
# SELLER MANAGEMENT VIEWSETS
# =============================================

class SellerViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing sellers
    
    Provides CRUD operations for sellers with different permission levels
    """
    serializer_class = SellerSerializer
    pagination_class = DRPPagination
    
    def get_queryset(self):
        queryset = Seller.objects.all()
        
        # Filter parameters
        verification_status = self.request.query_params.get('verification_status')
        is_active = self.request.query_params.get('is_active')
        trust_score_min = self.request.query_params.get('trust_score_min')
        search = self.request.query_params.get('search')
        
        if verification_status:
            queryset = queryset.filter(verification_status=verification_status)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        if trust_score_min:
            queryset = queryset.filter(trust_score__gte=float(trust_score_min))
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | 
                Q(email__icontains=search) |
                Q(business_name__icontains=search)
            )
        
        return queryset.order_by('-created_at')
    
    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            permission_classes = [IsAdminUser]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return SellerCreateSerializer
        return SellerSerializer
    
    @action(detail=True, methods=['post'], permission_classes=[IsAdminUser])
    def verify(self, request, pk=None):
        """
        Verify a seller
        """
        seller = self.get_object()
        seller.verification_status = 'VERIFIED'
        seller.verified_at = timezone.now()
        seller.verified_by = request.user
        seller.save()
        
        # Send notification
        send_notification(
            seller=seller,
            title='Account Verified',
            message='Your seller account has been verified. You can now request DRPs.',
            notification_type='SELLER_VERIFIED'
        )
        
        return Response({
            'status': 'success',
            'message': 'Seller verified successfully'
        })
    
    @action(detail=True, methods=['post'], permission_classes=[IsAdminUser])
    def flag(self, request, pk=None):
        """
        Flag a seller for security review
        """
        seller = self.get_object()
        reason = request.data.get('reason', 'MANUAL_FLAG')
        notes = request.data.get('notes', '')
        
        seller.verification_status = 'FLAGGED'
        seller.is_active = False
        seller.save()
        
        # Revoke all active DRPs
        active_drps = DRP.objects.filter(
            seller=seller,
            status='ACTIVE',
            expires_at__gt=timezone.now()
        )
        
        for drp in active_drps:
            drp.status = 'REVOKED'
            drp.revoked_at = timezone.now()
            drp.revoked_by = request.user
            drp.revocation_reason = 'SELLER_FLAGGED'
            drp.save()
        
        # Send notification
        send_notification(
            seller=seller,
            title='Account Flagged',
            message=f'Your account has been flagged for review. Reason: {reason}',
            notification_type='SELLER_FLAGGED'
        )
        
        return Response({
            'status': 'success',
            'message': 'Seller flagged successfully',
            'revoked_drps': active_drps.count()
        })
    
    @action(detail=True, methods=['get'])
    def drp_history(self, request, pk=None):
        """
        Get DRP history for a seller
        """
        seller = self.get_object()
        drps = DRP.objects.filter(seller=seller).order_by('-created_at')
        
        # Paginate results
        paginator = DRPPagination()
        paginated_drps = paginator.paginate_queryset(drps, request)
        serializer = DRPSerializer(paginated_drps, many=True)
        
        return paginator.get_paginated_response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def verification_stats(self, request, pk=None):
        """
        Get verification statistics for a seller
        """
        seller = self.get_object()
        
        # Get stats
        total_drps = DRP.objects.filter(seller=seller).count()
        active_drps = DRP.objects.filter(
            seller=seller,
            status='ACTIVE',
            expires_at__gt=timezone.now()
        ).count()
        total_verifications = VerificationRequest.objects.filter(
            drp__seller=seller,
            status='SUCCESS'
        ).count()
        
        recent_verifications = VerificationRequest.objects.filter(
            drp__seller=seller,
            status='SUCCESS',
            created_at__gte=timezone.now() - timedelta(days=30)
        ).count()
        
        return Response({
            'seller_id': seller.id,
            'total_drps_issued': total_drps,
            'active_drps': active_drps,
            'total_verifications': total_verifications,
            'recent_verifications_30d': recent_verifications,
            'trust_score': seller.trust_score,
            'verification_status': seller.verification_status,
            'member_since': seller.created_at.strftime('%Y-%m-%d')
        })

# =============================================
# DRP MANAGEMENT VIEWSETS
# =============================================

class DRPViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing DRPs
    """
    serializer_class = DRPSerializer
    pagination_class = DRPPagination
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = DRP.objects.select_related('seller').all()
        
        # Filter parameters
        status = self.request.query_params.get('status')
        seller_id = self.request.query_params.get('seller_id')
        drp_type = self.request.query_params.get('drp_type')
        
        if status:
            queryset = queryset.filter(status=status)
        if seller_id:
            queryset = queryset.filter(seller_id=seller_id)
        if drp_type:
            queryset = queryset.filter(drp_type=drp_type)
        
        return queryset.order_by('-created_at')
    
    @action(detail=True, methods=['get'])
    def verification_logs(self, request, pk=None):
        """
        Get verification logs for a specific DRP
        """
        drp = self.get_object()
        logs = VerificationRequest.objects.filter(drp=drp).order_by('-created_at')
        
        paginator = DRPPagination()
        paginated_logs = paginator.paginate_queryset(logs, request)
        serializer = VerificationRequestSerializer(paginated_logs, many=True)
        
        return paginator.get_paginated_response(serializer.data)

# =============================================
# ADMIN DASHBOARD VIEWS
# =============================================

@staff_member_required
def admin_dashboard(request):
    """
    Admin dashboard view with comprehensive metrics
    """
    # Get dashboard metrics
    total_sellers = Seller.objects.count()
    verified_sellers = Seller.objects.filter(verification_status='VERIFIED').count()
    flagged_sellers = Seller.objects.filter(verification_status='FLAGGED').count()
    
    total_drps = DRP.objects.count()
    active_drps = DRP.objects.filter(
        status='ACTIVE',
        expires_at__gt=timezone.now()
    ).count()
    
    total_verifications = VerificationRequest.objects.filter(status='SUCCESS').count()
    recent_verifications = VerificationRequest.objects.filter(
        status='SUCCESS',
        created_at__gte=timezone.now() - timedelta(days=7)
    ).count()
    
    # Get recent activity
    recent_drps = DRP.objects.select_related('seller').order_by('-created_at')[:10]
    recent_verifications_list = VerificationRequest.objects.select_related(
        'drp__seller'
    ).order_by('-created_at')[:10]
    
    # Get flagged sellers
    flagged_sellers_list = Seller.objects.filter(
        verification_status='FLAGGED'
    ).order_by('-updated_at')[:5]
    
    context = {
        'total_sellers': total_sellers,
        'verified_sellers': verified_sellers,
        'flagged_sellers': flagged_sellers,
        'total_drps': total_drps,
        'active_drps': active_drps,
        'total_verifications': total_verifications,
        'recent_verifications': recent_verifications,
        'recent_drps': recent_drps,
        'recent_verifications_list': recent_verifications_list,
        'flagged_sellers_list': flagged_sellers_list,
    }
    
    return render(request, 'admin/dashboard.html', context)

# =============================================
# AJAX ENDPOINTS FOR FRONTEND
# =============================================

@csrf_exempt
@require_http_methods(["POST"])
def ajax_verify_drp(request):
    """
    AJAX endpoint for DRP verification
    """
    try:
        data = json.loads(request.body)
        token = data.get('token')
        
        if not token:
            return JsonResponse({
                'status': 'error',
                'message': 'Token is required'
            }, status=400)
        
        # Use the existing verify view logic
        verify_view = DRPVerifyView()
        verify_request = type('Request', (), {
            'data': {'token': token},
            'META': request.META
        })()
        
        response = verify_view.post(verify_request)
        
        return JsonResponse(response.data)
        
    except Exception as e:
        logger.error(f"AJAX verify error: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Internal server error'
        }, status=500)

@csrf_exempt
@require_http_methods(["POST"])
@staff_member_required
def ajax_flag_seller(request):
    """
    AJAX endpoint for flagging sellers
    """
    try:
        data = json.loads(request.body)
        seller_id = data.get('seller_id')
        reason = data.get('reason', 'MANUAL_FLAG')
        notes = data.get('notes', '')
        
        if not seller_id:
            return JsonResponse({
                'status': 'error',
                'message': 'Seller ID is required'
            }, status=400)
        
        seller = get_object_or_404(Seller, id=seller_id)
        
        # Flag the seller
        seller.verification_status = 'FLAGGED'
        seller.is_active = False
        seller.save()
        
        # Revoke active DRPs
        active_drps = DRP.objects.filter(
            seller=seller,
            status='ACTIVE',
            expires_at__gt=timezone.now()
        )
        
        revoked_count = active_drps.update(
            status='REVOKED',
            revoked_at=timezone.now(),
            revoked_by=request.user,
            revocation_reason='SELLER_FLAGGED'
        )
        
        return JsonResponse({
            'status': 'success',
            'message': 'Seller flagged successfully',
            'revoked_drps': revoked_count
        })
        
    except Exception as e:
        logger.error(f"AJAX flag seller error: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Internal server error'
        }, status=500)

# =============================================
# FRONTEND VIEWS
# =============================================

def verify_drp_page(request):
    """
    Frontend page for DRP verification
    """
    return render(request, 'drp/verify.html')

def seller_portal(request):
    """
    Seller portal page
    """
    return render(request, 'drp/seller_portal.html')

# =============================================
# UTILITY API ENDPOINTS
# =============================================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_seller_stats(request):
    """
    Get comprehensive seller statistics
    """
    stats = {
        'total_sellers': Seller.objects.count(),
        'verified_sellers': Seller.objects.filter(verification_status='VERIFIED').count(),
        'pending_sellers': Seller.objects.filter(verification_status='PENDING').count(),
        'flagged_sellers': Seller.objects.filter(verification_status='FLAGGED').count(),
        'active_sellers': Seller.objects.filter(is_active=True).count(),
        'avg_trust_score': Seller.objects.aggregate(Avg('trust_score'))['trust_score__avg'] or 0,
    }
    
    return Response(stats)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_drp_stats(request):
    """
    Get comprehensive DRP statistics
    """
    now = timezone.now()
    
    stats = {
        'total_drps': DRP.objects.count(),
        'active_drps': DRP.objects.filter(status='ACTIVE', expires_at__gt=now).count(),
        'expired_drps': DRP.objects.filter(status='ACTIVE', expires_at__lte=now).count(),
        'revoked_drps': DRP.objects.filter(status='REVOKED').count(),
        'total_verifications': VerificationRequest.objects.filter(status='SUCCESS').count(),
        'failed_verifications': VerificationRequest.objects.filter(status='FAILED').count(),
        'recent_verifications': VerificationRequest.objects.filter(
            status='SUCCESS',
            created_at__gte=now - timedelta(days=7)
        ).count(),
    }
    
    return Response(stats)

@api_view(['GET'])
@permission_classes([IsAdminUser])
def get_security_alerts(request):
    """
    Get security alerts and suspicious activities
    """
    alerts = []
    
    # Check for multiple failed verifications from same IP
    from django.db.models import Count
    suspicious_ips = VerificationRequest.objects.filter(
        status='FAILED',
        created_at__gte=timezone.now() - timedelta(hours=1)
    ).values('customer_ip').annotate(
        count=Count('id')
    ).filter(count__gte=5)
    
    for ip_data in suspicious_ips:
        alerts.append({
            'type': 'SUSPICIOUS_IP',
            'severity': 'HIGH',
            'message': f"IP {ip_data['customer_ip']} has {ip_data['count']} failed verification attempts in the last hour",
            'ip_address': ip_data['customer_ip'],
            'count': ip_data['count'],
            'timestamp': timezone.now().isoformat()
        })
    
    # Check for recently flagged sellers
    recent_flagged = Seller.objects.filter(
        verification_status='FLAGGED',
        updated_at__gte=timezone.now() - timedelta(days=1)
    ).count()
    
    if recent_flagged > 0:
        alerts.append({
            'type': 'FLAGGED_SELLERS',
            'severity': 'MEDIUM',
            'message': f"{recent_flagged} sellers have been flagged in the last 24 hours",
            'count': recent_flagged,
            'timestamp': timezone.now().isoformat()
        })
    
    # Check for expired DRPs that are still marked as active
    expired_active = DRP.objects.filter(
        status='ACTIVE',
        expires_at__lt=timezone.now() - timedelta(minutes=5)
    ).count()
    
    if expired_active > 0:
        alerts.append({
            'type': 'EXPIRED_ACTIVE_DRPS',
            'severity': 'LOW',
            'message': f"{expired_active} DRPs are expired but still marked as active",
            'count': expired_active,
            'timestamp': timezone.now().isoformat()
        })
    
    return Response({
        'alerts': alerts,
        'total_alerts': len(alerts),
        'timestamp': timezone.now().isoformat()
    })

@api_view(['POST'])
@permission_classes([IsAdminUser])
def bulk_revoke_drps(request):
    """
    Bulk revoke DRPs based on criteria
    """
    try:
        seller_ids = request.data.get('seller_ids', [])
        reason = request.data.get('reason', 'BULK_REVOCATION')
        notes = request.data.get('notes', '')
        
        if not seller_ids:
            return Response({
                'status': 'error',
                'message': 'At least one seller ID is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get active DRPs for specified sellers
        active_drps = DRP.objects.filter(
            seller_id__in=seller_ids,
            status='ACTIVE',
            expires_at__gt=timezone.now()
        )
        
        revoked_count = 0
        for drp in active_drps:
            drp.status = 'REVOKED'
            drp.revoked_at = timezone.now()
            drp.revoked_by = request.user
            drp.revocation_reason = reason
            drp.revocation_notes = notes
            drp.save()
            
            # Log activity
            log_drp_activity(
                drp=drp,
                action='REVOKED',
                user=request.user,
                details=f'Bulk revocation. Reason: {reason}'
            )
            
            revoked_count += 1
        
        return Response({
            'status': 'success',
            'message': f'Successfully revoked {revoked_count} DRPs',
            'revoked_count': revoked_count
        })
        
    except Exception as e:
        logger.error(f"Bulk revoke error: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def export_drp_data(request):
    """
    Export DRP data for reporting
    """
    try:
        # Get query parameters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        export_format = request.query_params.get('format', 'json')
        
        # Build queryset
        queryset = DRP.objects.select_related('seller').all()
        
        if start_date:
            queryset = queryset.filter(created_at__gte=start_date)
        if end_date:
            queryset = queryset.filter(created_at__lte=end_date)
        
        # Limit results for performance
        queryset = queryset.order_by('-created_at')[:1000]
        
        # Prepare data
        data = []
        for drp in queryset:
            data.append({
                'id': drp.id,
                'seller_id': drp.seller.id,
                'seller_name': drp.seller.name,
                'drp_type': drp.drp_type,
                'status': drp.status,
                'issued_at': drp.issued_at.isoformat(),
                'expires_at': drp.expires_at.isoformat(),
                'verification_count': drp.verification_requests.filter(status='SUCCESS').count(),
                'trust_score': drp.seller.trust_score,
                'verification_status': drp.seller.verification_status
            })
        
        if export_format == 'csv':
            import csv
            from django.http import HttpResponse
            
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="drp_data.csv"'
            
            writer = csv.DictWriter(response, fieldnames=data[0].keys() if data else [])
            writer.writeheader()
            writer.writerows(data)
            
            return response
        
        return Response({
            'status': 'success',
            'data': data,
            'total_records': len(data),
            'export_timestamp': timezone.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# =============================================
# WEBHOOK ENDPOINTS
# =============================================

@csrf_exempt
@require_http_methods(["POST"])
def webhook_seller_update(request):
    """
    Webhook endpoint for external seller updates
    """
    try:
        # Verify webhook signature (implement your own verification logic)
        signature = request.headers.get('X-Webhook-Signature')
        if not signature:
            return JsonResponse({'error': 'Missing signature'}, status=400)
        
        data = json.loads(request.body)
        seller_id = data.get('seller_id')
        action = data.get('action')
        
        if not seller_id or not action:
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        try:
            seller = Seller.objects.get(id=seller_id)
        except Seller.DoesNotExist:
            return JsonResponse({'error': 'Seller not found'}, status=404)
        
        # Handle different actions
        if action == 'suspend':
            seller.is_active = False
            seller.save()
            
            # Revoke active DRPs
            DRP.objects.filter(
                seller=seller,
                status='ACTIVE',
                expires_at__gt=timezone.now()
            ).update(
                status='REVOKED',
                revoked_at=timezone.now(),
                revocation_reason='WEBHOOK_SUSPENSION'
            )
            
        elif action == 'reactivate':
            seller.is_active = True
            seller.save()
            
        elif action == 'update_trust_score':
            new_score = data.get('trust_score')
            if new_score is not None:
                seller.trust_score = max(0, min(100, int(new_score)))
                seller.save()
        
        return JsonResponse({
            'status': 'success',
            'message': f'Seller {action} completed successfully'
        })
        
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Internal server error'
        }, status=500)

# =============================================
# MONITORING AND HEALTH CHECK ENDPOINTS
# =============================================

@api_view(['GET'])
@permission_classes([])
def health_check(request):
    """
    Health check endpoint for monitoring
    """
    try:
        # Check database connectivity
        seller_count = Seller.objects.count()
        
        # Check for any critical issues
        issues = []
        
        # Check for expired active DRPs
        expired_active = DRP.objects.filter(
            status='ACTIVE',
            expires_at__lt=timezone.now() - timedelta(minutes=15)
        ).count()
        
        if expired_active > 10:
            issues.append(f"{expired_active} DRPs are expired but still active")
        
        # Check for high failure rate
        recent_failures = VerificationRequest.objects.filter(
            status='FAILED',
            created_at__gte=timezone.now() - timedelta(minutes=15)
        ).count()
        
        recent_success = VerificationRequest.objects.filter(
            status='SUCCESS',
            created_at__gte=timezone.now() - timedelta(minutes=15)
        ).count()
        
        if recent_failures > 0 and recent_success > 0:
            failure_rate = recent_failures / (recent_failures + recent_success)
            if failure_rate > 0.5:
                issues.append(f"High verification failure rate: {failure_rate:.2%}")
        
        status_code = 200 if not issues else 503
        
        return Response({
            'status': 'healthy' if not issues else 'unhealthy',
            'timestamp': timezone.now().isoformat(),
            'database_status': 'connected',
            'total_sellers': seller_count,
            'issues': issues,
            'version': '1.0.0'
        }, status=status_code)
        
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return Response({
            'status': 'unhealthy',
            'timestamp': timezone.now().isoformat(),
            'error': 'Database connection failed'
        }, status=503)

@api_view(['GET'])
@permission_classes([IsAdminUser])
def system_metrics(request):
    """
    Get detailed system metrics for monitoring
    """
    try:
        now = timezone.now()
        
        # Time-based metrics
        metrics = {
            'timestamp': now.isoformat(),
            'sellers': {
                'total': Seller.objects.count(),
                'active': Seller.objects.filter(is_active=True).count(),
                'verified': Seller.objects.filter(verification_status='VERIFIED').count(),
                'flagged': Seller.objects.filter(verification_status='FLAGGED').count(),
                'new_today': Seller.objects.filter(created_at__date=now.date()).count(),
            },
            'drps': {
                'total': DRP.objects.count(),
                'active': DRP.objects.filter(status='ACTIVE', expires_at__gt=now).count(),
                'expired': DRP.objects.filter(status='ACTIVE', expires_at__lte=now).count(),
                'revoked': DRP.objects.filter(status='REVOKED').count(),
                'issued_today': DRP.objects.filter(issued_at__date=now.date()).count(),
            },
            'verifications': {
                'total': VerificationRequest.objects.count(),
                'successful': VerificationRequest.objects.filter(status='SUCCESS').count(),
                'failed': VerificationRequest.objects.filter(status='FAILED').count(),
                'today': VerificationRequest.objects.filter(created_at__date=now.date()).count(),
                'last_hour': VerificationRequest.objects.filter(
                    created_at__gte=now - timedelta(hours=1)
                ).count(),
            },
            'performance': {
                'avg_trust_score': Seller.objects.aggregate(
                    Avg('trust_score')
                )['trust_score__avg'] or 0,
                'verification_success_rate': 0,
                'active_drp_ratio': 0,
            }
        }
        
        # Calculate success rate
        total_verifications = metrics['verifications']['total']
        if total_verifications > 0:
            metrics['performance']['verification_success_rate'] = (
                metrics['verifications']['successful'] / total_verifications * 100
            )
        
        # Calculate active DRP ratio
        total_drps = metrics['drps']['total']
        if total_drps > 0:
            metrics['performance']['active_drp_ratio'] = (
                metrics['drps']['active'] / total_drps * 100
            )
        
        return Response(metrics)
        
    except Exception as e:
        logger.error(f"System metrics error: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Failed to retrieve system metrics'
        }, status=500)