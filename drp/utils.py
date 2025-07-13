"""
Digital Retailer Pass (DRP) Utilities
=====================================
Core utilities for JWT token generation, validation, and QR code creation
for Walmart Marketplace seller verification system.
"""

import jwt
import qrcode
import base64
from io import BytesIO
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from typing import Dict, Optional, Tuple, Any
import logging

logger = logging.getLogger(__name__)

# DRP Configuration Constants
DRP_TOKEN_EXPIRY_MINUTES = 10  # Token expires in 10 minutes
DRP_ALGORITHM = 'HS256'
DRP_ISSUER = 'walmart-marketplace'
DRP_AUDIENCE = 'walmart-customers'

# Trust Score Tiers
TRUST_TIERS = {
    'BASIC': {'min_score': 0, 'max_score': 59, 'badge': 'Basic'},
    'VERIFIED': {'min_score': 60, 'max_score': 84, 'badge': 'Verified'},
    'GOLD': {'min_score': 85, 'max_score': 100, 'badge': 'Gold Seller'}
}

class DRPTokenError(Exception):
    """Custom exception for DRP token operations"""
    pass

class DRPUtils:
    """
    Utility class for Digital Retailer Pass operations
    """
    
    @staticmethod
    def get_trust_tier(trust_score: int) -> str:
        """
        Determine trust tier based on seller's trust score
        
        Args:
            trust_score: Integer score between 0-100
            
        Returns:
            String badge level (Basic/Verified/Gold Seller)
        """
        for tier, config in TRUST_TIERS.items():
            if config['min_score'] <= trust_score <= config['max_score']:
                return config['badge']
        return 'Basic'  # Default fallback
    
    @staticmethod
    def generate_drp_token(seller_id: int, seller_name: str, trust_score: int, 
                          seller_email: str = None) -> str:
        """
        Generate a JWT token for Digital Retailer Pass
        
        Args:
            seller_id: Unique seller identifier
            seller_name: Seller's display name
            trust_score: Seller's trust score (0-100)
            seller_email: Optional seller email for additional verification
            
        Returns:
            JWT token string
            
        Raises:
            DRPTokenError: If token generation fails
        """
        try:
            # Current time
            now = timezone.now()
            expiry = now + timedelta(minutes=DRP_TOKEN_EXPIRY_MINUTES)
            
            # JWT payload
            payload = {
                'seller_id': seller_id,
                'seller_name': seller_name,
                'trust_score': trust_score,
                'trust_tier': DRPUtils.get_trust_tier(trust_score),
                'iat': int(now.timestamp()),  # Issued at
                'exp': int(expiry.timestamp()),  # Expiration
                'iss': DRP_ISSUER,  # Issuer
                'aud': DRP_AUDIENCE,  # Audience
                'drp_version': '1.0'
            }
            
            # Add email if provided
            if seller_email:
                payload['seller_email'] = seller_email
            
            # Generate token
            token = jwt.encode(
                payload,
                settings.SECRET_KEY,
                algorithm=DRP_ALGORITHM
            )
            
            logger.info(f"DRP token generated for seller {seller_id}")
            return token
            
        except Exception as e:
            logger.error(f"Failed to generate DRP token: {str(e)}")
            raise DRPTokenError(f"Token generation failed: {str(e)}")
    
    @staticmethod
    def validate_drp_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Validate a DRP JWT token
        
        Args:
            token: JWT token string to validate
            
        Returns:
            Tuple of (is_valid, payload_dict, error_message)
        """
        try:
            # Decode and validate token
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[DRP_ALGORITHM],
                audience=DRP_AUDIENCE,
                issuer=DRP_ISSUER
            )
            
            # Additional validation checks
            required_fields = ['seller_id', 'seller_name', 'trust_score', 'trust_tier']
            for field in required_fields:
                if field not in payload:
                    return False, None, f"Missing required field: {field}"
            
            # Validate trust score range
            trust_score = payload.get('trust_score')
            if not isinstance(trust_score, int) or not (0 <= trust_score <= 100):
                return False, None, "Invalid trust score"
            
            logger.info(f"DRP token validated for seller {payload['seller_id']}")
            return True, payload, None
            
        except jwt.ExpiredSignatureError:
            return False, None, "Token has expired"
        except jwt.InvalidTokenError as e:
            return False, None, f"Invalid token: {str(e)}"
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return False, None, f"Validation error: {str(e)}"
    
    @staticmethod
    def generate_qr_code(token: str, size: int = 10, border: int = 4) -> str:
        """
        Generate a QR code from DRP token and return as base64 string
        
        Args:
            token: JWT token to encode in QR
            size: Size of QR code boxes (default: 10)
            border: Border size (default: 4)
            
        Returns:
            Base64 encoded PNG image string
            
        Raises:
            DRPTokenError: If QR generation fails
        """
        try:
            # Create QR code instance
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=size,
                border=border,
            )
            
            # Add token data
            qr.add_data(token)
            qr.make(fit=True)
            
            # Create QR image
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = BytesIO()
            qr_image.save(buffer, format='PNG')
            buffer.seek(0)
            
            # Encode to base64
            qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            logger.info("QR code generated successfully")
            return qr_base64
            
        except Exception as e:
            logger.error(f"QR code generation failed: {str(e)}")
            raise DRPTokenError(f"QR generation failed: {str(e)}")
    
    @staticmethod
    def create_drp_response(seller_id: int, seller_name: str, trust_score: int,
                           seller_email: str = None, include_qr: bool = True) -> Dict[str, Any]:
        """
        Create a complete DRP response with token and QR code
        
        Args:
            seller_id: Unique seller identifier
            seller_name: Seller's display name
            trust_score: Seller's trust score (0-100)
            seller_email: Optional seller email
            include_qr: Whether to include QR code in response
            
        Returns:
            Dictionary containing DRP token, QR code, and metadata
        """
        try:
            # Generate token
            token = DRPUtils.generate_drp_token(
                seller_id, seller_name, trust_score, seller_email
            )
            
            # Prepare response
            response = {
                'drp_token': token,
                'seller_id': seller_id,
                'seller_name': seller_name,
                'trust_score': trust_score,
                'trust_tier': DRPUtils.get_trust_tier(trust_score),
                'expires_in_minutes': DRP_TOKEN_EXPIRY_MINUTES,
                'issued_at': timezone.now().isoformat(),
                'valid_until': (timezone.now() + timedelta(minutes=DRP_TOKEN_EXPIRY_MINUTES)).isoformat()
            }
            
            # Add QR code if requested
            if include_qr:
                qr_base64 = DRPUtils.generate_qr_code(token)
                response['qr_code'] = qr_base64
                response['qr_data_url'] = f"data:image/png;base64,{qr_base64}"
            
            return response
            
        except Exception as e:
            logger.error(f"DRP response creation failed: {str(e)}")
            raise DRPTokenError(f"Response creation failed: {str(e)}")
    
    @staticmethod
    def verify_drp_token(token: str) -> Dict[str, Any]:
        """
        Verify a DRP token and return verification status
        
        Args:
            token: JWT token to verify
            
        Returns:
            Dictionary containing verification results
        """
        is_valid, payload, error = DRPUtils.validate_drp_token(token)
        
        if is_valid:
            return {
                'status': 'valid',
                'verified': True,
                'seller_id': payload['seller_id'],
                'seller_name': payload['seller_name'],
                'trust_score': payload['trust_score'],
                'trust_tier': payload['trust_tier'],
                'issued_at': datetime.fromtimestamp(payload['iat']).isoformat(),
                'expires_at': datetime.fromtimestamp(payload['exp']).isoformat(),
                'message': 'DRP token is valid and verified'
            }
        else:
            return {
                'status': 'invalid',
                'verified': False,
                'error': error,
                'message': f'DRP verification failed: {error}'
            }
    
    @staticmethod
    def extract_seller_id_from_token(token: str) -> Optional[int]:
        """
        Extract seller ID from token without full validation
        Useful for logging and tracking purposes
        
        Args:
            token: JWT token string
            
        Returns:
            Seller ID if extractable, None otherwise
        """
        try:
            # Decode without verification (just for extraction)
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload.get('seller_id')
        except Exception:
            return None
    
    @staticmethod
    def get_token_expiry(token: str) -> Optional[datetime]:
        """
        Get expiry time from token
        
        Args:
            token: JWT token string
            
        Returns:
            Expiry datetime if extractable, None otherwise
        """
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            exp_timestamp = payload.get('exp')
            if exp_timestamp:
                return datetime.fromtimestamp(exp_timestamp)
            return None
        except Exception:
            return None

# Convenience functions for direct usage
def generate_drp_for_seller(seller_id: int, seller_name: str, trust_score: int,
                           seller_email: str = None) -> Dict[str, Any]:
    """
    Convenience function to generate DRP for a seller
    
    Args:
        seller_id: Unique seller identifier
        seller_name: Seller's display name
        trust_score: Seller's trust score (0-100)
        seller_email: Optional seller email
        
    Returns:
        Complete DRP response dictionary
    """
    return DRPUtils.create_drp_response(seller_id, seller_name, trust_score, seller_email)

def verify_customer_drp(token: str) -> Dict[str, Any]:
    """
    Convenience function for customer DRP verification
    
    Args:
        token: JWT token to verify
        
    Returns:
        Verification results dictionary
    """
    return DRPUtils.verify_drp_token(token)

# Example usage and testing functions
def create_sample_drp_tokens():
    """
    Create sample DRP tokens for testing
    Returns dictionary with sample tokens
    """
    samples = {
        'basic_seller': generate_drp_for_seller(1, "ABC Electronics", 45),
        'verified_seller': generate_drp_for_seller(2, "TechWorld Store", 75, "tech@world.com"),
        'gold_seller': generate_drp_for_seller(3, "Premium Gadgets", 92, "premium@gadgets.com")
    }
    return samples

if __name__ == "__main__":
    # Quick test of utilities
    print("DRP Utils Test")
    print("-" * 40)
    
    # Test token generation
    sample_token = DRPUtils.generate_drp_token(123, "Test Seller", 80)
    print(f"Generated token: {sample_token[:50]}...")
    
    # Test validation
    is_valid, payload, error = DRPUtils.validate_drp_token(sample_token)
    print(f"Token valid: {is_valid}")
    if payload:
        print(f"Seller: {payload['seller_name']}, Trust: {payload['trust_tier']}")
    
    # Test QR generation
    qr_code = DRPUtils.generate_qr_code(sample_token)
    print(f"QR code generated: {len(qr_code)} characters")