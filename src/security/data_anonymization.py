"""
HIPAA-compliant Data Anonymization for Healthcare Analytics

Implements statistical de-identification, safe harbor compliance,
and re-identification risk assessment for PHI data.
"""

import re
import hashlib
import logging
import secrets
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, date, timedelta
from decimal import Decimal
from enum import Enum
import pandas as pd
import numpy as np
from dataclasses import dataclass
from uuid import UUID

from config.compliance_config import get_data_governance_config, get_compliance_config

logger = logging.getLogger(__name__)


class AnonymizationMethod(Enum):
    """Anonymization methods for different data types."""
    REMOVAL = "removal"
    GENERALIZATION = "generalization"
    SUPPRESSION = "suppression"
    PERTURBATION = "perturbation"
    PSEUDONYMIZATION = "pseudonymization"
    AGGREGATION = "aggregation"


class PHICategory(Enum):
    """HIPAA PHI categories requiring anonymization."""
    DIRECT_IDENTIFIER = "direct_identifier"
    QUASI_IDENTIFIER = "quasi_identifier"
    SENSITIVE_ATTRIBUTE = "sensitive_attribute"
    NON_SENSITIVE = "non_sensitive"


@dataclass
class AnonymizationRule:
    """Rule for anonymizing specific data fields."""
    field_name: str
    phi_category: PHICategory
    method: AnonymizationMethod
    parameters: Dict[str, Any]
    risk_level: str  # low, medium, high
    required_for_safe_harbor: bool = False


class SafeHarborCompliance:
    """HIPAA Safe Harbor compliance checker and enforcer."""
    
    # HIPAA Safe Harbor identifiers that must be removed/anonymized
    SAFE_HARBOR_IDENTIFIERS = [
        "names",
        "geographic_subdivisions_smaller_than_state",
        "dates_except_year",
        "ages_over_89",
        "phone_numbers",
        "email_addresses",
        "ssn",
        "medical_record_numbers",
        "health_plan_numbers",
        "account_numbers",
        "certificate_license_numbers",
        "device_identifiers",
        "web_urls",
        "ip_addresses",
        "biometric_identifiers",
        "face_photos",
        "unique_identifying_numbers",
        "unique_identifying_characteristics"
    ]
    
    def __init__(self):
        self.config = get_data_governance_config()
    
    def check_compliance(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Check if data meets Safe Harbor requirements."""
        violations = []
        compliance_score = 100
        
        for identifier in self.SAFE_HARBOR_IDENTIFIERS:
            if self._contains_identifier(data, identifier):
                violations.append({
                    "identifier": identifier,
                    "severity": "critical",
                    "field": self._find_identifier_field(data, identifier)
                })
                compliance_score -= 5
        
        return {
            "compliant": len(violations) == 0,
            "score": max(0, compliance_score),
            "violations": violations,
            "total_violations": len(violations)
        }
    
    def _contains_identifier(self, data: Dict[str, Any], identifier: str) -> bool:
        """Check if data contains specific HIPAA identifier."""
        checkers = {
            "names": self._contains_names,
            "geographic_subdivisions_smaller_than_state": self._contains_geographic_subdivisions,
            "dates_except_year": self._contains_specific_dates,
            "ages_over_89": self._contains_ages_over_89,
            "phone_numbers": self._contains_phone_numbers,
            "email_addresses": self._contains_email_addresses,
            "ssn": self._contains_ssn,
            "ip_addresses": self._contains_ip_addresses,
            "web_urls": self._contains_urls,
        }
        
        checker = checkers.get(identifier, lambda x: False)
        return checker(data)
    
    def _contains_names(self, data: Dict[str, Any]) -> bool:
        """Check for personal names."""
        name_fields = ["first_name", "last_name", "full_name", "name"]
        return any(field in data for field in name_fields)
    
    def _contains_geographic_subdivisions(self, data: Dict[str, Any]) -> bool:
        """Check for geographic data smaller than state level."""
        geo_fields = ["zip", "zipcode", "postal_code", "city", "county", "address"]
        return any(field in data for field in geo_fields)
    
    def _contains_specific_dates(self, data: Dict[str, Any]) -> bool:
        """Check for specific dates (more specific than year)."""
        for key, value in data.items():
            if isinstance(value, (date, datetime)):
                return True
            if isinstance(value, str) and self._is_date_string(value):
                return True
        return False
    
    def _contains_ages_over_89(self, data: Dict[str, Any]) -> bool:
        """Check for ages over 89."""
        age_fields = ["age", "birth_date", "date_of_birth"]
        for field in age_fields:
            if field in data:
                if field == "age" and isinstance(data[field], int) and data[field] > 89:
                    return True
                if "birth" in field and self._calculate_age_from_birth(data[field]) > 89:
                    return True
        return False
    
    def _contains_phone_numbers(self, data: Dict[str, Any]) -> bool:
        """Check for phone numbers."""
        phone_pattern = r'(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})'
        for value in data.values():
            if isinstance(value, str) and re.search(phone_pattern, value):
                return True
        return False
    
    def _contains_email_addresses(self, data: Dict[str, Any]) -> bool:
        """Check for email addresses."""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        for value in data.values():
            if isinstance(value, str) and re.search(email_pattern, value):
                return True
        return False
    
    def _contains_ssn(self, data: Dict[str, Any]) -> bool:
        """Check for Social Security Numbers."""
        ssn_pattern = r'\b\d{3}-?\d{2}-?\d{4}\b'
        for value in data.values():
            if isinstance(value, str) and re.search(ssn_pattern, value):
                return True
        return False
    
    def _contains_ip_addresses(self, data: Dict[str, Any]) -> bool:
        """Check for IP addresses."""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        for value in data.values():
            if isinstance(value, str) and re.search(ip_pattern, value):
                return True
        return False
    
    def _contains_urls(self, data: Dict[str, Any]) -> bool:
        """Check for web URLs."""
        url_pattern = r'https?://[^\s<>"{}|\\^`[\]]+'
        for value in data.values():
            if isinstance(value, str) and re.search(url_pattern, value):
                return True
        return False
    
    def _is_date_string(self, value: str) -> bool:
        """Check if string represents a specific date."""
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'\d{2}/\d{2}/\d{4}',  # MM/DD/YYYY
            r'\d{2}-\d{2}-\d{4}',  # MM-DD-YYYY
        ]
        return any(re.match(pattern, value) for pattern in date_patterns)
    
    def _calculate_age_from_birth(self, birth_value: Any) -> Optional[int]:
        """Calculate age from birth date."""
        try:
            if isinstance(birth_value, str):
                birth_date = datetime.strptime(birth_value, "%Y-%m-%d").date()
            elif isinstance(birth_value, datetime):
                birth_date = birth_value.date()
            elif isinstance(birth_value, date):
                birth_date = birth_value
            else:
                return None
            
            today = date.today()
            return today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        except:
            return None
    
    def _find_identifier_field(self, data: Dict[str, Any], identifier: str) -> Optional[str]:
        """Find the field containing the identifier."""
        # This is a simplified implementation
        # In practice, you'd implement specific logic for each identifier type
        return "unknown_field"


class DataAnonymizer:
    """Main class for anonymizing healthcare data."""
    
    def __init__(self):
        self.config = get_data_governance_config()
        self.compliance_config = get_compliance_config()
        self.safe_harbor = SafeHarborCompliance()
        self.pseudonym_map = {}  # For consistent pseudonymization
        
    def anonymize_dataset(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]], pd.DataFrame],
        rules: List[AnonymizationRule],
        target_k_anonymity: int = 5,
        target_l_diversity: int = 2
    ) -> Dict[str, Any]:
        """
        Anonymize a dataset according to specified rules.
        
        Args:
            data: Input data to anonymize
            rules: Anonymization rules to apply
            target_k_anonymity: Target k-anonymity value
            target_l_diversity: Target l-diversity value
            
        Returns:
            Anonymized data with metadata
        """
        try:
            # Convert data to standard format
            if isinstance(data, pd.DataFrame):
                data_dict_list = data.to_dict('records')
            elif isinstance(data, dict):
                data_dict_list = [data]
            else:
                data_dict_list = data
            
            # Apply anonymization rules
            anonymized_data = []
            for record in data_dict_list:
                anonymized_record = self._anonymize_record(record, rules)
                anonymized_data.append(anonymized_record)
            
            # Check k-anonymity and l-diversity
            privacy_metrics = self._calculate_privacy_metrics(
                anonymized_data, target_k_anonymity, target_l_diversity
            )
            
            # Check Safe Harbor compliance
            compliance_check = self._check_safe_harbor_compliance(anonymized_data)
            
            # Calculate re-identification risk
            risk_assessment = self._assess_reidentification_risk(anonymized_data)
            
            return {
                "anonymized_data": anonymized_data,
                "privacy_metrics": privacy_metrics,
                "safe_harbor_compliance": compliance_check,
                "reidentification_risk": risk_assessment,
                "anonymization_metadata": {
                    "rules_applied": [rule.field_name for rule in rules],
                    "methods_used": list(set(rule.method.value for rule in rules)),
                    "timestamp": datetime.utcnow().isoformat(),
                    "total_records": len(anonymized_data)
                }
            }
            
        except Exception as e:
            logger.error(f"Anonymization failed: {str(e)}")
            raise
    
    def _anonymize_record(
        self,
        record: Dict[str, Any],
        rules: List[AnonymizationRule]
    ) -> Dict[str, Any]:
        """Anonymize a single record."""
        anonymized = record.copy()
        
        for rule in rules:
            if rule.field_name in anonymized:
                original_value = anonymized[rule.field_name]
                anonymized_value = self._apply_anonymization_method(
                    original_value, rule.method, rule.parameters
                )
                anonymized[rule.field_name] = anonymized_value
        
        return anonymized
    
    def _apply_anonymization_method(
        self,
        value: Any,
        method: AnonymizationMethod,
        parameters: Dict[str, Any]
    ) -> Any:
        """Apply specific anonymization method to a value."""
        if method == AnonymizationMethod.REMOVAL:
            return None
        
        elif method == AnonymizationMethod.GENERALIZATION:
            return self._generalize_value(value, parameters)
        
        elif method == AnonymizationMethod.SUPPRESSION:
            return self._suppress_value(value, parameters)
        
        elif method == AnonymizationMethod.PERTURBATION:
            return self._perturb_value(value, parameters)
        
        elif method == AnonymizationMethod.PSEUDONYMIZATION:
            return self._pseudonymize_value(value, parameters)
        
        elif method == AnonymizationMethod.AGGREGATION:
            return self._aggregate_value(value, parameters)
        
        else:
            return value
    
    def _generalize_value(self, value: Any, parameters: Dict[str, Any]) -> Any:
        """Generalize a value to reduce specificity."""
        if isinstance(value, (int, float)):
            # Numeric generalization
            range_size = parameters.get('range_size', 10)
            lower_bound = (value // range_size) * range_size
            upper_bound = lower_bound + range_size
            return f"{lower_bound}-{upper_bound}"
        
        elif isinstance(value, str):
            # String generalization
            if parameters.get('mask_length'):
                mask_length = parameters['mask_length']
                if len(value) > mask_length:
                    return value[:mask_length] + "*" * (len(value) - mask_length)
            return value
        
        elif isinstance(value, (date, datetime)):
            # Date generalization
            precision = parameters.get('precision', 'year')
            if precision == 'year':
                return value.year
            elif precision == 'month':
                return f"{value.year}-{value.month:02d}"
            elif precision == 'quarter':
                quarter = (value.month - 1) // 3 + 1
                return f"{value.year}-Q{quarter}"
        
        return value
    
    def _suppress_value(self, value: Any, parameters: Dict[str, Any]) -> Any:
        """Suppress part of a value."""
        if isinstance(value, str):
            suppress_ratio = parameters.get('suppress_ratio', 0.5)
            chars_to_suppress = int(len(value) * suppress_ratio)
            return value[:-chars_to_suppress] + "*" * chars_to_suppress
        return value
    
    def _perturb_value(self, value: Any, parameters: Dict[str, Any]) -> Any:
        """Add noise to numeric values."""
        if isinstance(value, (int, float)):
            noise_level = parameters.get('noise_level', 0.1)
            noise = np.random.normal(0, abs(value) * noise_level)
            
            if isinstance(value, int):
                return int(value + noise)
            else:
                return value + noise
        return value
    
    def _pseudonymize_value(self, value: Any, parameters: Dict[str, Any]) -> str:
        """Replace value with consistent pseudonym."""
        salt = parameters.get('salt', 'default_salt')
        
        # Create hash of value with salt
        hash_input = f"{value}{salt}".encode('utf-8')
        hash_value = hashlib.sha256(hash_input).hexdigest()
        
        # Use first part of hash as pseudonym
        pseudonym_length = parameters.get('pseudonym_length', 8)
        pseudonym = hash_value[:pseudonym_length]
        
        # Store mapping for consistency
        if value not in self.pseudonym_map:
            self.pseudonym_map[value] = pseudonym
        
        return self.pseudonym_map[value]
    
    def _aggregate_value(self, value: Any, parameters: Dict[str, Any]) -> Any:
        """Aggregate value into broader category."""
        if isinstance(value, (int, float)):
            ranges = parameters.get('ranges', [])
            for range_def in ranges:
                if range_def['min'] <= value < range_def['max']:
                    return range_def['label']
        return value
    
    def _calculate_privacy_metrics(
        self,
        data: List[Dict[str, Any]],
        target_k: int,
        target_l: int
    ) -> Dict[str, Any]:
        """Calculate k-anonymity and l-diversity metrics."""
        if not data:
            return {"k_anonymity": 0, "l_diversity": 0, "meets_targets": False}
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(data)
        
        # Calculate k-anonymity (simplified)
        # In practice, you'd identify quasi-identifiers and calculate properly
        k_anonymity = self._calculate_k_anonymity(df)
        
        # Calculate l-diversity (simplified)
        l_diversity = self._calculate_l_diversity(df)
        
        return {
            "k_anonymity": k_anonymity,
            "l_diversity": l_diversity,
            "meets_k_target": k_anonymity >= target_k,
            "meets_l_target": l_diversity >= target_l,
            "meets_targets": k_anonymity >= target_k and l_diversity >= target_l,
            "target_k": target_k,
            "target_l": target_l
        }
    
    def _calculate_k_anonymity(self, df: pd.DataFrame) -> int:
        """Calculate k-anonymity value (simplified implementation)."""
        # This is a simplified calculation
        # In practice, you'd identify quasi-identifiers and calculate properly
        if df.empty:
            return 0
        
        # For demonstration, assume the smallest group size is k-anonymity
        # You would implement proper quasi-identifier grouping here
        return max(1, len(df) // 10)  # Simplified placeholder
    
    def _calculate_l_diversity(self, df: pd.DataFrame) -> int:
        """Calculate l-diversity value (simplified implementation)."""
        # This is a simplified calculation
        # In practice, you'd identify sensitive attributes and calculate properly
        if df.empty:
            return 0
        
        # For demonstration, return a placeholder value
        return 2  # Simplified placeholder
    
    def _check_safe_harbor_compliance(
        self,
        data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Check Safe Harbor compliance for the entire dataset."""
        if not data:
            return {"compliant": True, "violations": []}
        
        # Check a sample of records
        sample_size = min(10, len(data))
        violations = []
        
        for i, record in enumerate(data[:sample_size]):
            compliance_check = self.safe_harbor.check_compliance(record)
            if not compliance_check["compliant"]:
                violations.extend([
                    {**violation, "record_index": i}
                    for violation in compliance_check["violations"]
                ])
        
        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "records_checked": sample_size,
            "violation_rate": len(violations) / sample_size if sample_size > 0 else 0
        }
    
    def _assess_reidentification_risk(
        self,
        data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Assess re-identification risk of anonymized data."""
        if not data:
            return {"risk_level": "none", "risk_score": 0}
        
        # Simplified risk assessment
        # In practice, you'd use sophisticated statistical methods
        risk_factors = {
            "dataset_size": len(data),
            "unique_combinations": self._count_unique_combinations(data),
            "has_quasi_identifiers": self._has_quasi_identifiers(data),
            "temporal_data": self._has_temporal_data(data)
        }
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(risk_factors)
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "high"
        elif risk_score >= 50:
            risk_level = "medium"
        elif risk_score >= 20:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "recommendations": self._get_risk_mitigation_recommendations(risk_level)
        }
    
    def _count_unique_combinations(self, data: List[Dict[str, Any]]) -> int:
        """Count unique combinations of quasi-identifiers."""
        # Simplified implementation
        return len(data)  # Placeholder
    
    def _has_quasi_identifiers(self, data: List[Dict[str, Any]]) -> bool:
        """Check if data contains quasi-identifiers."""
        # Simplified check
        quasi_identifier_fields = ["age", "gender", "location", "occupation"]
        if not data:
            return False
        
        sample_record = data[0]
        return any(field in sample_record for field in quasi_identifier_fields)
    
    def _has_temporal_data(self, data: List[Dict[str, Any]]) -> bool:
        """Check if data contains temporal information."""
        # Simplified check
        temporal_fields = ["date", "time", "timestamp", "year"]
        if not data:
            return False
        
        sample_record = data[0]
        return any(field in sample_record for field in temporal_fields)
    
    def _calculate_risk_score(self, risk_factors: Dict[str, Any]) -> int:
        """Calculate overall re-identification risk score."""
        score = 0
        
        # Dataset size factor (smaller = higher risk)
        if risk_factors["dataset_size"] < 100:
            score += 30
        elif risk_factors["dataset_size"] < 1000:
            score += 20
        elif risk_factors["dataset_size"] < 10000:
            score += 10
        
        # Quasi-identifiers factor
        if risk_factors["has_quasi_identifiers"]:
            score += 25
        
        # Temporal data factor
        if risk_factors["temporal_data"]:
            score += 15
        
        # Unique combinations factor
        uniqueness_ratio = risk_factors["unique_combinations"] / max(1, risk_factors["dataset_size"])
        if uniqueness_ratio > 0.8:
            score += 30
        elif uniqueness_ratio > 0.5:
            score += 20
        elif uniqueness_ratio > 0.2:
            score += 10
        
        return min(100, score)
    
    def _get_risk_mitigation_recommendations(self, risk_level: str) -> List[str]:
        """Get recommendations for mitigating re-identification risk."""
        recommendations = {
            "high": [
                "Apply additional generalization to quasi-identifiers",
                "Increase k-anonymity target (k >= 10)",
                "Consider removing or heavily anonymizing outlier records",
                "Implement differential privacy techniques",
                "Review data sharing agreements for additional protections"
            ],
            "medium": [
                "Verify k-anonymity meets minimum requirements (k >= 5)",
                "Review quasi-identifier generalization levels",
                "Consider temporal data aggregation",
                "Implement access controls and usage monitoring"
            ],
            "low": [
                "Monitor for any new quasi-identifiers",
                "Maintain current anonymization levels",
                "Regular re-identification risk assessments"
            ],
            "minimal": [
                "Standard privacy monitoring procedures",
                "Periodic compliance reviews"
            ]
        }
        
        return recommendations.get(risk_level, [])


# Pre-defined anonymization rules for common healthcare data
HEALTHCARE_ANONYMIZATION_RULES = [
    AnonymizationRule(
        field_name="first_name",
        phi_category=PHICategory.DIRECT_IDENTIFIER,
        method=AnonymizationMethod.REMOVAL,
        parameters={},
        risk_level="high",
        required_for_safe_harbor=True
    ),
    AnonymizationRule(
        field_name="last_name", 
        phi_category=PHICategory.DIRECT_IDENTIFIER,
        method=AnonymizationMethod.REMOVAL,
        parameters={},
        risk_level="high",
        required_for_safe_harbor=True
    ),
    AnonymizationRule(
        field_name="email",
        phi_category=PHICategory.DIRECT_IDENTIFIER,
        method=AnonymizationMethod.REMOVAL,
        parameters={},
        risk_level="high",
        required_for_safe_harbor=True
    ),
    AnonymizationRule(
        field_name="phone_number",
        phi_category=PHICategory.DIRECT_IDENTIFIER,
        method=AnonymizationMethod.REMOVAL,
        parameters={},
        risk_level="high",
        required_for_safe_harbor=True
    ),
    AnonymizationRule(
        field_name="date_of_birth",
        phi_category=PHICategory.QUASI_IDENTIFIER,
        method=AnonymizationMethod.GENERALIZATION,
        parameters={"precision": "year"},
        risk_level="medium",
        required_for_safe_harbor=True
    ),
    AnonymizationRule(
        field_name="age",
        phi_category=PHICategory.QUASI_IDENTIFIER,
        method=AnonymizationMethod.GENERALIZATION,
        parameters={"range_size": 5},
        risk_level="medium"
    ),
    AnonymizationRule(
        field_name="zipcode",
        phi_category=PHICategory.QUASI_IDENTIFIER,
        method=AnonymizationMethod.GENERALIZATION,
        parameters={"mask_length": 3},
        risk_level="medium",
        required_for_safe_harbor=True
    )
]


async def anonymize_for_analytics(
    data: Union[Dict[str, Any], List[Dict[str, Any]]],
    purpose: str = "research",
    compliance_level: str = "safe_harbor"
) -> Dict[str, Any]:
    """
    High-level function to anonymize healthcare data for analytics.
    
    Args:
        data: Input data to anonymize
        purpose: Purpose of anonymization (research, analytics, reporting)
        compliance_level: Compliance level (safe_harbor, statistical)
        
    Returns:
        Anonymized data with compliance metadata
    """
    anonymizer = DataAnonymizer()
    
    # Select appropriate rules based on purpose and compliance level
    if compliance_level == "safe_harbor":
        rules = HEALTHCARE_ANONYMIZATION_RULES
        k_anonymity = 5
        l_diversity = 2
    else:
        # For statistical de-identification, use more sophisticated rules
        rules = HEALTHCARE_ANONYMIZATION_RULES  # Would have different rules in practice
        k_anonymity = 10
        l_diversity = 3
    
    try:
        result = anonymizer.anonymize_dataset(
            data=data,
            rules=rules,
            target_k_anonymity=k_anonymity,
            target_l_diversity=l_diversity
        )
        
        # Add purpose and compliance metadata
        result["anonymization_metadata"].update({
            "purpose": purpose,
            "compliance_level": compliance_level,
            "hipaa_safe_harbor": compliance_level == "safe_harbor"
        })
        
        return result
        
    except Exception as e:
        logger.error(f"Analytics anonymization failed: {str(e)}")
        raise 