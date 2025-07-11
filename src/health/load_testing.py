"""
Healthcare Application Load Testing

Load testing utilities for healthcare applications with HIPAA-compliant
test data generation and performance benchmarking capabilities.
"""

import asyncio
import logging
import time
import random
import aiohttp
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import statistics

logger = logging.getLogger(__name__)


class LoadTestType(Enum):
    """Types of load tests."""
    BASELINE = "baseline"
    STRESS = "stress"
    SPIKE = "spike"
    VOLUME = "volume"
    ENDURANCE = "endurance"
    SCALABILITY = "scalability"


@dataclass
class LoadTestConfig:
    """Load test configuration."""
    test_name: str
    test_type: LoadTestType
    target_url: str
    concurrent_users: int
    test_duration_seconds: int
    ramp_up_seconds: int
    endpoints: List[str]
    test_data_file: Optional[str] = None
    think_time_seconds: float = 1.0
    max_response_time_ms: int = 2000
    target_success_rate: float = 0.99
    
    
@dataclass
class TestResult:
    """Individual test result."""
    endpoint: str
    method: str
    response_time_ms: float
    status_code: int
    success: bool
    timestamp: datetime
    error_message: Optional[str] = None
    response_size_bytes: int = 0


@dataclass
class LoadTestReport:
    """Load test report."""
    test_name: str
    test_type: LoadTestType
    start_time: datetime
    end_time: datetime
    total_requests: int
    successful_requests: int
    failed_requests: int
    success_rate: float
    avg_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    max_response_time_ms: float
    min_response_time_ms: float
    requests_per_second: float
    concurrent_users: int
    errors: Dict[str, int]
    endpoint_stats: Dict[str, Dict[str, Any]]
    recommendations: List[str]


class HealthcareLoadTester:
    """Comprehensive load testing for healthcare applications."""
    
    def __init__(self, base_url: str, auth_token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.session = None
        
        # Healthcare-specific test scenarios
        self.test_scenarios = {
            "user_authentication": {
                "endpoints": ["/auth/login", "/auth/refresh", "/auth/logout"],
                "methods": ["POST", "POST", "POST"],
                "weights": [0.4, 0.4, 0.2]
            },
            "voice_upload_workflow": {
                "endpoints": ["/api/voice/upload", "/api/voice/analyze", "/api/voice/results"],
                "methods": ["POST", "POST", "GET"],
                "weights": [0.5, 0.3, 0.2]
            },
            "user_management": {
                "endpoints": ["/api/users", "/api/users/{id}", "/api/users/{id}/profile"],
                "methods": ["GET", "GET", "PUT"],
                "weights": [0.3, 0.4, 0.3]
            },
            "notification_system": {
                "endpoints": ["/api/notifications", "/api/notifications/send", "/api/notifications/preferences"],
                "methods": ["GET", "POST", "PUT"],
                "weights": [0.5, 0.3, 0.2]
            },
            "compliance_monitoring": {
                "endpoints": ["/compliance/status", "/compliance/audit", "/compliance/reports"],
                "methods": ["GET", "GET", "GET"],
                "weights": [0.4, 0.3, 0.3]
            },
            "health_checks": {
                "endpoints": ["/health/status", "/health/database", "/health/metrics"],
                "methods": ["GET", "GET", "GET"],
                "weights": [0.5, 0.25, 0.25]
            }
        }
        
        # Synthetic test data generators
        self.test_data_generators = {
            "user_data": self._generate_user_data,
            "voice_data": self._generate_voice_data,
            "notification_data": self._generate_notification_data,
            "compliance_data": self._generate_compliance_data
        }
    
    async def run_load_test(self, config: LoadTestConfig) -> LoadTestReport:
        """Run a comprehensive load test."""
        try:
            logger.info(f"Starting load test: {config.test_name}")
            
            # Initialize session
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers=self._get_auth_headers()
            )
            
            start_time = datetime.utcnow()
            test_results = []
            
            try:
                # Run the load test based on type
                if config.test_type == LoadTestType.BASELINE:
                    test_results = await self._run_baseline_test(config)
                elif config.test_type == LoadTestType.STRESS:
                    test_results = await self._run_stress_test(config)
                elif config.test_type == LoadTestType.SPIKE:
                    test_results = await self._run_spike_test(config)
                elif config.test_type == LoadTestType.VOLUME:
                    test_results = await self._run_volume_test(config)
                elif config.test_type == LoadTestType.ENDURANCE:
                    test_results = await self._run_endurance_test(config)
                elif config.test_type == LoadTestType.SCALABILITY:
                    test_results = await self._run_scalability_test(config)
                
                end_time = datetime.utcnow()
                
                # Generate report
                report = self._generate_load_test_report(config, test_results, start_time, end_time)
                
                logger.info(f"Load test completed: {config.test_name}")
                return report
                
            finally:
                await self.session.close()
            
        except Exception as e:
            logger.error(f"Load test failed: {e}")
            raise
    
    async def run_healthcare_scenario_test(
        self,
        scenario_name: str,
        concurrent_users: int = 10,
        duration_seconds: int = 300
    ) -> LoadTestReport:
        """Run a healthcare-specific scenario test."""
        if scenario_name not in self.test_scenarios:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        
        scenario = self.test_scenarios[scenario_name]
        
        config = LoadTestConfig(
            test_name=f"healthcare_scenario_{scenario_name}",
            test_type=LoadTestType.BASELINE,
            target_url=self.base_url,
            concurrent_users=concurrent_users,
            test_duration_seconds=duration_seconds,
            ramp_up_seconds=min(60, duration_seconds // 5),
            endpoints=scenario["endpoints"],
            think_time_seconds=random.uniform(1.0, 3.0)
        )
        
        return await self.run_load_test(config)
    
    async def run_api_benchmark(self) -> Dict[str, Any]:
        """Run comprehensive API performance benchmark."""
        try:
            logger.info("Starting API performance benchmark")
            
            benchmark_results = {
                "timestamp": datetime.utcnow().isoformat(),
                "test_scenarios": {},
                "overall_performance": {},
                "recommendations": []
            }
            
            # Run all healthcare scenarios
            for scenario_name in self.test_scenarios.keys():
                logger.info(f"Running benchmark for scenario: {scenario_name}")
                
                try:
                    result = await self.run_healthcare_scenario_test(
                        scenario_name,
                        concurrent_users=5,  # Light load for benchmark
                        duration_seconds=120
                    )
                    
                    benchmark_results["test_scenarios"][scenario_name] = {
                        "success_rate": result.success_rate,
                        "avg_response_time_ms": result.avg_response_time_ms,
                        "p95_response_time_ms": result.p95_response_time_ms,
                        "requests_per_second": result.requests_per_second,
                        "status": "pass" if result.success_rate >= 0.95 and result.p95_response_time_ms <= 500 else "fail"
                    }
                    
                except Exception as e:
                    benchmark_results["test_scenarios"][scenario_name] = {
                        "status": "error",
                        "error": str(e)
                    }
            
            # Calculate overall performance
            successful_scenarios = [
                s for s in benchmark_results["test_scenarios"].values()
                if s.get("status") == "pass"
            ]
            
            if successful_scenarios:
                benchmark_results["overall_performance"] = {
                    "overall_success_rate": sum(s["success_rate"] for s in successful_scenarios) / len(successful_scenarios),
                    "overall_avg_response_time": sum(s["avg_response_time_ms"] for s in successful_scenarios) / len(successful_scenarios),
                    "scenarios_passed": len(successful_scenarios),
                    "scenarios_total": len(self.test_scenarios),
                    "benchmark_score": len(successful_scenarios) / len(self.test_scenarios) * 100
                }
            
            # Generate recommendations
            benchmark_results["recommendations"] = self._generate_benchmark_recommendations(benchmark_results)
            
            return benchmark_results
            
        except Exception as e:
            logger.error(f"API benchmark failed: {e}")
            raise
    
    async def test_scalability_limits(
        self,
        start_users: int = 10,
        max_users: int = 1000,
        step_size: int = 50,
        step_duration: int = 120
    ) -> Dict[str, Any]:
        """Test application scalability limits."""
        try:
            logger.info("Starting scalability limit testing")
            
            scalability_results = {
                "timestamp": datetime.utcnow().isoformat(),
                "test_steps": [],
                "breaking_point": None,
                "recommendations": []
            }
            
            current_users = start_users
            
            while current_users <= max_users:
                logger.info(f"Testing with {current_users} concurrent users")
                
                # Create test config
                config = LoadTestConfig(
                    test_name=f"scalability_{current_users}_users",
                    test_type=LoadTestType.SCALABILITY,
                    target_url=self.base_url,
                    concurrent_users=current_users,
                    test_duration_seconds=step_duration,
                    ramp_up_seconds=30,
                    endpoints=["/health/status", "/api/users"],
                    think_time_seconds=1.0
                )
                
                # Run test
                result = await self.run_load_test(config)
                
                step_result = {
                    "concurrent_users": current_users,
                    "success_rate": result.success_rate,
                    "avg_response_time_ms": result.avg_response_time_ms,
                    "p95_response_time_ms": result.p95_response_time_ms,
                    "requests_per_second": result.requests_per_second,
                    "failed_requests": result.failed_requests,
                    "test_passed": result.success_rate >= 0.95 and result.p95_response_time_ms <= 1000
                }
                
                scalability_results["test_steps"].append(step_result)
                
                # Check if we've hit the breaking point
                if not step_result["test_passed"]:
                    scalability_results["breaking_point"] = {
                        "user_limit": current_users,
                        "reason": "Success rate or response time threshold exceeded",
                        "success_rate": result.success_rate,
                        "p95_response_time_ms": result.p95_response_time_ms
                    }
                    break
                
                current_users += step_size
                
                # Brief pause between tests
                await asyncio.sleep(10)
            
            # Generate scalability recommendations
            scalability_results["recommendations"] = self._generate_scalability_recommendations(scalability_results)
            
            return scalability_results
            
        except Exception as e:
            logger.error(f"Scalability testing failed: {e}")
            raise
    
    # Load test implementations
    
    async def _run_baseline_test(self, config: LoadTestConfig) -> List[TestResult]:
        """Run baseline performance test."""
        return await self._run_concurrent_test(config)
    
    async def _run_stress_test(self, config: LoadTestConfig) -> List[TestResult]:
        """Run stress test with high load."""
        # Increase concurrent users for stress testing
        stress_config = config
        stress_config.concurrent_users = config.concurrent_users * 2
        return await self._run_concurrent_test(stress_config)
    
    async def _run_spike_test(self, config: LoadTestConfig) -> List[TestResult]:
        """Run spike test with sudden load increase."""
        results = []
        
        # Normal load phase
        normal_config = config
        normal_config.test_duration_seconds = config.test_duration_seconds // 3
        results.extend(await self._run_concurrent_test(normal_config))
        
        # Spike phase
        spike_config = config
        spike_config.concurrent_users = config.concurrent_users * 5
        spike_config.test_duration_seconds = config.test_duration_seconds // 3
        spike_config.ramp_up_seconds = 5  # Quick ramp up
        results.extend(await self._run_concurrent_test(spike_config))
        
        # Recovery phase
        recovery_config = config
        recovery_config.test_duration_seconds = config.test_duration_seconds // 3
        results.extend(await self._run_concurrent_test(recovery_config))
        
        return results
    
    async def _run_volume_test(self, config: LoadTestConfig) -> List[TestResult]:
        """Run volume test with large amount of data."""
        # Volume testing focuses on data processing
        return await self._run_concurrent_test(config)
    
    async def _run_endurance_test(self, config: LoadTestConfig) -> List[TestResult]:
        """Run endurance test for extended period."""
        # Endurance test runs for longer duration
        endurance_config = config
        endurance_config.test_duration_seconds = max(3600, config.test_duration_seconds)  # At least 1 hour
        return await self._run_concurrent_test(endurance_config)
    
    async def _run_scalability_test(self, config: LoadTestConfig) -> List[TestResult]:
        """Run scalability test."""
        return await self._run_concurrent_test(config)
    
    async def _run_concurrent_test(self, config: LoadTestConfig) -> List[TestResult]:
        """Run concurrent load test."""
        results = []
        tasks = []
        
        # Calculate user ramp-up schedule
        ramp_up_delay = config.ramp_up_seconds / config.concurrent_users if config.concurrent_users > 0 else 0
        
        # Create tasks for concurrent users
        for user_id in range(config.concurrent_users):
            start_delay = user_id * ramp_up_delay
            task = asyncio.create_task(
                self._simulate_user_session(config, user_id, start_delay)
            )
            tasks.append(task)
        
        # Wait for all tasks to complete
        user_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect results
        for user_result in user_results:
            if isinstance(user_result, list):
                results.extend(user_result)
            elif isinstance(user_result, Exception):
                logger.error(f"User simulation failed: {user_result}")
        
        return results
    
    async def _simulate_user_session(
        self,
        config: LoadTestConfig,
        user_id: int,
        start_delay: float
    ) -> List[TestResult]:
        """Simulate individual user session."""
        results = []
        
        # Initial delay for ramp-up
        if start_delay > 0:
            await asyncio.sleep(start_delay)
        
        session_start = time.time()
        session_end = session_start + config.test_duration_seconds
        
        while time.time() < session_end:
            # Select random endpoint
            endpoint = random.choice(config.endpoints)
            
            # Make request
            result = await self._make_request(endpoint, config, user_id)
            results.append(result)
            
            # Think time between requests
            await asyncio.sleep(config.think_time_seconds + random.uniform(0, 1))
        
        return results
    
    async def _make_request(
        self,
        endpoint: str,
        config: LoadTestConfig,
        user_id: int
    ) -> TestResult:
        """Make HTTP request and record result."""
        url = f"{self.base_url}{endpoint}"
        method = "GET"  # Default method
        
        # Determine method based on endpoint
        if any(x in endpoint for x in ["/auth/login", "/upload", "/send"]):
            method = "POST"
        elif any(x in endpoint for x in ["/profile", "/preferences"]):
            method = "PUT"
        
        start_time = time.time()
        
        try:
            # Prepare request data
            data = None
            if method in ["POST", "PUT"]:
                data = self._get_test_data_for_endpoint(endpoint, user_id)
            
            # Make request
            async with self.session.request(
                method,
                url,
                json=data if data else None,
                headers=self._get_auth_headers()
            ) as response:
                response_time = (time.time() - start_time) * 1000  # ms
                response_text = await response.text()
                
                return TestResult(
                    endpoint=endpoint,
                    method=method,
                    response_time_ms=response_time,
                    status_code=response.status,
                    success=200 <= response.status < 400,
                    timestamp=datetime.utcnow(),
                    response_size_bytes=len(response_text)
                )
        
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            return TestResult(
                endpoint=endpoint,
                method=method,
                response_time_ms=response_time,
                status_code=0,
                success=False,
                timestamp=datetime.utcnow(),
                error_message=str(e)
            )
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "HealthcareLoadTester/1.0"
        }
        
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        
        return headers
    
    def _get_test_data_for_endpoint(self, endpoint: str, user_id: int) -> Optional[Dict[str, Any]]:
        """Get test data for specific endpoint."""
        if "/auth/login" in endpoint:
            return self._generate_user_data(user_id)
        elif "/upload" in endpoint:
            return self._generate_voice_data(user_id)
        elif "/send" in endpoint:
            return self._generate_notification_data(user_id)
        elif "/compliance" in endpoint:
            return self._generate_compliance_data(user_id)
        else:
            return None
    
    # Test data generators
    
    def _generate_user_data(self, user_id: int) -> Dict[str, Any]:
        """Generate synthetic user data."""
        return {
            "email": f"loadtest_user_{user_id}@example.com",
            "password": "TestPassword123!",
            "first_name": f"LoadTest",
            "last_name": f"User{user_id}"
        }
    
    def _generate_voice_data(self, user_id: int) -> Dict[str, Any]:
        """Generate synthetic voice analysis data."""
        return {
            "file_name": f"test_audio_{user_id}_{int(time.time())}.wav",
            "duration_seconds": random.randint(5, 30),
            "sample_rate": 44100,
            "format": "wav",
            "metadata": {
                "user_id": user_id,
                "session_id": f"session_{user_id}_{int(time.time())}"
            }
        }
    
    def _generate_notification_data(self, user_id: int) -> Dict[str, Any]:
        """Generate synthetic notification data."""
        return {
            "recipient_id": user_id,
            "type": random.choice(["email", "sms", "push"]),
            "title": f"Test Notification {int(time.time())}",
            "message": "This is a load test notification",
            "priority": random.choice(["low", "medium", "high"])
        }
    
    def _generate_compliance_data(self, user_id: int) -> Dict[str, Any]:
        """Generate synthetic compliance data."""
        return {
            "audit_type": "access_log",
            "user_id": user_id,
            "resource": "patient_data",
            "action": "view",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    # Report generation
    
    def _generate_load_test_report(
        self,
        config: LoadTestConfig,
        results: List[TestResult],
        start_time: datetime,
        end_time: datetime
    ) -> LoadTestReport:
        """Generate comprehensive load test report."""
        
        successful_results = [r for r in results if r.success]
        failed_results = [r for r in results if not r.success]
        
        response_times = [r.response_time_ms for r in successful_results]
        
        # Calculate statistics
        total_requests = len(results)
        successful_requests = len(successful_results)
        failed_requests = len(failed_results)
        success_rate = successful_requests / total_requests if total_requests > 0 else 0
        
        test_duration = (end_time - start_time).total_seconds()
        requests_per_second = total_requests / test_duration if test_duration > 0 else 0
        
        # Response time statistics
        if response_times:
            avg_response_time = statistics.mean(response_times)
            p95_response_time = sorted(response_times)[int(0.95 * len(response_times))]
            p99_response_time = sorted(response_times)[int(0.99 * len(response_times))]
            max_response_time = max(response_times)
            min_response_time = min(response_times)
        else:
            avg_response_time = p95_response_time = p99_response_time = 0
            max_response_time = min_response_time = 0
        
        # Error analysis
        errors = {}
        for result in failed_results:
            error_key = result.error_message or f"HTTP_{result.status_code}"
            errors[error_key] = errors.get(error_key, 0) + 1
        
        # Endpoint statistics
        endpoint_stats = {}
        for endpoint in set(r.endpoint for r in results):
            endpoint_results = [r for r in results if r.endpoint == endpoint]
            endpoint_successful = [r for r in endpoint_results if r.success]
            
            if endpoint_results:
                endpoint_response_times = [r.response_time_ms for r in endpoint_successful]
                endpoint_stats[endpoint] = {
                    "total_requests": len(endpoint_results),
                    "successful_requests": len(endpoint_successful),
                    "success_rate": len(endpoint_successful) / len(endpoint_results),
                    "avg_response_time_ms": statistics.mean(endpoint_response_times) if endpoint_response_times else 0,
                    "p95_response_time_ms": sorted(endpoint_response_times)[int(0.95 * len(endpoint_response_times))] if endpoint_response_times else 0
                }
        
        # Generate recommendations
        recommendations = self._generate_performance_recommendations(
            success_rate, avg_response_time, p95_response_time, errors
        )
        
        return LoadTestReport(
            test_name=config.test_name,
            test_type=config.test_type,
            start_time=start_time,
            end_time=end_time,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            success_rate=success_rate,
            avg_response_time_ms=avg_response_time,
            p95_response_time_ms=p95_response_time,
            p99_response_time_ms=p99_response_time,
            max_response_time_ms=max_response_time,
            min_response_time_ms=min_response_time,
            requests_per_second=requests_per_second,
            concurrent_users=config.concurrent_users,
            errors=errors,
            endpoint_stats=endpoint_stats,
            recommendations=recommendations
        )
    
    def _generate_performance_recommendations(
        self,
        success_rate: float,
        avg_response_time: float,
        p95_response_time: float,
        errors: Dict[str, int]
    ) -> List[str]:
        """Generate performance recommendations."""
        recommendations = []
        
        if success_rate < 0.95:
            recommendations.append(f"Success rate ({success_rate:.2%}) is below acceptable threshold (95%). Investigate error causes.")
        
        if avg_response_time > 500:
            recommendations.append(f"Average response time ({avg_response_time:.0f}ms) exceeds recommended threshold (500ms). Consider optimization.")
        
        if p95_response_time > 1000:
            recommendations.append(f"95th percentile response time ({p95_response_time:.0f}ms) is too high. Optimize slow endpoints.")
        
        if errors:
            most_common_error = max(errors.items(), key=lambda x: x[1])
            recommendations.append(f"Most common error: {most_common_error[0]} ({most_common_error[1]} occurrences). Investigate root cause.")
        
        if not recommendations:
            recommendations.append("Performance meets acceptable thresholds. Monitor for regressions.")
        
        return recommendations
    
    def _generate_benchmark_recommendations(self, benchmark_results: Dict[str, Any]) -> List[str]:
        """Generate benchmark recommendations."""
        recommendations = []
        
        overall_perf = benchmark_results.get("overall_performance", {})
        benchmark_score = overall_perf.get("benchmark_score", 0)
        
        if benchmark_score < 80:
            recommendations.append("Overall benchmark score is below 80%. Multiple scenarios need optimization.")
        elif benchmark_score < 90:
            recommendations.append("Benchmark score is acceptable but has room for improvement.")
        else:
            recommendations.append("Excellent benchmark performance across all scenarios.")
        
        # Scenario-specific recommendations
        for scenario_name, result in benchmark_results.get("test_scenarios", {}).items():
            if result.get("status") == "fail":
                if result.get("success_rate", 0) < 0.95:
                    recommendations.append(f"{scenario_name}: Low success rate. Check for errors and timeouts.")
                if result.get("p95_response_time_ms", 0) > 500:
                    recommendations.append(f"{scenario_name}: High response times. Optimize performance.")
        
        return recommendations
    
    def _generate_scalability_recommendations(self, scalability_results: Dict[str, Any]) -> List[str]:
        """Generate scalability recommendations."""
        recommendations = []
        
        breaking_point = scalability_results.get("breaking_point")
        if breaking_point:
            user_limit = breaking_point["user_limit"]
            recommendations.append(f"Application breaks at {user_limit} concurrent users. Consider horizontal scaling.")
            
            if breaking_point.get("success_rate", 1) < 0.95:
                recommendations.append("Failure due to error rate increase. Investigate error handling and resource limits.")
            
            if breaking_point.get("p95_response_time_ms", 0) > 1000:
                recommendations.append("Failure due to response time degradation. Optimize slow operations and consider caching.")
        else:
            max_users_tested = max(step["concurrent_users"] for step in scalability_results["test_steps"])
            recommendations.append(f"Application handled {max_users_tested} concurrent users successfully. Continue testing with higher loads.")
        
        return recommendations


# Standalone functions for convenience
async def run_healthcare_load_test(
    base_url: str,
    test_type: LoadTestType = LoadTestType.BASELINE,
    concurrent_users: int = 10,
    duration_seconds: int = 300,
    auth_token: Optional[str] = None
) -> LoadTestReport:
    """Run a healthcare load test."""
    tester = HealthcareLoadTester(base_url, auth_token)
    
    config = LoadTestConfig(
        test_name=f"healthcare_load_test_{test_type.value}",
        test_type=test_type,
        target_url=base_url,
        concurrent_users=concurrent_users,
        test_duration_seconds=duration_seconds,
        ramp_up_seconds=min(60, duration_seconds // 5),
        endpoints=["/health/status", "/api/users", "/api/voice/upload"]
    )
    
    return await tester.run_load_test(config)

async def benchmark_healthcare_api(
    base_url: str,
    auth_token: Optional[str] = None
) -> Dict[str, Any]:
    """Benchmark healthcare API performance."""
    tester = HealthcareLoadTester(base_url, auth_token)
    return await tester.run_api_benchmark() 