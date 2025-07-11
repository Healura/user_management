#!/usr/bin/env python3
"""
Performance Benchmarking Script

Comprehensive performance testing and benchmarking for healthcare user management
service with load testing, stress testing, and performance monitoring.
"""

import os
import sys
import json
import time
import argparse
import asyncio
import statistics
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple

# Add the src directory to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from health.load_testing import HealthcareLoadTester, LoadTestConfig, LoadTestType, run_healthcare_load_test


class PerformanceBenchmark:
    """Comprehensive performance benchmarking suite."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_performance_config(config_file)
        self.results = {}
        
        # Performance targets
        self.targets = {
            "api_response_time_p95": 500,  # ms
            "api_response_time_p99": 1000,  # ms
            "throughput_min": 100,  # requests/second
            "error_rate_max": 0.01,  # 1%
            "cpu_usage_max": 80,  # percentage
            "memory_usage_max": 80,  # percentage
            "concurrent_users_min": 100  # concurrent users
        }
        
        # Test scenarios
        self.test_scenarios = {
            "baseline": {
                "concurrent_users": 10,
                "duration": 300,  # 5 minutes
                "description": "Baseline performance test"
            },
            "load": {
                "concurrent_users": 50,
                "duration": 600,  # 10 minutes
                "description": "Normal load test"
            },
            "stress": {
                "concurrent_users": 200,
                "duration": 300,  # 5 minutes
                "description": "Stress test"
            },
            "spike": {
                "concurrent_users": 500,
                "duration": 120,  # 2 minutes
                "description": "Spike test"
            },
            "endurance": {
                "concurrent_users": 25,
                "duration": 3600,  # 1 hour
                "description": "Endurance test"
            }
        }
    
    async def run_comprehensive_benchmark(self) -> Dict[str, Any]:
        """Run comprehensive performance benchmark."""
        benchmark_result = {
            "timestamp": datetime.now().isoformat(),
            "test_scenarios": {},
            "performance_summary": {},
            "baseline_comparison": {},
            "recommendations": [],
            "overall_score": 0
        }
        
        print("Starting comprehensive performance benchmark...")
        
        try:
            # Run baseline test first
            print("\n1. Running baseline performance test...")
            baseline_result = await self._run_scenario_test("baseline")
            benchmark_result["test_scenarios"]["baseline"] = baseline_result
            
            # Store baseline for comparison
            self.baseline_metrics = self._extract_key_metrics(baseline_result)
            
            # Run load test
            print("\n2. Running load test...")
            load_result = await self._run_scenario_test("load")
            benchmark_result["test_scenarios"]["load"] = load_result
            
            # Run stress test
            print("\n3. Running stress test...")
            stress_result = await self._run_scenario_test("stress")
            benchmark_result["test_scenarios"]["stress"] = stress_result
            
            # Run spike test
            print("\n4. Running spike test...")
            spike_result = await self._run_scenario_test("spike")
            benchmark_result["test_scenarios"]["spike"] = spike_result
            
            # Optional endurance test
            if self.config.get("run_endurance_test", False):
                print("\n5. Running endurance test...")
                endurance_result = await self._run_scenario_test("endurance")
                benchmark_result["test_scenarios"]["endurance"] = endurance_result
            
            # Generate performance summary
            benchmark_result["performance_summary"] = self._generate_performance_summary(
                benchmark_result["test_scenarios"]
            )
            
            # Generate baseline comparison
            benchmark_result["baseline_comparison"] = self._compare_to_baseline(
                benchmark_result["test_scenarios"]
            )
            
            # Generate recommendations
            benchmark_result["recommendations"] = self._generate_performance_recommendations(
                benchmark_result
            )
            
            # Calculate overall score
            benchmark_result["overall_score"] = self._calculate_overall_score(
                benchmark_result["test_scenarios"]
            )
            
            print(f"\n✅ Comprehensive benchmark completed. Overall Score: {benchmark_result['overall_score']}/100")
            
            return benchmark_result
            
        except Exception as e:
            print(f"❌ Benchmark failed: {e}")
            benchmark_result["error"] = str(e)
            return benchmark_result
    
    async def run_quick_benchmark(self) -> Dict[str, Any]:
        """Run quick performance benchmark."""
        print("Starting quick performance benchmark...")
        
        quick_result = {
            "timestamp": datetime.now().isoformat(),
            "baseline_test": {},
            "load_test": {},
            "performance_score": 0,
            "recommendations": []
        }
        
        try:
            # Quick baseline test (2 minutes)
            print("Running quick baseline test...")
            baseline_config = self.test_scenarios["baseline"].copy()
            baseline_config["duration"] = 120
            baseline_config["concurrent_users"] = 5
            
            baseline_result = await self._run_custom_test(baseline_config)
            quick_result["baseline_test"] = baseline_result
            
            # Quick load test (3 minutes)
            print("Running quick load test...")
            load_config = self.test_scenarios["load"].copy()
            load_config["duration"] = 180
            load_config["concurrent_users"] = 20
            
            load_result = await self._run_custom_test(load_config)
            quick_result["load_test"] = load_result
            
            # Calculate performance score
            quick_result["performance_score"] = self._calculate_quick_score(
                baseline_result, load_result
            )
            
            # Generate recommendations
            quick_result["recommendations"] = self._generate_quick_recommendations(
                baseline_result, load_result
            )
            
            print(f"✅ Quick benchmark completed. Score: {quick_result['performance_score']}/100")
            
            return quick_result
            
        except Exception as e:
            print(f"❌ Quick benchmark failed: {e}")
            quick_result["error"] = str(e)
            return quick_result
    
    async def run_scalability_test(
        self,
        start_users: int = 10,
        max_users: int = 500,
        step_size: int = 25,
        step_duration: int = 120
    ) -> Dict[str, Any]:
        """Run scalability test to find breaking point."""
        print(f"Starting scalability test: {start_users} to {max_users} users")
        
        scalability_result = {
            "timestamp": datetime.now().isoformat(),
            "test_parameters": {
                "start_users": start_users,
                "max_users": max_users,
                "step_size": step_size,
                "step_duration": step_duration
            },
            "test_steps": [],
            "breaking_point": None,
            "max_stable_users": 0,
            "recommendations": []
        }
        
        try:
            current_users = start_users
            
            while current_users <= max_users:
                print(f"Testing with {current_users} concurrent users...")
                
                # Create test configuration
                test_config = {
                    "concurrent_users": current_users,
                    "duration": step_duration,
                    "description": f"Scalability test - {current_users} users"
                }
                
                # Run test
                step_result = await self._run_custom_test(test_config)
                
                # Analyze results
                step_analysis = {
                    "concurrent_users": current_users,
                    "success_rate": step_result.get("success_rate", 0),
                    "avg_response_time": step_result.get("avg_response_time_ms", 0),
                    "p95_response_time": step_result.get("p95_response_time_ms", 0),
                    "requests_per_second": step_result.get("requests_per_second", 0),
                    "test_passed": self._evaluate_step_success(step_result)
                }
                
                scalability_result["test_steps"].append(step_analysis)
                
                # Check if this is the breaking point
                if not step_analysis["test_passed"]:
                    scalability_result["breaking_point"] = {
                        "user_count": current_users,
                        "failure_reason": self._identify_failure_reason(step_result),
                        "metrics": step_analysis
                    }
                    break
                else:
                    scalability_result["max_stable_users"] = current_users
                
                current_users += step_size
                
                # Brief pause between tests
                await asyncio.sleep(10)
            
            # Generate scalability recommendations
            scalability_result["recommendations"] = self._generate_scalability_recommendations(
                scalability_result
            )
            
            print(f"✅ Scalability test completed. Max stable users: {scalability_result['max_stable_users']}")
            
            return scalability_result
            
        except Exception as e:
            print(f"❌ Scalability test failed: {e}")
            scalability_result["error"] = str(e)
            return scalability_result
    
    async def run_stress_test(self, target_users: int = 200, duration: int = 300) -> Dict[str, Any]:
        """Run focused stress test."""
        print(f"Starting stress test: {target_users} users for {duration} seconds")
        
        stress_config = {
            "concurrent_users": target_users,
            "duration": duration,
            "description": f"Stress test - {target_users} users"
        }
        
        stress_result = await self._run_custom_test(stress_config)
        
        # Enhanced stress analysis
        stress_analysis = {
            "timestamp": datetime.now().isoformat(),
            "test_parameters": stress_config,
            "results": stress_result,
            "stress_indicators": self._analyze_stress_indicators(stress_result),
            "recovery_analysis": await self._analyze_recovery(),
            "recommendations": self._generate_stress_recommendations(stress_result)
        }
        
        return stress_analysis
    
    async def benchmark_api_endpoints(self) -> Dict[str, Any]:
        """Benchmark individual API endpoints."""
        print("Starting API endpoint benchmarking...")
        
        endpoint_benchmark = {
            "timestamp": datetime.now().isoformat(),
            "endpoints": {},
            "summary": {},
            "recommendations": []
        }
        
        # Key endpoints to test
        endpoints = {
            "health_status": "/health/status",
            "user_list": "/api/users",
            "user_login": "/auth/login",
            "voice_upload": "/api/voice/upload",
            "notifications": "/api/notifications"
        }
        
        load_tester = HealthcareLoadTester(
            self.config.get("base_url", "http://localhost:8000"),
            self.config.get("auth_token")
        )
        
        for endpoint_name, endpoint_path in endpoints.items():
            print(f"Benchmarking {endpoint_name}...")
            
            try:
                # Create focused test for this endpoint
                endpoint_config = LoadTestConfig(
                    test_name=f"endpoint_benchmark_{endpoint_name}",
                    test_type=LoadTestType.BASELINE,
                    target_url=self.config.get("base_url", "http://localhost:8000"),
                    concurrent_users=10,
                    test_duration_seconds=60,
                    ramp_up_seconds=10,
                    endpoints=[endpoint_path]
                )
                
                result = await load_tester.run_load_test(endpoint_config)
                
                endpoint_benchmark["endpoints"][endpoint_name] = {
                    "endpoint": endpoint_path,
                    "avg_response_time": result.avg_response_time_ms,
                    "p95_response_time": result.p95_response_time_ms,
                    "p99_response_time": result.p99_response_time_ms,
                    "success_rate": result.success_rate,
                    "requests_per_second": result.requests_per_second,
                    "status": self._evaluate_endpoint_performance(result)
                }
                
            except Exception as e:
                endpoint_benchmark["endpoints"][endpoint_name] = {
                    "endpoint": endpoint_path,
                    "error": str(e),
                    "status": "error"
                }
        
        # Generate endpoint summary
        endpoint_benchmark["summary"] = self._summarize_endpoint_results(
            endpoint_benchmark["endpoints"]
        )
        
        # Generate endpoint recommendations
        endpoint_benchmark["recommendations"] = self._generate_endpoint_recommendations(
            endpoint_benchmark["endpoints"]
        )
        
        print("✅ API endpoint benchmarking completed")
        
        return endpoint_benchmark
    
    # Helper methods
    
    async def _run_scenario_test(self, scenario_name: str) -> Dict[str, Any]:
        """Run a predefined test scenario."""
        scenario = self.test_scenarios[scenario_name]
        return await self._run_custom_test(scenario)
    
    async def _run_custom_test(self, test_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run a custom test configuration."""
        try:
            load_tester = HealthcareLoadTester(
                self.config.get("base_url", "http://localhost:8000"),
                self.config.get("auth_token")
            )
            
            # Determine test type based on concurrent users
            concurrent_users = test_config["concurrent_users"]
            if concurrent_users >= 200:
                test_type = LoadTestType.STRESS
            elif concurrent_users >= 100:
                test_type = LoadTestType.VOLUME
            else:
                test_type = LoadTestType.BASELINE
            
            # Create load test configuration
            load_config = LoadTestConfig(
                test_name=f"perf_test_{test_config.get('description', 'custom')}",
                test_type=test_type,
                target_url=self.config.get("base_url", "http://localhost:8000"),
                concurrent_users=concurrent_users,
                test_duration_seconds=test_config["duration"],
                ramp_up_seconds=min(60, test_config["duration"] // 5),
                endpoints=self.config.get("test_endpoints", ["/health/status", "/api/users"])
            )
            
            # Run load test
            result = await load_tester.run_load_test(load_config)
            
            # Convert to dictionary format
            return {
                "test_name": result.test_name,
                "test_type": result.test_type.value,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat(),
                "total_requests": result.total_requests,
                "successful_requests": result.successful_requests,
                "failed_requests": result.failed_requests,
                "success_rate": result.success_rate,
                "avg_response_time_ms": result.avg_response_time_ms,
                "p95_response_time_ms": result.p95_response_time_ms,
                "p99_response_time_ms": result.p99_response_time_ms,
                "max_response_time_ms": result.max_response_time_ms,
                "min_response_time_ms": result.min_response_time_ms,
                "requests_per_second": result.requests_per_second,
                "concurrent_users": result.concurrent_users,
                "errors": result.errors,
                "endpoint_stats": result.endpoint_stats
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "test_config": test_config
            }
    
    def _extract_key_metrics(self, test_result: Dict[str, Any]) -> Dict[str, float]:
        """Extract key metrics from test result."""
        return {
            "avg_response_time": test_result.get("avg_response_time_ms", 0),
            "p95_response_time": test_result.get("p95_response_time_ms", 0),
            "success_rate": test_result.get("success_rate", 0),
            "requests_per_second": test_result.get("requests_per_second", 0)
        }
    
    def _generate_performance_summary(self, test_scenarios: Dict[str, Any]) -> Dict[str, Any]:
        """Generate performance summary across all scenarios."""
        summary = {
            "best_response_time": float('inf'),
            "worst_response_time": 0,
            "best_throughput": 0,
            "worst_success_rate": 1.0,
            "scenarios_passed": 0,
            "total_scenarios": len(test_scenarios)
        }
        
        for scenario_name, result in test_scenarios.items():
            if "error" in result:
                continue
            
            # Response time analysis
            avg_response = result.get("avg_response_time_ms", 0)
            if avg_response > 0:
                summary["best_response_time"] = min(summary["best_response_time"], avg_response)
                summary["worst_response_time"] = max(summary["worst_response_time"], avg_response)
            
            # Throughput analysis
            throughput = result.get("requests_per_second", 0)
            summary["best_throughput"] = max(summary["best_throughput"], throughput)
            
            # Success rate analysis
            success_rate = result.get("success_rate", 0)
            summary["worst_success_rate"] = min(summary["worst_success_rate"], success_rate)
            
            # Scenario pass/fail
            if self._evaluate_scenario_success(result):
                summary["scenarios_passed"] += 1
        
        # Fix infinity values
        if summary["best_response_time"] == float('inf'):
            summary["best_response_time"] = 0
        
        return summary
    
    def _compare_to_baseline(self, test_scenarios: Dict[str, Any]) -> Dict[str, Any]:
        """Compare test results to baseline."""
        if "baseline" not in test_scenarios or not hasattr(self, 'baseline_metrics'):
            return {}
        
        baseline = self.baseline_metrics
        comparison = {}
        
        for scenario_name, result in test_scenarios.items():
            if scenario_name == "baseline" or "error" in result:
                continue
            
            scenario_metrics = self._extract_key_metrics(result)
            
            comparison[scenario_name] = {
                "response_time_change": self._calculate_percentage_change(
                    baseline["avg_response_time"], scenario_metrics["avg_response_time"]
                ),
                "throughput_change": self._calculate_percentage_change(
                    baseline["requests_per_second"], scenario_metrics["requests_per_second"]
                ),
                "success_rate_change": self._calculate_percentage_change(
                    baseline["success_rate"], scenario_metrics["success_rate"]
                )
            }
        
        return comparison
    
    def _calculate_percentage_change(self, baseline: float, current: float) -> float:
        """Calculate percentage change from baseline."""
        if baseline == 0:
            return 0
        return ((current - baseline) / baseline) * 100
    
    def _generate_performance_recommendations(self, benchmark_result: Dict[str, Any]) -> List[str]:
        """Generate performance recommendations."""
        recommendations = []
        
        summary = benchmark_result.get("performance_summary", {})
        
        # Response time recommendations
        worst_response = summary.get("worst_response_time", 0)
        if worst_response > self.targets["api_response_time_p95"]:
            recommendations.append(
                f"Response times exceed target ({worst_response:.0f}ms > {self.targets['api_response_time_p95']}ms). "
                "Consider optimizing slow endpoints and implementing caching."
            )
        
        # Throughput recommendations
        best_throughput = summary.get("best_throughput", 0)
        if best_throughput < self.targets["throughput_min"]:
            recommendations.append(
                f"Throughput below target ({best_throughput:.1f} < {self.targets['throughput_min']} req/s). "
                "Consider horizontal scaling or performance optimization."
            )
        
        # Success rate recommendations
        worst_success_rate = summary.get("worst_success_rate", 1.0)
        if worst_success_rate < (1 - self.targets["error_rate_max"]):
            recommendations.append(
                f"Success rate below target ({worst_success_rate:.2%}). "
                "Investigate error causes and improve error handling."
            )
        
        # Scenario-specific recommendations
        scenarios = benchmark_result.get("test_scenarios", {})
        
        if "stress" in scenarios:
            stress_result = scenarios["stress"]
            if not self._evaluate_scenario_success(stress_result):
                recommendations.append(
                    "Stress test failed. System may not handle high load well. "
                    "Consider implementing circuit breakers and rate limiting."
                )
        
        if "spike" in scenarios:
            spike_result = scenarios["spike"]
            if not self._evaluate_scenario_success(spike_result):
                recommendations.append(
                    "Spike test failed. System may not handle sudden load increases. "
                    "Consider implementing auto-scaling and load balancing."
                )
        
        if not recommendations:
            recommendations.append("Performance meets all targets. Continue monitoring for regressions.")
        
        return recommendations
    
    def _calculate_overall_score(self, test_scenarios: Dict[str, Any]) -> int:
        """Calculate overall performance score (0-100)."""
        score = 100
        
        for scenario_name, result in test_scenarios.items():
            if "error" in result:
                score -= 20
                continue
            
            # Response time scoring
            avg_response = result.get("avg_response_time_ms", 0)
            if avg_response > self.targets["api_response_time_p99"]:
                score -= 15
            elif avg_response > self.targets["api_response_time_p95"]:
                score -= 5
            
            # Success rate scoring
            success_rate = result.get("success_rate", 0)
            if success_rate < 0.95:
                score -= 20
            elif success_rate < 0.99:
                score -= 10
            
            # Throughput scoring (only for load tests)
            if scenario_name in ["load", "stress"]:
                throughput = result.get("requests_per_second", 0)
                if throughput < self.targets["throughput_min"]:
                    score -= 10
        
        return max(0, min(100, score))
    
    def _calculate_quick_score(self, baseline_result: Dict[str, Any], load_result: Dict[str, Any]) -> int:
        """Calculate quick performance score."""
        score = 100
        
        # Baseline scoring
        baseline_response = baseline_result.get("avg_response_time_ms", 0)
        if baseline_response > 200:
            score -= 20
        elif baseline_response > 100:
            score -= 10
        
        # Load test scoring
        load_response = load_result.get("avg_response_time_ms", 0)
        load_success = load_result.get("success_rate", 0)
        
        if load_response > 500:
            score -= 30
        elif load_response > 300:
            score -= 15
        
        if load_success < 0.95:
            score -= 25
        elif load_success < 0.99:
            score -= 10
        
        return max(0, min(100, score))
    
    def _generate_quick_recommendations(self, baseline_result: Dict[str, Any], load_result: Dict[str, Any]) -> List[str]:
        """Generate quick recommendations."""
        recommendations = []
        
        baseline_response = baseline_result.get("avg_response_time_ms", 0)
        load_response = load_result.get("avg_response_time_ms", 0)
        load_success = load_result.get("success_rate", 0)
        
        if baseline_response > 200:
            recommendations.append("Baseline response time is high. Optimize application performance.")
        
        if load_response > 500:
            recommendations.append("Load test response time is excessive. Consider scaling resources.")
        
        if load_success < 0.95:
            recommendations.append("Load test success rate is low. Investigate error causes.")
        
        response_degradation = ((load_response - baseline_response) / baseline_response) * 100
        if response_degradation > 100:
            recommendations.append("Significant performance degradation under load. Review system capacity.")
        
        if not recommendations:
            recommendations.append("Performance is acceptable for current load levels.")
        
        return recommendations
    
    def _evaluate_step_success(self, step_result: Dict[str, Any]) -> bool:
        """Evaluate if a scalability test step was successful."""
        success_rate = step_result.get("success_rate", 0)
        p95_response = step_result.get("p95_response_time_ms", 0)
        
        return (success_rate >= 0.95 and 
                p95_response <= self.targets["api_response_time_p95"])
    
    def _evaluate_scenario_success(self, scenario_result: Dict[str, Any]) -> bool:
        """Evaluate if a test scenario was successful."""
        if "error" in scenario_result:
            return False
        
        success_rate = scenario_result.get("success_rate", 0)
        avg_response = scenario_result.get("avg_response_time_ms", 0)
        
        return (success_rate >= 0.95 and 
                avg_response <= self.targets["api_response_time_p95"])
    
    def _evaluate_endpoint_performance(self, result) -> str:
        """Evaluate individual endpoint performance."""
        if result.success_rate < 0.95:
            return "poor"
        elif result.p95_response_time_ms > self.targets["api_response_time_p95"]:
            return "slow"
        elif result.avg_response_time_ms < 100:
            return "excellent"
        else:
            return "good"
    
    def _identify_failure_reason(self, step_result: Dict[str, Any]) -> str:
        """Identify reason for test step failure."""
        success_rate = step_result.get("success_rate", 0)
        p95_response = step_result.get("p95_response_time_ms", 0)
        
        if success_rate < 0.95:
            return f"High error rate: {(1-success_rate)*100:.1f}%"
        elif p95_response > self.targets["api_response_time_p95"]:
            return f"High response time: {p95_response:.0f}ms"
        else:
            return "Performance degradation"
    
    def _generate_scalability_recommendations(self, scalability_result: Dict[str, Any]) -> List[str]:
        """Generate scalability recommendations."""
        recommendations = []
        
        max_users = scalability_result.get("max_stable_users", 0)
        breaking_point = scalability_result.get("breaking_point")
        
        if breaking_point:
            failure_reason = breaking_point.get("failure_reason", "")
            
            if "error rate" in failure_reason:
                recommendations.append("High error rate under load. Implement better error handling and circuit breakers.")
            elif "response time" in failure_reason:
                recommendations.append("Response time degradation. Consider horizontal scaling and caching.")
            
            recommendations.append(f"Current capacity limit: {max_users} concurrent users. Plan scaling before reaching this limit.")
        else:
            recommendations.append(f"System handled {max_users} users successfully. Continue testing with higher loads.")
        
        return recommendations
    
    def _analyze_stress_indicators(self, stress_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze stress test indicators."""
        return {
            "response_time_degradation": stress_result.get("avg_response_time_ms", 0) > self.targets["api_response_time_p95"],
            "high_error_rate": stress_result.get("success_rate", 1) < 0.95,
            "throughput_drop": stress_result.get("requests_per_second", 0) < self.targets["throughput_min"],
            "system_instability": stress_result.get("p99_response_time_ms", 0) > self.targets["api_response_time_p99"] * 2
        }
    
    async def _analyze_recovery(self) -> Dict[str, Any]:
        """Analyze system recovery after stress test."""
        print("Analyzing system recovery...")
        
        # Wait a bit for system to recover
        await asyncio.sleep(30)
        
        # Run a quick test to check recovery
        recovery_config = {
            "concurrent_users": 5,
            "duration": 60,
            "description": "Recovery test"
        }
        
        recovery_result = await self._run_custom_test(recovery_config)
        
        return {
            "recovery_time_seconds": 30,
            "post_stress_performance": recovery_result.get("avg_response_time_ms", 0),
            "recovered_successfully": recovery_result.get("success_rate", 0) > 0.95
        }
    
    def _generate_stress_recommendations(self, stress_result: Dict[str, Any]) -> List[str]:
        """Generate stress test recommendations."""
        recommendations = []
        
        success_rate = stress_result.get("success_rate", 0)
        avg_response = stress_result.get("avg_response_time_ms", 0)
        
        if success_rate < 0.95:
            recommendations.append("High error rate under stress. Implement rate limiting and circuit breakers.")
        
        if avg_response > self.targets["api_response_time_p95"]:
            recommendations.append("Response time degradation under stress. Consider performance optimization.")
        
        return recommendations
    
    def _summarize_endpoint_results(self, endpoints: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize endpoint benchmark results."""
        summary = {
            "total_endpoints": len(endpoints),
            "excellent_endpoints": 0,
            "good_endpoints": 0,
            "slow_endpoints": 0,
            "poor_endpoints": 0,
            "error_endpoints": 0
        }
        
        for endpoint_data in endpoints.values():
            status = endpoint_data.get("status", "error")
            
            if status == "excellent":
                summary["excellent_endpoints"] += 1
            elif status == "good":
                summary["good_endpoints"] += 1
            elif status == "slow":
                summary["slow_endpoints"] += 1
            elif status == "poor":
                summary["poor_endpoints"] += 1
            else:
                summary["error_endpoints"] += 1
        
        return summary
    
    def _generate_endpoint_recommendations(self, endpoints: Dict[str, Any]) -> List[str]:
        """Generate endpoint-specific recommendations."""
        recommendations = []
        
        for endpoint_name, endpoint_data in endpoints.items():
            status = endpoint_data.get("status", "error")
            
            if status == "poor":
                recommendations.append(f"Endpoint {endpoint_name} has poor performance. Investigate and optimize.")
            elif status == "slow":
                recommendations.append(f"Endpoint {endpoint_name} is slow. Consider caching or optimization.")
            elif status == "error":
                recommendations.append(f"Endpoint {endpoint_name} has errors. Check logs and fix issues.")
        
        return recommendations
    
    def _load_performance_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Load performance test configuration."""
        default_config = {
            "base_url": "http://localhost:8000",
            "auth_token": None,
            "run_endurance_test": False,
            "test_endpoints": [
                "/health/status",
                "/api/users",
                "/auth/login"
            ]
        }
        
        if config_file and Path(config_file).exists():
            with open(config_file) as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config


def main():
    """Main performance test function."""
    parser = argparse.ArgumentParser(description="Healthcare Service Performance Tester")
    parser.add_argument("test_type", choices=["benchmark", "quick", "scalability", "stress", "endpoints"], 
                       help="Type of performance test to run")
    parser.add_argument("--config", help="Performance test configuration file")
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--users", type=int, help="Number of concurrent users (for stress test)")
    parser.add_argument("--duration", type=int, help="Test duration in seconds")
    parser.add_argument("--max-users", type=int, default=500, help="Maximum users for scalability test")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    async def run_tests():
        performance_tester = PerformanceBenchmark(args.config)
        
        try:
            if args.test_type == "benchmark":
                result = await performance_tester.run_comprehensive_benchmark()
            elif args.test_type == "quick":
                result = await performance_tester.run_quick_benchmark()
            elif args.test_type == "scalability":
                result = await performance_tester.run_scalability_test(max_users=args.max_users)
            elif args.test_type == "stress":
                users = args.users or 200
                duration = args.duration or 300
                result = await performance_tester.run_stress_test(users, duration)
            elif args.test_type == "endpoints":
                result = await performance_tester.benchmark_api_endpoints()
            
            # Output results
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                # Print summary
                if "overall_score" in result:
                    print(f"Overall Score: {result['overall_score']}/100")
                
                if "recommendations" in result and result["recommendations"]:
                    print("\nRecommendations:")
                    for rec in result["recommendations"]:
                        print(f"  - {rec}")
                
                if args.verbose:
                    print("\nDetailed Results:")
                    print(json.dumps(result, indent=2))
            
            # Save to file if specified
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"\nResults saved to {args.output}")
            
            # Determine exit code based on results
            if "error" in result:
                return False
            elif "overall_score" in result:
                return result["overall_score"] >= 70  # 70% threshold
            else:
                return True
            
        except Exception as e:
            print(f"ERROR: Performance test failed: {e}")
            return False
    
    # Run async tests
    success = asyncio.run(run_tests())
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main() 